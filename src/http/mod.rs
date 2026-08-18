//! Streaming HTTP API for file and hash scanning.

use std::time::Instant;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::engine::{Database, IncrementalHashers, ScanVerdict};
use crate::error::Error;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub cfg: Config,
}

#[derive(Debug, Deserialize)]
pub struct ScanQuery {
    pub filename: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub duration_us: u64,
}

#[derive(Debug, Deserialize)]
pub struct HashRequest {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub hash: Option<String>,
    pub size: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct InfoResponse {
    pub databases: Vec<DbInfoJson>,
    pub signatures: SigCounts,
    pub loaded_at_unix: u64,
}

#[derive(Debug, Serialize)]
pub struct DbInfoJson {
    pub name: String,
    pub version: u32,
    pub header_signatures: u32,
    pub flevel: u32,
    pub builder: String,
    pub time: String,
    pub md5: String,
}

#[derive(Debug, Serialize)]
pub struct SigCounts {
    pub file_hash: usize,
    pub section_hash: usize,
    pub body: usize,
    pub logical: usize,
    pub skipped: usize,
}

pub fn router(state: AppState) -> Router {
    let max = state.cfg.max_bytes as usize;
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/info", get(info))
        .route("/scan", post(scan))
        .route("/scan/hash", post(scan_hash))
        .route("/scan/hashes", post(scan_hashes))
        .with_state(state)
        .layer(DefaultBodyLimit::max(max.saturating_add(1024 * 1024)))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(300)))
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    let eng = state.db.current();
    let ready = eng.meta.file_hashes + eng.meta.body_sigs + eng.meta.logical_sigs > 0
        || !eng.meta.databases.is_empty();
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(serde_json::json!({
            "ready": ready,
            "file_hashes": eng.meta.file_hashes,
            "body_sigs": eng.meta.body_sigs,
        })),
    )
}

async fn info(State(state): State<AppState>) -> impl IntoResponse {
    let eng = state.db.current();
    Json(InfoResponse {
        databases: eng
            .meta
            .databases
            .iter()
            .map(|d| DbInfoJson {
                name: d.name.clone(),
                version: d.version,
                header_signatures: d.signatures,
                flevel: d.flevel,
                builder: d.builder.clone(),
                time: d.time.clone(),
                md5: d.md5.clone(),
            })
            .collect(),
        signatures: SigCounts {
            file_hash: eng.meta.file_hashes,
            section_hash: eng.meta.section_hashes,
            body: eng.meta.body_sigs,
            logical: eng.meta.logical_sigs,
            skipped: eng.meta.skipped_sigs,
        },
        loaded_at_unix: eng.meta.loaded_at_unix,
    })
}

async fn scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<ScanQuery>,
    request: axum::extract::Request,
) -> Response {
    let ctype = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ctype.starts_with("multipart/form-data") {
        return match Multipart::from_request(request, &()).await {
            Ok(mp) => match scan_multipart_fields(state, mp).await {
                Ok(r) => r.into_response(),
                Err(e) => error_response(e),
            },
            Err(e) => error_response(Error::Http(e.to_string())),
        };
    }
    match scan_body(state, request.into_body()).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => error_response(e),
    }
}

async fn scan_multipart_fields(
    state: AppState,
    mut multipart: Multipart,
) -> Result<Json<ScanResponse>, Error> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| Error::Http(e.to_string()))?
    {
        let bytes = field
            .bytes()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        if bytes.len() as u64 > state.cfg.max_bytes {
            return Err(Error::PayloadTooLarge(state.cfg.max_bytes));
        }
        let mut hasher = IncrementalHashers::new();
        hasher.update(&bytes);
        let hashes = hasher.finalize();
        return Ok(Json(finish_scan(&state, &bytes, &hashes)));
    }
    Err(Error::Http("multipart body had no file field".into()))
}

async fn scan_body(state: AppState, body: Body) -> Result<ScanResponse, Error> {
    let mut hasher = IncrementalHashers::new();
    let mut buf = Vec::new();
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Error::Http(e.to_string()))?;
        hasher.update(&chunk);
        if hasher.len() > state.cfg.max_bytes {
            return Err(Error::PayloadTooLarge(state.cfg.max_bytes));
        }
        buf.extend_from_slice(&chunk);
    }
    let hashes = hasher.finalize();
    Ok(finish_scan(&state, &buf, &hashes))
}

fn finish_scan(state: &AppState, data: &[u8], hashes: &crate::engine::HashBytes) -> ScanResponse {
    let t0 = Instant::now();
    let eng = state.db.current();
    let result = eng.scan_prehashed(data, hashes);
    let duration_us = t0.elapsed().as_micros() as u64;
    match result.verdict {
        ScanVerdict::Clean => ScanResponse {
            result: "clean",
            signature: None,
            size: result.hashes.size,
            md5: result.hashes.md5,
            sha1: result.hashes.sha1,
            sha256: result.hashes.sha256,
            duration_us,
        },
        ScanVerdict::Infected { signature } => ScanResponse {
            result: "infected",
            signature: Some(signature),
            size: result.hashes.size,
            md5: result.hashes.md5,
            sha1: result.hashes.sha1,
            sha256: result.hashes.sha256,
            duration_us,
        },
    }
}

async fn scan_hash(State(state): State<AppState>, Json(req): Json<HashRequest>) -> Response {
    let t0 = Instant::now();
    let digest = req.hash.or(req.sha256).or(req.sha1).or(req.md5);
    let Some(digest) = digest else {
        return error_response(Error::InvalidHash("missing hash field".into()));
    };
    let eng = state.db.current();
    match eng.lookup_hex(&digest, req.size) {
        Ok(Some(signature)) => Json(ScanResponse {
            result: "infected",
            signature: Some(signature),
            size: req.size.unwrap_or(0),
            md5: String::new(),
            sha1: String::new(),
            sha256: digest,
            duration_us: t0.elapsed().as_micros() as u64,
        })
        .into_response(),
        Ok(None) => Json(ScanResponse {
            result: "clean",
            signature: None,
            size: req.size.unwrap_or(0),
            md5: String::new(),
            sha1: String::new(),
            sha256: digest,
            duration_us: t0.elapsed().as_micros() as u64,
        })
        .into_response(),
        Err(e) => error_response(e),
    }
}

async fn scan_hashes(State(state): State<AppState>, body: Body) -> Response {
    let mut stream = body.into_data_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(c) => {
                if buf.len() + c.len() > 16 * 1024 * 1024 {
                    return error_response(Error::PayloadTooLarge(16 * 1024 * 1024));
                }
                buf.extend_from_slice(&c);
            }
            Err(e) => return error_response(Error::Http(e.to_string())),
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let eng = state.db.current();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (digest, size) = if line.starts_with('{') {
            match serde_json::from_str::<HashRequest>(line) {
                Ok(r) => (
                    r.hash.or(r.sha256).or(r.sha1).or(r.md5).unwrap_or_default(),
                    r.size,
                ),
                Err(_) => {
                    out.push(serde_json::json!({"error": "invalid json", "line": line}));
                    continue;
                }
            }
        } else if let Some((algo, hex)) = line.split_once(':') {
            let _ = algo;
            (hex.to_string(), None)
        } else {
            (line.to_string(), None)
        };
        match eng.lookup_hex(&digest, size) {
            Ok(Some(sig)) => out.push(serde_json::json!({
                "result": "infected",
                "hash": digest,
                "signature": sig
            })),
            Ok(None) => out.push(serde_json::json!({
                "result": "clean",
                "hash": digest
            })),
            Err(e) => out.push(serde_json::json!({"error": e.to_string(), "hash": digest})),
        }
    }
    Json(out).into_response()
}

fn error_response(e: Error) -> Response {
    let (code, msg) = match &e {
        Error::PayloadTooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, e.to_string()),
        Error::InvalidHash(_) => (StatusCode::BAD_REQUEST, e.to_string()),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    (code, Json(serde_json::json!({"error": msg}))).into_response()
}

pub async fn serve(cfg: Config, db: Database) -> anyhow::Result<()> {
    let addr = cfg.listen.clone();
    let app = router(AppState { db, cfg });
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "defender listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cvd::unpack::pack_cvd;
    use crate::cvd::VerifyMode;
    use crate::engine::{hash_bytes, Engine, EICAR};
    use axum::body::Body;
    use axum::http::Request;
    use md5::{Digest, Md5};
    use tower::ServiceExt;

    fn test_cfg() -> Config {
        Config {
            listen: "127.0.0.1:0".into(),
            db_dir: "/tmp".into(),
            update_interval: std::time::Duration::from_secs(3600),
            mirrors: vec![],
            max_bytes: 1024 * 1024,
            load_pua: false,
            verify_official: false,
            user_agent: "test".into(),
            databases: vec!["main".into()],
        }
    }

    fn test_app() -> Router {
        let md5 = hex::encode(Md5::digest(EICAR));
        let hdb = format!("{md5}:68:Eicar-Test-Signature\n");
        let cvd = pack_cvd(&[("t.hdb", hdb.as_bytes())], 1, "u").unwrap();
        let eng = Engine::from_cvd_bytes("t", &cvd, VerifyMode::Integrity, false).unwrap();
        router(AppState {
            db: Database::new(eng),
            cfg: test_cfg(),
        })
    }

    async fn send(app: Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
        (status, v)
    }

    #[tokio::test]
    async fn health_ok() {
        let (st, v) = send(
            test_app(),
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["status"], "ok");
    }

    #[tokio::test]
    async fn scan_eicar_stream() {
        let (st, v) = send(
            test_app(),
            Request::builder()
                .method("POST")
                .uri("/scan")
                .header("content-type", "application/octet-stream")
                .body(Body::from(EICAR.to_vec()))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["result"], "infected");
        assert!(v["signature"].as_str().unwrap().contains("Eicar"));
    }

    #[tokio::test]
    async fn scan_clean() {
        let (st, v) = send(
            test_app(),
            Request::builder()
                .method("POST")
                .uri("/scan")
                .body(Body::from(&b"not a virus"[..]))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["result"], "clean");
    }

    #[tokio::test]
    async fn scan_hash_endpoint() {
        let h = hash_bytes(EICAR);
        let _body = serde_json::json!({"sha256": hex::encode(h.sha256), "size": 68});
        // only md5 is in the test db
        let body = serde_json::json!({"md5": hex::encode(h.md5), "size": 68});
        let (st, v) = send(
            test_app(),
            Request::builder()
                .method("POST")
                .uri("/scan/hash")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["result"], "infected");
        let _ = h;
    }

    #[tokio::test]
    async fn scan_hashes_stream() {
        let h = hash_bytes(EICAR);
        let md5 = hex::encode(h.md5);
        let body = format!("{md5}\n00000000000000000000000000000000\n");
        let (st, v) = send(
            test_app(),
            Request::builder()
                .method("POST")
                .uri("/scan/hashes")
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(v.is_array());
        assert_eq!(v[0]["result"], "infected");
        assert_eq!(v[1]["result"], "clean");
    }

    #[tokio::test]
    async fn info_and_ready() {
        let (st, v) = send(
            test_app(),
            Request::builder().uri("/info").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(v["signatures"]["file_hash"].as_u64().unwrap() >= 1);
        let (st, _) = send(
            test_app(),
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    #[tokio::test]
    async fn payload_too_large() {
        let mut cfg = test_cfg();
        cfg.max_bytes = 8;
        let md5 = hex::encode(Md5::digest(EICAR));
        let hdb = format!("{md5}:68:Eicar-Test-Signature\n");
        let cvd = pack_cvd(&[("t.hdb", hdb.as_bytes())], 1, "u").unwrap();
        let eng = Engine::from_cvd_bytes("t", &cvd, VerifyMode::Integrity, false).unwrap();
        let app = router(AppState {
            db: Database::new(eng),
            cfg,
        });
        let (st, _) = send(
            app,
            Request::builder()
                .method("POST")
                .uri("/scan")
                .body(Body::from(vec![0u8; 64]))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
