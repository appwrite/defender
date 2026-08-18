//! End-to-end HTTP benchmarks against a live TCP listener.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use defender::config::Config;
use defender::cvd::unpack::pack_cvd;
use defender::cvd::VerifyMode;
use defender::engine::{hash_bytes, Database, Engine, EICAR};
use defender::http::{router, AppState};
use md5::{Digest, Md5};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

fn bench_cfg() -> Config {
    Config {
        listen: "127.0.0.1:0".into(),
        db_dir: "/tmp".into(),
        update_interval: Duration::from_secs(3600),
        mirrors: vec![],
        max_bytes: 8 * 1024 * 1024,
        load_pua: false,
        verify_official: false,
        user_agent: "defender-bench".into(),
        databases: vec!["bench".into()],
    }
}

fn synthetic_engine() -> Engine {
    let md5 = hex::encode(Md5::digest(EICAR));
    let mut hdb = format!("{md5}:68:Eicar-Test-Signature\n");
    for i in 0u32..10_000 {
        let d = Md5::digest(i.to_le_bytes());
        hdb.push_str(&format!(
            "{}:{}:Win.Test.Bench-{i}\n",
            hex::encode(d),
            16 + (i % 50)
        ));
    }
    let ndb = "Eicar-Test-Signature:0:*:58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a\n";
    let cvd = pack_cvd(
        &[("bench.hdb", hdb.as_bytes()), ("bench.ndb", ndb.as_bytes())],
        1,
        "bench",
    )
    .unwrap();
    Engine::from_cvd_bytes("bench.cvd", &cvd, VerifyMode::Integrity, false).unwrap()
}

#[derive(Clone)]
struct LiveServer {
    base: String,
    client: reqwest::Client,
    eicar_md5: String,
}

impl LiveServer {
    async fn spawn(engine: Engine) -> Self {
        let app = router(AppState {
            db: Database::new(engine),
            cfg: bench_cfg(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(64)
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let base = format!("http://{addr}");
        // Warm the accept path and HTTP parser.
        for _ in 0..8 {
            let _ = client.get(format!("{base}/health")).send().await.unwrap();
        }
        LiveServer {
            base,
            client,
            eicar_md5: hex::encode(Md5::digest(EICAR)),
        }
    }

    async fn get(&self, path: &str) -> reqwest::StatusCode {
        let r = self
            .client
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap();
        let status = r.status();
        let _ = r.bytes().await.unwrap();
        status
    }

    async fn post_bytes(&self, path: &str, body: Vec<u8>) -> (reqwest::StatusCode, String) {
        let r = self
            .client
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await
            .unwrap();
        let status = r.status();
        let text = r.text().await.unwrap();
        (status, text)
    }

    async fn post_json(&self, path: &str, json: String) -> (reqwest::StatusCode, String) {
        let r = self
            .client
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/json")
            .body(json)
            .send()
            .await
            .unwrap();
        let status = r.status();
        let text = r.text().await.unwrap();
        (status, text)
    }
}

fn http_e2e(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let srv = rt.block_on(LiveServer::spawn(synthetic_engine()));
    let hashes = hash_bytes(EICAR);
    let hash_json = serde_json::json!({"md5": hex::encode(hashes.md5), "size": 68}).to_string();
    let hash_lines = format!(
        "{}\n{}\n00000000000000000000000000000000\n",
        srv.eicar_md5,
        hex::encode(hashes.sha256)
    );
    let clean_1k = vec![0x5Au8; 1024];
    let clean_64k = vec![0x5Au8; 64 * 1024];
    let clean_1m = vec![0x5Au8; 1024 * 1024];
    let eicar = EICAR.to_vec();

    let mut g = c.benchmark_group("http_e2e_tcp");
    g.sample_size(50);

    g.throughput(Throughput::Elements(1));
    g.bench_function("GET /health", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(srv.get("/health").await) });
    });
    g.bench_function("GET /info", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(srv.get("/info").await) });
    });
    g.bench_function("POST /scan eicar", |b| {
        let body = eicar.clone();
        b.to_async(&rt).iter(|| async {
            let (st, text) = srv.post_bytes("/scan", body.clone()).await;
            assert_eq!(st, reqwest::StatusCode::OK);
            assert!(text.contains("infected"), "{text}");
            black_box(st)
        });
    });
    g.bench_function("POST /scan/hash eicar md5", |b| {
        let json = hash_json.clone();
        b.to_async(&rt).iter(|| async {
            let (st, text) = srv.post_json("/scan/hash", json.clone()).await;
            assert_eq!(st, reqwest::StatusCode::OK);
            assert!(text.contains("infected"), "{text}");
            black_box(st)
        });
    });
    g.bench_function("POST /scan/hashes 3 lines", |b| {
        let body = hash_lines.clone();
        b.to_async(&rt).iter(|| async {
            let (st, _) = srv
                .post_bytes("/scan/hashes", body.clone().into_bytes())
                .await;
            assert_eq!(st, reqwest::StatusCode::OK);
            black_box(st)
        });
    });

    g.throughput(Throughput::Bytes(clean_1k.len() as u64));
    g.bench_function("POST /scan clean 1KiB", |b| {
        let body = clean_1k.clone();
        b.to_async(&rt).iter(|| async {
            let (st, text) = srv.post_bytes("/scan", body.clone()).await;
            assert_eq!(st, reqwest::StatusCode::OK);
            assert!(text.contains("clean"), "{text}");
            black_box(st)
        });
    });
    g.throughput(Throughput::Bytes(clean_64k.len() as u64));
    g.bench_function("POST /scan clean 64KiB", |b| {
        let body = clean_64k.clone();
        b.to_async(&rt).iter(|| async {
            let (st, text) = srv.post_bytes("/scan", body.clone()).await;
            assert_eq!(st, reqwest::StatusCode::OK);
            assert!(text.contains("clean"), "{text}");
            black_box(st)
        });
    });
    g.throughput(Throughput::Bytes(clean_1m.len() as u64));
    g.bench_function("POST /scan clean 1MiB", |b| {
        let body = clean_1m.clone();
        b.to_async(&rt).iter(|| async {
            let (st, text) = srv.post_bytes("/scan", body.clone()).await;
            assert_eq!(st, reqwest::StatusCode::OK);
            assert!(text.contains("clean"), "{text}");
            black_box(st)
        });
    });

    g.throughput(Throughput::Elements(32));
    g.bench_function("POST /scan eicar x32 concurrent", |b| {
        let body = eicar.clone();
        b.to_async(&rt).iter(|| async {
            let mut set = tokio::task::JoinSet::new();
            for _ in 0..32 {
                let srv = srv.clone();
                let body = body.clone();
                set.spawn(async move { srv.post_bytes("/scan", body).await });
            }
            while let Some(res) = set.join_next().await {
                let (st, text) = res.unwrap();
                assert_eq!(st, reqwest::StatusCode::OK);
                assert!(text.contains("infected"), "{text}");
            }
        });
    });
    g.finish();
}

fn http_e2e_official_daily(c: &mut Criterion) {
    let path = "/tmp/defender-db/daily.cvd";
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skip http_e2e_official_daily: {path} missing");
        return;
    };
    let rt = Runtime::new().unwrap();
    let engine = Engine::from_cvd_bytes("daily.cvd", &bytes, VerifyMode::Official, false)
        .expect("official daily.cvd");
    eprintln!(
        "official daily engine: hashes={} body={} logical={}",
        engine.meta.file_hashes, engine.meta.body_sigs, engine.meta.logical_sigs
    );
    let srv = rt.block_on(LiveServer::spawn(engine));
    let hashes = hash_bytes(EICAR);
    let hash_json = serde_json::json!({"md5": hex::encode(hashes.md5), "size": 68}).to_string();
    let eicar = EICAR.to_vec();
    let clean_64k = vec![0x5Au8; 64 * 1024];

    let mut g = c.benchmark_group("http_e2e_tcp_daily_cvd");
    g.sample_size(40);
    g.throughput(Throughput::Elements(1));
    g.bench_function("POST /scan eicar", |b| {
        let body = eicar.clone();
        b.to_async(&rt).iter(|| async {
            let (st, text) = srv.post_bytes("/scan", body.clone()).await;
            assert_eq!(st, reqwest::StatusCode::OK);
            assert!(text.contains("infected"), "{text}");
            black_box(st)
        });
    });
    g.bench_function("POST /scan/hash eicar md5", |b| {
        let json = hash_json.clone();
        b.to_async(&rt).iter(|| async {
            let (st, text) = srv.post_json("/scan/hash", json.clone()).await;
            assert_eq!(st, reqwest::StatusCode::OK);
            assert!(text.contains("infected"), "{text}");
            black_box(st)
        });
    });
    g.throughput(Throughput::Bytes(clean_64k.len() as u64));
    g.bench_function("POST /scan clean 64KiB", |b| {
        let body = clean_64k.clone();
        b.to_async(&rt).iter(|| async {
            let (st, text) = srv.post_bytes("/scan", body.clone()).await;
            assert_eq!(st, reqwest::StatusCode::OK);
            assert!(text.contains("clean"), "{text}");
            black_box(st)
        });
    });
    g.throughput(Throughput::Elements(16));
    g.bench_function("POST /scan eicar x16 concurrent", |b| {
        let body = eicar.clone();
        b.to_async(&rt).iter(|| async {
            let mut set = tokio::task::JoinSet::new();
            for _ in 0..16 {
                let srv = srv.clone();
                let body = body.clone();
                set.spawn(async move { srv.post_bytes("/scan", body).await });
            }
            while let Some(res) = set.join_next().await {
                let (st, text) = res.unwrap();
                assert_eq!(st, reqwest::StatusCode::OK);
                assert!(text.contains("infected"), "{text}");
            }
        });
    });
    g.finish();
}

criterion_group!(benches, http_e2e, http_e2e_official_daily);
criterion_main!(benches);
