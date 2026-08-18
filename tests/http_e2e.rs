//! Live TCP end-to-end checks for the HTTP server.

use std::time::Duration;

use defender::config::Config;
use defender::cvd::unpack::pack_cvd;
use defender::cvd::VerifyMode;
use defender::engine::{hash_bytes, Database, Engine, EICAR};
use defender::http::{router, AppState};
use md5::{Digest, Md5};
use tokio::net::TcpListener;

fn cfg() -> Config {
    Config {
        listen: "127.0.0.1:0".into(),
        db_dir: "/tmp".into(),
        update_interval: Duration::from_secs(3600),
        mirrors: vec![],
        max_bytes: 1024 * 1024,
        load_pua: false,
        verify_official: false,
        user_agent: "e2e".into(),
        databases: vec!["t".into()],
    }
}

async fn spawn() -> (String, reqwest::Client) {
    let md5 = hex::encode(Md5::digest(EICAR));
    let hdb = format!("{md5}:68:Eicar-Test-Signature\n");
    let cvd = pack_cvd(&[("t.hdb", hdb.as_bytes())], 1, "e2e").unwrap();
    let eng = Engine::from_cvd_bytes("t", &cvd, VerifyMode::Integrity, false).unwrap();
    let app = router(AppState {
        db: Database::new(eng),
        cfg: cfg(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    (format!("http://{addr}"), client)
}

#[tokio::test]
async fn tcp_scan_and_hash() {
    let (base, client) = spawn().await;
    let health: serde_json::Value = client
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");

    let infected: serde_json::Value = client
        .post(format!("{base}/scan"))
        .header("content-type", "application/octet-stream")
        .body(EICAR.to_vec())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(infected["result"], "infected");
    assert!(infected["signature"].as_str().unwrap().contains("Eicar"));

    let clean: serde_json::Value = client
        .post(format!("{base}/scan"))
        .body("not malware")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(clean["result"], "clean");

    let h = hash_bytes(EICAR);
    let looked: serde_json::Value = client
        .post(format!("{base}/scan/hash"))
        .json(&serde_json::json!({"md5": hex::encode(h.md5), "size": 68}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(looked["result"], "infected");
    assert_eq!(looked["md5"], hex::encode(h.md5));
}
