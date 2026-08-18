use std::path::Path;

use anyhow::Context;
use tracing_subscriber::EnvFilter;

use defender::config::Config;
use defender::cvd::VerifyMode;
use defender::engine::{Database, Engine};
use defender::http;
use defender::updater::Updater;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env();
    tracing::info!(
        db_dir = %cfg.db_dir.display(),
        listen = %cfg.listen,
        mirrors = ?cfg.mirrors,
        "starting defender"
    );

    if let Err(e) = std::fs::create_dir_all(&cfg.db_dir) {
        tracing::warn!(error = %e, "could not create db dir");
    }

    let engine = load_startup_engine(&cfg);
    tracing::info!(
        file_hashes = engine.meta.file_hashes,
        body = engine.meta.body_sigs,
        logical = engine.meta.logical_sigs,
        dbs = engine.meta.databases.len(),
        "loaded local virus database"
    );
    let db = Database::new(engine);

    let updater = Updater::new(cfg.clone(), db.clone()).context("http client")?;
    tokio::spawn(async move {
        // Catch up immediately, then poll forever. Swaps the live engine
        // without dropping in-flight scans.
        if let Err(e) = updater.tick().await {
            tracing::warn!(error = %e, "initial database refresh failed");
        }
        updater.run().await;
    });

    http::serve(cfg, db).await.context("http server")?;
    Ok(())
}

fn load_startup_engine(cfg: &Config) -> Engine {
    if !Path::new(&cfg.db_dir).exists() {
        return Engine::empty();
    }
    let mode = if cfg.verify_official {
        VerifyMode::Official
    } else {
        VerifyMode::Integrity
    };
    match Engine::load_dir(&cfg.db_dir, mode, cfg.load_pua) {
        Ok(eng) => eng,
        Err(e) => {
            tracing::error!(error = %e, "failed to load local database; starting empty");
            Engine::empty()
        }
    }
}
