use std::io::IsTerminal;
use std::path::Path;
use std::time::Instant;

use anyhow::Context;
use tracing_subscriber::EnvFilter;

use defender::config::Config;
use defender::cvd::VerifyMode;
use defender::engine::{Database, Engine};
use defender::http;
use defender::updater::Updater;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = Config::from_env();
    tracing::info!(
        version = VERSION,
        listen = %cfg.listen,
        db_dir = %cfg.db_dir.display(),
        databases = ?cfg.databases,
        mirrors = ?cfg.mirrors,
        update_interval_secs = cfg.update_interval.as_secs(),
        max_bytes = cfg.max_bytes,
        verify_official = cfg.verify_official,
        load_pua = cfg.load_pua,
        "starting defender"
    );
    if !cfg.verify_official {
        tracing::warn!(
            "CVD digital signature verification is disabled (DEFENDER_SKIP_DSIG); MD5 is still checked"
        );
    }

    if let Err(e) = std::fs::create_dir_all(&cfg.db_dir) {
        tracing::error!(
            db_dir = %cfg.db_dir.display(),
            error = %e,
            "could not create database directory"
        );
    }

    let t0 = Instant::now();
    let engine = load_startup_engine(&cfg);
    log_engine_summary(&engine, t0.elapsed().as_millis() as u64);
    let db = Database::new(engine);

    let updater = Updater::new(cfg.clone(), db.clone()).context("http client")?;
    let interval_secs = cfg.update_interval.as_secs();
    tokio::spawn(async move {
        tracing::info!("running initial virus database refresh");
        match updater.tick().await {
            Ok(true) => tracing::info!("initial virus database refresh applied a new engine"),
            Ok(false) => tracing::info!("initial virus database refresh: already current"),
            Err(e) => tracing::warn!(error = %e, "initial virus database refresh failed"),
        }
        tracing::info!(interval_secs, "database updater scheduled");
        updater.run().await;
    });

    http::serve(cfg, db).await.context("http server")?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .with_ansi(std::io::stdout().is_terminal())
        .compact()
        .init();
}

fn log_engine_summary(engine: &Engine, elapsed_ms: u64) {
    let sigs = engine.meta.file_hashes + engine.meta.body_sigs + engine.meta.logical_sigs;
    if engine.meta.databases.is_empty() && sigs == 0 {
        tracing::warn!(
            elapsed_ms,
            "startup engine is empty; scans return clean until a database is loaded"
        );
        return;
    }
    tracing::info!(
        file_hashes = engine.meta.file_hashes,
        section_hashes = engine.meta.section_hashes,
        body = engine.meta.body_sigs,
        logical = engine.meta.logical_sigs,
        skipped = engine.meta.skipped_sigs,
        databases = engine.meta.databases.len(),
        elapsed_ms,
        "startup engine ready"
    );
}

fn load_startup_engine(cfg: &Config) -> Engine {
    if !Path::new(&cfg.db_dir).exists() {
        tracing::warn!(
            db_dir = %cfg.db_dir.display(),
            "database directory does not exist; starting with an empty engine"
        );
        return Engine::empty();
    }
    let mode = if cfg.verify_official {
        VerifyMode::Official
    } else {
        VerifyMode::Integrity
    };
    tracing::info!(
        db_dir = %cfg.db_dir.display(),
        verify = ?mode,
        load_pua = cfg.load_pua,
        "loading local virus databases"
    );
    match Engine::load_dir(&cfg.db_dir, mode, cfg.load_pua) {
        Ok(eng) => eng,
        Err(e) => {
            tracing::error!(
                error = %e,
                "failed to load local database; starting with an empty engine"
            );
            Engine::empty()
        }
    }
}
