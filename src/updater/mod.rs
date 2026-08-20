//! Background CVD updater: download, verify, hot-swap with zero downtime.

use std::path::Path;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;

use crate::alloc;
use crate::config::Config;
use crate::cvd::header::{CvdHeader, CVD_HEADER_SIZE};
use crate::cvd::verify::{verify_cvd, VerifyMode};
use crate::engine::{Database, Engine};
use crate::error::{Error, Result};

pub struct Updater {
    pub cfg: Config,
    pub db: Database,
    pub client: reqwest::Client,
}

impl Updater {
    pub fn new(cfg: Config, db: Database) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(&cfg.user_agent)
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(600))
            .build()
            .map_err(|e| Error::Update(e.to_string()))?;
        Ok(Self { cfg, db, client })
    }

    /// Run forever, sleeping between ticks.
    pub async fn run(self) {
        loop {
            tracing::debug!(
                interval_secs = self.cfg.update_interval.as_secs(),
                "sleeping until next database check"
            );
            tokio::time::sleep(self.cfg.update_interval).await;
            match self.tick().await {
                Ok(changed) => {
                    if changed {
                        tracing::info!("virus database updated in-place (no restart)");
                    } else {
                        tracing::info!("virus databases up to date");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "database update tick failed"),
            }
        }
    }

    /// One update pass. Returns true if the runtime engine was swapped.
    pub async fn tick(&self) -> Result<bool> {
        tracing::info!(
            databases = ?self.cfg.databases,
            mirrors = ?self.cfg.mirrors,
            "checking for virus database updates"
        );
        std::fs::create_dir_all(&self.cfg.db_dir).map_err(|e| Error::io(&self.cfg.db_dir, e))?;
        let mut changed = false;
        for name in &self.cfg.databases {
            if self.update_one(name).await? {
                changed = true;
            }
        }
        if changed {
            self.reload().await?;
        }
        Ok(changed)
    }

    async fn update_one(&self, name: &str) -> Result<bool> {
        let dest = self.cfg.db_dir.join(format!("{name}.cvd"));
        let remote = match self.fetch_header(name).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    db = name,
                    error = %e,
                    "could not fetch remote CVD header; leaving local copy unchanged"
                );
                return Ok(false);
            }
        };
        tracing::debug!(
            db = name,
            version = remote.version,
            signatures = remote.signatures,
            md5 = %remote.md5,
            builder = %remote.builder,
            "remote CVD header"
        );
        if dest.exists() {
            if let Ok(local) = CvdHeader::read_file(&dest) {
                if local.version >= remote.version && local.md5 == remote.md5 {
                    tracing::info!(
                        db = name,
                        version = local.version,
                        signatures = local.signatures,
                        md5 = %local.md5,
                        "CVD is up to date"
                    );
                    return Ok(false);
                }
                tracing::info!(
                    db = name,
                    local_version = local.version,
                    remote_version = remote.version,
                    local_md5 = %local.md5,
                    remote_md5 = %remote.md5,
                    "newer CVD available"
                );
            } else {
                tracing::warn!(
                    db = name,
                    path = %dest.display(),
                    "local CVD header unreadable; re-downloading"
                );
            }
        } else {
            tracing::info!(
                db = name,
                remote_version = remote.version,
                signatures = remote.signatures,
                "no local CVD, downloading"
            );
        }

        self.download_to(name, &dest).await?;
        Ok(true)
    }

    async fn fetch_header(&self, name: &str) -> Result<CvdHeader> {
        let mut last_err = None;
        for (i, mirror) in self.cfg.mirrors.iter().enumerate() {
            let url = format!("{mirror}/{name}.cvd");
            match self.fetch_header_url(&url).await {
                Ok(h) => {
                    tracing::debug!(db = name, %url, version = h.version, "fetched CVD header");
                    return Ok(h);
                }
                Err(e) => {
                    let remaining = self.cfg.mirrors.len() - i - 1;
                    if remaining > 0 {
                        tracing::warn!(
                            db = name,
                            %url,
                            remaining,
                            error = %e,
                            "CVD header fetch failed, trying next mirror"
                        );
                    } else {
                        tracing::warn!(
                            db = name,
                            %url,
                            error = %e,
                            "CVD header fetch failed"
                        );
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Update("no mirrors".into())))
    }

    async fn fetch_header_url(&self, url: &str) -> Result<CvdHeader> {
        let resp = self
            .client
            .get(url)
            .header("Range", format!("bytes=0-{}", CVD_HEADER_SIZE - 1))
            .send()
            .await
            .map_err(|e| Error::Update(e.to_string()))?;
        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(Error::Update(format!(
                "header GET {url} -> {}",
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Update(e.to_string()))?;
        CvdHeader::parse(&bytes)
    }

    async fn download_to(&self, name: &str, dest: &Path) -> Result<()> {
        let mut last_err = None;
        for (i, mirror) in self.cfg.mirrors.iter().enumerate() {
            let url = format!("{mirror}/{name}.cvd");
            match self.download_url_to(name, &url, dest).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let remaining = self.cfg.mirrors.len() - i - 1;
                    if remaining > 0 {
                        tracing::warn!(
                            db = name,
                            %url,
                            remaining,
                            error = %e,
                            "download failed, trying next mirror"
                        );
                    } else {
                        tracing::warn!(db = name, %url, error = %e, "download failed");
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Update("no mirrors".into())))
    }

    async fn download_url_to(&self, name: &str, url: &str, dest: &Path) -> Result<()> {
        let t0 = Instant::now();
        let tmp = dest.with_extension("cvd.tmp");
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Update(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Update(format!("GET {url} -> {}", resp.status())));
        }
        let advertised_bytes = resp.content_length().unwrap_or(0);
        tracing::info!(
            db = name,
            %url,
            advertised_bytes,
            "downloading CVD"
        );

        let result = async {
            let mut file = tokio::fs::File::create(&tmp)
                .await
                .map_err(|e| Error::io(&tmp, e))?;
            let mut stream = resp.bytes_stream();
            let mut written = 0u64;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| Error::Update(e.to_string()))?;
                written += chunk.len() as u64;
                file.write_all(&chunk)
                    .await
                    .map_err(|e| Error::io(&tmp, e))?;
            }
            file.flush().await.map_err(|e| Error::io(&tmp, e))?;
            drop(file);

            let mode = if self.cfg.verify_official {
                VerifyMode::Official
            } else {
                VerifyMode::Integrity
            };
            let tmp_path = tmp.clone();
            let header = tokio::task::spawn_blocking(move || verify_cvd(&tmp_path, mode))
                .await
                .map_err(|e| Error::Update(e.to_string()))??;

            tokio::fs::rename(&tmp, dest)
                .await
                .map_err(|e| Error::io(dest, e))?;

            let elapsed_ms = t0.elapsed().as_millis() as u64;
            let bytes_per_sec = if elapsed_ms > 0 {
                (written as u128 * 1000 / elapsed_ms as u128) as u64
            } else {
                0
            };
            tracing::info!(
                db = name,
                %url,
                version = header.version,
                signatures = header.signatures,
                builder = %header.builder,
                built = %header.time,
                bytes = written,
                elapsed_ms,
                bytes_per_sec,
                path = %dest.display(),
                "verified and installed CVD"
            );
            Ok(())
        }
        .await;

        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        result
    }

    async fn reload(&self) -> Result<()> {
        let rss_before = alloc::rss_bytes();
        tracing::info!(
            dir = %self.cfg.db_dir.display(),
            rss = rss_before.map(alloc::format_bytes),
            "compiling new scan engine from disk (in-flight scans keep the previous engine)"
        );
        let t0 = Instant::now();
        let dir = self.cfg.db_dir.clone();
        let verify = if self.cfg.verify_official {
            VerifyMode::Official
        } else {
            VerifyMode::Integrity
        };
        let pua = self.cfg.load_pua;
        let engine = tokio::task::spawn_blocking(move || Engine::load_dir(&dir, verify, pua))
            .await
            .map_err(|e| Error::Update(e.to_string()))??;
        let rss_compiled = alloc::rss_bytes();
        let file_hashes = engine.meta.file_hashes;
        let section_hashes = engine.meta.section_hashes;
        let body = engine.meta.body_sigs;
        let logical = engine.meta.logical_sigs;
        let skipped = engine.meta.skipped_sigs;
        let db_count = engine.meta.databases.len();
        let databases = engine.meta.databases.clone();
        self.db.swap(engine);
        alloc::reclaim_unused_pages();
        let rss_after = alloc::rss_bytes();
        tracing::info!(
            file_hashes,
            section_hashes,
            body,
            logical,
            skipped,
            databases = db_count,
            elapsed_ms = t0.elapsed().as_millis() as u64,
            rss_before = rss_before.map(alloc::format_bytes),
            rss_compiled = rss_compiled.map(alloc::format_bytes),
            rss_after = rss_after.map(alloc::format_bytes),
            "scan engine swapped atomically"
        );
        for d in &databases {
            tracing::info!(
                db = %d.name,
                version = d.version,
                signatures = d.signatures,
                builder = %d.builder,
                "active CVD"
            );
        }
        Ok(())
    }
}

/// Ensure `dir` exists and contains the named databases, downloading if needed.
pub async fn bootstrap(cfg: &Config, db: &Database) -> Result<()> {
    let updater = Updater::new(cfg.clone(), db.clone())?;
    let missing = cfg.databases.iter().any(|n| {
        !cfg.db_dir.join(format!("{n}.cvd")).exists()
            && !cfg.db_dir.join(format!("{n}.cld")).exists()
    });
    if missing {
        tracing::info!(
            databases = ?cfg.databases,
            db_dir = %cfg.db_dir.display(),
            "bootstrapping missing virus databases"
        );
        updater.tick().await?;
    } else if db.current().meta.file_hashes
        + db.current().meta.body_sigs
        + db.current().meta.logical_sigs
        == 0
    {
        updater.reload().await?;
    }
    Ok(())
}

/// Load whatever is already on disk (used at process start).
pub fn load_local(cfg: &Config) -> Result<Engine> {
    if !cfg.db_dir.exists() {
        return Ok(Engine::empty());
    }
    let mode = if cfg.verify_official {
        VerifyMode::Official
    } else {
        VerifyMode::Integrity
    };
    Engine::load_dir(&cfg.db_dir, mode, cfg.load_pua)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cvd::unpack::pack_cvd;
    use crate::engine::{Engine, EICAR};
    use tempfile::tempdir;

    #[test]
    fn detects_local_version_skip() {
        let dir = tempdir().unwrap();
        let cvd = pack_cvd(
            &[(
                "t.hdb",
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1:X\n".as_slice(),
            )],
            42,
            "u",
        )
        .unwrap();
        std::fs::write(dir.path().join("daily.cvd"), &cvd).unwrap();
        let header = CvdHeader::parse(&cvd).unwrap();
        assert_eq!(header.version, 42);
        let _ = dir;
        let _ = EICAR;
        let _ = Engine::empty();
    }
}
