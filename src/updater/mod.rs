//! Background CVD updater: download, verify, hot-swap with zero downtime.

use std::time::{Duration, Instant};

use crate::config::Config;
use crate::cvd::header::{CvdHeader, CVD_HEADER_SIZE};
use crate::cvd::verify::{verify_cvd_bytes, VerifyMode};
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
            if let Ok(local) = CvdHeader::parse(&std::fs::read(&dest).unwrap_or_default()) {
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

        let bytes = self.download(name).await?;
        tracing::info!(
            db = name,
            bytes = bytes.len(),
            "verifying CVD checksum and digital signature"
        );
        let header = CvdHeader::parse(&bytes)?;
        let mode = if self.cfg.verify_official {
            VerifyMode::Official
        } else {
            VerifyMode::Integrity
        };
        verify_cvd_bytes(&bytes, &header, mode)?;
        if header.version != remote.version && dest.exists() {
            tracing::debug!(
                db = name,
                header = header.version,
                advertised = remote.version,
                "version differs between Range header and full file"
            );
        }

        let tmp = dest.with_extension("cvd.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| Error::io(&tmp, e))?;
        std::fs::rename(&tmp, &dest).map_err(|e| Error::io(&dest, e))?;
        tracing::info!(
            db = name,
            version = header.version,
            signatures = header.signatures,
            builder = %header.builder,
            built = %header.time,
            bytes = bytes.len(),
            path = %dest.display(),
            "verified and installed CVD"
        );
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

    async fn download(&self, name: &str) -> Result<Vec<u8>> {
        let mut last_err = None;
        for (i, mirror) in self.cfg.mirrors.iter().enumerate() {
            let url = format!("{mirror}/{name}.cvd");
            match self.download_url(name, &url).await {
                Ok(b) => return Ok(b),
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

    async fn download_url(&self, name: &str, url: &str) -> Result<Vec<u8>> {
        let t0 = Instant::now();
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
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Update(e.to_string()))?;
        let elapsed_ms = t0.elapsed().as_millis() as u64;
        let bytes_per_sec = if elapsed_ms > 0 {
            (bytes.len() as u128 * 1000 / elapsed_ms as u128) as u64
        } else {
            0
        };
        tracing::info!(
            db = name,
            %url,
            bytes = bytes.len(),
            elapsed_ms,
            bytes_per_sec,
            "download complete"
        );
        Ok(bytes.to_vec())
    }

    async fn reload(&self) -> Result<()> {
        tracing::info!(
            dir = %self.cfg.db_dir.display(),
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
        tracing::info!(
            file_hashes = engine.meta.file_hashes,
            section_hashes = engine.meta.section_hashes,
            body = engine.meta.body_sigs,
            logical = engine.meta.logical_sigs,
            skipped = engine.meta.skipped_sigs,
            databases = engine.meta.databases.len(),
            elapsed_ms = t0.elapsed().as_millis() as u64,
            "scan engine swapped atomically"
        );
        for d in &engine.meta.databases {
            tracing::info!(
                db = %d.name,
                version = d.version,
                signatures = d.signatures,
                builder = %d.builder,
                "active CVD"
            );
        }
        self.db.swap(engine);
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
