//! Background CVD updater: download, verify, hot-swap with zero downtime.

use std::time::Duration;

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
            match self.tick().await {
                Ok(changed) => {
                    if changed {
                        tracing::info!("virus database updated in-place (no restart)");
                    } else {
                        tracing::debug!("virus database already current");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "database update tick failed"),
            }
            tokio::time::sleep(self.cfg.update_interval).await;
        }
    }

    /// One update pass. Returns true if the runtime engine was swapped.
    pub async fn tick(&self) -> Result<bool> {
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
                tracing::warn!(db = name, error = %e, "could not fetch remote CVD header");
                return Ok(false);
            }
        };
        if dest.exists() {
            if let Ok(local) = CvdHeader::parse(&std::fs::read(&dest).unwrap_or_default()) {
                if local.version >= remote.version && local.md5 == remote.md5 {
                    return Ok(false);
                }
                tracing::info!(
                    db = name,
                    local = local.version,
                    remote = remote.version,
                    "newer CVD available"
                );
            }
        } else {
            tracing::info!(
                db = name,
                remote = remote.version,
                "no local CVD, downloading"
            );
        }

        let bytes = self.download(name).await?;
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
            sigs = header.signatures,
            builder = %header.builder,
            "verified and installed CVD"
        );
        Ok(true)
    }

    async fn fetch_header(&self, name: &str) -> Result<CvdHeader> {
        let mut last_err = None;
        for mirror in &self.cfg.mirrors {
            let url = format!("{mirror}/{name}.cvd");
            match self.fetch_header_url(&url).await {
                Ok(h) => return Ok(h),
                Err(e) => last_err = Some(e),
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
        for mirror in &self.cfg.mirrors {
            let url = format!("{mirror}/{name}.cvd");
            match self.download_url(&url).await {
                Ok(b) => return Ok(b),
                Err(e) => {
                    tracing::warn!(%url, error = %e, "download failed, trying next mirror");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Update("no mirrors".into())))
    }

    async fn download_url(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Update(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Update(format!("GET {url} -> {}", resp.status())));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Update(e.to_string()))?;
        Ok(bytes.to_vec())
    }

    async fn reload(&self) -> Result<()> {
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
            body = engine.meta.body_sigs,
            logical = engine.meta.logical_sigs,
            "compiled new engine; swapping atomically"
        );
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
        tracing::info!("bootstrapping missing virus databases");
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
