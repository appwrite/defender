//! Runtime configuration from environment variables.

use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: String,
    pub db_dir: PathBuf,
    pub update_interval: Duration,
    pub mirrors: Vec<String>,
    pub max_bytes: u64,
    pub load_pua: bool,
    pub verify_official: bool,
    pub user_agent: String,
    pub databases: Vec<String>,
}

impl Config {
    pub fn from_env() -> Self {
        let listen = std::env::var("DEFENDER_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
        let db_dir = PathBuf::from(
            std::env::var("DEFENDER_DB_DIR").unwrap_or_else(|_| "/var/lib/defender/db".into()),
        );
        let secs: u64 = std::env::var("DEFENDER_UPDATE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600);
        let mirrors = std::env::var("DEFENDER_MIRRORS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().trim_end_matches('/').to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .filter(|v: &Vec<String>| !v.is_empty())
            .unwrap_or_else(|| {
                vec![
                    "https://database.clamav.net".into(),
                    "https://packages.microsoft.com/clamav".into(),
                ]
            });
        let max_bytes: u64 = std::env::var("DEFENDER_MAX_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(64 * 1024 * 1024);
        let load_pua = std::env::var("DEFENDER_LOAD_PUA")
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let verify_official = std::env::var("DEFENDER_SKIP_DSIG")
            .map(|s| s != "1" && !s.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        let user_agent = std::env::var("DEFENDER_USER_AGENT")
            .unwrap_or_else(|_| "ClamAV/1.4.2 (defender; rust-http)".into());
        let databases = std::env::var("DEFENDER_DATABASES")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .filter(|v: &Vec<String>| !v.is_empty())
            .unwrap_or_else(|| vec!["main".into(), "daily".into()]);
        Self {
            listen,
            db_dir,
            update_interval: Duration::from_secs(secs.max(30)),
            mirrors,
            max_bytes,
            load_pua,
            verify_official,
            user_agent,
            databases,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let c = Config::from_env();
        assert!(c.listen.contains("8080") || !c.listen.is_empty());
        assert!(!c.mirrors.is_empty());
        assert!(c.max_bytes > 0);
        assert!(c.databases.contains(&"main".to_string()) || !c.databases.is_empty());
    }
}
