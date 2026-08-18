//! High-performance streaming virus scanner using ClamAV public databases.

pub mod config;
pub mod cvd;
pub mod engine;
pub mod error;
pub mod http;
pub mod signatures;
pub mod updater;

pub use config::Config;
pub use engine::{Database, Engine, ScanResult, ScanVerdict, EICAR};
pub use error::{Error, Result};
