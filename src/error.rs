//! Error types for CVD parsing, signature loading, scanning, and HTTP.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid CVD header: {0}")]
    CvdHeader(String),

    #[error("CVD body MD5 mismatch: header={expected} actual={actual}")]
    CvdChecksum { expected: String, actual: String },

    #[error("CVD digital signature verification failed")]
    CvdSignature,

    #[error("failed to unpack CVD archive: {0}")]
    CvdUnpack(String),

    #[error("invalid signature line in {file}: {reason}")]
    Signature { file: String, reason: String },

    #[error("I/O error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("I/O error: {0}")]
    IoSimple(#[from] io::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("database update failed: {0}")]
    Update(String),

    #[error("scan payload exceeds configured maximum ({0} bytes)")]
    PayloadTooLarge(u64),

    #[error("invalid hash: {0}")]
    InvalidHash(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
