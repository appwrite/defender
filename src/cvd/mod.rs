//! ClamAV Virus Database (CVD / CLD) container format.
//!
//! A CVD is a 512-byte ASCII header followed by a gzip-compressed tar archive.
//! The header is colon-separated:
//!
//! ```text
//! ClamAV-VDB:{build time}:{version}:{signatures}:{flevel}:{md5}:{dsig}:{builder}:{stime}
//! ```
//!
//! Official databases are authenticated by verifying the body MD5 against the
//! header and the RSA digital signature (legacy MD5-RSA and RSASSA-PSS).

pub mod header;
pub mod unpack;
pub mod verify;

pub use header::CvdHeader;
pub use unpack::{for_each_cvd_member, unpack_cvd, UnpackedDb};
pub use verify::{verify_cvd, verify_cvd_bytes, VerifyMode};

use crate::error::Result;
use std::path::Path;

/// Load and fully verify a CVD/CLD file from disk.
pub fn load_file(path: impl AsRef<Path>, mode: VerifyMode) -> Result<(CvdHeader, UnpackedDb)> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).map_err(|e| crate::error::Error::io(path, e))?;
    load_bytes(&bytes, mode)
}

/// Load and fully verify a CVD/CLD from an in-memory buffer.
pub fn load_bytes(bytes: &[u8], mode: VerifyMode) -> Result<(CvdHeader, UnpackedDb)> {
    let header = CvdHeader::parse(bytes)?;
    verify_cvd_bytes(bytes, &header, mode)?;
    let unpacked = unpack_cvd(bytes)?;
    Ok((header, unpacked))
}
