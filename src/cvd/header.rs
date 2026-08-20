//! 512-byte ClamAV CVD/CLD header parser.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::{Error, Result};

/// Size of the fixed CVD header prefix.
pub const CVD_HEADER_SIZE: usize = 512;

/// Parsed ClamAV-VDB header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvdHeader {
    pub magic: String,
    pub time: String,
    pub version: u32,
    pub signatures: u32,
    pub flevel: u32,
    pub md5: String,
    pub dsig: String,
    pub builder: String,
    pub stime: u64,
}

impl CvdHeader {
    /// Parse a CVD/CLD header from the first 512 bytes of `data`.
    ///
    /// Time historically contained colons (`10:45 +0000`); modern databases
    /// replace them with dashes. Fields are therefore split from the right.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < CVD_HEADER_SIZE {
            return Err(Error::CvdHeader(format!(
                "truncated header ({} bytes, need {CVD_HEADER_SIZE})",
                data.len()
            )));
        }
        let raw = &data[..CVD_HEADER_SIZE];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(CVD_HEADER_SIZE);
        let text = std::str::from_utf8(&raw[..end])
            .map_err(|_| Error::CvdHeader("header is not valid UTF-8".into()))?
            .trim();

        Self::parse_str(text)
    }

    pub fn parse_str(text: &str) -> Result<Self> {
        let text = text.trim();
        if !text.starts_with("ClamAV-VDB:") {
            return Err(Error::CvdHeader(
                "magic mismatch (expected ClamAV-VDB:)".into(),
            ));
        }
        let rest = &text["ClamAV-VDB:".len()..];

        // Prefer 8 fields (with stime). Fall back to 7 for ancient files.
        let parsed = split_right(rest, 8).or_else(|| split_right(rest, 7));
        let parts =
            parsed.ok_or_else(|| Error::CvdHeader("not enough colon-separated fields".into()))?;

        let (time, version, signatures, flevel, md5, dsig, builder, stime) = if parts.len() == 8 {
            (
                parts[0].to_string(),
                parse_u32(parts[1], "version")?,
                parse_u32(parts[2], "signatures")?,
                parse_u32(parts[3], "flevel")?,
                parts[4].to_string(),
                parts[5].to_string(),
                parts[6].to_string(),
                parse_u64(parts[7], "stime").unwrap_or(0),
            )
        } else {
            (
                parts[0].to_string(),
                parse_u32(parts[1], "version")?,
                parse_u32(parts[2], "signatures")?,
                parse_u32(parts[3], "flevel")?,
                parts[4].to_string(),
                parts[5].to_string(),
                parts[6].to_string(),
                0,
            )
        };

        if md5.len() != 32 || !md5.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::CvdHeader(format!("invalid MD5 field: {md5}")));
        }
        if dsig.is_empty() {
            return Err(Error::CvdHeader("empty digital signature".into()));
        }
        if builder.is_empty() {
            return Err(Error::CvdHeader("empty builder".into()));
        }

        Ok(Self {
            magic: "ClamAV-VDB".into(),
            time,
            version,
            signatures,
            flevel,
            md5: md5.to_ascii_lowercase(),
            dsig,
            builder,
            stime,
        })
    }

    /// Read only the 512-byte header from `path` (does not load the gzip body).
    pub fn read_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut file = File::open(path).map_err(|e| Error::io(path, e))?;
        let mut buf = [0u8; CVD_HEADER_SIZE];
        file.read_exact(&mut buf).map_err(|e| Error::io(path, e))?;
        Self::parse(&buf)
    }

    /// Serialize back to a 512-byte padded header.
    pub fn to_bytes(&self) -> [u8; CVD_HEADER_SIZE] {
        let s = format!(
            "ClamAV-VDB:{}:{}:{}:{}:{}:{}:{}:{}",
            self.time,
            self.version,
            self.signatures,
            self.flevel,
            self.md5,
            self.dsig,
            self.builder,
            self.stime
        );
        let mut buf = [0u8; CVD_HEADER_SIZE];
        let bytes = s.as_bytes();
        let n = bytes.len().min(CVD_HEADER_SIZE);
        buf[..n].copy_from_slice(&bytes[..n]);
        buf
    }
}

fn split_right(rest: &str, n: usize) -> Option<Vec<&str>> {
    let parts: Vec<&str> = rest.rsplitn(n, ':').collect();
    if parts.len() != n {
        return None;
    }
    // rsplitn yields from the right; reverse to left-to-right field order.
    Some(parts.into_iter().rev().collect())
}

fn parse_u32(s: &str, field: &str) -> Result<u32> {
    s.parse()
        .map_err(|_| Error::CvdHeader(format!("invalid {field}: {s}")))
}

fn parse_u64(s: &str, field: &str) -> Result<u64> {
    s.parse()
        .map_err(|_| Error::CvdHeader(format!("invalid {field}: {s}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "ClamAV-VDB:11 Sep 2025 08-29 -0400:339:80:90:8bdb03f60b90cfc4c8d500543233de96:ow+EI2l1J6dXNMseMugc4ZK0cdbnUyDZY7x/Or+pIuzjIaYmWBt6MflLRusmT+y2dQamP0RjLrSAHjeU8DwyuWmTIkoTo1wrY1B3ZEUDC/Ta5vpv0cxYy4MPgMkeNovlXmEKCWX4m3orZS+3VJ/9J9grZ2rxcJubE9RAU5CXmEg:nrandolp:1757593759";

    #[test]
    fn parse_modern_header() {
        let h = CvdHeader::parse_str(SAMPLE).unwrap();
        assert_eq!(h.version, 339);
        assert_eq!(h.signatures, 80);
        assert_eq!(h.flevel, 90);
        assert_eq!(h.md5, "8bdb03f60b90cfc4c8d500543233de96");
        assert_eq!(h.builder, "nrandolp");
        assert_eq!(h.stime, 1757593759);
        assert_eq!(h.time, "11 Sep 2025 08-29 -0400");
        assert!(h.dsig.starts_with("ow+EI2l1"));
    }

    #[test]
    fn parse_time_with_colons() {
        let s = "ClamAV-VDB:10 Mar 2008 10:45 +0000:6191:59084:26:6e6e29dae36b4b7315932c921e568330:ABCDEF:ccordes:1205145900";
        let h = CvdHeader::parse_str(s).unwrap();
        assert_eq!(h.time, "10 Mar 2008 10:45 +0000");
        assert_eq!(h.version, 6191);
        assert_eq!(h.builder, "ccordes");
    }

    #[test]
    fn parse_padded_512() {
        let mut buf = [0u8; 600];
        let b = SAMPLE.as_bytes();
        buf[..b.len()].copy_from_slice(b);
        let h = CvdHeader::parse(&buf).unwrap();
        assert_eq!(h.version, 339);
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(
            CvdHeader::parse_str("NOPE:1:1:1:1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:sig:b:1").is_err()
        );
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(CvdHeader::parse(&[1, 2, 3]).is_err());
    }

    #[test]
    fn roundtrip_bytes() {
        let h = CvdHeader::parse_str(SAMPLE).unwrap();
        let bytes = h.to_bytes();
        let h2 = CvdHeader::parse(&bytes).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn read_file_ignores_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daily.cvd");
        let h = CvdHeader::parse_str(SAMPLE).unwrap();
        let mut bytes = h.to_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 1024 * 1024]);
        std::fs::write(&path, &bytes).unwrap();
        let loaded = CvdHeader::read_file(&path).unwrap();
        assert_eq!(loaded, h);
    }
}
