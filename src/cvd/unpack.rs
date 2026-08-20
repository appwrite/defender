//! Unpack the gzip+tar body that follows a 512-byte CVD header.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use flate2::read::GzDecoder;
use tar::Archive;

use super::header::CVD_HEADER_SIZE;
use crate::error::{Error, Result};
use crate::signatures::is_signature_member;

/// Files extracted from a CVD/CLD archive, keyed by file name (no path).
#[derive(Debug, Clone, Default)]
pub struct UnpackedDb {
    pub files: BTreeMap<String, Vec<u8>>,
}

impl UnpackedDb {
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.files.get(name).map(|v| v.as_slice())
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(|s| s.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Decode the gzip-compressed tar that starts at byte 512.
pub fn unpack_cvd(data: &[u8]) -> Result<UnpackedDb> {
    if data.len() < CVD_HEADER_SIZE {
        return Err(Error::CvdUnpack("file shorter than header".into()));
    }
    unpack_body(&data[CVD_HEADER_SIZE..])
}

pub fn unpack_body(body: &[u8]) -> Result<UnpackedDb> {
    let gz = GzDecoder::new(Cursor::new(body));
    let mut files = BTreeMap::new();
    for_each_archive_file(gz, true, true, |name, data| {
        files.insert(name, data);
        Ok(())
    })?;
    Ok(UnpackedDb { files })
}

/// Stream CVD tar members from disk without retaining the compressed file or
/// previously visited members. The 512-byte header is skipped; callers should
/// already have authenticated the file.
///
/// Non-signature members (bytecode, YARA, …) and PUA files (when `load_pua` is
/// false) are consumed and discarded without keeping their contents.
pub fn for_each_cvd_member(
    path: impl AsRef<Path>,
    load_pua: bool,
    mut visit: impl FnMut(&str, &[u8]) -> Result<()>,
) -> Result<()> {
    let path = path.as_ref();
    let mut file = File::open(path).map_err(|e| Error::io(path, e))?;
    let mut hdr = [0u8; CVD_HEADER_SIZE];
    file.read_exact(&mut hdr).map_err(|e| Error::io(path, e))?;
    let gz = GzDecoder::new(file);
    for_each_archive_file(gz, false, load_pua, |name, data| visit(&name, &data))
}

fn for_each_archive_file<R: Read>(
    reader: R,
    load_all: bool,
    load_pua: bool,
    mut visit: impl FnMut(String, Vec<u8>) -> Result<()>,
) -> Result<()> {
    let mut archive = Archive::new(reader);
    archive.set_overwrite(false);
    archive.set_preserve_permissions(false);

    let entries = archive
        .entries()
        .map_err(|e| Error::CvdUnpack(e.to_string()))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| Error::CvdUnpack(e.to_string()))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path().map_err(|e| Error::CvdUnpack(e.to_string()))?;
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::CvdUnpack("non-utf8 member name".into()))?
            .to_string();
        if !load_all && !is_signature_member(&name, load_pua) {
            std::io::copy(&mut entry, &mut std::io::sink())
                .map_err(|e| Error::CvdUnpack(e.to_string()))?;
            continue;
        }
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| Error::CvdUnpack(e.to_string()))?;
        visit(name, buf)?;
    }
    Ok(())
}

/// Build a synthetic CVD body (gzip tar) from name → contents. Header is not included.
pub fn pack_body(files: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, *data)
                .map_err(|e| Error::CvdUnpack(e.to_string()))?;
        }
        builder
            .finish()
            .map_err(|e| Error::CvdUnpack(e.to_string()))?;
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write;
    encoder
        .write_all(&tar_buf)
        .map_err(|e| Error::CvdUnpack(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| Error::CvdUnpack(e.to_string()))
}

/// Build a full synthetic CVD (header + gzip tar) with a correct MD5 and dummy dsig.
pub fn pack_cvd(files: &[(&str, &[u8])], version: u32, builder: &str) -> Result<Vec<u8>> {
    let body = pack_body(files)?;
    let md5 = super::verify::md5_hex(&body);
    let header = super::CvdHeader {
        magic: "ClamAV-VDB".into(),
        time: "01 Jan 2020 00-00 +0000".into(),
        version,
        signatures: 0,
        flevel: 90,
        md5,
        dsig: "unsigned".into(),
        builder: builder.into(),
        stime: 0,
    };
    let mut out = Vec::with_capacity(CVD_HEADER_SIZE + body.len());
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cvd::header::CvdHeader;
    use crate::cvd::verify::{verify_cvd_bytes, VerifyMode};

    #[test]
    fn pack_unpack_roundtrip() {
        let files = [
            (
                "test.hdb",
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1:Eicar-Test-File\n".as_slice(),
            ),
            ("test.ndb", b"Eicar:0:*:585530\n".as_slice()),
        ];
        let cvd = pack_cvd(&files, 1, "unit").unwrap();
        let header = CvdHeader::parse(&cvd).unwrap();
        verify_cvd_bytes(&cvd, &header, VerifyMode::Integrity).unwrap();
        let unpacked = unpack_cvd(&cvd).unwrap();
        assert_eq!(unpacked.files.len(), 2);
        assert_eq!(unpacked.get("test.hdb").unwrap(), files[0].1);
        assert_eq!(unpacked.get("test.ndb").unwrap(), files[1].1);
    }

    #[test]
    fn for_each_member_matches_unpack() {
        let files = [
            (
                "test.hdb",
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1:Eicar-Test-File\n".as_slice(),
            ),
            ("test.ndb", b"Eicar:0:*:585530\n".as_slice()),
            ("skip.cbc", b"not-a-signature".as_slice()),
        ];
        let cvd = pack_cvd(&files, 1, "unit").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.cvd");
        std::fs::write(&path, &cvd).unwrap();

        let mut seen = Vec::new();
        for_each_cvd_member(&path, false, |name, data| {
            seen.push((name.to_string(), data.to_vec()));
            Ok(())
        })
        .unwrap();
        seen.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, "test.hdb");
        assert_eq!(seen[1].0, "test.ndb");
        assert_eq!(seen[0].1, files[0].1);
        assert_eq!(seen[1].1, files[1].1);
    }
}
