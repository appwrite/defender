//! File-hash (`.hdb` / `.hsb`) and PE-section-hash (`.mdb` / `.msb`) signatures.
//!
//! Formats (ClamAV):
//! * `.hdb`: `MD5:Size:Name[:MinFL[:MaxFL]]`
//! * `.hsb`: `SHA1|SHA256:Size:Name[:MinFL[:MaxFL]]` (algorithm from hex length)
//! * `.mdb`: `SectionSize:MD5:Name` (size **first**, unlike `.hdb`)
//! * `.msb`: `SectionSize:SHA1|SHA256:Name`
//! * `.fp` / `.sfp`: same layout, used as false-positive allow-lists
//!
//! `Size` may be `*` meaning any length.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Md5,
    Sha1,
    Sha256,
}

#[derive(Debug, Clone)]
pub struct HashSig {
    pub algo: HashAlgo,
    pub digest: Vec<u8>,
    /// `None` means `*` (any size).
    pub size: Option<u32>,
    pub name: String,
}

impl HashSig {
    pub fn parse_line(line: &str, force: Option<HashAlgo>) -> Result<Self> {
        Self::parse_ordered(line, force, false)
    }

    /// PE section hashes (`.mdb` / `.msb`) put size before the digest.
    pub fn parse_mdb_line(line: &str, force: Option<HashAlgo>) -> Result<Self> {
        Self::parse_ordered(line, force, true)
    }

    fn parse_ordered(line: &str, force: Option<HashAlgo>, size_first: bool) -> Result<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Err(Error::Signature {
                file: "hash".into(),
                reason: "empty".into(),
            });
        }
        let mut parts = line.split(':');
        let (hex, size_s) = if size_first {
            let size_s = parts.next().ok_or_else(|| sig("missing size"))?;
            let hex = parts.next().ok_or_else(|| sig("missing hash"))?;
            (hex, size_s)
        } else {
            let hex = parts.next().ok_or_else(|| sig("missing hash"))?;
            let size_s = parts.next().ok_or_else(|| sig("missing size"))?;
            (hex, size_s)
        };
        let name = parts.next().ok_or_else(|| sig("missing name"))?;
        // Remaining fields are optional flevel; ignore.
        if name.is_empty() {
            return Err(sig("empty name"));
        }
        let algo = match force {
            Some(a) => a,
            None => match hex.len() {
                32 => HashAlgo::Md5,
                40 => HashAlgo::Sha1,
                64 => HashAlgo::Sha256,
                n => {
                    return Err(sig(&format!("unsupported hash length {n}")));
                }
            },
        };
        let expected = match algo {
            HashAlgo::Md5 => 32,
            HashAlgo::Sha1 => 40,
            HashAlgo::Sha256 => 64,
        };
        if hex.len() != expected || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(sig("invalid digest hex"));
        }
        let digest = hex::decode(hex).map_err(|_| sig("invalid digest hex"))?;
        let size = if size_s == "*" {
            None
        } else {
            Some(size_s.parse().map_err(|_| sig("invalid size"))?)
        };
        Ok(Self {
            algo,
            digest,
            size,
            name: name.to_string(),
        })
    }
}

fn sig(reason: &str) -> Error {
    Error::Signature {
        file: "hash".into(),
        reason: reason.into(),
    }
}

#[derive(Debug, Default, Clone)]
pub struct HashDb {
    pub md5: FxHashMap<[u8; 16], (Option<u32>, u32)>,
    pub sha1: FxHashMap<[u8; 20], (Option<u32>, u32)>,
    pub sha256: FxHashMap<[u8; 32], (Option<u32>, u32)>,
    pub names: Vec<String>,
}

impl HashDb {
    pub fn intern(&mut self, name: &str) -> u32 {
        let id = self.names.len() as u32;
        self.names.push(name.to_string());
        id
    }

    pub fn insert(&mut self, sig: HashSig) {
        let id = self.intern(&sig.name);
        match sig.algo {
            HashAlgo::Md5 => {
                let mut k = [0u8; 16];
                k.copy_from_slice(&sig.digest);
                self.md5.entry(k).or_insert((sig.size, id));
            }
            HashAlgo::Sha1 => {
                let mut k = [0u8; 20];
                k.copy_from_slice(&sig.digest);
                self.sha1.entry(k).or_insert((sig.size, id));
            }
            HashAlgo::Sha256 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&sig.digest);
                self.sha256.entry(k).or_insert((sig.size, id));
            }
        }
    }

    pub fn load_text(&mut self, text: &str, force: Option<HashAlgo>) -> usize {
        let mut n = 0;
        for line in text.split('\n') {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(sig) = HashSig::parse_line(line, force) {
                self.insert(sig);
                n += 1;
            }
        }
        n
    }

    pub fn load_mdb_text(&mut self, text: &str, force: Option<HashAlgo>) -> usize {
        let mut n = 0;
        for line in text.split('\n') {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(sig) = HashSig::parse_mdb_line(line, force) {
                self.insert(sig);
                n += 1;
            }
        }
        n
    }

    pub fn lookup_md5(&self, digest: &[u8; 16], size: u64) -> Option<&str> {
        lookup(&self.md5, digest, size, &self.names)
    }
    pub fn lookup_sha1(&self, digest: &[u8; 20], size: u64) -> Option<&str> {
        lookup(&self.sha1, digest, size, &self.names)
    }
    pub fn lookup_sha256(&self, digest: &[u8; 32], size: u64) -> Option<&str> {
        lookup(&self.sha256, digest, size, &self.names)
    }

    pub fn len(&self) -> usize {
        self.md5.len() + self.sha1.len() + self.sha256.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn shrink_to_fit(&mut self) {
        self.md5.shrink_to_fit();
        self.sha1.shrink_to_fit();
        self.sha256.shrink_to_fit();
        self.names.shrink_to_fit();
    }
}

fn lookup<'a, const N: usize>(
    map: &FxHashMap<[u8; N], (Option<u32>, u32)>,
    digest: &[u8; N],
    size: u64,
    names: &'a [String],
) -> Option<&'a str> {
    let (sz, id) = map.get(digest)?;
    if let Some(exp) = sz {
        if *exp as u64 != size {
            return None;
        }
    }
    names.get(*id as usize).map(|s| s.as_str())
}

#[derive(Debug, Default, Clone)]
pub struct FpSet {
    pub md5: FxHashSet<[u8; 16]>,
    pub sha1: FxHashSet<[u8; 20]>,
    pub sha256: FxHashSet<[u8; 32]>,
}

impl FpSet {
    pub fn load_text(&mut self, text: &str) {
        for line in text.split('\n') {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(sig) = HashSig::parse_line(line, None) {
                match sig.algo {
                    HashAlgo::Md5 => {
                        let mut k = [0u8; 16];
                        k.copy_from_slice(&sig.digest);
                        self.md5.insert(k);
                    }
                    HashAlgo::Sha1 => {
                        let mut k = [0u8; 20];
                        k.copy_from_slice(&sig.digest);
                        self.sha1.insert(k);
                    }
                    HashAlgo::Sha256 => {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&sig.digest);
                        self.sha256.insert(k);
                    }
                }
            }
        }
    }

    pub fn contains_md5(&self, d: &[u8; 16]) -> bool {
        self.md5.contains(d)
    }
    pub fn contains_sha1(&self, d: &[u8; 20]) -> bool {
        self.sha1.contains(d)
    }
    pub fn contains_sha256(&self, d: &[u8; 32]) -> bool {
        self.sha256.contains(d)
    }

    pub fn shrink_to_fit(&mut self) {
        self.md5.shrink_to_fit();
        self.sha1.shrink_to_fit();
        self.sha256.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hdb() {
        let s = HashSig::parse_line(
            "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature",
            None,
        )
        .unwrap();
        assert_eq!(s.algo, HashAlgo::Md5);
        assert_eq!(s.size, Some(68));
        assert_eq!(s.name, "Eicar-Test-Signature");
    }

    #[test]
    fn parse_mdb_size_first() {
        let s = HashSig::parse_mdb_line(
            "45056:3ea7d00dedd30bcdf46191358c36ffa4:Eicar-Test-Signature",
            None,
        )
        .unwrap();
        assert_eq!(s.algo, HashAlgo::Md5);
        assert_eq!(s.size, Some(45056));
        assert_eq!(s.name, "Eicar-Test-Signature");
        assert!(HashSig::parse_line(
            "45056:3ea7d00dedd30bcdf46191358c36ffa4:Eicar-Test-Signature",
            None
        )
        .is_err());
    }

    #[test]
    fn parse_wildcard_size() {
        let s = HashSig::parse_line(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:*:Eicar",
            None,
        )
        .unwrap();
        assert_eq!(s.algo, HashAlgo::Sha256);
        assert_eq!(s.size, None);
    }

    #[test]
    fn lookup_respects_size() {
        let mut db = HashDb::default();
        db.load_text(
            "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n",
            None,
        );
        let mut md5 = [0u8; 16];
        md5.copy_from_slice(&hex::decode("44d88612fea8a8f36de82e1278abb02f").unwrap());
        assert_eq!(db.lookup_md5(&md5, 68), Some("Eicar-Test-Signature"));
        assert_eq!(db.lookup_md5(&md5, 1), None);
    }

    #[test]
    fn rejects_bad_lines() {
        assert!(HashSig::parse_line("zz:1:x", None).is_err());
        assert!(HashSig::parse_line("aa:1", None).is_err());
    }
}
