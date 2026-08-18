//! Compiled virus database and streaming scanner.

mod pe;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use arc_swap::ArcSwap;
use md5::{Digest, Md5};
use rustc_hash::{FxHashMap, FxHashSet};
use sha1::Sha1;
use sha2::Sha256;

use crate::cvd::{load_bytes, CvdHeader, UnpackedDb, VerifyMode};
use crate::error::{Error, Result};
use crate::signatures::hash::{FpSet, HashAlgo, HashDb};
use crate::signatures::ldb::{load_ldb, LogicalSig};
use crate::signatures::ndb::{load_ndb, OffsetKind, TargetType};
use crate::signatures::HexPattern;

use pe::PeImage;

/// EICAR test file (standard 68-byte string).
pub const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[derive(Debug, Clone)]
pub struct DbMeta {
    pub databases: Vec<CvdInfo>,
    pub file_hashes: usize,
    pub section_hashes: usize,
    pub body_sigs: usize,
    pub logical_sigs: usize,
    pub skipped_sigs: usize,
    pub loaded_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct CvdInfo {
    pub name: String,
    pub version: u32,
    pub signatures: u32,
    pub flevel: u32,
    pub builder: String,
    pub time: String,
    pub md5: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct HashBytes {
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
    pub size: u64,
}

impl HashBytes {
    pub fn to_hex(&self) -> FileHashes {
        FileHashes {
            md5: hex::encode(self.md5),
            sha1: hex::encode(self.sha1),
            sha256: hex::encode(self.sha256),
            size: self.size,
        }
    }
}

#[derive(Default)]
pub struct IncrementalHashers {
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
    size: u64,
}

impl IncrementalHashers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        self.sha1.update(data);
        self.sha256.update(data);
        self.size += data.len() as u64;
    }

    pub fn finalize(self) -> HashBytes {
        let md5: [u8; 16] = self.md5.finalize().into();
        let sha1: [u8; 20] = self.sha1.finalize().into();
        let sha256: [u8; 32] = self.sha256.finalize().into();
        HashBytes {
            md5,
            sha1,
            sha256,
            size: self.size,
        }
    }
}

pub fn hash_bytes(data: &[u8]) -> HashBytes {
    let mut h = IncrementalHashers::new();
    h.update(data);
    h.finalize()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanVerdict {
    Clean,
    Infected { signature: String },
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub verdict: ScanVerdict,
    pub hashes: FileHashes,
}

struct BodyRule {
    name: String,
    target: TargetType,
    offset: OffsetKind,
    pattern: HexPattern,
}

struct LogicalRule {
    sig: LogicalSig,
}

/// Fully compiled, immutable scan engine. Cheap to share via `Arc`.
pub struct Engine {
    pub meta: DbMeta,
    file_hash: HashDb,
    section_hash: HashDb,
    fp: FpSet,
    ignored: FxHashSet<String>,
    ignored_prefix: Vec<String>,
    ac: Option<AhoCorasick>,
    /// AC pattern id → body rules whose anchor is that pattern.
    ac_body: Vec<Vec<usize>>,
    body: Vec<BodyRule>,
    /// Rules with no usable anchor.
    slow_body: Vec<usize>,
    ac_sub: Vec<Vec<(usize, usize)>>, // ac_id → (logical_idx, subsig_idx)
    logical: Vec<LogicalRule>,
    slow_logical: Vec<(usize, usize)>,
}

impl Engine {
    pub fn empty() -> Self {
        Self {
            meta: DbMeta {
                databases: vec![],
                file_hashes: 0,
                section_hashes: 0,
                body_sigs: 0,
                logical_sigs: 0,
                skipped_sigs: 0,
                loaded_at_unix: now_unix(),
            },
            file_hash: HashDb::default(),
            section_hash: HashDb::default(),
            fp: FpSet::default(),
            ignored: FxHashSet::default(),
            ignored_prefix: vec![],
            ac: None,
            ac_body: vec![],
            body: vec![],
            slow_body: vec![],
            ac_sub: vec![],
            logical: vec![],
            slow_logical: vec![],
        }
    }

    pub fn load_dir(dir: impl AsRef<Path>, verify: VerifyMode, load_pua: bool) -> Result<Self> {
        let dir = dir.as_ref();
        let mut builder = EngineBuilder::new();
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| Error::io(dir, e))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for path in entries {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            match ext.as_str() {
                "cvd" | "cld" => {
                    let bytes = std::fs::read(&path).map_err(|e| Error::io(&path, e))?;
                    let mode = if ext == "cvd" {
                        verify
                    } else {
                        VerifyMode::Integrity
                    };
                    let (header, unpacked) = load_bytes(&bytes, mode)?;
                    builder.add_cvd(&name, header, &unpacked, load_pua);
                }
                _ => builder.add_named_file(
                    &name,
                    &std::fs::read(&path).unwrap_or_default(),
                    load_pua,
                ),
            }
        }
        Ok(builder.build())
    }

    pub fn from_unpacked(info: CvdInfo, unpacked: &UnpackedDb, load_pua: bool) -> Self {
        let mut b = EngineBuilder::new();
        b.add_cvd(&info.name, header_from_info(&info), unpacked, load_pua);
        b.build()
    }

    pub fn from_cvd_bytes(
        name: &str,
        bytes: &[u8],
        verify: VerifyMode,
        load_pua: bool,
    ) -> Result<Self> {
        let (header, unpacked) = load_bytes(bytes, verify)?;
        let mut b = EngineBuilder::new();
        b.add_cvd(name, header, &unpacked, load_pua);
        Ok(b.build())
    }

    pub fn scan(&self, data: &[u8]) -> ScanResult {
        let hashes = hash_bytes(data);
        self.scan_prehashed(data, &hashes)
    }

    pub fn scan_prehashed(&self, data: &[u8], hashes: &HashBytes) -> ScanResult {
        let hex = hashes.to_hex();
        if let Some(name) = self.lookup_hashes(hashes) {
            if !self.is_ignored(name) && !self.is_fp(hashes) {
                return ScanResult {
                    verdict: ScanVerdict::Infected {
                        signature: name.to_string(),
                    },
                    hashes: hex,
                };
            }
        }
        if self.is_fp(hashes) {
            return ScanResult {
                verdict: ScanVerdict::Clean,
                hashes: hex,
            };
        }
        if let Some(name) = self.scan_sections(data) {
            if !self.is_ignored(name) {
                return ScanResult {
                    verdict: ScanVerdict::Infected {
                        signature: name.to_string(),
                    },
                    hashes: hex,
                };
            }
        }
        if let Some(name) = self.scan_body(data) {
            return ScanResult {
                verdict: ScanVerdict::Infected { signature: name },
                hashes: hex,
            };
        }
        ScanResult {
            verdict: ScanVerdict::Clean,
            hashes: hex,
        }
    }

    pub fn lookup_hashes(&self, h: &HashBytes) -> Option<&str> {
        self.file_hash
            .lookup_sha256(&h.sha256, h.size)
            .or_else(|| self.file_hash.lookup_sha1(&h.sha1, h.size))
            .or_else(|| self.file_hash.lookup_md5(&h.md5, h.size))
    }

    pub fn lookup_hex(&self, hex_digest: &str, size: Option<u64>) -> Result<Option<String>> {
        let hex_digest = hex_digest.trim();
        if !hex_digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidHash("non-hex digest".into()));
        }
        let bytes = hex::decode(hex_digest).map_err(|_| Error::InvalidHash("decode".into()))?;
        let size = size.unwrap_or(u64::MAX);
        let name = match bytes.len() {
            16 => {
                let mut k = [0u8; 16];
                k.copy_from_slice(&bytes);
                if size == u64::MAX {
                    self.file_hash
                        .md5
                        .get(&k)
                        .map(|(_, id)| self.file_hash.names[*id as usize].clone())
                } else {
                    self.file_hash.lookup_md5(&k, size).map(|s| s.to_string())
                }
            }
            20 => {
                let mut k = [0u8; 20];
                k.copy_from_slice(&bytes);
                if size == u64::MAX {
                    self.file_hash
                        .sha1
                        .get(&k)
                        .map(|(_, id)| self.file_hash.names[*id as usize].clone())
                } else {
                    self.file_hash.lookup_sha1(&k, size).map(|s| s.to_string())
                }
            }
            32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                if size == u64::MAX {
                    self.file_hash
                        .sha256
                        .get(&k)
                        .map(|(_, id)| self.file_hash.names[*id as usize].clone())
                } else {
                    self.file_hash
                        .lookup_sha256(&k, size)
                        .map(|s| s.to_string())
                }
            }
            n => return Err(Error::InvalidHash(format!("unsupported length {n}"))),
        };
        Ok(name.filter(|n| !self.is_ignored(n)))
    }

    fn is_fp(&self, h: &HashBytes) -> bool {
        self.fp.contains_sha256(&h.sha256)
            || self.fp.contains_sha1(&h.sha1)
            || self.fp.contains_md5(&h.md5)
    }

    fn is_ignored(&self, name: &str) -> bool {
        if self.ignored.contains(name) {
            return true;
        }
        self.ignored_prefix.iter().any(|p| name.starts_with(p))
    }

    fn scan_sections(&self, data: &[u8]) -> Option<&str> {
        if self.section_hash.is_empty() {
            return None;
        }
        let pe = PeImage::parse(data)?;
        for s in &pe.sections {
            if s.raw_ptr >= data.len() {
                continue;
            }
            let end = (s.raw_ptr + s.raw_size).min(data.len());
            let bytes = &data[s.raw_ptr..end];
            if bytes.is_empty() {
                continue;
            }
            let d = Md5::digest(bytes);
            let mut k = [0u8; 16];
            k.copy_from_slice(&d);
            if let Some(name) = self.section_hash.lookup_md5(&k, bytes.len() as u64) {
                return Some(name);
            }
            let d = Sha256::digest(bytes);
            let mut k32 = [0u8; 32];
            k32.copy_from_slice(&d);
            if let Some(name) = self.section_hash.lookup_sha256(&k32, bytes.len() as u64) {
                return Some(name);
            }
        }
        None
    }

    fn scan_body(&self, data: &[u8]) -> Option<String> {
        let kind = detect_kind(data);
        let pe = if kind == TargetType::Pe {
            PeImage::parse(data)
        } else {
            None
        };
        let mut counts: FxHashMap<(usize, usize), u32> = FxHashMap::default();
        let mut dirty: FxHashSet<usize> = FxHashSet::default();

        if let Some(ac) = &self.ac {
            for m in ac.find_overlapping_iter(data) {
                let pid = m.pattern().as_usize();
                let start = m.start();
                if let Some(rules) = self.ac_body.get(pid) {
                    for &ri in rules {
                        let rule = &self.body[ri];
                        if !target_ok(rule.target, kind) {
                            continue;
                        }
                        let pat_start = start.saturating_sub(rule.pattern.anchor_off);
                        if !offset_ok(&rule.offset, pat_start, data.len(), pe.as_ref()) {
                            continue;
                        }
                        if rule.pattern.matches_at(data, pat_start) && !self.is_ignored(&rule.name)
                        {
                            return Some(rule.name.clone());
                        }
                    }
                }
                if let Some(subs) = self.ac_sub.get(pid) {
                    for &(li, si) in subs {
                        let rule = &self.logical[li];
                        if !target_ok(rule.sig.target, kind) {
                            continue;
                        }
                        if let Some((lo, hi)) = rule.sig.file_size {
                            if data.len() < lo as usize || data.len() > hi as usize {
                                continue;
                            }
                        }
                        let sub = &rule.sig.subsigs[si];
                        let pat_start = start.saturating_sub(sub.pattern.anchor_off);
                        if !offset_ok(&sub.offset, pat_start, data.len(), pe.as_ref()) {
                            continue;
                        }
                        if sub.pattern.matches_at(data, pat_start) {
                            *counts.entry((li, si)).or_insert(0) += 1;
                            dirty.insert(li);
                        }
                    }
                }
            }
        }
        for &ri in &self.slow_body {
            let rule = &self.body[ri];
            if !target_ok(rule.target, kind) {
                continue;
            }
            if find_with_offset(&rule.pattern, &rule.offset, data, pe.as_ref()).is_some()
                && !self.is_ignored(&rule.name)
            {
                return Some(rule.name.clone());
            }
        }
        for &(li, si) in &self.slow_logical {
            let rule = &self.logical[li];
            if !target_ok(rule.sig.target, kind) {
                continue;
            }
            let sub = &rule.sig.subsigs[si];
            if find_with_offset(&sub.pattern, &sub.offset, data, pe.as_ref()).is_some() {
                *counts.entry((li, si)).or_insert(0) += 1;
                dirty.insert(li);
            }
        }
        for li in dirty {
            let rule = &self.logical[li];
            if !target_ok(rule.sig.target, kind) {
                continue;
            }
            if let Some((lo, hi)) = rule.sig.file_size {
                if data.len() < lo as usize || data.len() > hi as usize {
                    continue;
                }
            }
            let mut hit = vec![0u32; rule.sig.subsigs.len()];
            for si in 0..hit.len() {
                if let Some(c) = counts.get(&(li, si)) {
                    hit[si] = *c;
                }
            }
            if rule.sig.eval(&hit) && !self.is_ignored(&rule.sig.name) {
                return Some(rule.sig.name.clone());
            }
        }
        None
    }
}

fn header_from_info(info: &CvdInfo) -> CvdHeader {
    CvdHeader {
        magic: "ClamAV-VDB".into(),
        time: info.time.clone(),
        version: info.version,
        signatures: info.signatures,
        flevel: info.flevel,
        md5: info.md5.clone(),
        dsig: String::new(),
        builder: info.builder.clone(),
        stime: 0,
    }
}

fn detect_kind(data: &[u8]) -> TargetType {
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        TargetType::Pe
    } else if data.len() >= 4 && data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        TargetType::Elf
    } else if data.len() >= 4 && data.starts_with(b"%PDF") {
        TargetType::Pdf
    } else if data.len() >= 4
        && (data.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
            || data.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
            || data.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
            || data.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]))
    {
        TargetType::MachO
    } else {
        TargetType::Any
    }
}

fn target_ok(need: TargetType, have: TargetType) -> bool {
    need == TargetType::Any || need == have || have == TargetType::Any
}

fn offset_ok(off: &OffsetKind, at: usize, len: usize, pe: Option<&PeImage>) -> bool {
    match *off {
        OffsetKind::Any => true,
        OffsetKind::Absolute { at: start, shift } => {
            at >= start as usize && at <= start as usize + shift as usize
        }
        OffsetKind::Eof { n, shift } => {
            let base = len.saturating_sub(n as usize);
            at >= base && at <= base + shift as usize
        }
        OffsetKind::EntryPoint { add, shift } => {
            let Some(pe) = pe else { return false };
            let base = if add >= 0 {
                pe.entry_point_off.saturating_add(add as usize)
            } else {
                pe.entry_point_off.saturating_sub((-add) as usize)
            };
            at >= base && at <= base + shift as usize
        }
        OffsetKind::Section { index, add, shift } => {
            let Some(pe) = pe else { return false };
            let Some(s) = pe.sections.get(index as usize) else {
                return false;
            };
            let base = s.raw_ptr.saturating_add(add as usize);
            at >= base && at <= base + shift as usize
        }
        OffsetKind::LastSection { add, shift } => {
            let Some(pe) = pe else { return false };
            let Some(s) = pe.sections.last() else {
                return false;
            };
            let base = s.raw_ptr.saturating_add(add as usize);
            at >= base && at <= base + shift as usize
        }
    }
}

fn find_with_offset(
    pattern: &HexPattern,
    offset: &OffsetKind,
    data: &[u8],
    pe: Option<&PeImage>,
) -> Option<usize> {
    let (from, to) = match *offset {
        OffsetKind::Any => (0, None),
        OffsetKind::Absolute { at, shift } => (at as usize, Some(at as usize + shift as usize + 1)),
        OffsetKind::Eof { n, shift } => {
            let base = data.len().saturating_sub(n as usize);
            (base, Some(base + shift as usize + 1))
        }
        OffsetKind::EntryPoint { add, shift } => {
            let pe = pe?;
            let base = if add >= 0 {
                pe.entry_point_off.saturating_add(add as usize)
            } else {
                pe.entry_point_off.saturating_sub((-add) as usize)
            };
            (base, Some(base + shift as usize + 1))
        }
        OffsetKind::Section { index, add, shift } => {
            let pe = pe?;
            let s = pe.sections.get(index as usize)?;
            let base = s.raw_ptr.saturating_add(add as usize);
            (base, Some(base + shift as usize + 1))
        }
        OffsetKind::LastSection { add, shift } => {
            let pe = pe?;
            let s = pe.sections.last()?;
            let base = s.raw_ptr.saturating_add(add as usize);
            (base, Some(base + shift as usize + 1))
        }
    };
    pattern.find(data, from, to)
}

struct EngineBuilder {
    file_hash: HashDb,
    section_hash: HashDb,
    fp: FpSet,
    ignored: FxHashSet<String>,
    ignored_prefix: Vec<String>,
    body: Vec<BodyRule>,
    logical: Vec<LogicalRule>,
    databases: Vec<CvdInfo>,
    skipped: usize,
}

impl EngineBuilder {
    fn new() -> Self {
        Self {
            file_hash: HashDb::default(),
            section_hash: HashDb::default(),
            fp: FpSet::default(),
            ignored: FxHashSet::default(),
            ignored_prefix: vec![],
            body: vec![],
            logical: vec![],
            databases: vec![],
            skipped: 0,
        }
    }

    fn add_cvd(&mut self, name: &str, header: CvdHeader, unpacked: &UnpackedDb, load_pua: bool) {
        self.databases.push(CvdInfo {
            name: name.to_string(),
            version: header.version,
            signatures: header.signatures,
            flevel: header.flevel,
            builder: header.builder,
            time: header.time,
            md5: header.md5,
        });
        for (fname, data) in &unpacked.files {
            self.add_named_file(fname, data, load_pua);
        }
    }

    fn add_named_file(&mut self, name: &str, data: &[u8], load_pua: bool) {
        let lower = name.to_ascii_lowercase();
        let pua = lower.ends_with('u')
            && matches!(
                lower.rsplit_once('.').map(|(_, e)| e),
                Some("hdu" | "hsu" | "mdu" | "msu" | "ndu" | "ldu")
            );
        if pua && !load_pua {
            return;
        }
        let text = match std::str::from_utf8(data) {
            Ok(t) => t,
            Err(_) => return,
        };
        if lower.ends_with(".hdb") || lower.ends_with(".hdu") {
            self.file_hash.load_text(text, Some(HashAlgo::Md5));
        } else if lower.ends_with(".hsb") || lower.ends_with(".hsu") {
            let _ = self.file_hash.load_text(text, None);
        } else if lower.ends_with(".mdb") || lower.ends_with(".mdu") {
            self.section_hash.load_mdb_text(text, Some(HashAlgo::Md5));
        } else if lower.ends_with(".msb") || lower.ends_with(".msu") {
            self.section_hash.load_mdb_text(text, None);
        } else if lower.ends_with(".ndb") || lower.ends_with(".ndu") {
            let (sigs, skipped) = load_ndb(text);
            self.skipped += skipped;
            for s in sigs {
                self.body.push(BodyRule {
                    name: s.name,
                    target: s.target,
                    offset: s.offset,
                    pattern: s.pattern,
                });
            }
        } else if lower.ends_with(".ldb") || lower.ends_with(".ldu") {
            let (sigs, skipped) = load_ldb(text);
            self.skipped += skipped;
            for s in sigs {
                self.logical.push(LogicalRule { sig: s });
            }
        } else if lower.ends_with(".fp") || lower.ends_with(".sfp") {
            self.fp.load_text(text);
        } else if lower.ends_with(".ign") || lower.ends_with(".ign2") {
            for line in text.split('\n') {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(prefix) = line.strip_suffix(":*") {
                    self.ignored_prefix.push(prefix.to_string());
                } else {
                    self.ignored.insert(line.to_string());
                }
            }
        }
    }

    fn build(self) -> Engine {
        let mut needles: Vec<Vec<u8>> = Vec::new();
        let mut needle_idx: FxHashMap<Vec<u8>, usize> = FxHashMap::default();

        let intern = |needles: &mut Vec<Vec<u8>>,
                      map: &mut FxHashMap<Vec<u8>, usize>,
                      anchor: &[u8]|
         -> Option<usize> {
            if anchor.len() < 2 {
                return None;
            }
            if let Some(&i) = map.get(anchor) {
                return Some(i);
            }
            let i = needles.len();
            needles.push(anchor.to_vec());
            map.insert(anchor.to_vec(), i);
            Some(i)
        };

        let mut ac_body: Vec<Vec<usize>> = Vec::new();
        let mut slow_body = Vec::new();
        for (ri, rule) in self.body.iter().enumerate() {
            if let Some(id) = intern(&mut needles, &mut needle_idx, &rule.pattern.anchor) {
                if ac_body.len() <= id {
                    ac_body.resize(id + 1, Vec::new());
                }
                ac_body[id].push(ri);
            } else {
                slow_body.push(ri);
            }
        }

        let mut ac_sub: Vec<Vec<(usize, usize)>> = Vec::new();
        let mut slow_logical = Vec::new();
        for (li, rule) in self.logical.iter().enumerate() {
            for (si, sub) in rule.sig.subsigs.iter().enumerate() {
                if let Some(id) = intern(&mut needles, &mut needle_idx, &sub.pattern.anchor) {
                    if ac_sub.len() <= id {
                        ac_sub.resize(id + 1, Vec::new());
                    }
                    ac_sub[id].push((li, si));
                } else {
                    slow_logical.push((li, si));
                }
            }
        }

        let n = needles.len();
        if ac_body.len() < n {
            ac_body.resize(n, Vec::new());
        }
        if ac_sub.len() < n {
            ac_sub.resize(n, Vec::new());
        }

        let ac = if needles.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .ascii_case_insensitive(false)
                .build(&needles)
                .ok()
        };

        let meta = DbMeta {
            databases: self.databases,
            file_hashes: self.file_hash.len(),
            section_hashes: self.section_hash.len(),
            body_sigs: self.body.len(),
            logical_sigs: self.logical.len(),
            skipped_sigs: self.skipped,
            loaded_at_unix: now_unix(),
        };

        Engine {
            meta,
            file_hash: self.file_hash,
            section_hash: self.section_hash,
            fp: self.fp,
            ignored: self.ignored,
            ignored_prefix: self.ignored_prefix,
            ac,
            ac_body,
            body: self.body,
            slow_body,
            ac_sub,
            logical: self.logical,
            slow_logical,
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Hot-swappable engine handle. In-flight scans keep the previous `Arc`.
#[derive(Clone)]
pub struct Database {
    engine: Arc<ArcSwap<Engine>>,
}

impl Database {
    pub fn new(engine: Engine) -> Self {
        Self {
            engine: Arc::new(ArcSwap::from_pointee(engine)),
        }
    }

    pub fn current(&self) -> arc_swap::Guard<Arc<Engine>> {
        self.engine.load()
    }

    pub fn swap(&self, engine: Engine) {
        self.engine.store(Arc::new(engine));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cvd::unpack::pack_cvd;

    fn eicar_engine() -> Engine {
        let md5 = hex::encode(Md5::digest(EICAR));
        let sha256 = hex::encode(Sha256::digest(EICAR));
        let hdb = format!("{md5}:68:Eicar-Test-Signature\n");
        let hsb = format!("{sha256}:68:Eicar-Test-Signature\n");
        let ndb = "Eicar-Test-Signature:0:*:58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a\n";
        let cvd = pack_cvd(
            &[
                ("test.hdb", hdb.as_bytes()),
                ("test.hsb", hsb.as_bytes()),
                ("test.ndb", ndb.as_bytes()),
            ],
            1,
            "unit",
        )
        .unwrap();
        Engine::from_cvd_bytes("test.cvd", &cvd, VerifyMode::Integrity, false).unwrap()
    }

    #[test]
    fn detects_eicar_by_hash_and_body() {
        let eng = eicar_engine();
        match eng.scan(EICAR).verdict {
            ScanVerdict::Infected { signature } => {
                assert!(signature.contains("Eicar"));
            }
            ScanVerdict::Clean => panic!("eicar not detected"),
        }
        assert!(matches!(
            eng.scan(b"hello world").verdict,
            ScanVerdict::Clean
        ));
    }

    #[test]
    fn hash_lookup_api() {
        let eng = eicar_engine();
        let h = hash_bytes(EICAR);
        assert!(eng.lookup_hashes(&h).is_some());
        let hex = hex::encode(h.sha256);
        assert!(eng.lookup_hex(&hex, Some(68)).unwrap().is_some());
        assert!(eng.lookup_hex(&hex, Some(1)).unwrap().is_none());
    }

    #[test]
    fn hot_swap_zero_downtime() {
        let db = Database::new(Engine::empty());
        assert!(matches!(
            db.current().scan(EICAR).verdict,
            ScanVerdict::Clean
        ));
        db.swap(eicar_engine());
        assert!(matches!(
            db.current().scan(EICAR).verdict,
            ScanVerdict::Infected { .. }
        ));
        let old = db.current();
        db.swap(Engine::empty());
        // previous guard still sees infected engine
        assert!(matches!(
            old.scan(EICAR).verdict,
            ScanVerdict::Infected { .. }
        ));
        assert!(matches!(
            db.current().scan(EICAR).verdict,
            ScanVerdict::Clean
        ));
    }

    #[test]
    fn logical_and_fp_and_ign() {
        let ldb = "Test.Log;Target:0;0&1;58354f21;50254041\n";
        let ign = "Test.Log\n";
        let cvd = pack_cvd(
            &[("t.ldb", ldb.as_bytes()), ("t.ign2", ign.as_bytes())],
            1,
            "u",
        )
        .unwrap();
        let eng = Engine::from_cvd_bytes("t", &cvd, VerifyMode::Integrity, false).unwrap();
        // ignored name → clean even though body matches
        assert!(matches!(eng.scan(EICAR).verdict, ScanVerdict::Clean));
    }

    #[test]
    fn incremental_hashers_match_oneshot() {
        let mut inc = IncrementalHashers::new();
        inc.update(&EICAR[..20]);
        inc.update(&EICAR[20..]);
        let a = inc.finalize();
        let b = hash_bytes(EICAR);
        assert_eq!(a.md5, b.md5);
        assert_eq!(a.sha256, b.sha256);
        assert_eq!(a.size, 68);
    }
}
