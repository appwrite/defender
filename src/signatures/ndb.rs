//! Extended signatures (`.ndb` / `.ndu`).
//!
//! `MalwareName:TargetType:Offset:HexSignature[:min_flevel[:max_flevel]]`

use super::hexpat::HexPattern;
use crate::error::{Error, Result};

/// ClamAV target types we interpret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TargetType {
    Any = 0,
    Pe = 1,
    Ole2 = 2,
    Html = 3,
    Mail = 4,
    Graphics = 5,
    Elf = 6,
    Text = 7,
    MachO = 9,
    Pdf = 10,
    Flash = 11,
    Java = 12,
    Other = 255,
}

impl TargetType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Any,
            1 => Self::Pe,
            2 => Self::Ole2,
            3 => Self::Html,
            4 => Self::Mail,
            5 => Self::Graphics,
            6 => Self::Elf,
            7 => Self::Text,
            9 => Self::MachO,
            10 => Self::Pdf,
            11 => Self::Flash,
            12 => Self::Java,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetKind {
    Any,
    Absolute { at: u32, shift: u32 },
    Eof { n: u32, shift: u32 },
    EntryPoint { add: i32, shift: u32 },
    Section { index: u32, add: u32, shift: u32 },
    LastSection { add: u32, shift: u32 },
}

impl OffsetKind {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s == "*" {
            return Ok(Self::Any);
        }
        let (base, shift) = match s.split_once(',') {
            Some((b, sh)) => (b, sh.parse::<u32>().map_err(|_| err("invalid MaxShift"))?),
            None => (s, 0),
        };
        if let Some(rest) = base.strip_prefix("EOF-") {
            let n = rest.parse().map_err(|_| err("invalid EOF-n"))?;
            return Ok(Self::Eof { n, shift });
        }
        if let Some(rest) = base.strip_prefix("EP+") {
            let n: i32 = rest.parse().map_err(|_| err("invalid EP+n"))?;
            return Ok(Self::EntryPoint { add: n, shift });
        }
        if let Some(rest) = base.strip_prefix("EP-") {
            let n: i32 = rest.parse().map_err(|_| err("invalid EP-n"))?;
            return Ok(Self::EntryPoint { add: -n, shift });
        }
        if base == "EP" {
            return Ok(Self::EntryPoint { add: 0, shift });
        }
        if let Some(rest) = base.strip_prefix("SL+") {
            let n = rest.parse().map_err(|_| err("invalid SL+n"))?;
            return Ok(Self::LastSection { add: n, shift });
        }
        if let Some(rest) = base.strip_prefix("SE") {
            if rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
                let index = rest.parse().map_err(|_| err("invalid SEx"))?;
                return Ok(Self::Section {
                    index,
                    add: 0,
                    shift,
                });
            }
        }
        if let Some(rest) = base.strip_prefix('S') {
            // Sx+n
            if let Some((idx, add)) = rest.split_once('+') {
                let index = idx.parse().map_err(|_| err("invalid Sx+n"))?;
                let add = add.parse().map_err(|_| err("invalid Sx+n"))?;
                return Ok(Self::Section { index, add, shift });
            }
        }
        let at = base.parse().map_err(|_| err("invalid absolute offset"))?;
        Ok(Self::Absolute { at, shift })
    }
}

#[derive(Debug, Clone)]
pub struct NdbSig {
    pub name: String,
    pub target: TargetType,
    pub offset: OffsetKind,
    pub pattern: HexPattern,
}

impl NdbSig {
    pub fn parse_line(line: &str) -> Result<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Err(err("empty"));
        }
        let mut parts = line.splitn(4, ':');
        let name = parts.next().ok_or_else(|| err("missing name"))?;
        let target = parts.next().ok_or_else(|| err("missing target"))?;
        let offset = parts.next().ok_or_else(|| err("missing offset"))?;
        let rest = parts.next().ok_or_else(|| err("missing hexsig"))?;
        // rest may include :min_flevel:max_flevel — hex cannot contain ':' except flevel.
        // Hex signatures don't use `:`; flevel fields are trailing integers.
        let hex = strip_flevel(rest);
        let target: u8 = target.parse().map_err(|_| err("bad target"))?;
        Ok(Self {
            name: name.to_string(),
            target: TargetType::from_u8(target),
            offset: OffsetKind::parse(offset)?,
            pattern: HexPattern::parse(hex)?,
        })
    }
}

fn strip_flevel(rest: &str) -> &str {
    // If the last one/two colon fields are integers, they are flevel.
    let bytes = rest.as_bytes();
    // Find last colon
    if let Some(i) = rest.rfind(':') {
        let tail = &rest[i + 1..];
        if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            let head = &rest[..i];
            if let Some(j) = head.rfind(':') {
                let mid = &head[j + 1..];
                if !mid.is_empty() && mid.bytes().all(|b| b.is_ascii_digit()) {
                    return &head[..j];
                }
            }
            // single trailing flevel? Unusual (spec requires min then max) — still strip.
            // But hex could theoretically... it cannot contain ':'.
            // If there's only one extra field, it is min_flevel.
            return head;
        }
    }
    let _ = bytes;
    rest
}

fn err(reason: &str) -> Error {
    Error::Signature {
        file: "ndb".into(),
        reason: reason.into(),
    }
}

pub fn load_ndb(text: &str) -> (Vec<NdbSig>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0;
    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match NdbSig::parse_line(line) {
            Ok(s) => out.push(s),
            Err(_) => skipped += 1,
        }
    }
    (out, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eicar_ndb() {
        let line = "Eicar-Test-Signature:0:*:58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a";
        let s = NdbSig::parse_line(line).unwrap();
        assert_eq!(s.name, "Eicar-Test-Signature");
        assert_eq!(s.target, TargetType::Any);
        assert_eq!(s.offset, OffsetKind::Any);
        assert!(s.pattern.anchor.starts_with(b"X5O"));
    }

    #[test]
    fn parse_offsets() {
        assert_eq!(
            OffsetKind::parse("10,5").unwrap(),
            OffsetKind::Absolute { at: 10, shift: 5 }
        );
        assert_eq!(
            OffsetKind::parse("EOF-8").unwrap(),
            OffsetKind::Eof { n: 8, shift: 0 }
        );
        assert_eq!(
            OffsetKind::parse("EP+16").unwrap(),
            OffsetKind::EntryPoint { add: 16, shift: 0 }
        );
        assert_eq!(
            OffsetKind::parse("S0+0").unwrap(),
            OffsetKind::Section {
                index: 0,
                add: 0,
                shift: 0
            }
        );
    }

    #[test]
    fn strips_flevel() {
        let s = NdbSig::parse_line("T:0:*:414243:90:255").unwrap();
        assert_eq!(s.pattern.anchor, b"ABC");
    }
}
