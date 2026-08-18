//! Logical signatures (`.ldb`).
//!
//! `SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;...`

use super::hexpat::{widen, HexPattern};
use super::ndb::{OffsetKind, TargetType};
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct LogicalSig {
    pub name: String,
    pub target: TargetType,
    pub file_size: Option<(u32, u32)>,
    pub expr: LogExpr,
    pub subsigs: Vec<SubSig>,
}

#[derive(Debug, Clone)]
pub struct SubSig {
    pub offset: OffsetKind,
    pub pattern: HexPattern,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogExpr {
    /// Subsignature index; `count` is `None` (at least once), `Eq(n)`, `Between(a,b)`, `Gt(n)`, `Lt(n)`.
    Atom {
        index: usize,
        count: CountPred,
    },
    And(Box<LogExpr>, Box<LogExpr>),
    Or(Box<LogExpr>, Box<LogExpr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountPred {
    AtLeastOne,
    Eq(u32),
    Between(u32, u32),
    Gt(u32),
    Lt(u32),
}

impl CountPred {
    pub fn matches(self, hits: u32) -> bool {
        match self {
            Self::AtLeastOne => hits >= 1,
            Self::Eq(n) => hits == n,
            Self::Between(a, b) => hits >= a && hits <= b,
            Self::Gt(n) => hits > n,
            Self::Lt(n) => hits < n,
        }
    }
}

impl LogicalSig {
    pub fn parse_line(line: &str) -> Result<Self> {
        let line = line.trim().trim_end_matches(';');
        if line.is_empty() || line.starts_with('#') {
            return Err(err("empty"));
        }
        let mut parts = line.splitn(4, ';');
        let name = parts.next().ok_or_else(|| err("missing name"))?;
        let tdb = parts.next().ok_or_else(|| err("missing TDB"))?;
        let expr_s = parts.next().ok_or_else(|| err("missing expression"))?;
        let rest = parts.next().unwrap_or("");
        if name.is_empty() {
            return Err(err("empty name"));
        }
        let (target, file_size) = parse_tdb(tdb)?;
        let expr = parse_expr(expr_s)?;
        let mut subsigs = Vec::new();
        for raw in rest.split(';') {
            if raw.is_empty() {
                continue;
            }
            subsigs.push(parse_subsig(raw)?);
        }
        Ok(Self {
            name: name.to_string(),
            target,
            file_size,
            expr,
            subsigs,
        })
    }

    pub fn eval(&self, hit_counts: &[u32]) -> bool {
        eval(&self.expr, hit_counts)
    }
}

fn parse_tdb(tdb: &str) -> Result<(TargetType, Option<(u32, u32)>)> {
    let mut target = TargetType::Any;
    let mut file_size = None;
    for part in tdb.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once(':').ok_or_else(|| err("TDB pair"))?;
        match k {
            "Target" => {
                let n: u8 = v.parse().map_err(|_| err("bad Target"))?;
                target = TargetType::from_u8(n);
            }
            "FileSize" => {
                if let Some((a, b)) = v.split_once('-') {
                    let lo = a.parse().map_err(|_| err("FileSize"))?;
                    let hi = b.parse().map_err(|_| err("FileSize"))?;
                    file_size = Some((lo, hi));
                }
            }
            _ => {}
        }
    }
    Ok((target, file_size))
}

fn parse_subsig(raw: &str) -> Result<SubSig> {
    // Optional `offset:` prefix, optional `::modifiers` suffix.
    let (body, modifiers) = match raw.rsplit_once("::") {
        Some((b, m)) => (b, m),
        None => (raw, ""),
    };
    let (offset, hex) = if let Some((off, hex)) = split_offset_hex(body) {
        (OffsetKind::parse(off)?, hex)
    } else {
        (OffsetKind::Any, body)
    };
    let mut pattern = HexPattern::parse(hex)?;
    if modifiers.contains('w') {
        pattern = widen(&pattern);
    }
    Ok(SubSig { offset, pattern })
}

fn split_offset_hex(body: &str) -> Option<(&str, &str)> {
    // offset is `*`, digits, EP+/EOF-/S… before the first hex-looking field.
    let (off, hex) = body.split_once(':')?;
    if hex.is_empty() {
        return None;
    }
    // Heuristic: offset tokens never start with a hex pair that is clearly a pattern
    // of length >= 2 without offset keywords. If `off` parses as OffsetKind, take it.
    if OffsetKind::parse(off).is_ok() {
        return Some((off, hex));
    }
    None
}

fn parse_expr(s: &str) -> Result<LogExpr> {
    let s = s.trim();
    let bytes = s.as_bytes();
    let mut i = 0;
    let expr = parse_or(bytes, &mut i)?;
    if i != bytes.len() {
        return Err(err(&format!("trailing expression at {i}")));
    }
    Ok(expr)
}

fn skip_ws(s: &[u8], i: &mut usize) {
    while *i < s.len() && s[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

fn parse_or(s: &[u8], i: &mut usize) -> Result<LogExpr> {
    let mut left = parse_and(s, i)?;
    loop {
        skip_ws(s, i);
        if *i < s.len() && s[*i] == b'|' {
            *i += 1;
            let right = parse_and(s, i)?;
            left = LogExpr::Or(Box::new(left), Box::new(right));
        } else {
            break;
        }
    }
    Ok(left)
}

fn parse_and(s: &[u8], i: &mut usize) -> Result<LogExpr> {
    let mut left = parse_atom(s, i)?;
    loop {
        skip_ws(s, i);
        if *i < s.len() && s[*i] == b'&' {
            *i += 1;
            let right = parse_atom(s, i)?;
            left = LogExpr::And(Box::new(left), Box::new(right));
        } else {
            break;
        }
    }
    Ok(left)
}

fn parse_atom(s: &[u8], i: &mut usize) -> Result<LogExpr> {
    skip_ws(s, i);
    if *i < s.len() && s[*i] == b'(' {
        *i += 1;
        let inner = parse_or(s, i)?;
        skip_ws(s, i);
        if *i >= s.len() || s[*i] != b')' {
            return Err(err("unclosed '(' in expression"));
        }
        *i += 1;
        return Ok(inner);
    }
    if *i >= s.len() || !s[*i].is_ascii_digit() {
        return Err(err("expected subsig index"));
    }
    let start = *i;
    while *i < s.len() && s[*i].is_ascii_digit() {
        *i += 1;
    }
    let index: usize = std::str::from_utf8(&s[start..*i])
        .unwrap()
        .parse()
        .map_err(|_| err("bad index"))?;
    skip_ws(s, i);
    let count = if *i < s.len() && matches!(s[*i], b'=' | b'>' | b'<') {
        let op = s[*i];
        *i += 1;
        skip_ws(s, i);
        let nstart = *i;
        while *i < s.len() && s[*i].is_ascii_digit() {
            *i += 1;
        }
        if nstart == *i {
            return Err(err("missing count"));
        }
        let n: u32 = std::str::from_utf8(&s[nstart..*i])
            .unwrap()
            .parse()
            .map_err(|_| err("bad count"))?;
        skip_ws(s, i);
        if *i < s.len() && s[*i] == b',' {
            *i += 1;
            skip_ws(s, i);
            let n2s = *i;
            while *i < s.len() && s[*i].is_ascii_digit() {
                *i += 1;
            }
            let n2: u32 = std::str::from_utf8(&s[n2s..*i])
                .unwrap()
                .parse()
                .map_err(|_| err("bad count range"))?;
            CountPred::Between(n, n2)
        } else {
            match op {
                b'=' => CountPred::Eq(n),
                b'>' => CountPred::Gt(n),
                b'<' => CountPred::Lt(n),
                _ => CountPred::AtLeastOne,
            }
        }
    } else {
        CountPred::AtLeastOne
    };
    Ok(LogExpr::Atom { index, count })
}

fn eval(expr: &LogExpr, hits: &[u32]) -> bool {
    match expr {
        LogExpr::Atom { index, count } => {
            let n = hits.get(*index).copied().unwrap_or(0);
            count.matches(n)
        }
        LogExpr::And(a, b) => eval(a, hits) && eval(b, hits),
        LogExpr::Or(a, b) => eval(a, hits) || eval(b, hits),
    }
}

fn err(reason: &str) -> Error {
    Error::Signature {
        file: "ldb".into(),
        reason: reason.into(),
    }
}

pub fn load_ldb(text: &str) -> (Vec<LogicalSig>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0;
    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match LogicalSig::parse_line(line) {
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
    fn parse_simple_ldb() {
        let line = "Test.Logical;Target:0;0&1;41414141;42424242";
        let s = LogicalSig::parse_line(line).unwrap();
        assert_eq!(s.name, "Test.Logical");
        assert_eq!(s.subsigs.len(), 2);
        assert!(s.eval(&[1, 1]));
        assert!(!s.eval(&[1, 0]));
        assert!(matches!(s.expr, LogExpr::And(_, _)));
    }

    #[test]
    fn parse_or_and_counts() {
        let line = "T;Target:1;(0|1)&2=2;aaaa;bbbb;cccc";
        let s = LogicalSig::parse_line(line).unwrap();
        assert_eq!(s.target, TargetType::Pe);
        assert!(s.eval(&[1, 0, 2]));
        assert!(!s.eval(&[0, 0, 2]));
        assert!(!s.eval(&[1, 0, 1]));
    }

    #[test]
    fn parse_offset_subsig() {
        let line = "T;Target:0;0;0:4142";
        let s = LogicalSig::parse_line(line).unwrap();
        assert_eq!(
            s.subsigs[0].offset,
            OffsetKind::Absolute { at: 0, shift: 0 }
        );
        assert_eq!(s.subsigs[0].pattern.anchor, b"AB");
    }
}
