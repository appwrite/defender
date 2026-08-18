//! ClamAV hexadecimal body-signature compiler and matcher.

use crate::error::{Error, Result};

/// A compiled ClamAV hex signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexPattern {
    pub tokens: Vec<Token>,
    /// Longest literal fragment, used as an Aho-Corasick needle.
    pub anchor: Vec<u8>,
    /// Byte offset of `anchor` from the start of a fully-literal prefix.
    pub anchor_off: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Lit(Vec<u8>),
    Any,
    /// `hi`/`lo` are the required nibble, `None` means wildcard nibble (`?`).
    Nibble {
        hi: Option<u8>,
        lo: Option<u8>,
    },
    /// `{n}`, `{n-m}`, `{n-}`, `{-n}`, `*`, or `[n-m]`.
    Skip {
        min: usize,
        max: Option<usize>,
    },
    /// `(aa|bb|cc)` or multi-byte fixed-width `(aabb|ccdd)`.
    Alt {
        options: Vec<Vec<u8>>,
        negated: bool,
    },
    /// `(B)` word / file boundary.
    WordBoundary,
    /// `(L)` CR, CRLF, or file boundary.
    LineBoundary,
    /// `(W)` non-alphanumeric.
    NonAlnum,
}

impl HexPattern {
    pub fn parse(sig: &str) -> Result<Self> {
        let tokens = tokenize(sig)?;
        let (anchor, anchor_off) = longest_anchor(&tokens);
        Ok(Self {
            tokens,
            anchor,
            anchor_off,
        })
    }

    pub fn min_len(&self) -> usize {
        self.tokens
            .iter()
            .map(|t| match t {
                Token::Lit(v) => v.len(),
                Token::Any | Token::Nibble { .. } => 1,
                Token::Skip { min, .. } => *min,
                Token::Alt { options, .. } => options.iter().map(|o| o.len()).min().unwrap_or(0),
                Token::WordBoundary | Token::LineBoundary | Token::NonAlnum => 0,
            })
            .sum()
    }

    /// True if the pattern matches `haystack` at `at` (pattern starts at `at`).
    pub fn matches_at(&self, haystack: &[u8], at: usize) -> bool {
        match_tokens(&self.tokens, haystack, at).is_some()
    }

    /// Search `haystack` for the first match, optionally constrained to `[from, to]`.
    pub fn find(&self, haystack: &[u8], from: usize, to: Option<usize>) -> Option<usize> {
        let end = to.unwrap_or(haystack.len()).min(haystack.len());
        if from > end {
            return None;
        }
        if !self.anchor.is_empty() {
            let mut search_from = from.saturating_add(self.anchor_off);
            while let Some(rel) = find_slice(&haystack[search_from..end], &self.anchor) {
                let anchor_at = search_from + rel;
                let start = anchor_at.saturating_sub(self.anchor_off);
                if start >= from && start <= end && self.matches_at(haystack, start) {
                    return Some(start);
                }
                search_from = anchor_at.saturating_add(1);
                if search_from >= end {
                    break;
                }
            }
            return None;
        }
        for i in from..=end {
            if self.matches_at(haystack, i) {
                return Some(i);
            }
        }
        None
    }
}

fn find_slice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn tokenize(sig: &str) -> Result<Vec<Token>> {
    let s = sig.trim().as_bytes();
    let mut i = 0;
    let mut tokens = Vec::new();
    let mut lit = Vec::new();

    let flush = |lit: &mut Vec<u8>, tokens: &mut Vec<Token>| {
        if !lit.is_empty() {
            tokens.push(Token::Lit(std::mem::take(lit)));
        }
    };

    while i < s.len() {
        match s[i] {
            b'*' => {
                flush(&mut lit, &mut tokens);
                tokens.push(Token::Skip { min: 0, max: None });
                i += 1;
            }
            b'{' => {
                flush(&mut lit, &mut tokens);
                let close = s[i..]
                    .iter()
                    .position(|&c| c == b'}')
                    .ok_or_else(|| err(sig, "unclosed '{'"))?;
                let inner = std::str::from_utf8(&s[i + 1..i + close])
                    .map_err(|_| err(sig, "invalid skip"))?;
                tokens.push(parse_skip(inner, sig)?);
                i += close + 1;
            }
            b'[' => {
                flush(&mut lit, &mut tokens);
                let close = s[i..]
                    .iter()
                    .position(|&c| c == b']')
                    .ok_or_else(|| err(sig, "unclosed '['"))?;
                let inner = std::str::from_utf8(&s[i + 1..i + close])
                    .map_err(|_| err(sig, "invalid [n-m]"))?;
                tokens.push(parse_skip(inner, sig)?);
                i += close + 1;
            }
            b'(' => {
                flush(&mut lit, &mut tokens);
                let close = find_matching_paren(s, i)?;
                let inner =
                    std::str::from_utf8(&s[i + 1..close]).map_err(|_| err(sig, "invalid group"))?;
                tokens.push(parse_group(inner, sig)?);
                i = close + 1;
            }
            b'!' if i + 1 < s.len() && s[i + 1] == b'(' => {
                flush(&mut lit, &mut tokens);
                let close = find_matching_paren(s, i + 1)?;
                let inner = std::str::from_utf8(&s[i + 2..close])
                    .map_err(|_| err(sig, "invalid negated group"))?;
                match parse_group(inner, sig)? {
                    Token::Alt { options, .. } => {
                        tokens.push(Token::Alt {
                            options,
                            negated: true,
                        });
                    }
                    _ => return Err(err(sig, "negation only valid on alternates")),
                }
                i = close + 1;
            }
            b'?' => {
                // ?? / ?a  — may complete a pending high nibble hex digit
                if i + 1 >= s.len() {
                    return Err(err(sig, "trailing '?'"));
                }
                let nxt = s[i + 1];
                if nxt == b'?' {
                    flush(&mut lit, &mut tokens);
                    tokens.push(Token::Any);
                    i += 2;
                } else if is_hex(nxt) {
                    flush(&mut lit, &mut tokens);
                    tokens.push(Token::Nibble {
                        hi: None,
                        lo: Some(hex_val(nxt)),
                    });
                    i += 2;
                } else {
                    return Err(err(sig, "invalid nibble wildcard"));
                }
            }
            c if is_hex(c) => {
                if i + 1 >= s.len() {
                    return Err(err(sig, "odd number of hex digits"));
                }
                let d2 = s[i + 1];
                if d2 == b'?' {
                    flush(&mut lit, &mut tokens);
                    tokens.push(Token::Nibble {
                        hi: Some(hex_val(c)),
                        lo: None,
                    });
                    i += 2;
                } else if is_hex(d2) {
                    lit.push((hex_val(c) << 4) | hex_val(d2));
                    i += 2;
                } else {
                    return Err(err(sig, "invalid hex pair"));
                }
            }
            b'\n' | b'\r' | b' ' | b'\t' => i += 1,
            _ => return Err(err(sig, &format!("unexpected byte 0x{:02x}", s[i]))),
        }
    }
    flush(&mut lit, &mut tokens);
    if tokens.is_empty() {
        return Err(err(sig, "empty pattern"));
    }
    Ok(tokens)
}

fn parse_skip(inner: &str, sig: &str) -> Result<Token> {
    let inner = inner.trim();
    if inner.is_empty() {
        return Err(err(sig, "empty {}"));
    }
    if let Some(rest) = inner.strip_prefix('-') {
        let n: usize = rest.parse().map_err(|_| err(sig, "invalid {-n}"))?;
        return Ok(Token::Skip {
            min: 0,
            max: Some(n),
        });
    }
    if let Some(rest) = inner.strip_suffix('-') {
        let n: usize = rest.parse().map_err(|_| err(sig, "invalid {n-}"))?;
        return Ok(Token::Skip { min: n, max: None });
    }
    if let Some((a, b)) = inner.split_once('-') {
        let min: usize = a.parse().map_err(|_| err(sig, "invalid {n-m}"))?;
        let max: usize = b.parse().map_err(|_| err(sig, "invalid {n-m}"))?;
        if max < min {
            return Err(err(sig, "{n-m} with m < n"));
        }
        return Ok(Token::Skip {
            min,
            max: Some(max),
        });
    }
    let n: usize = inner.parse().map_err(|_| err(sig, "invalid {n}"))?;
    Ok(Token::Skip {
        min: n,
        max: Some(n),
    })
}

fn parse_group(inner: &str, sig: &str) -> Result<Token> {
    match inner {
        "B" => return Ok(Token::WordBoundary),
        "L" => return Ok(Token::LineBoundary),
        "W" => return Ok(Token::NonAlnum),
        _ => {}
    }
    let mut options = Vec::new();
    for alt in inner.split('|') {
        let alt = alt.trim();
        if alt.is_empty() {
            return Err(err(sig, "empty alternate"));
        }
        // Recursively allow hex (no nested groups) — decode as raw hex bytes.
        let mut bytes = Vec::new();
        let a = alt.as_bytes();
        let mut i = 0;
        while i < a.len() {
            if i + 1 >= a.len() || !is_hex(a[i]) || !is_hex(a[i + 1]) {
                return Err(err(sig, "alternate is not even hex"));
            }
            bytes.push((hex_val(a[i]) << 4) | hex_val(a[i + 1]));
            i += 2;
        }
        options.push(bytes);
    }
    if options.is_empty() {
        return Err(err(sig, "empty alternate set"));
    }
    Ok(Token::Alt {
        options,
        negated: false,
    })
}

fn find_matching_paren(s: &[u8], open: usize) -> Result<usize> {
    let mut depth = 0;
    for i in open..s.len() {
        match s[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
    }
    Err(err(std::str::from_utf8(s).unwrap_or(""), "unclosed '('"))
}

fn longest_anchor(tokens: &[Token]) -> (Vec<u8>, usize) {
    let mut best: &[u8] = &[];
    let mut best_off = 0usize;
    let mut off = 0usize;
    for t in tokens {
        match t {
            Token::Lit(v) => {
                if v.len() > best.len() {
                    best = v;
                    best_off = off;
                }
                off += v.len();
            }
            Token::Any | Token::Nibble { .. } => off += 1,
            Token::Skip { min, max } => {
                // Unbounded / wide skips break a contiguous prefix offset.
                if max.is_none() || max.unwrap().saturating_sub(*min) > 0 {
                    off = usize::MAX / 4;
                } else {
                    off += *min;
                }
            }
            Token::Alt { options, .. } => {
                off += options.iter().map(|o| o.len()).min().unwrap_or(0);
            }
            Token::WordBoundary | Token::LineBoundary | Token::NonAlnum => {}
        }
    }
    (best.to_vec(), best_off)
}

fn match_tokens(tokens: &[Token], hay: &[u8], pos: usize) -> Option<usize> {
    fn rec(tokens: &[Token], hay: &[u8], mut pos: usize) -> Option<usize> {
        let mut i = 0;
        while i < tokens.len() {
            match &tokens[i] {
                Token::Lit(v) => {
                    if pos + v.len() > hay.len() || &hay[pos..pos + v.len()] != v.as_slice() {
                        return None;
                    }
                    pos += v.len();
                    i += 1;
                }
                Token::Any => {
                    if pos >= hay.len() {
                        return None;
                    }
                    pos += 1;
                    i += 1;
                }
                Token::Nibble { hi, lo } => {
                    if pos >= hay.len() {
                        return None;
                    }
                    let b = hay[pos];
                    if let Some(h) = hi {
                        if b >> 4 != *h {
                            return None;
                        }
                    }
                    if let Some(l) = lo {
                        if b & 0x0f != *l {
                            return None;
                        }
                    }
                    pos += 1;
                    i += 1;
                }
                Token::Skip { min, max } => {
                    let rest = &tokens[i + 1..];
                    let start = pos + *min;
                    if start > hay.len() {
                        return None;
                    }
                    match *max {
                        None => {
                            // greedy-but-backtracking: try next literal via memchr-like search
                            if rest.is_empty() {
                                return Some(hay.len());
                            }
                            for npos in start..=hay.len() {
                                if rec(rest, hay, npos).is_some() {
                                    return Some(npos);
                                }
                            }
                            return None;
                        }
                        Some(max) => {
                            let hi = (pos + max).min(hay.len());
                            if rest.is_empty() {
                                return if start <= hay.len()
                                    && pos + max >= hay.len().saturating_sub(0)
                                {
                                    Some(hay.len())
                                } else {
                                    Some(start.min(hay.len()))
                                };
                            }
                            for npos in start..=hi {
                                if rec(rest, hay, npos).is_some() {
                                    return Some(npos);
                                }
                            }
                            return None;
                        }
                    }
                }
                Token::Alt { options, negated } => {
                    if *negated {
                        let width = options.first().map(|o| o.len()).unwrap_or(1);
                        if pos + width > hay.len() {
                            return None;
                        }
                        let slice = &hay[pos..pos + width];
                        if options.iter().any(|o| o.as_slice() == slice) {
                            return None;
                        }
                        pos += width;
                    } else {
                        let mut hit = false;
                        for o in options {
                            if pos + o.len() <= hay.len()
                                && &hay[pos..pos + o.len()] == o.as_slice()
                            {
                                pos += o.len();
                                hit = true;
                                break;
                            }
                        }
                        if !hit {
                            return None;
                        }
                    }
                    i += 1;
                }
                Token::WordBoundary => {
                    let left = if pos == 0 {
                        true
                    } else {
                        !hay[pos - 1].is_ascii_alphanumeric()
                    };
                    let right = if pos >= hay.len() {
                        true
                    } else {
                        !hay[pos].is_ascii_alphanumeric()
                    };
                    if !(left || right) && pos != 0 && pos != hay.len() {
                        // ClamAV (B) matches word boundaries including file bounds.
                        let at_bound = pos == 0 || pos == hay.len();
                        let between = pos > 0
                            && pos < hay.len()
                            && hay[pos - 1].is_ascii_alphanumeric()
                                != hay[pos].is_ascii_alphanumeric();
                        if !at_bound && !between {
                            return None;
                        }
                    } else if !(pos == 0 || pos == hay.len() || left || right) {
                        let between = pos > 0
                            && pos < hay.len()
                            && hay[pos - 1].is_ascii_alphanumeric()
                                != hay[pos].is_ascii_alphanumeric();
                        if !between {
                            return None;
                        }
                    }
                    i += 1;
                }
                Token::LineBoundary => {
                    if pos == 0 || pos == hay.len() {
                        i += 1;
                    } else if hay[pos] == b'\n' {
                        pos += 1;
                        i += 1;
                    } else if hay[pos] == b'\r' {
                        pos += 1;
                        if pos < hay.len() && hay[pos] == b'\n' {
                            pos += 1;
                        }
                        i += 1;
                    } else {
                        return None;
                    }
                }
                Token::NonAlnum => {
                    if pos >= hay.len() || hay[pos].is_ascii_alphanumeric() {
                        return None;
                    }
                    pos += 1;
                    i += 1;
                }
            }
        }
        Some(pos)
    }
    rec(tokens, hay, pos)
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn err(sig: &str, reason: &str) -> Error {
    Error::Signature {
        file: "hex".into(),
        reason: format!("{reason} in `{sig}`"),
    }
}

/// Widen a pattern (`::w` modifier): insert 0x00 after every literal byte.
pub fn widen(pattern: &HexPattern) -> HexPattern {
    let tokens: Vec<Token> = pattern
        .tokens
        .iter()
        .map(|t| match t {
            Token::Lit(v) => {
                let mut w = Vec::with_capacity(v.len() * 2);
                for b in v {
                    w.push(*b);
                    w.push(0);
                }
                Token::Lit(w)
            }
            other => other.clone(),
        })
        .collect();
    let (anchor, anchor_off) = longest_anchor(&tokens);
    HexPattern {
        tokens,
        anchor,
        anchor_off,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_eicar_prefix() {
        let p = HexPattern::parse("58354f21").unwrap();
        assert_eq!(p.anchor, b"X5O!");
        assert!(p.matches_at(b"X5O!rest", 0));
        assert!(!p.matches_at(b"XX5O!", 0));
    }

    #[test]
    fn any_and_nibble() {
        let p = HexPattern::parse("41??43").unwrap();
        assert!(p.find(b"AQC", 0, None).is_some());
        assert!(p.find(b"AzC", 0, None).is_some());
        assert!(p.find(b"AQCZ", 0, None).is_some());
        let p = HexPattern::parse("4?41").unwrap();
        assert!(p.matches_at(b"AA", 0));
        assert!(p.matches_at(b"JA", 0)); // 0x4a
        assert!(!p.matches_at(b"\x5aA", 0));
    }

    #[test]
    fn skip_exact_and_star() {
        let p = HexPattern::parse("41{2}42").unwrap();
        assert!(p.find(b"AxxB", 0, None).is_some());
        assert!(p.find(b"AxxxB", 0, None).is_none());
        let p = HexPattern::parse("4141*4242").unwrap();
        assert!(p.find(b"AAhelloBB", 0, None).is_some());
        assert!(p.find(b"AABB", 0, None).is_some());
        assert!(p.find(b"AA", 0, None).is_none());
    }

    #[test]
    fn skip_range() {
        let p = HexPattern::parse("41{1-3}42").unwrap();
        assert!(p.find(b"AxB", 0, None).is_some());
        assert!(p.find(b"AxxxB", 0, None).is_some());
        assert!(p.find(b"AxxxxB", 0, None).is_none());
        let p = HexPattern::parse("41{-2}42").unwrap();
        assert!(p.find(b"AB", 0, None).is_some());
        assert!(p.find(b"AxxB", 0, None).is_some());
        assert!(p.find(b"AxxxB", 0, None).is_none());
    }

    #[test]
    fn alternates() {
        let p = HexPattern::parse("41(42|43)44").unwrap();
        assert!(p.find(b"ABD", 0, None).is_some());
        assert!(p.find(b"ACD", 0, None).is_some());
        assert!(p.find(b"AED", 0, None).is_none());
    }

    #[test]
    fn bracket_range() {
        let p = HexPattern::parse("64[4-4]61616161").unwrap();
        let mut buf = vec![0x64];
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.extend_from_slice(b"aaaa");
        assert!(p.find(&buf, 0, None).is_some());
    }

    #[test]
    fn word_boundary_and_non_alnum() {
        let p = HexPattern::parse("4141(W)4242").unwrap();
        assert!(p.find(b"AA-BB", 0, None).is_some());
        assert!(p.find(b"AAxBB", 0, None).is_none());
    }
}
