//! ClamAV hexadecimal body-signature compiler and matcher.

use crate::error::{Error, Result};

/// A compiled ClamAV hex signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexPattern {
    pub tokens: Vec<Token>,
    /// Longest literal fragment, used as an Aho-Corasick needle.
    pub anchor: Vec<u8>,
    /// Minimum byte offset of `anchor` from the start of a match.
    pub anchor_off: usize,
    /// Maximum byte offset of `anchor` from the start of a match.
    /// `None` when a preceding skip is unbounded. Equal to `Some(anchor_off)`
    /// when every token before the anchor has a single width.
    pub anchor_max_off: Option<usize>,
    /// Index of the `Lit` token chosen as `anchor`.
    anchor_idx: Option<usize>,
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
        Ok(compile(tokens))
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
        if self.anchor.is_empty() {
            return (from..=end).find(|&i| self.matches_at(haystack, i));
        }
        // `to` limits the pattern start, not how far the match may read.
        let search_to = match self.anchor_max_off {
            Some(max) => end
                .saturating_add(max)
                .saturating_add(self.anchor.len())
                .min(haystack.len()),
            None => haystack.len(),
        };
        let (prefix_core, _) = split_unbounded_suffix(self.prefix_tokens());
        let core_starts = if self.anchor_max_off.is_none() && !prefix_core.is_empty() {
            let starts = collect_starts(&compile(prefix_core.to_vec()), haystack);
            if starts.is_empty() {
                return None;
            }
            Some(starts)
        } else {
            None
        };
        let mut search_from = from.saturating_add(self.anchor_off);
        while let Some(window) = haystack.get(search_from..search_to) {
            let Some(rel) = find_slice(window, &self.anchor) else {
                break;
            };
            let anchor_at = search_from + rel;
            if let Some(start) =
                self.match_start_for_anchor(haystack, anchor_at, from, end, core_starts.as_deref())
            {
                return Some(start);
            }
            search_from = anchor_at.saturating_add(1);
            if search_from >= search_to {
                break;
            }
        }
        None
    }

    pub(crate) fn prefix_tokens(&self) -> &[Token] {
        match self.anchor_idx {
            Some(i) => &self.tokens[..i],
            None => &[],
        }
    }

    pub(crate) fn suffix_matches(&self, haystack: &[u8], anchor_at: usize) -> bool {
        let Some(idx) = self.anchor_idx else {
            return true;
        };
        let after = anchor_at.saturating_add(self.anchor.len());
        match_tokens(&self.tokens[idx + 1..], haystack, after).is_some()
    }

    /// Starts of the prefix before a trailing unbounded skip, or `None` if the
    /// prefix is skip-only. `Some([])` means that core never occurs in `hay`.
    pub(crate) fn prefix_core_starts(&self, hay: &[u8]) -> Option<Vec<usize>> {
        let (core, _) = split_unbounded_suffix(self.prefix_tokens());
        if core.is_empty() {
            return None;
        }
        Some(collect_starts(&compile(core.to_vec()), hay))
    }

    /// Pattern-start positions that could place `anchor` at `anchor_at`.
    pub(crate) fn candidate_start_range(
        &self,
        anchor_at: usize,
    ) -> Option<std::ops::RangeInclusive<usize>> {
        let min = self.anchor_off;
        if anchor_at < min {
            return None;
        }
        let hi = anchor_at - min;
        let lo = match self.anchor_max_off {
            Some(max) => anchor_at.saturating_sub(max),
            None => 0,
        };
        if lo > hi {
            None
        } else {
            Some(lo..=hi)
        }
    }

    fn match_start_for_anchor(
        &self,
        haystack: &[u8],
        anchor_at: usize,
        from: usize,
        end: usize,
        core_starts: Option<&[usize]>,
    ) -> Option<usize> {
        let range = self.candidate_start_range(anchor_at)?;
        let lo = (*range.start()).max(from);
        let hi = (*range.end()).min(end);
        if lo > hi {
            return None;
        }
        const SMALL: usize = 64;
        if let Some(cores) = core_starts {
            if !self.suffix_matches(haystack, anchor_at) {
                return None;
            }
            return cores
                .iter()
                .copied()
                .find(|&s| s >= lo && s <= hi && self.matches_at(haystack, s));
        }
        if hi - lo <= SMALL || self.anchor_max_off.is_some() {
            return (lo..=hi).find(|&start| self.matches_at(haystack, start));
        }
        if self.suffix_matches(haystack, anchor_at) && self.matches_at(haystack, lo) {
            Some(lo)
        } else {
            None
        }
    }
}

fn compile(tokens: Vec<Token>) -> HexPattern {
    let (anchor, anchor_off, anchor_max_off, anchor_idx) = longest_anchor(&tokens);
    HexPattern {
        tokens,
        anchor,
        anchor_off,
        anchor_max_off,
        anchor_idx,
    }
}

fn split_unbounded_suffix(tokens: &[Token]) -> (&[Token], usize) {
    let mut min_skip = 0usize;
    let mut last = tokens.len();
    while last > 0 {
        match &tokens[last - 1] {
            Token::Skip { min, max: None } => {
                min_skip = min_skip.saturating_add(*min);
                last -= 1;
            }
            _ => break,
        }
    }
    (&tokens[..last], min_skip)
}

fn collect_starts(pattern: &HexPattern, hay: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(s) = pattern.find(hay, from, None) {
        out.push(s);
        match s.checked_add(1) {
            Some(next) if next <= hay.len() => from = next,
            _ => break,
        }
        if from > hay.len() {
            break;
        }
    }
    out
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

fn token_width(t: &Token) -> (usize, Option<usize>) {
    match t {
        Token::Lit(v) => (v.len(), Some(v.len())),
        Token::Any | Token::Nibble { .. } | Token::NonAlnum => (1, Some(1)),
        Token::Skip { min, max } => (*min, *max),
        Token::Alt { options, negated } => {
            if *negated {
                let w = options.first().map(|o| o.len()).unwrap_or(1);
                (w, Some(w))
            } else {
                (
                    options.iter().map(|o| o.len()).min().unwrap_or(0),
                    options.iter().map(|o| o.len()).max(),
                )
            }
        }
        Token::WordBoundary => (0, Some(0)),
        // File bounds consume 0; CR/LF in the middle consume 1 or 2.
        Token::LineBoundary => (0, Some(2)),
    }
}

fn add_width(min: &mut usize, max: &mut Option<usize>, dmin: usize, dmax: Option<usize>) {
    *min = min.saturating_add(dmin);
    *max = match (*max, dmax) {
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
        _ => None,
    };
}

fn longest_anchor(tokens: &[Token]) -> (Vec<u8>, usize, Option<usize>, Option<usize>) {
    let mut best: &[u8] = &[];
    let mut best_min = 0usize;
    let mut best_max = Some(0usize);
    let mut best_idx = None;
    let mut min_off = 0usize;
    let mut max_off = Some(0usize);
    for (idx, t) in tokens.iter().enumerate() {
        if let Token::Lit(v) = t {
            if v.len() > best.len() {
                best = v;
                best_min = min_off;
                best_max = max_off;
                best_idx = Some(idx);
            }
        }
        let (dmin, dmax) = token_width(t);
        add_width(&mut min_off, &mut max_off, dmin, dmax);
    }
    (best.to_vec(), best_min, best_max, best_idx)
}

fn remaining_ok(pos: usize, need: usize, hay_len: usize) -> bool {
    need <= hay_len.saturating_sub(pos)
}

fn match_tokens(tokens: &[Token], hay: &[u8], pos: usize) -> Option<usize> {
    fn rec(tokens: &[Token], hay: &[u8], mut pos: usize) -> Option<usize> {
        let mut i = 0;
        while i < tokens.len() {
            match &tokens[i] {
                Token::Lit(v) => {
                    if !remaining_ok(pos, v.len(), hay.len())
                        || &hay[pos..pos + v.len()] != v.as_slice()
                    {
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
                    let start = pos.saturating_add(*min);
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
                            let hi = pos.saturating_add(max).min(hay.len());
                            if rest.is_empty() {
                                return if start <= hay.len() && pos.saturating_add(max) >= hay.len()
                                {
                                    Some(hay.len())
                                } else {
                                    Some(start.min(hay.len()))
                                };
                            }
                            if start > hi {
                                return None;
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
                        if !remaining_ok(pos, width, hay.len()) {
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
                            if remaining_ok(pos, o.len(), hay.len())
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
                    if pos > hay.len() {
                        return None;
                    }
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
                    if pos > hay.len() {
                        return None;
                    }
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
    compile(tokens)
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

    #[test]
    fn variable_skip_records_prefix_span() {
        let p = HexPattern::parse("41{1-3}424242").unwrap();
        assert_eq!(p.anchor, b"BBB");
        assert_eq!(p.anchor_off, 2);
        assert_eq!(p.anchor_max_off, Some(4));

        let p = HexPattern::parse("41*42424242").unwrap();
        assert_eq!(p.anchor, b"BBBB");
        assert_eq!(p.anchor_off, 1);
        assert_eq!(p.anchor_max_off, None);

        let p = HexPattern::parse("{2-}414243").unwrap();
        assert_eq!(p.anchor, b"ABC");
        assert_eq!(p.anchor_off, 2);
        assert_eq!(p.anchor_max_off, None);
    }

    #[test]
    fn find_does_not_panic_on_short_haystack_or_large_from() {
        let p = HexPattern::parse("41{1-3}424242").unwrap();
        assert!(p.find(b"AxBBB", 0, None).is_some());
        assert!(p.find(b"ABBB", 0, None).is_none());
        assert!(p.find(b"xx", 0, None).is_none());
        assert!(p.find(b"", 0, None).is_none());
        assert!(p.find(b"ABC", 10, None).is_none());
        assert!(p.find(b"ABBB", usize::MAX, None).is_none());

        let p = HexPattern::parse("41424344").unwrap();
        assert!(p.find(b"ABCD", 8, None).is_none());
        assert!(p.find(b"AB", 0, Some(1)).is_none());
        assert!(p.find(b"ABCD", 3, Some(3)).is_none());
    }

    #[test]
    fn unbounded_prefix_skips_absent_core_without_quadratic_scan() {
        let p = HexPattern::parse("4142*414141").unwrap();
        let hay = vec![b'A'; 8192];
        assert!(p.find(&hay, 0, None).is_none());

        let mut hit = vec![0u8; 80];
        hit[10] = b'A';
        hit[11] = b'B';
        hit[50] = b'A';
        hit[51] = b'A';
        hit[52] = b'A';
        assert_eq!(p.find(&hit, 0, None), Some(10));
    }

    #[test]
    fn find_shifted_match_when_anchor_follows_variable_skip() {
        let p = HexPattern::parse("41{1-3}424242").unwrap();
        let mut hay = b"xxxxA".to_vec();
        hay.extend_from_slice(&[0x11, 0x22]);
        hay.extend_from_slice(b"BBB");
        assert_eq!(p.find(&hay, 0, None), Some(4));
        assert_eq!(p.find(b"AxBBB", 0, None), Some(0));
        assert!(p.find(b"ABBB", 0, None).is_none());
        assert!(p.find(b"AxxxxBBB", 0, None).is_none());

        let p = HexPattern::parse("41*42424242").unwrap();
        assert_eq!(p.find(b"zzA----BBBB", 0, None), Some(2));

        let p = HexPattern::parse("{1-4}414243").unwrap();
        assert_eq!(p.find(b"xxxxABC", 0, None), Some(0));
    }

    #[test]
    fn find_when_longest_literal_follows_non_alnum_or_line() {
        let p = HexPattern::parse("41(W)424242").unwrap();
        assert_eq!(p.find(b"xxA-BBB", 0, None), Some(2));
        assert!(p.find(b"xxAxBBB", 0, None).is_none());

        let p = HexPattern::parse("41(L)424242").unwrap();
        assert_eq!(p.find(b"xxA\nBBB", 0, None), Some(2));
        assert_eq!(p.find(b"xxA\r\nBBB", 0, None), Some(2));
    }

    #[test]
    fn find_when_anchor_follows_variable_width_alt() {
        let p = HexPattern::parse("41(42|4344)454545").unwrap();
        assert_eq!(p.find(b"xxABEEE", 0, None), Some(2));
        assert_eq!(p.find(b"xxACDEEE", 0, None), Some(2));
        assert!(p.find(b"xxAFEEE", 0, None).is_none());
    }

    #[test]
    fn match_tokens_survives_out_of_range_and_huge_skip() {
        let p = HexPattern::parse(&format!("41{{{}}}42", usize::MAX)).unwrap();
        assert!(!p.matches_at(b"AB", 0));
        assert!(!p.matches_at(b"AB", usize::MAX));
        assert!(p.find(b"AB", 0, None).is_none());

        let p = HexPattern::parse("41(L)42").unwrap();
        assert!(!p.matches_at(b"A\nB", 50));
        assert!(!p.matches_at(b"A\nB", usize::MAX));

        let p = HexPattern::parse("41(B)42").unwrap();
        assert!(!p.matches_at(b"AB", 50));
        assert!(!p.matches_at(&[], 1));
    }

    fn brute_find(p: &HexPattern, hay: &[u8], from: usize, to: Option<usize>) -> Option<usize> {
        let end = to.unwrap_or(hay.len()).min(hay.len());
        if from > end {
            return None;
        }
        (from..=end).find(|&i| p.matches_at(hay, i))
    }

    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn find_agrees_with_brute_force_scan() {
        let sigs = [
            "414243",
            "41{1-3}424242",
            "41*42424242",
            "41{-2}4243",
            "41{2-}424242",
            "??424242",
            "41(W)424242",
            "41(L)424242",
            "41(42|4344)454647",
            "{1-4}414243",
            "41{0-8}42{0-8}434445",
            "4?4243",
            "4141*42",
            "*424344",
            "41{5-}4242",
            "616263(42|434445)464748",
            "41!(42)434445",
            "64[2-4]616161",
            "41(B)424242",
        ];
        let mut seed = 0x00c0_ffee_u64;
        let mut hays: Vec<Vec<u8>> = vec![
            vec![],
            b"A".to_vec(),
            b"ABC".to_vec(),
            b"xxABBB".to_vec(),
            b"A-BBB".to_vec(),
            b"A\nBBB".to_vec(),
            b"A\r\nBBB".to_vec(),
            (0u8..=40).collect(),
        ];
        for _ in 0..40 {
            let n = 8 + (xorshift(&mut seed) as usize % 48);
            hays.push((0..n).map(|_| xorshift(&mut seed) as u8 % 80).collect());
        }
        let froms = [0usize, 1, 2, 5, 16, 40, 80, 100];
        let tos = [None, Some(0), Some(1), Some(8), Some(20), Some(64)];
        for sig in sigs {
            let p = HexPattern::parse(sig).unwrap();
            for hay in &hays {
                for &from in &froms {
                    for &to in &tos {
                        let got = p.find(hay, from, to);
                        let exp = brute_find(&p, hay, from, to);
                        assert_eq!(got, exp, "sig={sig} from={from} to={to:?} hay={hay:?}");
                    }
                }
            }
        }
    }
}
