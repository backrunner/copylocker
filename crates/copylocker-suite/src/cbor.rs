//! Deterministic CBOR: a strict subset reader and a canonical writer.
//!
//! Signatures cover *encoded bytes*. If two encodings of the same value were both accepted, an
//! attacker could re-encode a signed artifact into different bytes and — depending on what the
//! verifier hashes — either break verification or slip a second valid form past a duplicate
//! check. So this module does two things:
//!
//! 1. **Writes** only canonical form (RFC 8949 §4.2.1): shortest-form integers, definite
//!    lengths, map keys sorted by the bytewise lexicographic order of their encoded form.
//! 2. **Rejects** any input that is not already canonical, by re-encoding what it parsed and
//!    comparing bytes.
//!
//! The supported subset is deliberately narrow: unsigned and negative integers, byte strings,
//! text strings, arrays, maps, booleans, and null. Floats, tags, indefinite-length items, and
//! `undefined` are rejected outright rather than parsed and ignored — an unsupported major type
//! in an artifact is a protocol violation, not a field to skip.

use alloc::string::String;
use alloc::vec::Vec;

use crate::CodecError;

/// Default nesting depth limit (`protocol-spec.md §10.1`).
pub const DEFAULT_MAX_DEPTH: u8 = 16;

/// A CBOR value in the supported subset.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum CborValue {
    /// Major type 0.
    Uint(u64),
    /// Major type 1, stored as the encoded `-1 - n` argument.
    Nint(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<CborValue>),
    /// Major type 5. Held as a vector so the writer can sort; duplicates are rejected on parse.
    Map(Vec<(CborValue, CborValue)>),
    /// Major type 7, simple value 20/21.
    Bool(bool),
    /// Major type 7, simple value 22.
    Null,
}

impl CborValue {
    /// Build an integer value, choosing the correct major type.
    #[must_use]
    pub fn int(v: i64) -> Self {
        if v < 0 {
            // -1 - v, computed without overflowing at i64::MIN.
            Self::Nint((-(v + 1)) as u64)
        } else {
            Self::Uint(v as u64)
        }
    }

    /// Read an integer, whichever major type it used.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Uint(v) => i64::try_from(*v).ok(),
            Self::Nint(v) => i64::try_from(*v).ok().map(|n| -n - 1),
            _ => None,
        }
    }

    /// Read an unsigned integer.
    #[must_use]
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(v) => Some(*v),
            _ => None,
        }
    }

    /// Borrow a byte string.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Borrow a text string.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t),
            _ => None,
        }
    }

    /// Borrow an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[CborValue]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Borrow a map's entries.
    #[must_use]
    pub fn as_map(&self) -> Option<&[(CborValue, CborValue)]> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Read a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Whether this is [`CborValue::Null`].
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Look up a map entry by small unsigned key, the form used by every protocol artifact.
    #[must_use]
    pub fn get(&self, key: u64) -> Option<&CborValue> {
        let entries = self.as_map()?;
        entries
            .iter()
            .find(|(k, _)| k.as_uint() == Some(key))
            .map(|(_, v)| v)
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn to_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_into(&mut out);
        out
    }

    fn write_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Uint(v) => write_head(out, 0, *v),
            Self::Nint(v) => write_head(out, 1, *v),
            Self::Bytes(b) => {
                write_head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Self::Text(t) => {
                write_head(out, 3, t.len() as u64);
                out.extend_from_slice(t.as_bytes());
            }
            Self::Array(a) => {
                write_head(out, 4, a.len() as u64);
                for item in a {
                    item.write_into(out);
                }
            }
            Self::Map(m) => {
                // Canonical ordering: sort by the encoded bytes of each key.
                let mut encoded: Vec<(Vec<u8>, &CborValue)> =
                    m.iter().map(|(k, v)| (k.to_canonical(), v)).collect();
                encoded.sort_by(|a, b| a.0.cmp(&b.0));
                write_head(out, 5, encoded.len() as u64);
                for (k, v) in encoded {
                    out.extend_from_slice(&k);
                    v.write_into(out);
                }
            }
            Self::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            Self::Null => out.push(0xf6),
        }
    }
}

/// Write a major-type head with the shortest possible argument encoding.
fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | (arg as u8));
    } else if arg <= u64::from(u8::MAX) {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= u64::from(u16::MAX) {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u64::from(u32::MAX) {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Limits applied while parsing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Limits {
    /// Maximum nesting depth.
    pub max_depth: u8,
    /// Maximum number of elements in any single array or map.
    pub max_items: usize,
    /// Maximum length of any single byte or text string.
    pub max_string: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_items: 4096,
            max_string: 64 * 1024,
        }
    }
}

/// Parse canonical CBOR, rejecting anything non-canonical or outside the limits.
///
/// Trailing bytes after the first complete value are an error: a decoder that ignored them
/// would let an attacker append data that some other parser might read.
pub fn decode_canonical(bytes: &[u8], limits: Limits) -> Result<CborValue, CodecError> {
    let mut p = Parser {
        buf: bytes,
        pos: 0,
        limits,
    };
    let v = p.value(0)?;
    if p.pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    // Canonicity check: whatever we parsed must re-encode to exactly the input.
    if v.to_canonical() != bytes {
        return Err(CodecError::NotCanonical);
    }
    Ok(v)
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
    limits: Limits,
}

impl Parser<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::Malformed)?;
        let slice = self.buf.get(self.pos..end).ok_or(CodecError::Malformed)?;
        self.pos = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, CodecError> {
        let b = *self.buf.get(self.pos).ok_or(CodecError::Malformed)?;
        self.pos += 1;
        Ok(b)
    }

    /// Read a major type and its argument. Indefinite lengths (`31`) and the reserved
    /// additional-information values `28..=30` are rejected here rather than downstream.
    fn head(&mut self) -> Result<(u8, u64), CodecError> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => u64::from(self.byte()?),
            25 => {
                let bytes: [u8; 2] = self
                    .take(2)?
                    .try_into()
                    .map_err(|_| CodecError::Malformed)?;
                u64::from(u16::from_be_bytes(bytes))
            }
            26 => {
                let bytes: [u8; 4] = self
                    .take(4)?
                    .try_into()
                    .map_err(|_| CodecError::Malformed)?;
                u64::from(u32::from_be_bytes(bytes))
            }
            27 => {
                let bytes: [u8; 8] = self
                    .take(8)?
                    .try_into()
                    .map_err(|_| CodecError::Malformed)?;
                u64::from_be_bytes(bytes)
            }
            _ => return Err(CodecError::Malformed),
        };
        Ok((major, arg))
    }

    fn count(&self, arg: u64) -> Result<usize, CodecError> {
        let n = usize::try_from(arg).map_err(|_| CodecError::TooLong)?;
        if n > self.limits.max_items {
            return Err(CodecError::TooLong);
        }
        Ok(n)
    }

    fn value(&mut self, depth: u8) -> Result<CborValue, CodecError> {
        if depth > self.limits.max_depth {
            return Err(CodecError::DepthExceeded);
        }
        let (major, arg) = self.head()?;
        match major {
            0 => Ok(CborValue::Uint(arg)),
            1 => Ok(CborValue::Nint(arg)),
            2 => {
                let n = usize::try_from(arg).map_err(|_| CodecError::TooLong)?;
                if n > self.limits.max_string {
                    return Err(CodecError::TooLong);
                }
                Ok(CborValue::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = usize::try_from(arg).map_err(|_| CodecError::TooLong)?;
                if n > self.limits.max_string {
                    return Err(CodecError::TooLong);
                }
                let raw = self.take(n)?;
                let s = core::str::from_utf8(raw).map_err(|_| CodecError::Malformed)?;
                Ok(CborValue::Text(String::from(s)))
            }
            4 => {
                let n = self.count(arg)?;
                let mut items = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                let n = self.count(arg)?;
                let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    let k = self.value(depth + 1)?;
                    // A duplicate key makes the map ambiguous; which one wins would depend on
                    // the reader. Reject rather than pick.
                    if entries.iter().any(|(ek, _)| *ek == k) {
                        return Err(CodecError::NotCanonical);
                    }
                    let v = self.value(depth + 1)?;
                    entries.push((k, v));
                }
                Ok(CborValue::Map(entries))
            }
            7 => match arg {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                _ => Err(CodecError::Malformed),
            },
            // Major type 6 is tags: unsupported by design.
            _ => Err(CodecError::Malformed),
        }
    }
}

/// Builder for a canonical map keyed by small unsigned integers, the shape every protocol
/// artifact uses.
#[derive(Default, Debug)]
pub struct MapBuilder {
    entries: Vec<(CborValue, CborValue)>,
}

impl MapBuilder {
    /// A new, empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a field.
    pub fn put(&mut self, key: u64, value: CborValue) -> &mut Self {
        self.entries.push((CborValue::Uint(key), value));
        self
    }

    /// Insert a field only when present. Optional protocol fields are *omitted*, never encoded
    /// as null, so that the canonical form of "absent" is unambiguous.
    pub fn put_opt(&mut self, key: u64, value: Option<CborValue>) -> &mut Self {
        if let Some(v) = value {
            self.put(key, v);
        }
        self
    }

    /// Finish, producing the map value.
    #[must_use]
    pub fn build(self) -> CborValue {
        CborValue::Map(self.entries)
    }

    /// Finish and encode.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.build().to_canonical()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn rt(v: &CborValue) -> Result<CborValue, CodecError> {
        let bytes = v.to_canonical();
        decode_canonical(&bytes, Limits::default())
    }

    #[test]
    fn integers_use_shortest_form() {
        assert_eq!(CborValue::Uint(0).to_canonical(), vec![0x00]);
        assert_eq!(CborValue::Uint(23).to_canonical(), vec![0x17]);
        assert_eq!(CborValue::Uint(24).to_canonical(), vec![0x18, 0x18]);
        assert_eq!(CborValue::Uint(255).to_canonical(), vec![0x18, 0xff]);
        assert_eq!(CborValue::Uint(256).to_canonical(), vec![0x19, 0x01, 0x00]);
        assert_eq!(CborValue::int(-1).to_canonical(), vec![0x20]);
        assert_eq!(CborValue::int(-100).to_canonical(), vec![0x38, 0x63]);
    }

    #[test]
    fn non_shortest_integer_encoding_is_rejected() {
        // 0 encoded in two bytes rather than one.
        let bad = vec![0x18, 0x00];
        assert_eq!(
            decode_canonical(&bad, Limits::default()),
            Err(CodecError::NotCanonical)
        );
    }

    #[test]
    fn indefinite_length_is_rejected() {
        // 0x5f = indefinite-length byte string.
        assert_eq!(
            decode_canonical(&[0x5f, 0xff], Limits::default()),
            Err(CodecError::Malformed)
        );
    }

    #[test]
    fn tags_and_floats_are_rejected() {
        assert_eq!(
            decode_canonical(&[0xc0, 0x00], Limits::default()),
            Err(CodecError::Malformed),
            "tag"
        );
        assert_eq!(
            decode_canonical(&[0xfa, 0, 0, 0, 0], Limits::default()),
            Err(CodecError::Malformed),
            "float32"
        );
    }

    #[test]
    fn map_keys_are_sorted_by_encoded_bytes() {
        let m = CborValue::Map(vec![
            (CborValue::Uint(10), CborValue::Uint(1)),
            (CborValue::Uint(1), CborValue::Uint(2)),
            (CborValue::Uint(255), CborValue::Uint(3)),
        ]);
        let enc = m.to_canonical();
        // header, then keys in ascending encoded order: 0x01, 0x0a, 0x18ff
        assert_eq!(enc.first(), Some(&0xa3));
        assert_eq!(enc.get(1), Some(&0x01));
        assert_eq!(enc.get(3), Some(&0x0a));
        assert_eq!(enc.get(5), Some(&0x18));
        // And it must survive the canonicity check.
        assert_eq!(
            rt(&m)
                .ok()
                .and_then(|decoded| decoded.as_map().map(<[_]>::len)),
            Some(3)
        );
    }

    #[test]
    fn out_of_order_map_is_rejected() {
        // Same three entries, written with keys descending.
        let mut bad = vec![0xa2];
        bad.extend_from_slice(&[0x0a, 0x01]); // key 10
        bad.extend_from_slice(&[0x01, 0x02]); // key 1
        assert_eq!(
            decode_canonical(&bad, Limits::default()),
            Err(CodecError::NotCanonical)
        );
    }

    #[test]
    fn duplicate_map_keys_are_rejected() {
        let mut bad = vec![0xa2];
        bad.extend_from_slice(&[0x01, 0x01]);
        bad.extend_from_slice(&[0x01, 0x02]);
        assert_eq!(
            decode_canonical(&bad, Limits::default()),
            Err(CodecError::NotCanonical)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut b = CborValue::Uint(1).to_canonical();
        b.push(0x00);
        assert_eq!(
            decode_canonical(&b, Limits::default()),
            Err(CodecError::TrailingBytes)
        );
    }

    #[test]
    fn depth_limit_is_enforced() {
        let limits = Limits {
            max_depth: 4,
            ..Limits::default()
        };
        let mut v = CborValue::Uint(0);
        for _ in 0..10 {
            v = CborValue::Array(vec![v]);
        }
        assert_eq!(
            decode_canonical(&v.to_canonical(), limits),
            Err(CodecError::DepthExceeded)
        );
    }

    #[test]
    fn truncated_input_does_not_panic() {
        let full = CborValue::Map(vec![(CborValue::Uint(1), CborValue::Bytes(vec![7; 40]))])
            .to_canonical();
        for cut in 0..full.len() {
            // The contract is "returns an error", not "returns a specific error".
            if let Some(prefix) = full.get(..cut) {
                let _ = decode_canonical(prefix, Limits::default());
            }
        }
    }

    #[test]
    fn every_supported_type_roundtrips() {
        let v = CborValue::Map(vec![
            (CborValue::Uint(0), CborValue::Uint(1)),
            (CborValue::Uint(1), CborValue::int(-42)),
            (CborValue::Uint(2), CborValue::Bytes(vec![1, 2, 3])),
            (CborValue::Uint(3), CborValue::Text("héllo".into())),
            (
                CborValue::Uint(4),
                CborValue::Array(vec![CborValue::Bool(true), CborValue::Null]),
            ),
        ]);
        assert_eq!(rt(&v), Ok(v));
    }

    #[test]
    fn int_conversion_roundtrips_at_the_extremes() {
        for n in [0i64, 1, -1, i64::MAX, i64::MIN + 1] {
            assert_eq!(CborValue::int(n).as_int(), Some(n), "value {n}");
        }
    }

    #[test]
    fn builder_omits_absent_optional_fields() {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(1));
        b.put_opt(1, None);
        b.put_opt(2, Some(CborValue::Uint(9)));
        let v = b.build();
        assert_eq!(v.as_map().map(<[_]>::len), Some(2));
        assert!(v.get(1).is_none());
        assert_eq!(v.get(2).and_then(CborValue::as_uint), Some(9));
    }
}
