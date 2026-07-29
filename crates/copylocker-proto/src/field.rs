//! Typed field accessors over a decoded CBOR map.
//!
//! Artifacts are keyed by small unsigned integers. These helpers turn "field 4 must be a
//! 16-byte string" into one call that either yields the value or names the offending field, so
//! that every artifact decoder reads as a flat list of requirements.

use alloc::string::String;
use alloc::vec::Vec;

use copylocker_suite::cbor::CborValue;
use copylocker_suite::CodecError;
use copylocker_types::{EpochId, Fingerprint, LicenseId, MachineId, SuiteId};

use crate::ProtoError;

/// Read a required field, or report which one was missing.
pub(crate) fn req(map: &CborValue, key: u64) -> Result<&CborValue, ProtoError> {
    map.get(key)
        .ok_or(ProtoError::Codec(CodecError::MissingField(key as u8)))
}

/// Read an optional field. A field encoded as explicit `null` counts as absent, so that both
/// spellings of "not present" behave the same for callers.
pub(crate) fn opt(map: &CborValue, key: u64) -> Option<&CborValue> {
    match map.get(key) {
        Some(v) if v.is_null() => None,
        other => other,
    }
}

fn mismatch(key: u64) -> ProtoError {
    ProtoError::Codec(CodecError::TypeMismatch(key as u8))
}

/// Required unsigned integer.
pub(crate) fn uint(map: &CborValue, key: u64) -> Result<u64, ProtoError> {
    req(map, key)?.as_uint().ok_or_else(|| mismatch(key))
}

/// Required unsigned integer narrowed to `u8`.
pub(crate) fn u8_field(map: &CborValue, key: u64) -> Result<u8, ProtoError> {
    u8::try_from(uint(map, key)?).map_err(|_| ProtoError::FieldOutOfRange(key as u8))
}

/// Required unsigned integer narrowed to `u32`.
pub(crate) fn u32_field(map: &CborValue, key: u64) -> Result<u32, ProtoError> {
    u32::try_from(uint(map, key)?).map_err(|_| ProtoError::FieldOutOfRange(key as u8))
}

/// Required signed integer (a Unix timestamp, in practice).
pub(crate) fn int(map: &CborValue, key: u64) -> Result<i64, ProtoError> {
    req(map, key)?.as_int().ok_or_else(|| mismatch(key))
}

/// Optional unsigned integer.
pub(crate) fn opt_uint(map: &CborValue, key: u64) -> Result<Option<u64>, ProtoError> {
    match opt(map, key) {
        None => Ok(None),
        Some(v) => v.as_uint().map(Some).ok_or_else(|| mismatch(key)),
    }
}

/// Required byte string of any length.
pub(crate) fn bytes(map: &CborValue, key: u64) -> Result<Vec<u8>, ProtoError> {
    req(map, key)?
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| mismatch(key))
}

/// Optional byte string.
pub(crate) fn opt_bytes(map: &CborValue, key: u64) -> Result<Option<Vec<u8>>, ProtoError> {
    match opt(map, key) {
        None => Ok(None),
        Some(v) => v
            .as_bytes()
            .map(|b| Some(b.to_vec()))
            .ok_or_else(|| mismatch(key)),
    }
}

/// Required byte string of exactly `N` bytes.
///
/// A length mismatch is reported as a *range* error rather than a type error: the field was the
/// right CBOR type but the wrong width, which usually means a version skew rather than garbage.
pub(crate) fn fixed<const N: usize>(map: &CborValue, key: u64) -> Result<[u8; N], ProtoError> {
    let b = req(map, key)?.as_bytes().ok_or_else(|| mismatch(key))?;
    b.try_into()
        .map_err(|_| ProtoError::FieldOutOfRange(key as u8))
}

/// Required text string.
pub(crate) fn text(map: &CborValue, key: u64) -> Result<String, ProtoError> {
    req(map, key)?
        .as_text()
        .map(String::from)
        .ok_or_else(|| mismatch(key))
}

/// Optional text string.
pub(crate) fn opt_text(map: &CborValue, key: u64) -> Result<Option<String>, ProtoError> {
    match opt(map, key) {
        None => Ok(None),
        Some(v) => v
            .as_text()
            .map(|t| Some(String::from(t)))
            .ok_or_else(|| mismatch(key)),
    }
}

/// Required array of text strings.
pub(crate) fn text_array(map: &CborValue, key: u64) -> Result<Vec<String>, ProtoError> {
    let arr = req(map, key)?.as_array().ok_or_else(|| mismatch(key))?;
    arr.iter()
        .map(|v| v.as_text().map(String::from).ok_or_else(|| mismatch(key)))
        .collect()
}

/// Required array of fixed-width byte strings.
pub(crate) fn fixed_array<const N: usize>(
    map: &CborValue,
    key: u64,
) -> Result<Vec<[u8; N]>, ProtoError> {
    let arr = req(map, key)?.as_array().ok_or_else(|| mismatch(key))?;
    arr.iter()
        .map(|v| {
            v.as_bytes()
                .ok_or_else(|| mismatch(key))?
                .try_into()
                .map_err(|_| ProtoError::FieldOutOfRange(key as u8))
        })
        .collect()
}

/// Required `SuiteId`.
pub(crate) fn suite_id(map: &CborValue, key: u64) -> Result<SuiteId, ProtoError> {
    Ok(SuiteId(fixed::<4>(map, key)?))
}

/// Required `LicenseId`.
pub(crate) fn license_id(map: &CborValue, key: u64) -> Result<LicenseId, ProtoError> {
    Ok(LicenseId(fixed::<16>(map, key)?))
}

/// Required `MachineId`.
pub(crate) fn machine_id(map: &CborValue, key: u64) -> Result<MachineId, ProtoError> {
    Ok(MachineId(fixed::<16>(map, key)?))
}

/// Required `EpochId`.
pub(crate) fn epoch_id(map: &CborValue, key: u64) -> Result<EpochId, ProtoError> {
    Ok(EpochId(fixed::<8>(map, key)?))
}

/// Required `Fingerprint` (variable width, since vendors may supply their own scheme).
pub(crate) fn fingerprint(map: &CborValue, key: u64) -> Result<Fingerprint, ProtoError> {
    Ok(Fingerprint::from_vec(bytes(map, key)?))
}

/// Required map of text keys to byte-string values, e.g. `wrapped_keks`.
pub(crate) fn text_bytes_map(
    map: &CborValue,
    key: u64,
) -> Result<alloc::collections::BTreeMap<String, Vec<u8>>, ProtoError> {
    let entries = req(map, key)?.as_map().ok_or_else(|| mismatch(key))?;
    entries
        .iter()
        .map(|(k, v)| {
            let k = k.as_text().ok_or_else(|| mismatch(key))?;
            let v = v.as_bytes().ok_or_else(|| mismatch(key))?;
            Ok((String::from(k), v.to_vec()))
        })
        .collect()
}

/// Optional map of text keys to byte-string values.
pub(crate) fn opt_text_bytes_map(
    map: &CborValue,
    key: u64,
) -> Result<Option<alloc::collections::BTreeMap<String, Vec<u8>>>, ProtoError> {
    match opt(map, key) {
        None => Ok(None),
        Some(_) => text_bytes_map(map, key).map(Some),
    }
}

/// Encode a text-keyed byte map.
pub(crate) fn enc_text_bytes_map(m: &alloc::collections::BTreeMap<String, Vec<u8>>) -> CborValue {
    CborValue::Map(
        m.iter()
            .map(|(k, v)| (CborValue::Text(k.clone()), CborValue::Bytes(v.clone())))
            .collect(),
    )
}
