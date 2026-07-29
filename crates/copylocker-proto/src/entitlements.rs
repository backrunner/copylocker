//! Wire encoding for resolved entitlements (`licensing-model.md §9`).
//!
//! ```cddl
//! entitlements = {
//!   0: [* tstr],            ; features — fully expanded, ordered
//!   1: { * tstr => int },   ; limits (-1 = unlimited)
//!   2: tstr,                ; tier_id
//!   3: tstr,                ; tier_label
//!   4: uint,                ; catalog_version
//!   5: ? version_scope,
//!   6: ? subscription_hint,
//! }
//! ```

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;

use copylocker_suite::cbor::{CborValue, MapBuilder};
use copylocker_suite::CodecError;
use copylocker_types::{Entitlements, SubscriptionHint, SubscriptionState, VersionScope};

use crate::field;
use crate::ProtoError;

/// Encode entitlements.
///
/// `features` and `limits` come from ordered collections, and the canonical CBOR writer sorts
/// map keys, so the output is byte-reproducible for a given input — which is what lets a
/// signature over a credential be re-derived and compared (`licensing-model.md §2.2`).
#[must_use]
pub fn encode(e: &Entitlements) -> CborValue {
    let mut b = MapBuilder::new();
    b.put(
        0,
        CborValue::Array(e.features.iter().cloned().map(CborValue::Text).collect()),
    );
    b.put(
        1,
        CborValue::Map(
            e.limits
                .iter()
                .map(|(k, v)| (CborValue::Text(k.clone()), CborValue::int(*v)))
                .collect(),
        ),
    );
    b.put(2, CborValue::Text(e.tier_id.clone()));
    b.put(3, CborValue::Text(e.tier_label.clone()));
    b.put(4, CborValue::Uint(u64::from(e.catalog_version)));
    b.put_opt(5, e.version_scope.as_ref().map(encode_version_scope));
    b.put_opt(6, e.subscription_hint.as_ref().map(encode_hint));
    b.build()
}

/// Decode entitlements.
pub fn decode(v: &CborValue) -> Result<Entitlements, ProtoError> {
    if v.as_map().is_none() {
        return Err(ProtoError::Codec(CodecError::Malformed));
    }
    let feature_list = field::text_array(v, 0)?;
    let features: BTreeSet<String> = feature_list.iter().cloned().collect();
    // A duplicate would mean the sender's set was not actually a set; the signature covers the
    // list form, so silently collapsing duplicates would let two encodings mean one value.
    if features.len() != feature_list.len() {
        return Err(ProtoError::Codec(CodecError::NotCanonical));
    }

    let limits_raw = field::req(v, 1)?
        .as_map()
        .ok_or(ProtoError::Codec(CodecError::TypeMismatch(1)))?;
    let mut limits = BTreeMap::new();
    for (k, val) in limits_raw {
        let key = k
            .as_text()
            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(1)))?;
        let n = val
            .as_int()
            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(1)))?;
        limits.insert(String::from(key), n);
    }

    Ok(Entitlements {
        features,
        limits,
        tier_id: field::text(v, 2)?,
        tier_label: field::text(v, 3)?,
        catalog_version: field::u32_field(v, 4)?,
        version_scope: match field::opt(v, 5) {
            None => None,
            Some(vs) => Some(decode_version_scope(vs)?),
        },
        subscription_hint: match field::opt(v, 6) {
            None => None,
            Some(h) => Some(decode_hint(h)?),
        },
    })
}

/// ```cddl
/// version_scope = { 0: uint } / { 1: tstr } / { 2: int } / { 3: [* tstr] }
/// ```
#[must_use]
pub fn encode_version_scope(vs: &VersionScope) -> CborValue {
    let mut b = MapBuilder::new();
    match vs {
        VersionScope::Unlimited => b.put(0, CborValue::Uint(0)),
        VersionScope::SemverRange(r) => b.put(1, CborValue::Text(r.clone())),
        VersionScope::ReleasedBefore(t) => b.put(2, CborValue::int(*t)),
        VersionScope::Pinned(ids) => b.put(
            3,
            CborValue::Array(ids.iter().cloned().map(CborValue::Text).collect()),
        ),
    };
    b.build()
}

/// Decode a version scope.
pub fn decode_version_scope(v: &CborValue) -> Result<VersionScope, ProtoError> {
    let entries = v.as_map().ok_or(ProtoError::Codec(CodecError::Malformed))?;
    // Exactly one variant key, or the value is ambiguous.
    if entries.len() != 1 {
        return Err(ProtoError::Codec(CodecError::Malformed));
    }
    if field::opt(v, 0).is_some() {
        return Ok(VersionScope::Unlimited);
    }
    if field::opt(v, 1).is_some() {
        return Ok(VersionScope::SemverRange(field::text(v, 1)?));
    }
    if field::opt(v, 2).is_some() {
        return Ok(VersionScope::ReleasedBefore(field::int(v, 2)?));
    }
    if field::opt(v, 3).is_some() {
        return Ok(VersionScope::Pinned(field::text_array(v, 3)?));
    }
    Err(ProtoError::Codec(CodecError::UnknownDiscriminant))
}

/// ```cddl
/// subscription_hint = { 0: uint, 1: int, 2: ? uint, 3: ? uint }
/// ```
#[must_use]
pub fn encode_hint(h: &SubscriptionHint) -> CborValue {
    let mut b = MapBuilder::new();
    b.put(0, CborValue::Uint(h.state as u64));
    b.put(1, CborValue::int(h.current_period_end));
    b.put_opt(
        2,
        h.fallback_progress_months
            .map(|m| CborValue::Uint(u64::from(m))),
    );
    b.put_opt(
        3,
        h.fallback_required_months
            .map(|m| CborValue::Uint(u64::from(m))),
    );
    b.build()
}

/// Decode a subscription hint.
pub fn decode_hint(v: &CborValue) -> Result<SubscriptionHint, ProtoError> {
    let state_raw = field::u8_field(v, 0)?;
    Ok(SubscriptionHint {
        state: SubscriptionState::from_u8(state_raw)
            .ok_or(ProtoError::Codec(CodecError::UnknownDiscriminant))?,
        current_period_end: field::int(v, 1)?,
        fallback_progress_months: field::opt_uint(v, 2)?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ProtoError::FieldOutOfRange(2))?,
        fallback_required_months: field::opt_uint(v, 3)?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ProtoError::FieldOutOfRange(3))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use copylocker_suite::cbor::{decode_canonical, Limits};

    fn sample() -> Entitlements {
        let mut features = BTreeSet::new();
        features.insert("export.pdf".to_string());
        features.insert("export.png".to_string());
        let mut limits = BTreeMap::new();
        limits.insert("max_projects".to_string(), -1);
        limits.insert("max_members".to_string(), 25);
        Entitlements {
            features,
            limits,
            tier_id: "team".to_string(),
            tier_label: "团队版".to_string(),
            catalog_version: 7,
            version_scope: Some(VersionScope::ReleasedBefore(1_800_000_000)),
            subscription_hint: Some(SubscriptionHint {
                state: SubscriptionState::PastDue,
                current_period_end: 1_800_000_100,
                fallback_progress_months: Some(9),
                fallback_required_months: Some(12),
            }),
        }
    }

    #[test]
    fn roundtrips() {
        let e = sample();
        let encoded = encode(&e).to_canonical();
        let parsed = decode_canonical(&encoded, Limits::default()).unwrap();
        assert_eq!(decode(&parsed).unwrap(), e);
    }

    #[test]
    fn encoding_is_byte_reproducible() {
        // The signature is over these bytes, so two encodings of one value would be two
        // different signed messages.
        assert_eq!(
            encode(&sample()).to_canonical(),
            encode(&sample()).to_canonical()
        );
    }

    #[test]
    fn optional_fields_are_omitted_not_nulled() {
        let mut e = sample();
        e.version_scope = None;
        e.subscription_hint = None;
        let v = encode(&e);
        assert!(v.get(5).is_none());
        assert!(v.get(6).is_none());
        assert_eq!(decode(&v).unwrap(), e);
    }

    #[test]
    fn every_version_scope_variant_roundtrips() {
        for vs in [
            VersionScope::Unlimited,
            VersionScope::SemverRange("^3".to_string()),
            VersionScope::ReleasedBefore(-1),
            VersionScope::Pinned(vec!["rel_a".to_string(), "rel_b".to_string()]),
        ] {
            assert_eq!(
                decode_version_scope(&encode_version_scope(&vs)).unwrap(),
                vs
            );
        }
    }

    #[test]
    fn ambiguous_version_scope_is_rejected() {
        let v = CborValue::Map(vec![
            (CborValue::Uint(0), CborValue::Uint(0)),
            (CborValue::Uint(2), CborValue::int(5)),
        ]);
        assert!(decode_version_scope(&v).is_err());
        assert!(decode_version_scope(&CborValue::Map(vec![])).is_err());
    }

    #[test]
    fn unknown_subscription_state_is_rejected() {
        let v = CborValue::Map(vec![
            (CborValue::Uint(0), CborValue::Uint(99)),
            (CborValue::Uint(1), CborValue::int(0)),
        ]);
        assert!(decode_hint(&v).is_err());
    }

    #[test]
    fn duplicate_features_are_rejected() {
        let v = CborValue::Map(vec![
            (
                CborValue::Uint(0),
                CborValue::Array(vec![
                    CborValue::Text("a".into()),
                    CborValue::Text("a".into()),
                ]),
            ),
            (CborValue::Uint(1), CborValue::Map(vec![])),
            (CborValue::Uint(2), CborValue::Text("t".into())),
            (CborValue::Uint(3), CborValue::Text("T".into())),
            (CborValue::Uint(4), CborValue::Uint(1)),
        ]);
        assert!(decode(&v).is_err());
    }

    #[test]
    fn missing_required_field_names_the_field() {
        let v = CborValue::Map(vec![(CborValue::Uint(0), CborValue::Array(vec![]))]);
        assert_eq!(
            decode(&v),
            Err(ProtoError::Codec(CodecError::MissingField(1)))
        );
    }
}
