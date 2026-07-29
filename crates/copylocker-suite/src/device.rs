//! Device attributes and the fingerprint slot.
//!
//! The attribute set and its weights are documented in `20-client-core.md §3.1` precisely so
//! that a vendor can copy them into a privacy policy. Nothing here is meant to be secret.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use copylocker_types::Fingerprint;

use crate::cbor::CborValue;

/// Variant tags used by [`DeviceAttrs::canonical_bytes`]. Frozen: changing one changes every
/// fingerprint ever computed.
mod tag {
    /// [`super::AttrValue::Absent`].
    pub(super) const ABSENT: u64 = 0;
    /// [`super::AttrValue::Text`].
    pub(super) const TEXT: u64 = 1;
    /// [`super::AttrValue::Set`].
    pub(super) const SET: u64 = 2;
    /// [`super::AttrValue::Int`].
    pub(super) const INT: u64 = 3;
}

/// Encode one attribute value as `[tag, payload]`, or `[tag]` for absent.
fn encode_attr(v: &AttrValue) -> CborValue {
    match v {
        AttrValue::Absent => CborValue::Array(alloc::vec![CborValue::Uint(tag::ABSENT)]),
        AttrValue::Text(t) => CborValue::Array(alloc::vec![
            CborValue::Uint(tag::TEXT),
            CborValue::Text(t.clone())
        ]),
        AttrValue::Set(items) => CborValue::Array(alloc::vec![
            CborValue::Uint(tag::SET),
            CborValue::Array(items.iter().cloned().map(CborValue::Text).collect())
        ]),
        AttrValue::Int(n) => {
            CborValue::Array(alloc::vec![CborValue::Uint(tag::INT), CborValue::int(*n)])
        }
    }
}

/// Canonical attribute name, e.g. `machine_guid`, `cpu_id`, `mac_addrs`.
pub type AttrKey = String;

/// A normalised attribute value.
///
/// A *missing* attribute is represented explicitly as [`AttrValue::Absent`] rather than by
/// omitting the key. Omission would make `{a: x}` and `{a: x, b: absent}` hash identically,
/// so two genuinely different machines could collide (`20-client-core.md §3.2`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum AttrValue {
    /// The attribute could not be read on this platform or in this environment.
    Absent,
    /// A single normalised string: trimmed, lowercased, inner whitespace collapsed.
    Text(String),
    /// An unordered set, stored sorted and deduplicated so encoding is deterministic.
    Set(Vec<String>),
    /// An integer measurement such as core count.
    Int(i64),
}

impl AttrValue {
    /// Normalise a free-form string into [`AttrValue::Text`].
    ///
    /// Normalisation is part of the protocol: a client that trims differently produces a
    /// different fingerprint and loses its seat. The rules are: trim, lowercase (ASCII),
    /// collapse runs of whitespace to a single space.
    #[must_use]
    pub fn text(raw: &str) -> Self {
        let mut out = String::with_capacity(raw.len());
        let mut pending_space = false;
        for ch in raw.trim().chars() {
            if ch.is_whitespace() {
                pending_space = true;
                continue;
            }
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.extend(ch.to_lowercase());
        }
        Self::Text(out)
    }

    /// Normalise a collection into [`AttrValue::Set`]: each element normalised, then sorted and
    /// deduplicated.
    #[must_use]
    pub fn set<I: IntoIterator<Item = S>, S: AsRef<str>>(items: I) -> Self {
        let mut v: Vec<String> = items
            .into_iter()
            .map(|s| match Self::text(s.as_ref()) {
                Self::Text(t) => t,
                _ => String::new(),
            })
            .filter(|s| !s.is_empty())
            .collect();
        v.sort_unstable();
        v.dedup();
        Self::Set(v)
    }
}

/// How the device classifies its own execution environment.
///
/// Written into the attribute map so that a policy with `allow_vm = false` can be enforced
/// server-side (`20-client-core.md §3.3`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum EnvClass {
    /// No virtualisation indicators found.
    #[default]
    Bare = 0,
    /// Running under a hypervisor.
    VirtualMachine = 1,
    /// Running inside a container.
    Container = 2,
    /// Browser sandbox.
    Browser = 3,
}

impl EnvClass {
    /// Stable name used in the normalised attribute map.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bare => "bare",
            Self::VirtualMachine => "vm",
            Self::Container => "container",
            Self::Browser => "browser",
        }
    }
}

/// The normalised device attribute map.
///
/// `BTreeMap` rather than a hash map: iteration order is the encoding order, and the encoding
/// is what gets hashed.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DeviceAttrs {
    entries: BTreeMap<AttrKey, AttrValue>,
}

/// Reserved attribute key holding the [`EnvClass`].
pub const ATTR_ENV_CLASS: &str = "env_class";

impl DeviceAttrs {
    /// An empty attribute set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace an attribute.
    pub fn insert(&mut self, key: impl Into<AttrKey>, value: AttrValue) -> &mut Self {
        self.entries.insert(key.into(), value);
        self
    }

    /// Record the environment class.
    pub fn set_env_class(&mut self, class: EnvClass) -> &mut Self {
        self.insert(ATTR_ENV_CLASS, AttrValue::text(class.as_str()))
    }

    /// Read the recorded environment class, defaulting to [`EnvClass::Bare`].
    #[must_use]
    pub fn env_class(&self) -> EnvClass {
        match self.entries.get(ATTR_ENV_CLASS) {
            Some(AttrValue::Text(t)) => match t.as_str() {
                "vm" => EnvClass::VirtualMachine,
                "container" => EnvClass::Container,
                "browser" => EnvClass::Browser,
                _ => EnvClass::Bare,
            },
            _ => EnvClass::Bare,
        }
    }

    /// Look up an attribute. Absent keys and explicit [`AttrValue::Absent`] are distinct here;
    /// most callers want [`DeviceAttrs::get_present`].
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&AttrValue> {
        self.entries.get(key)
    }

    /// Look up an attribute, treating [`AttrValue::Absent`] as missing.
    #[must_use]
    pub fn get_present(&self, key: &str) -> Option<&AttrValue> {
        match self.entries.get(key) {
            Some(AttrValue::Absent) | None => None,
            Some(v) => Some(v),
        }
    }

    /// Iterate in canonical (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = (&AttrKey, &AttrValue)> {
        self.entries.iter()
    }

    /// Canonical CBOR encoding, the exact bytes the fingerprint is computed over.
    ///
    /// This encoding is **protocol-visible**: a client that encodes differently produces a
    /// different fingerprint and loses its seat, so the mapping is fixed here and asserted by
    /// `copylocker-suite-testkit`. Values are tagged by variant so that
    /// `Text("1")` and `Int(1)` cannot collide, and [`AttrValue::Absent`] is encoded explicitly
    /// rather than omitted (`20-client-core.md §3.2`).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let entries: Vec<(CborValue, CborValue)> = self
            .entries
            .iter()
            .map(|(k, v)| (CborValue::Text(k.clone()), encode_attr(v)))
            .collect();
        CborValue::Map(entries).to_canonical()
    }

    /// Number of attributes recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no attributes are recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Fingerprint computation and tolerant comparison.
pub trait FingerprintScheme {
    /// Compute the fingerprint digest over normalised attributes, salted per vendor.
    ///
    /// The salt is what stops one vendor's fingerprint database from being usable against
    /// another's, and stops an attacker from precomputing fingerprints for common hardware.
    fn compute(salt: &[u8], attrs: &DeviceAttrs) -> Fingerprint;

    /// Weighted similarity in `0..=100`.
    ///
    /// Hardware drifts: a replaced network card should not cost the user their seat. The server
    /// compares against `policy.fpr_tolerance` (default 70) and reuses the existing activation
    /// when the score clears it (`10-server-worker.md §2.4`).
    fn similarity(a: &DeviceAttrs, b: &DeviceAttrs) -> u8;

    /// Weight table used by [`FingerprintScheme::similarity`], exposed for documentation and
    /// for the console's "why did this match" view.
    fn weights() -> &'static [(&'static str, u8)];
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn text_normalisation_is_idempotent_and_case_folding() {
        let a = AttrValue::text("  Hello   WORLD \n");
        assert_eq!(a, AttrValue::Text("hello world".into()));
        let AttrValue::Text(ref once) = a else {
            unreachable!()
        };
        assert_eq!(AttrValue::text(once), a, "normalisation must be idempotent");
    }

    #[test]
    fn set_normalisation_sorts_and_dedupes() {
        let s = AttrValue::set(vec!["BB:22", "aa:11", "BB:22", "  "]);
        assert_eq!(s, AttrValue::Set(vec!["aa:11".into(), "bb:22".into()]));
    }

    #[test]
    fn absent_is_distinct_from_missing_in_the_encoding() {
        let mut a = DeviceAttrs::new();
        a.insert("cpu_id", AttrValue::text("x"));
        let mut b = DeviceAttrs::new();
        b.insert("cpu_id", AttrValue::text("x"));
        b.insert("board_serial", AttrValue::Absent);
        // Same "present" content, different attribute maps -> different canonical encodings.
        assert_ne!(a, b);
        assert_eq!(a.get_present("board_serial"), None);
        assert_eq!(b.get_present("board_serial"), None);
        assert_eq!(b.get("board_serial"), Some(&AttrValue::Absent));
    }

    #[test]
    fn canonical_bytes_are_stable_under_insertion_order() {
        let mut a = DeviceAttrs::new();
        a.insert("z_attr", AttrValue::Int(3));
        a.insert("a_attr", AttrValue::text("X"));
        let mut b = DeviceAttrs::new();
        b.insert("a_attr", AttrValue::text("x"));
        b.insert("z_attr", AttrValue::Int(3));
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn variant_tags_prevent_type_confusion() {
        let mut a = DeviceAttrs::new();
        a.insert("k", AttrValue::Int(1));
        let mut b = DeviceAttrs::new();
        b.insert("k", AttrValue::Text("1".into()));
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn absent_encodes_differently_from_omitted() {
        let mut a = DeviceAttrs::new();
        a.insert("k", AttrValue::text("v"));
        let mut b = DeviceAttrs::new();
        b.insert("k", AttrValue::text("v"));
        b.insert("missing", AttrValue::Absent);
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn env_class_roundtrips() {
        for c in [
            EnvClass::Bare,
            EnvClass::VirtualMachine,
            EnvClass::Container,
            EnvClass::Browser,
        ] {
            let mut a = DeviceAttrs::new();
            a.set_env_class(c);
            assert_eq!(a.env_class(), c);
        }
    }
}
