//! Desktop device-attribute collection (`20-client-core.md §3`).
//!
//! This crate only collects and normalises public, documented attributes. Canonical encoding,
//! vendor-salted hashing, and tolerant comparison stay in `copylocker-suite`, so platform I/O
//! cannot silently redefine the fingerprint protocol.

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use core::fmt;

use copylocker_suite::{DeviceAttrs, FingerprintScheme};
use copylocker_types::Fingerprint;

mod platform;

/// Failure to obtain fingerprint evidence.
///
/// Individual unavailable attributes are represented by `AttrValue::Absent`; collection only
/// fails when the target platform itself has no provider.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum FingerprintError {
    /// No system collector is implemented for this target.
    UnsupportedPlatform,
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str("unsupported fingerprint platform"),
        }
    }
}

impl std::error::Error for FingerprintError {}

/// Pluggable source of normalised device attributes.
pub trait FingerprintProvider: Send + Sync {
    /// Collect one deterministic snapshot.
    fn collect(&self) -> Result<DeviceAttrs, FingerprintError>;
}

/// The built-in provider for Windows, macOS, and Linux.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemFingerprintProvider;

impl FingerprintProvider for SystemFingerprintProvider {
    fn collect(&self) -> Result<DeviceAttrs, FingerprintError> {
        platform::collect()
    }
}

/// A collected attribute snapshot and its vendor-isolated digest.
pub struct FingerprintEvidence {
    fingerprint: Fingerprint,
    attrs: DeviceAttrs,
}

impl fmt::Debug for FingerprintEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FingerprintEvidence")
            .field("fingerprint", &self.fingerprint)
            .field("attribute_count", &self.attrs.len())
            .finish_non_exhaustive()
    }
}

impl FingerprintEvidence {
    /// The vendor-salted fingerprint digest.
    #[must_use]
    pub const fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Normalised attributes. Only upload these when the vendor explicitly enabled reporting.
    #[must_use]
    pub const fn attrs(&self) -> &DeviceAttrs {
        &self.attrs
    }

    /// Consume the evidence into its digest and attribute snapshot.
    #[must_use]
    pub fn into_parts(self) -> (Fingerprint, DeviceAttrs) {
        (self.fingerprint, self.attrs)
    }
}

/// Collect attributes and compute the fingerprint using a suite's fingerprint slot.
pub fn collect_with<P, F>(
    provider: &P,
    vendor_salt: &[u8],
) -> Result<FingerprintEvidence, FingerprintError>
where
    P: FingerprintProvider + ?Sized,
    F: FingerprintScheme,
{
    let attrs = provider.collect()?;
    let fingerprint = F::compute(vendor_salt, &attrs);
    Ok(FingerprintEvidence { fingerprint, attrs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_suite::{AttrValue, EnvClass};
    use copylocker_suite_std::HmacFingerprint;

    #[derive(Debug)]
    struct FixedProvider;

    impl FingerprintProvider for FixedProvider {
        fn collect(&self) -> Result<DeviceAttrs, FingerprintError> {
            let mut attrs = DeviceAttrs::new();
            attrs.insert("machine_id", AttrValue::text("machine-a"));
            attrs.insert("mac_addrs", AttrValue::set(["02:00:00:00:00:01"]));
            attrs.set_env_class(EnvClass::Bare);
            Ok(attrs)
        }
    }

    #[test]
    fn a_custom_provider_is_deterministic_and_vendor_isolated() {
        let first = collect_with::<_, HmacFingerprint>(&FixedProvider, b"vendor-a").unwrap();
        let replay = collect_with::<_, HmacFingerprint>(&FixedProvider, b"vendor-a").unwrap();
        let other_vendor = collect_with::<_, HmacFingerprint>(&FixedProvider, b"vendor-b").unwrap();

        assert_eq!(
            first.attrs().canonical_bytes(),
            replay.attrs().canonical_bytes()
        );
        assert_eq!(first.fingerprint(), replay.fingerprint());
        assert_ne!(first.fingerprint(), other_vendor.fingerprint());
    }

    #[test]
    fn debug_output_does_not_expose_attribute_values() {
        let evidence = collect_with::<_, HmacFingerprint>(&FixedProvider, b"salt").unwrap();
        let rendered = format!("{evidence:?}");
        assert!(rendered.contains("attribute_count"));
        assert!(!rendered.contains("machine-a"));
        assert!(!rendered.contains("02:00"));
    }

    #[test]
    fn system_collection_is_stable_across_ten_immediate_reads() {
        let provider = SystemFingerprintProvider;
        let first = provider.collect().unwrap().canonical_bytes();
        assert!(!first.is_empty());
        for _ in 0..9 {
            assert_eq!(provider.collect().unwrap().canonical_bytes(), first);
        }
    }
}
