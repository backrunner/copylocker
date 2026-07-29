//! HMAC-SHA-256 fingerprinting with weighted tolerance matching.

use copylocker_suite::device::{AttrValue, DeviceAttrs, FingerprintScheme};
use copylocker_types::Fingerprint;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

/// Attribute weights (`20-client-core.md §3.1`, `10-server-worker.md §2.4`).
///
/// Weights reflect *stability*, not uniqueness: a reinstall changes `machine_guid`, whereas a
/// CPU identifier survives almost everything. An attribute not listed here contributes nothing
/// to the similarity score, though it still changes the fingerprint digest.
///
/// The union of the per-platform keys is listed in one table so a single scheme serves
/// Windows, macOS, Linux, and the web; absent keys simply do not contribute.
const WEIGHTS: &[(&str, u8)] = &[
    // Windows
    ("machine_guid", 40),
    ("cpu_id", 15),
    ("board_serial", 15),
    ("disk_serial", 10),
    ("os_install_id", 10),
    // macOS
    ("platform_uuid", 45),
    ("hw_model_serial", 20),
    ("boot_volume_uuid", 15),
    // Linux
    ("machine_id", 40),
    ("dmi_product_uuid", 20),
    ("rootfs_uuid", 15),
    // Web
    ("web_device_id", 60),
    ("ua_platform", 15),
    ("hardware_concurrency", 10),
    // Shared, low weight
    ("mac_addrs", 10),
    ("hostname", 5),
    ("timezone", 5),
];

/// HMAC-SHA-256 over the canonical attribute encoding, salted per vendor.
///
/// The salt is what stops a fingerprint table from being portable between vendors and stops an
/// attacker precomputing fingerprints for common hardware configurations.
#[derive(Clone, Copy, Debug, Default)]
pub struct HmacFingerprint;

impl FingerprintScheme for HmacFingerprint {
    fn compute(salt: &[u8], attrs: &DeviceAttrs) -> Fingerprint {
        // HMAC accepts a key of any length, so this branch is unreachable in practice. It is
        // handled rather than unwrapped because `10-server-worker.md §4` forbids panicking
        // anywhere reachable from a request path; an all-zero digest matches nothing.
        let Ok(mut mac) = <Hmac<Sha256>>::new_from_slice(salt) else {
            return Fingerprint::from_vec(alloc::vec![0u8; 32]);
        };
        mac.update(&attrs.canonical_bytes());
        Fingerprint::from_vec(mac.finalize().into_bytes().to_vec())
    }

    fn similarity(a: &DeviceAttrs, b: &DeviceAttrs) -> u8 {
        let mut total: u32 = 0;
        let mut matched: u32 = 0;

        for (key, weight) in WEIGHTS {
            let (va, vb) = match (a.get_present(key), b.get_present(key)) {
                // Neither side reports the attribute: it carries no information either way, so
                // it must not inflate or deflate the score.
                (None, None) => continue,
                // One side is missing it. That is evidence of change, so the weight counts
                // toward the denominator but earns nothing.
                (None, Some(_)) | (Some(_), None) => {
                    total += u32::from(*weight);
                    continue;
                }
                (Some(x), Some(y)) => (x, y),
            };
            total += u32::from(*weight);
            matched += u32::from(*weight) * u32::from(value_score(va, vb)) / 100;
        }

        if total == 0 {
            // Nothing comparable was reported. Returning 0 keeps the caller fail-closed: with
            // no evidence of sameness, do not silently reuse a seat.
            return 0;
        }
        u8::try_from(matched * 100 / total).unwrap_or(100)
    }

    fn weights() -> &'static [(&'static str, u8)] {
        WEIGHTS
    }
}

/// Per-attribute score in `0..=100`.
///
/// Sets use Jaccard similarity so that gaining or losing one network interface out of several
/// is a partial change, not a total mismatch.
fn value_score(a: &AttrValue, b: &AttrValue) -> u8 {
    match (a, b) {
        (AttrValue::Text(x), AttrValue::Text(y)) => u8::from(x == y) * 100,
        (AttrValue::Int(x), AttrValue::Int(y)) => u8::from(x == y) * 100,
        (AttrValue::Set(x), AttrValue::Set(y)) => {
            if x.is_empty() && y.is_empty() {
                return 100;
            }
            let inter = x.iter().filter(|i| y.contains(i)).count();
            let union = x.len() + y.len() - inter;
            if union == 0 {
                return 100;
            }
            u8::try_from(inter * 100 / union).unwrap_or(100)
        }
        // Different variants for the same key means the client changed how it reports, which is
        // not evidence of the same machine.
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn windows_machine() -> DeviceAttrs {
        let mut a = DeviceAttrs::new();
        a.insert("machine_guid", AttrValue::text("A1B2-C3D4"));
        a.insert("cpu_id", AttrValue::text("BFEBFBFF000306A9"));
        a.insert("board_serial", AttrValue::text("BS-001"));
        a.insert("disk_serial", AttrValue::text("DS-001"));
        a.insert("os_install_id", AttrValue::text("2024-01-01"));
        a.insert("mac_addrs", AttrValue::set(vec!["aa:bb", "cc:dd"]));
        a.insert("hostname", AttrValue::text("workstation"));
        a
    }

    #[test]
    fn fingerprint_is_deterministic_and_salt_bound() {
        let a = windows_machine();
        let f1 = HmacFingerprint::compute(b"vendor-salt", &a);
        let f2 = HmacFingerprint::compute(b"vendor-salt", &a);
        let f3 = HmacFingerprint::compute(b"other-salt", &a);
        assert_eq!(f1, f2);
        assert_ne!(f1, f3, "the salt must isolate vendors");
        assert_eq!(f1.as_bytes().len(), 32);
    }

    #[test]
    fn any_attribute_change_changes_the_digest() {
        let base = HmacFingerprint::compute(b"s", &windows_machine());
        let mut changed = windows_machine();
        changed.insert("hostname", AttrValue::text("laptop"));
        assert_ne!(base, HmacFingerprint::compute(b"s", &changed));
    }

    #[test]
    fn identical_attributes_score_100() {
        assert_eq!(
            HmacFingerprint::similarity(&windows_machine(), &windows_machine()),
            100
        );
    }

    #[test]
    fn swapping_a_network_card_stays_above_the_default_tolerance() {
        // The scenario the tolerance exists for: hardware drifts, the user keeps their seat.
        let a = windows_machine();
        let mut b = windows_machine();
        b.insert("mac_addrs", AttrValue::set(vec!["ee:ff"]));
        b.insert("hostname", AttrValue::text("workstation-renamed"));
        let score = HmacFingerprint::similarity(&a, &b);
        assert!(
            score >= 70,
            "score {score} should clear the default tolerance of 70"
        );
        assert!(score < 100);
    }

    #[test]
    fn a_completely_different_machine_scores_far_below_tolerance() {
        let a = windows_machine();
        let mut b = DeviceAttrs::new();
        b.insert("machine_guid", AttrValue::text("ZZZZ-ZZZZ"));
        b.insert("cpu_id", AttrValue::text("DIFFERENT"));
        b.insert("board_serial", AttrValue::text("BS-999"));
        b.insert("disk_serial", AttrValue::text("DS-999"));
        b.insert("os_install_id", AttrValue::text("2020-01-01"));
        b.insert("mac_addrs", AttrValue::set(vec!["11:22"]));
        b.insert("hostname", AttrValue::text("other"));
        assert_eq!(HmacFingerprint::similarity(&a, &b), 0);
    }

    #[test]
    fn reinstalling_the_os_drops_below_tolerance() {
        // machine_guid and os_install_id both change: 50 of 100 weight lost.
        let a = windows_machine();
        let mut b = windows_machine();
        b.insert("machine_guid", AttrValue::text("NEW-GUID"));
        b.insert("os_install_id", AttrValue::text("2026-06-01"));
        let score = HmacFingerprint::similarity(&a, &b);
        assert!(score < 70, "score {score} should fall below tolerance");
    }

    #[test]
    fn no_comparable_attributes_scores_zero_not_one_hundred() {
        // Fail closed: absence of evidence must not read as evidence of sameness.
        let empty = DeviceAttrs::new();
        assert_eq!(HmacFingerprint::similarity(&empty, &empty), 0);
    }

    #[test]
    fn missing_on_one_side_counts_against_the_score() {
        let a = windows_machine();
        let mut b = windows_machine();
        b.insert("machine_guid", AttrValue::Absent);
        let score = HmacFingerprint::similarity(&a, &b);
        assert!(score < 100 && score > 0, "score was {score}");
    }

    #[test]
    fn jaccard_handles_partial_set_overlap() {
        let mut a = DeviceAttrs::new();
        a.insert("mac_addrs", AttrValue::set(vec!["a", "b", "c", "d"]));
        let mut b = DeviceAttrs::new();
        b.insert("mac_addrs", AttrValue::set(vec!["a", "b", "c", "e"]));
        // 3 shared of 5 distinct = 60.
        assert_eq!(HmacFingerprint::similarity(&a, &b), 60);
    }

    #[test]
    fn type_confusion_between_variants_scores_zero() {
        let mut a = DeviceAttrs::new();
        a.insert("hostname", AttrValue::text("1"));
        let mut b = DeviceAttrs::new();
        b.insert("hostname", AttrValue::Int(1));
        assert_eq!(HmacFingerprint::similarity(&a, &b), 0);
    }

    #[test]
    fn weights_table_is_exposed_and_nonempty() {
        assert!(!HmacFingerprint::weights().is_empty());
    }
}
