//! Tolerant activation matching (`10-server-worker.md §2.4`).
//!
//! Hardware drifts. A replaced network card, a renamed host, or a new disk should not cost the
//! user their seat and force a support ticket. Equally, "close enough" must not become a way to
//! share one licence across an office.

use copylocker_suite::device::{DeviceAttrs, FingerprintScheme};
use copylocker_types::Fingerprint;

/// What matching an incoming device against an existing activation concluded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MatchOutcome {
    /// The fingerprint digest is byte-identical. Reuse the activation as-is.
    Exact,
    /// Attributes are close enough under the policy tolerance. Reuse the seat, but re-issue the
    /// credential so it binds the *new* fingerprint, and refresh the stored attributes so the
    /// activation adapts to gradual hardware change.
    Tolerant {
        /// The similarity score achieved.
        score: u8,
    },
    /// Not the same device. A new seat is required.
    Distinct {
        /// The best score seen, for diagnostics.
        score: u8,
    },
}

impl MatchOutcome {
    /// Whether the existing activation should be reused.
    #[must_use]
    pub const fn reuses_seat(&self) -> bool {
        matches!(self, Self::Exact | Self::Tolerant { .. })
    }

    /// Whether a fresh credential must be issued binding the new fingerprint.
    #[must_use]
    pub const fn requires_reissue(&self) -> bool {
        matches!(self, Self::Tolerant { .. })
    }
}

/// Compare an incoming device against a stored activation.
///
/// `stored_attrs` and `incoming_attrs` are `None` when the policy has `report_attrs` disabled.
/// In that case only an exact digest match is possible — the privacy setting genuinely costs
/// tolerance, and that trade-off is documented rather than worked around
/// (`20-client-core.md §3.4`).
#[must_use]
pub fn match_device<F: FingerprintScheme>(
    stored_fp: &Fingerprint,
    incoming_fp: &Fingerprint,
    stored_attrs: Option<&DeviceAttrs>,
    incoming_attrs: Option<&DeviceAttrs>,
    tolerance: u8,
) -> MatchOutcome {
    if stored_fp == incoming_fp {
        return MatchOutcome::Exact;
    }

    let (Some(a), Some(b)) = (stored_attrs, incoming_attrs) else {
        // No attributes to compare: degrade to exact matching, which already failed.
        return MatchOutcome::Distinct { score: 0 };
    };

    let score = F::similarity(a, b);
    if score >= tolerance {
        MatchOutcome::Tolerant { score }
    } else {
        MatchOutcome::Distinct { score }
    }
}

/// Find the best matching activation among several.
///
/// Returns the index and outcome of the strongest match. Used when a licence has many seats and
/// a returning device must be paired with its own previous activation rather than an arbitrary
/// one.
#[must_use]
pub fn best_match<'a, F: FingerprintScheme, I>(
    candidates: I,
    incoming_fp: &Fingerprint,
    incoming_attrs: Option<&DeviceAttrs>,
    tolerance: u8,
) -> Option<(usize, MatchOutcome)>
where
    I: IntoIterator<Item = (&'a Fingerprint, Option<&'a DeviceAttrs>)>,
{
    let mut best: Option<(usize, MatchOutcome, u8)> = None;
    for (i, (fp, attrs)) in candidates.into_iter().enumerate() {
        let outcome = match_device::<F>(fp, incoming_fp, attrs, incoming_attrs, tolerance);
        let rank = match outcome {
            MatchOutcome::Exact => 255,
            MatchOutcome::Tolerant { score } | MatchOutcome::Distinct { score } => score,
        };
        let better = best.as_ref().is_none_or(|(_, _, r)| rank > *r);
        if better {
            best = Some((i, outcome, rank));
        }
        // An exact match cannot be beaten; stop early.
        if rank == 255 {
            break;
        }
    }
    best.map(|(i, o, _)| (i, o))
}

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_suite::device::AttrValue;
    use copylocker_suite_std::HmacFingerprint as Fpr;

    fn machine(guid: &str, macs: &[&str], host: &str) -> DeviceAttrs {
        let mut a = DeviceAttrs::new();
        a.insert("machine_guid", AttrValue::text(guid));
        a.insert("cpu_id", AttrValue::text("CPU-1"));
        a.insert("board_serial", AttrValue::text("BS-1"));
        a.insert("disk_serial", AttrValue::text("DS-1"));
        a.insert("os_install_id", AttrValue::text("2024-01-01"));
        a.insert("mac_addrs", AttrValue::set(macs.iter()));
        a.insert("hostname", AttrValue::text(host));
        a
    }

    fn fp(attrs: &DeviceAttrs) -> Fingerprint {
        <Fpr as FingerprintScheme>::compute(b"salt", attrs)
    }

    #[test]
    fn an_identical_device_matches_exactly() {
        let a = machine("G1", &["aa:bb"], "desk");
        let out = match_device::<Fpr>(&fp(&a), &fp(&a), Some(&a), Some(&a), 70);
        assert_eq!(out, MatchOutcome::Exact);
        assert!(out.reuses_seat());
        assert!(
            !out.requires_reissue(),
            "nothing changed, nothing to re-bind"
        );
    }

    #[test]
    fn a_swapped_network_card_keeps_the_seat_but_forces_a_reissue() {
        // The scenario tolerance exists for.
        let old = machine("G1", &["aa:bb"], "desk");
        let new = machine("G1", &["ee:ff"], "desk");
        let out = match_device::<Fpr>(&fp(&old), &fp(&new), Some(&old), Some(&new), 70);
        assert!(matches!(out, MatchOutcome::Tolerant { .. }));
        assert!(out.reuses_seat());
        assert!(
            out.requires_reissue(),
            "the credential must be re-bound to the new fingerprint"
        );
    }

    #[test]
    fn a_different_machine_needs_its_own_seat() {
        let a = machine("G1", &["aa:bb"], "desk");
        let mut b = machine("G2", &["cc:dd"], "laptop");
        b.insert("cpu_id", AttrValue::text("CPU-9"));
        b.insert("board_serial", AttrValue::text("BS-9"));
        b.insert("disk_serial", AttrValue::text("DS-9"));
        b.insert("os_install_id", AttrValue::text("2020-01-01"));
        let out = match_device::<Fpr>(&fp(&a), &fp(&b), Some(&a), Some(&b), 70);
        assert!(matches!(out, MatchOutcome::Distinct { .. }));
        assert!(!out.reuses_seat());
    }

    #[test]
    fn without_reported_attributes_only_exact_matches_work() {
        // The documented cost of `report_attrs = false`.
        let old = machine("G1", &["aa:bb"], "desk");
        let new = machine("G1", &["ee:ff"], "desk");
        assert_eq!(
            match_device::<Fpr>(&fp(&old), &fp(&new), None, None, 70),
            MatchOutcome::Distinct { score: 0 }
        );
        // An exact digest match still works without attributes.
        assert_eq!(
            match_device::<Fpr>(&fp(&old), &fp(&old), None, None, 70),
            MatchOutcome::Exact
        );
    }

    #[test]
    fn attributes_from_only_one_side_are_not_enough() {
        let old = machine("G1", &["aa:bb"], "desk");
        let new = machine("G1", &["ee:ff"], "desk");
        assert!(matches!(
            match_device::<Fpr>(&fp(&old), &fp(&new), Some(&old), None, 70),
            MatchOutcome::Distinct { .. }
        ));
    }

    #[test]
    fn tolerance_is_the_threshold_and_it_is_inclusive() {
        let old = machine("G1", &["aa:bb"], "desk");
        let new = machine("G1", &["ee:ff"], "laptop");
        let MatchOutcome::Tolerant { score } =
            match_device::<Fpr>(&fp(&old), &fp(&new), Some(&old), Some(&new), 0)
        else {
            unreachable!("a zero tolerance accepts anything")
        };
        // At exactly the achieved score the match must still succeed.
        assert!(matches!(
            match_device::<Fpr>(&fp(&old), &fp(&new), Some(&old), Some(&new), score),
            MatchOutcome::Tolerant { .. }
        ));
        // One point stricter and it must not.
        assert!(matches!(
            match_device::<Fpr>(&fp(&old), &fp(&new), Some(&old), Some(&new), score + 1),
            MatchOutcome::Distinct { .. }
        ));
    }

    #[test]
    fn a_tolerance_of_one_hundred_still_admits_an_unchanged_machine() {
        let a = machine("G1", &["aa:bb"], "desk");
        assert_eq!(
            match_device::<Fpr>(&fp(&a), &fp(&a), Some(&a), Some(&a), 100),
            MatchOutcome::Exact
        );
    }

    #[test]
    fn the_best_candidate_wins_among_several_seats() {
        // A returning device must pair with its own previous activation, not a stranger's.
        let mine_old = machine("G1", &["aa:bb"], "desk");
        let mine_new = machine("G1", &["ee:ff"], "desk");
        let mut other = machine("G2", &["cc:dd"], "laptop");
        other.insert("cpu_id", AttrValue::text("CPU-9"));
        other.insert("board_serial", AttrValue::text("BS-9"));

        let fp_other = fp(&other);
        let fp_mine = fp(&mine_old);
        let candidates = alloc::vec![(&fp_other, Some(&other)), (&fp_mine, Some(&mine_old)),];

        let (idx, outcome) = best_match::<Fpr, _>(candidates, &fp(&mine_new), Some(&mine_new), 70)
            .expect("a candidate must be chosen");
        assert_eq!(idx, 1, "it should match its own previous activation");
        assert!(outcome.reuses_seat());
    }

    #[test]
    fn an_exact_match_short_circuits_the_search() {
        let a = machine("G1", &["aa:bb"], "desk");
        let fp_a = fp(&a);
        let candidates = alloc::vec![(&fp_a, Some(&a)), (&fp_a, Some(&a))];
        let (idx, outcome) =
            best_match::<Fpr, _>(candidates, &fp_a, Some(&a), 70).expect("must match");
        assert_eq!(idx, 0);
        assert_eq!(outcome, MatchOutcome::Exact);
    }

    #[test]
    fn no_candidates_yields_no_match() {
        let a = machine("G1", &["aa:bb"], "desk");
        let empty: alloc::vec::Vec<(&Fingerprint, Option<&DeviceAttrs>)> = alloc::vec![];
        assert!(best_match::<Fpr, _>(empty, &fp(&a), Some(&a), 70).is_none());
    }
}
