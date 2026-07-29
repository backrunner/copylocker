//! Sharing-abuse heuristics (`10-server-worker.md §2.5`).
//!
//! The score is a **signal, not a verdict**. It rides along in the validation ticket so the
//! application can degrade gracefully, and it can drive an alert or a forced re-validation. It
//! must not silently lock anyone out: every signal here has an innocent explanation — a
//! consultant with many client machines, a travelling user, a fleet mid-rollout.

use alloc::vec::Vec;

/// Observations about one licence over a recent window.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct AnomalySignals {
    /// Distinct fingerprints seen in the last 24 hours.
    pub distinct_fingerprints_24h: u32,
    /// Seats the licence is entitled to.
    pub seats: u32,
    /// Whether the last two validations came from different countries less than two hours apart.
    pub impossible_travel: bool,
    /// How many times a single activation's attributes changed in the window.
    pub attr_churn: u32,
    /// Validations observed in the window.
    pub validations_in_window: u32,
    /// Validations the refresh interval would predict.
    pub expected_validations: u32,
    /// Distinct application versions seen under this licence.
    pub distinct_app_versions: u32,
}

/// Per-signal weights, summing to 100.
mod weight {
    /// Many fingerprints relative to seats.
    pub(super) const FINGERPRINT_SPREAD: u32 = 40;
    /// Geographically impossible movement.
    pub(super) const GEO_JUMP: u32 = 25;
    /// Attributes changing unusually fast.
    pub(super) const ATTR_CHURN: u32 = 15;
    /// Validating far more often than configured.
    pub(super) const CALL_RATE: u32 = 10;
    /// Many different application versions at once.
    pub(super) const VERSION_SPREAD: u32 = 10;
}

/// One contributing signal, for the console's "why is this flagged" view.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Contribution {
    /// Stable signal name.
    pub signal: &'static str,
    /// Points contributed, `0..=weight`.
    pub points: u32,
    /// Weight this signal can contribute at most.
    pub max: u32,
}

/// A computed suspicion score with its breakdown.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AnomalyScore {
    /// Total, clamped to `0..=100`.
    pub score: u8,
    /// Per-signal breakdown.
    pub contributions: Vec<Contribution>,
}

/// Compute a suspicion score.
///
/// Everything is integer arithmetic on counters the durable object already holds — no external
/// service, no floating point, and cheap enough to run inside the validation transaction.
#[must_use]
pub fn score(s: &AnomalySignals) -> AnomalyScore {
    let mut contributions = Vec::new();

    // Fingerprint spread: ramps from "one per seat" (innocent) to "twice the seats" (full
    // weight). A licence with N seats legitimately sees about N fingerprints.
    //
    // Widened to u64 before multiplying: release builds keep `overflow-checks` on, so an
    // arithmetic overflow here would panic inside a durable object and take the licence's state
    // with it (`00-crate-layout.md §5`, `10-server-worker.md §4`).
    let seats = u64::from(s.seats.max(1));
    let spread_points = if u64::from(s.distinct_fingerprints_24h) <= seats {
        0
    } else {
        let excess = u64::from(s.distinct_fingerprints_24h) - seats;
        u32::try_from(
            (excess * u64::from(weight::FINGERPRINT_SPREAD) / seats)
                .min(u64::from(weight::FINGERPRINT_SPREAD)),
        )
        .unwrap_or(weight::FINGERPRINT_SPREAD)
    };
    contributions.push(Contribution {
        signal: "fingerprint_spread",
        points: spread_points,
        max: weight::FINGERPRINT_SPREAD,
    });

    contributions.push(Contribution {
        signal: "geo_jump",
        points: if s.impossible_travel {
            weight::GEO_JUMP
        } else {
            0
        },
        max: weight::GEO_JUMP,
    });

    // Attribute churn: a couple of changes is ordinary maintenance.
    let churn_points = s
        .attr_churn
        .saturating_sub(2)
        .saturating_mul(5)
        .min(weight::ATTR_CHURN);
    contributions.push(Contribution {
        signal: "attr_churn",
        points: churn_points,
        max: weight::ATTR_CHURN,
    });

    // Call rate: only counts above three times the expected volume, since retries and restarts
    // routinely produce a modest excess. Widened to u64 for the same overflow reason as above.
    let threshold = u64::from(s.expected_validations.max(1)) * 3;
    let observed = u64::from(s.validations_in_window);
    let rate_points = if observed <= threshold {
        0
    } else {
        let excess = observed - threshold;
        u32::try_from(
            (excess * u64::from(weight::CALL_RATE) / threshold).min(u64::from(weight::CALL_RATE)),
        )
        .unwrap_or(weight::CALL_RATE)
    };
    contributions.push(Contribution {
        signal: "call_rate",
        points: rate_points,
        max: weight::CALL_RATE,
    });

    // Version spread: two versions is a normal rollout.
    let version_points = s
        .distinct_app_versions
        .saturating_sub(2)
        .saturating_mul(3)
        .min(weight::VERSION_SPREAD);
    contributions.push(Contribution {
        signal: "version_spread",
        points: version_points,
        max: weight::VERSION_SPREAD,
    });

    let total: u32 = contributions.iter().map(|c| c.points).sum();
    AnomalyScore {
        score: u8::try_from(total.min(100)).unwrap_or(100),
        contributions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ordinary() -> AnomalySignals {
        AnomalySignals {
            distinct_fingerprints_24h: 1,
            seats: 1,
            impossible_travel: false,
            attr_churn: 0,
            validations_in_window: 1,
            expected_validations: 1,
            distinct_app_versions: 1,
        }
    }

    #[test]
    fn an_ordinary_single_seat_user_scores_zero() {
        assert_eq!(score(&ordinary()).score, 0);
    }

    #[test]
    fn a_fully_used_team_licence_scores_zero() {
        // 25 machines on a 25-seat licence is exactly what was sold.
        let s = AnomalySignals {
            distinct_fingerprints_24h: 25,
            seats: 25,
            ..ordinary()
        };
        assert_eq!(score(&s).score, 0);
    }

    #[test]
    fn widespread_sharing_scores_high() {
        let s = AnomalySignals {
            distinct_fingerprints_24h: 40,
            seats: 1,
            impossible_travel: true,
            attr_churn: 8,
            validations_in_window: 200,
            expected_validations: 1,
            distinct_app_versions: 9,
        };
        assert!(score(&s).score >= 90, "got {}", score(&s).score);
    }

    #[test]
    fn the_score_never_exceeds_one_hundred() {
        let s = AnomalySignals {
            distinct_fingerprints_24h: u32::MAX,
            seats: 1,
            impossible_travel: true,
            attr_churn: u32::MAX,
            validations_in_window: u32::MAX,
            expected_validations: 1,
            distinct_app_versions: u32::MAX,
        };
        assert_eq!(score(&s).score, 100);
    }

    #[test]
    fn extreme_inputs_do_not_overflow() {
        // `overflow-checks` is on in release builds, so a panic here would be a live outage.
        let s = AnomalySignals {
            distinct_fingerprints_24h: u32::MAX,
            seats: u32::MAX,
            impossible_travel: true,
            attr_churn: u32::MAX,
            validations_in_window: u32::MAX,
            expected_validations: u32::MAX,
            distinct_app_versions: u32::MAX,
        };
        let out = score(&s);
        assert!(out.score <= 100);
    }

    #[test]
    fn zero_seats_is_treated_as_one_rather_than_dividing_by_zero() {
        let s = AnomalySignals {
            distinct_fingerprints_24h: 2,
            seats: 0,
            ..ordinary()
        };
        assert!(score(&s).score > 0);
    }

    #[test]
    fn a_travelling_user_alone_stays_below_a_lockout_threshold() {
        // One signal must never be enough on its own.
        let s = AnomalySignals {
            impossible_travel: true,
            ..ordinary()
        };
        assert_eq!(score(&s).score, weight::GEO_JUMP as u8);
        assert!(score(&s).score < 50);
    }

    #[test]
    fn a_rollout_across_two_versions_is_not_suspicious() {
        let s = AnomalySignals {
            distinct_app_versions: 2,
            ..ordinary()
        };
        assert_eq!(score(&s).score, 0);
    }

    #[test]
    fn occasional_hardware_maintenance_is_not_suspicious() {
        let s = AnomalySignals {
            attr_churn: 2,
            ..ordinary()
        };
        assert_eq!(score(&s).score, 0);
    }

    #[test]
    fn modest_retry_traffic_is_not_suspicious() {
        let s = AnomalySignals {
            validations_in_window: 3,
            expected_validations: 1,
            ..ordinary()
        };
        assert_eq!(score(&s).score, 0);
    }

    #[test]
    fn the_breakdown_covers_every_signal_and_respects_its_cap() {
        let out = score(&ordinary());
        assert_eq!(out.contributions.len(), 5);
        for c in &out.contributions {
            assert!(c.points <= c.max, "{} exceeded its weight", c.signal);
        }
        let total_weight: u32 = out.contributions.iter().map(|c| c.max).sum();
        assert_eq!(total_weight, 100, "weights must sum to 100");
    }
}
