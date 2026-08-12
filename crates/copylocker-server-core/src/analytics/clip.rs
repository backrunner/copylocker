//! Telemetry clipping for T1 self-reports (`90-analytics-telemetry.md §6`).
//!
//! T1 values are untrusted: a client can report `session_count = 10^9` to poison the
//! aggregates. Everything a telemetry block carries is therefore clipped against fixed
//! caps — and every feature id against the vendor allow-list — *before* it may be
//! persisted. The clip record comes back alongside the values so the Worker can count
//! each clipping or drop as an anomaly.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Cap on `session_count` per window per device.
pub const SESSION_COUNT_CAP: u64 = 10_000;

/// Cap on `days_active`: the window is at most 28 days.
pub const DAYS_ACTIVE_CAP: u64 = 28;

/// Cap on each of the four session-duration histogram buckets.
pub const HISTOGRAM_BUCKET_CAP: u64 = 10_000;

/// Cap on per-feature hit counts.
pub const FEATURE_HITS_CAP: u64 = 10_000;

/// Number of session-duration histogram buckets (`<5m / 5-30m / 30m-2h / >2h`).
pub const SESSION_DURATION_BUCKETS: usize = 4;

/// Maximum byte length of a feature id; longer keys are dropped even if allow-listed.
pub const MAX_FEATURE_KEY_LEN: usize = 128;

/// A decoded telemetry block (`90-analytics-telemetry.md §6` CDDL), pre-clipping.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TelemetryValues {
    /// Privacy-statement version the end user consented to; `0` means no consent.
    pub consent_version: u64,
    /// Server-supplied window start from the previous ticket; passes through untouched.
    pub window_start: u64,
    /// Sessions in the window, client-aggregated.
    pub session_count: u64,
    /// Bucketed session durations; exact durations never cross the wire.
    pub session_duration_histogram: [u64; SESSION_DURATION_BUCKETS],
    /// Per-feature hit counts, keyed by allow-listed feature id.
    pub feature_hits: BTreeMap<String, u64>,
    /// Days the app was used within the window, 0..=28.
    pub days_active: u64,
}

/// One clipping or drop applied by [`clip_telemetry`]; the Worker counts these as
/// anomalies (`90-analytics-telemetry.md §6` poisoning rules).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum ClipEvent {
    /// `session_count` exceeded [`SESSION_COUNT_CAP`].
    SessionCountClipped {
        /// Reported value.
        original: u64,
        /// Stored value.
        clipped: u64,
    },
    /// `days_active` exceeded [`DAYS_ACTIVE_CAP`].
    DaysActiveClipped {
        /// Reported value.
        original: u64,
        /// Stored value.
        clipped: u64,
    },
    /// A session-duration histogram bucket exceeded [`HISTOGRAM_BUCKET_CAP`].
    HistogramBucketClipped {
        /// Bucket index, `0..SESSION_DURATION_BUCKETS`.
        bucket: usize,
        /// Reported value.
        original: u64,
        /// Stored value.
        clipped: u64,
    },
    /// A feature hit count exceeded [`FEATURE_HITS_CAP`].
    FeatureHitsClipped {
        /// Feature id.
        key: String,
        /// Reported value.
        original: u64,
        /// Stored value.
        clipped: u64,
    },
    /// A feature id outside the allow-list (or overlong) was dropped entirely.
    FeatureKeyDropped {
        /// The offending key.
        key: String,
    },
}

/// The clipped telemetry block plus the record of everything that was clipped or dropped.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClippedTelemetry {
    /// Safe-to-store values.
    pub values: TelemetryValues,
    /// What had to be corrected, in the order it was applied. Empty means the report was
    /// already within bounds.
    pub events: Vec<ClipEvent>,
}

/// Consent gate (`90-analytics-telemetry.md §6`): `consent_version == 0` means the
/// telemetry block must be dropped — and the drop counted, because it usually signals an
/// SDK integration error. Kept as a separate predicate so the Worker can count drops
/// independently of clipping.
#[must_use]
pub fn consent_allows(consent_version: u64) -> bool {
    consent_version > 0
}

/// Clip a decoded telemetry block against the fixed caps and the vendor's feature
/// allow-list. `consent_version` and `window_start` pass through untouched; consent
/// enforcement is the caller's job, via [`consent_allows`].
#[must_use]
pub fn clip_telemetry(mut values: TelemetryValues, feature_allowlist: &[&str]) -> ClippedTelemetry {
    let mut events = Vec::new();

    if values.session_count > SESSION_COUNT_CAP {
        events.push(ClipEvent::SessionCountClipped {
            original: values.session_count,
            clipped: SESSION_COUNT_CAP,
        });
        values.session_count = SESSION_COUNT_CAP;
    }

    if values.days_active > DAYS_ACTIVE_CAP {
        events.push(ClipEvent::DaysActiveClipped {
            original: values.days_active,
            clipped: DAYS_ACTIVE_CAP,
        });
        values.days_active = DAYS_ACTIVE_CAP;
    }

    for (bucket, count) in values.session_duration_histogram.iter_mut().enumerate() {
        if *count > HISTOGRAM_BUCKET_CAP {
            events.push(ClipEvent::HistogramBucketClipped {
                bucket,
                original: *count,
                clipped: HISTOGRAM_BUCKET_CAP,
            });
            *count = HISTOGRAM_BUCKET_CAP;
        }
    }

    let keys: Vec<String> = values.feature_hits.keys().cloned().collect();
    for key in keys {
        let allowed = key.len() <= MAX_FEATURE_KEY_LEN && feature_allowlist.contains(&key.as_str());
        if !allowed {
            values.feature_hits.remove(&key);
            events.push(ClipEvent::FeatureKeyDropped { key });
        } else if let Some(hits) = values.feature_hits.get_mut(&key) {
            if *hits > FEATURE_HITS_CAP {
                events.push(ClipEvent::FeatureHitsClipped {
                    key,
                    original: *hits,
                    clipped: FEATURE_HITS_CAP,
                });
                *hits = FEATURE_HITS_CAP;
            }
        }
    }

    ClippedTelemetry { values, events }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean() -> TelemetryValues {
        TelemetryValues {
            consent_version: 3,
            window_start: 1_800_000_000,
            session_count: 12,
            session_duration_histogram: [10, 5, 2, 0],
            feature_hits: BTreeMap::from([(String::from("export"), 4)]),
            days_active: 9,
        }
    }

    #[test]
    fn a_clean_block_passes_through_untouched() {
        let out = clip_telemetry(clean(), &["export"]);
        assert_eq!(out.values, clean());
        assert!(out.events.is_empty());
    }

    #[test]
    fn a_poisoned_session_count_is_clipped_and_flagged() {
        // The §12 poisoning row.
        let mut v = clean();
        v.session_count = 1_000_000_000;
        let out = clip_telemetry(v, &["export"]);
        assert_eq!(out.values.session_count, SESSION_COUNT_CAP);
        assert_eq!(
            out.events,
            [ClipEvent::SessionCountClipped {
                original: 1_000_000_000,
                clipped: SESSION_COUNT_CAP
            }]
        );
    }

    #[test]
    fn days_active_is_capped_at_the_window_length() {
        let mut v = clean();
        v.days_active = 365;
        let out = clip_telemetry(v, &["export"]);
        assert_eq!(out.values.days_active, DAYS_ACTIVE_CAP);
        assert_eq!(
            out.events,
            [ClipEvent::DaysActiveClipped {
                original: 365,
                clipped: DAYS_ACTIVE_CAP
            }]
        );
    }

    #[test]
    fn histogram_buckets_are_capped_individually() {
        let mut v = clean();
        v.session_duration_histogram = [50_000, 5, HISTOGRAM_BUCKET_CAP, 1];
        let out = clip_telemetry(v, &["export"]);
        assert_eq!(
            out.values.session_duration_histogram,
            [HISTOGRAM_BUCKET_CAP, 5, HISTOGRAM_BUCKET_CAP, 1]
        );
        assert_eq!(
            out.events,
            [ClipEvent::HistogramBucketClipped {
                bucket: 0,
                original: 50_000,
                clipped: HISTOGRAM_BUCKET_CAP
            }]
        );
    }

    #[test]
    fn undeclared_feature_keys_are_dropped_and_declared_ones_capped() {
        let mut v = clean();
        v.feature_hits = BTreeMap::from([
            (String::from("export"), 7),
            (String::from("render"), 20_000),
            (String::from("undeclared"), 1),
        ]);
        let out = clip_telemetry(v, &["export", "render"]);
        assert_eq!(
            out.values.feature_hits,
            BTreeMap::from([
                (String::from("export"), 7),
                (String::from("render"), FEATURE_HITS_CAP),
            ])
        );
        assert_eq!(
            out.events,
            [
                ClipEvent::FeatureHitsClipped {
                    key: String::from("render"),
                    original: 20_000,
                    clipped: FEATURE_HITS_CAP,
                },
                ClipEvent::FeatureKeyDropped {
                    key: String::from("undeclared"),
                },
            ]
        );
    }

    #[test]
    fn overlong_feature_keys_are_dropped_even_when_allow_listed() {
        let long_key = "x".repeat(MAX_FEATURE_KEY_LEN + 1);
        let mut v = clean();
        v.feature_hits = BTreeMap::from([(long_key.clone(), 1)]);
        let out = clip_telemetry(v, &[long_key.as_str()]);
        assert!(out.values.feature_hits.is_empty());
        assert_eq!(out.events, [ClipEvent::FeatureKeyDropped { key: long_key }]);
    }

    #[test]
    fn consent_version_and_window_start_pass_through() {
        let mut v = clean();
        v.consent_version = 0;
        v.window_start = u64::MAX;
        let out = clip_telemetry(v, &["export"]);
        assert_eq!(out.values.consent_version, 0);
        assert_eq!(out.values.window_start, u64::MAX);
    }

    #[test]
    fn the_consent_gate_only_allows_explicit_consent() {
        assert!(!consent_allows(0));
        assert!(consent_allows(1));
        assert!(consent_allows(u64::MAX));
    }
}
