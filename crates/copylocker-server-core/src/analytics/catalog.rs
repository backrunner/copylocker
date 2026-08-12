//! The fixed metric catalog (`90-analytics-telemetry.md §2`).
//!
//! Every metric the Admin API can serve has exactly one entry here, so the
//! `/v1/admin/analytics/definitions` endpoint cannot drift from the documentation.
//! Metric ids are identifiers in stored rollups and API responses — **never rename one**;
//! add a new id instead.

/// Which collection tier a metric belongs to (`90-analytics-telemetry.md §1`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub enum MetricTier {
    /// Server-derived from signed credential usage; no extra collection.
    T0,
    /// Client-reported, pre-aggregated counts; requires vendor opt-in and end-user consent.
    T1,
}

/// One metric's precise definition, as served by `/v1/admin/analytics/definitions`.
///
/// `trusted` mirrors the tier: T0 metrics come from signed credential usage records,
/// T1 metrics are client self-reports (`90-analytics-telemetry.md §6`). The console must
/// never plot trusted and untrusted series on the same unlabelled graph.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
// `&'static str` fields are serialize-only; the catalog is a constant, never decoded.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct MetricDefinition {
    /// Stable metric identifier, e.g. `act.new`. **Immutable once published.**
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Terse, precise definition text for the definitions endpoint.
    pub definition: &'static str,
    /// Collection tier.
    pub tier: MetricTier,
    /// Whether the value derives from signed credential usage (T0) or a client self-report (T1).
    pub trusted: bool,
}

impl MetricDefinition {
    const fn t0(id: &'static str, name: &'static str, definition: &'static str) -> Self {
        Self {
            id,
            name,
            definition,
            tier: MetricTier::T0,
            trusted: true,
        }
    }

    const fn t1(id: &'static str, name: &'static str, definition: &'static str) -> Self {
        Self {
            id,
            name,
            definition,
            tier: MetricTier::T1,
            trusted: false,
        }
    }
}

/// The complete catalog, in documentation order.
static METRICS: &[MetricDefinition] = &[
    // --- §2.1 Activations (T0) ---
    MetricDefinition::t0(
        "act.new",
        "New activations",
        "Activations creating a new machine_id within the window; fingerprint-tolerance \
         reuses are deliberately excluded.",
    ),
    MetricDefinition::t0(
        "act.reactivation",
        "Reactivations",
        "Previously released or revoked devices activated again within the window; counted \
         separately from act.new.",
    ),
    MetricDefinition::t0(
        "act.by_path",
        "Activations by path",
        "Activation count grouped by path: online / offline_ar / olk / account.",
    ),
    MetricDefinition::t0(
        "act.failed",
        "Failed activations",
        "Rejected activations grouped by failure reason (seats full / invalid key / \
         fingerprint mismatch / rate limited).",
    ),
    MetricDefinition::t0(
        "act.time_to_first",
        "Time to first activation",
        "Distribution (P50/P90) of the delay from license issuance to first activation.",
    ),
    MetricDefinition::t0(
        "act.transfer",
        "Device transfers",
        "deactivate→activate pairs within the window; unusually high values suggest sharing.",
    ),
    // --- §2.2 Activity (T0) ---
    MetricDefinition::t0(
        "dev.checked_in",
        "Checked-in devices (window)",
        "Unique machine_ids with at least one successful validate or heartbeat in the window.",
    ),
    MetricDefinition::t0(
        "dev.checked_in_7d",
        "Checked-in devices (7 days)",
        "Unique machines checked in over a fixed 7-day window; the reliable WAU analogue.",
    ),
    MetricDefinition::t0(
        "dev.checked_in_28d",
        "Checked-in devices (28 days)",
        "Unique machines checked in over a fixed 28-day window; the reliable MAU analogue.",
    ),
    MetricDefinition::t0(
        "lic.active",
        "Active licenses",
        "Unique license_ids with at least one checked-in device in the window.",
    ),
    MetricDefinition::t0(
        "dev.stickiness",
        "Device stickiness",
        "Ratio dev.checked_in_7d / dev.checked_in_28d.",
    ),
    MetricDefinition::t0(
        "dev.dormant",
        "Dormant devices",
        "Devices in state active that have not checked in for longer than \
         refresh_after + grace.",
    ),
    MetricDefinition::t0(
        "dev.state_mix",
        "Device state mix",
        "Server-inferred share of Active / NeedsRevalidation / Grace / Dormant devices.",
    ),
    // --- §2.3 Versions (T0) ---
    MetricDefinition::t0(
        "ver.app_dist",
        "App version distribution",
        "Checked-in devices grouped by app_version.",
    ),
    MetricDefinition::t0(
        "ver.release_dist",
        "Release distribution",
        "Checked-in devices grouped by release_id / variant_id.",
    ),
    MetricDefinition::t0(
        "ver.sdk_dist",
        "SDK version distribution",
        "Checked-in devices grouped by sdk_version; drives SDK sunset decisions.",
    ),
    MetricDefinition::t0(
        "ver.adoption_curve",
        "Version adoption curve",
        "Cumulative daily share of devices on a new release after its publication.",
    ),
    MetricDefinition::t0(
        "ver.upgrade_lag",
        "Upgrade lag",
        "Distribution of the delay from release publication to device upgrade.",
    ),
    MetricDefinition::t0(
        "ver.os_arch_dist",
        "OS/arch distribution",
        "Checked-in devices grouped by os × arch.",
    ),
    MetricDefinition::t0(
        "ver.proto_suite_dist",
        "Protocol/suite distribution",
        "Checked-in devices grouped by proto_ver × suite_id; drives protocol and suite \
         migration decisions.",
    ),
    // --- §2.4 Commercial (T0) ---
    MetricDefinition::t0(
        "seat.utilization",
        "Seat utilization",
        "seats_used / seats, aggregated per license and per policy.",
    ),
    MetricDefinition::t0(
        "seat.exhausted",
        "Seat exhaustion rejections",
        "Activations rejected because seats were full; a strong upsell signal.",
    ),
    MetricDefinition::t0(
        "lic.churn",
        "License churn",
        "Share of licenses that checked in last window but not this window.",
    ),
    MetricDefinition::t0(
        "lic.renewal",
        "Renewal rate",
        "Share of licenses renewed before expiry.",
    ),
    MetricDefinition::t0(
        "trial.conversion",
        "Trial conversion",
        "Rate and delay of same-fingerprint conversions from trial to paid licenses.",
    ),
    MetricDefinition::t0(
        "geo.dist",
        "Geographic distribution",
        "Checked-in devices grouped by country (cf.country); IPs are never stored.",
    ),
    MetricDefinition::t0(
        "mode.dist",
        "Mode distribution",
        "Distribution of Mode O vs Mode E.",
    ),
    // --- §2.5 Health (T0) ---
    MetricDefinition::t0(
        "health.validate_success",
        "Validate success rate",
        "Share of validate requests that succeed.",
    ),
    MetricDefinition::t0(
        "health.grace_rate",
        "Grace rate",
        "Share of devices inferred to be in their grace window; a spike indicates server or \
         network trouble.",
    ),
    MetricDefinition::t0(
        "health.integrity_fail",
        "Integrity failures",
        "Integrity report failures grouped by release_id; a spike suggests a guard false \
         positive that needs a rollback.",
    ),
    MetricDefinition::t0(
        "health.suspicion",
        "Suspicious devices",
        "Devices with suspicion_score > 80.",
    ),
    MetricDefinition::t0(
        "health.clock_rollback",
        "Clock rollback detections",
        "Devices detected with a rolled-back clock.",
    ),
    // --- §2.6 Optional T1 metrics (untrusted, consent required) ---
    MetricDefinition::t1(
        "use.session_count",
        "Session count",
        "Client-aggregated number of sessions in the window; untrusted self-report.",
    ),
    MetricDefinition::t1(
        "use.session_duration",
        "Session duration",
        "Bucketed histogram (<5m / 5-30m / 30m-2h / >2h); exact durations are never reported.",
    ),
    MetricDefinition::t1(
        "use.feature_hits",
        "Feature hits",
        "Per-feature usage counts for feature ids declared in the vendor allow-list.",
    ),
    MetricDefinition::t1(
        "use.days_active",
        "Days active",
        "Integer 0-28: days the app was used within the window; cheap day-granularity signal.",
    ),
];

/// The full metric catalog, for the `/v1/admin/analytics/definitions` endpoint.
#[must_use]
pub fn metrics() -> &'static [MetricDefinition] {
    METRICS
}

/// Look up one metric definition by its stable id.
#[must_use]
pub fn metric_by_id(id: &str) -> Option<&'static MetricDefinition> {
    METRICS.iter().find(|m| m.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn metric_ids_are_unique() {
        let mut seen = BTreeSet::new();
        for m in metrics() {
            assert!(seen.insert(m.id), "duplicate metric id `{}`", m.id);
        }
    }

    #[test]
    fn every_metric_has_a_name_and_definition() {
        for m in metrics() {
            assert!(!m.name.is_empty(), "metric `{}` has no name", m.id);
            assert!(
                !m.definition.is_empty(),
                "metric `{}` has no definition",
                m.id
            );
        }
    }

    #[test]
    fn trusted_flag_matches_tier() {
        for m in metrics() {
            match m.tier {
                MetricTier::T0 => assert!(m.trusted, "T0 metric `{}` must be trusted", m.id),
                MetricTier::T1 => {
                    assert!(!m.trusted, "T1 metric `{}` must be untrusted", m.id)
                }
            }
        }
    }

    #[test]
    fn lookup_finds_known_ids_and_rejects_unknown() {
        assert_eq!(
            metric_by_id("act.new").map(|m| m.tier),
            Some(MetricTier::T0)
        );
        assert_eq!(
            metric_by_id("use.days_active").map(|m| m.tier),
            Some(MetricTier::T1)
        );
        assert!(metric_by_id("dev.dau").is_none());
        assert!(metric_by_id("").is_none());
    }

    #[test]
    fn the_catalog_covers_the_documented_ids() {
        let ids: BTreeSet<&str> = metrics().iter().map(|m| m.id).collect();
        for id in [
            "act.new",
            "act.reactivation",
            "act.by_path",
            "act.failed",
            "act.time_to_first",
            "act.transfer",
            "dev.checked_in",
            "dev.checked_in_7d",
            "dev.checked_in_28d",
            "lic.active",
            "dev.stickiness",
            "dev.dormant",
            "dev.state_mix",
            "ver.app_dist",
            "ver.release_dist",
            "ver.sdk_dist",
            "ver.adoption_curve",
            "ver.upgrade_lag",
            "ver.os_arch_dist",
            "ver.proto_suite_dist",
            "seat.utilization",
            "seat.exhausted",
            "lic.churn",
            "lic.renewal",
            "trial.conversion",
            "geo.dist",
            "mode.dist",
            "health.validate_success",
            "health.grace_rate",
            "health.integrity_fail",
            "health.suspicion",
            "health.clock_rollback",
            "use.session_count",
            "use.session_duration",
            "use.feature_hits",
            "use.days_active",
        ] {
            assert!(ids.contains(id), "catalog is missing `{id}`");
        }
        assert_eq!(metrics().len(), 36);
    }
}
