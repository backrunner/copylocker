//! Resolved entitlements as they appear on the wire.
//!
//! This is the **client-side** view: a flat, fully expanded snapshot. The catalog that produced
//! it (features, groups, tiers, grants) never leaves the server — that keeps the pricing
//! structure off the client and keeps the client small (`licensing-model.md §2.2`).
//!
//! The authoritative definition of the entitlement *specification* (the input to resolution)
//! lives in `copylocker-server-core::entitlement`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

/// A numeric limit. `-1` is the agreed encoding for "unlimited"
/// (`licensing-model.md §2.4`).
pub type LimitValue = i64;

/// Sentinel for an unlimited quota.
pub const LIMIT_UNLIMITED: LimitValue = -1;

/// Flattened entitlements written into a `MachineCredential` and refreshed by a
/// `ValidationTicket` (`licensing-model.md §9`).
///
/// Ordering matters: `features` is a sorted set and `limits` a sorted map so that the canonical
/// CBOR encoding — and therefore the signature — is reproducible.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Entitlements {
    /// Fully expanded feature identifiers. No globs, no duplicates, sorted.
    pub features: BTreeSet<String>,
    /// Numeric limits. Enforcement is the vendor application's responsibility; CopyLocker only
    /// signs the numbers (`licensing-model.md §2.5`).
    pub limits: BTreeMap<String, LimitValue>,
    /// Tier the user is on, for display.
    pub tier_id: String,
    /// Human-readable tier label, for display.
    pub tier_label: String,
    /// Catalog version this snapshot was resolved against, for dispute forensics.
    pub catalog_version: u32,
    /// Version scope, for client-side UX only. **Not** an enforcement point
    /// (`licensing-model.md §4.2`).
    pub version_scope: Option<VersionScope>,
    /// Subscription status hints for in-app messaging. Not a security decision.
    pub subscription_hint: Option<SubscriptionHint>,
}

impl Entitlements {
    /// Whether a specific feature is present.
    ///
    /// Callers must not use this as an access gate on its own — it is the *precondition* for
    /// `derive_feature_key`, which is the actual gate (ADR-0004).
    #[must_use]
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }

    /// Look up a limit, returning `None` when the key is absent.
    #[must_use]
    pub fn limit(&self, key: &str) -> Option<LimitValue> {
        self.limits.get(key).copied()
    }

    /// Whether a limit is present and unlimited.
    #[must_use]
    pub fn is_unlimited(&self, key: &str) -> bool {
        self.limit(key) == Some(LIMIT_UNLIMITED)
    }
}

/// Which application versions a license covers (`licensing-model.md §4`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
pub enum VersionScope {
    /// Every release, past and future.
    #[default]
    Unlimited,
    /// A semver range expression such as `^3` or `>=2.0 <4.0`.
    SemverRange(String),
    /// Releases whose `published_at` is at or before this instant. The recommended form: it is
    /// unambiguous where semver ranges are not (`licensing-model.md §4.1`).
    ReleasedBefore(i64),
    /// An explicit allow-list of release identifiers.
    Pinned(Vec<String>),
}

/// Lifecycle state of a subscription, mirrored to the client for messaging only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SubscriptionState {
    /// Paid and current.
    Active = 0,
    /// A payment failed; still usable during the dunning window.
    PastDue = 1,
    /// Cancelled but paid through the end of the current period.
    Canceling = 2,
    /// Dunning elapsed without payment.
    Suspended = 3,
}

impl SubscriptionState {
    /// Decode from the wire representation.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::PastDue),
            2 => Some(Self::Canceling),
            3 => Some(Self::Suspended),
            _ => None,
        }
    }
}

/// Subscription hints for in-app copy such as "update your payment method" or
/// "3 more months until you keep this version forever" (`licensing-model.md §9`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubscriptionHint {
    /// Current lifecycle state.
    pub state: SubscriptionState,
    /// End of the paid period, Unix seconds.
    pub current_period_end: i64,
    /// Consecutive paid months accumulated toward a perpetual fallback.
    pub fallback_progress_months: Option<u32>,
    /// Months required to earn the perpetual fallback.
    pub fallback_required_months: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn unlimited_limit_uses_negative_one() {
        let mut e = Entitlements::default();
        e.limits.insert("max_projects".to_string(), LIMIT_UNLIMITED);
        e.limits.insert("max_members".to_string(), 25);
        assert!(e.is_unlimited("max_projects"));
        assert!(!e.is_unlimited("max_members"));
        assert_eq!(e.limit("max_members"), Some(25));
        assert_eq!(e.limit("absent"), None);
    }

    #[test]
    fn features_are_a_sorted_set() {
        let mut e = Entitlements::default();
        e.features.insert("export.svg".to_string());
        e.features.insert("export.png".to_string());
        e.features.insert("export.png".to_string());
        let ordered: Vec<_> = e.features.iter().cloned().collect();
        assert_eq!(ordered, ["export.png", "export.svg"]);
    }
}
