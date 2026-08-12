//! Entitlement resolution (`licensing-model.md §2.2`, ADR-0009).
//!
//! Resolution turns a *specification* — a tier, plus extras, plus add-on grants, minus
//! exclusions — into a flat snapshot that gets signed into a credential. The client never sees
//! the catalog, only the result.
//!
//! # Determinism is a hard requirement
//!
//! The snapshot is signed. Two resolutions of the same inputs must produce byte-identical
//! output, or the same license would yield different credentials on different servers and
//! signature reproduction during a dispute would be impossible. That is why every collection
//! here is a `BTree*` and why the merge order is fixed rather than iteration-order dependent.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use copylocker_types::{Entitlements, LimitValue, SubscriptionHint, VersionScope};

use crate::catalog::{Catalog, CatalogError, MAX_GROUP_DEPTH};

/// What a grant confers.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum GrantTarget {
    /// A single feature.
    Feature {
        /// Feature identifier.
        id: String,
    },
    /// A whole group.
    Group {
        /// Group identifier.
        id: String,
    },
}

/// An add-on purchase or manual grant, optionally with its own validity window.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct Grant {
    /// What is granted.
    pub target: GrantTarget,
    /// Start of the grant, inclusive. `None` means "already started".
    #[cfg_attr(feature = "serde", serde(default))]
    pub valid_from: Option<i64>,
    /// End of the grant, exclusive. `None` means "follows the license".
    #[cfg_attr(feature = "serde", serde(default))]
    pub valid_until: Option<i64>,
    /// Order number or promotion code, for audit.
    #[cfg_attr(feature = "serde", serde(default))]
    pub source: String,
    /// Limit overrides carried by this grant.
    #[cfg_attr(feature = "serde", serde(default))]
    pub limits: BTreeMap<String, LimitValue>,
}

impl Grant {
    /// Whether the grant is in force at `now`.
    #[must_use]
    pub fn is_active(&self, now: i64) -> bool {
        let started = self.valid_from.is_none_or(|f| now >= f);
        let not_ended = self.valid_until.is_none_or(|u| now < u);
        started && not_ended
    }
}

/// How a numeric limit combines when several sources set it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LimitMergePolicy {
    /// Take the larger value. The default, because an add-on should never shrink a quota
    /// (`licensing-model.md §2.2`). `-1` (unlimited) always wins.
    #[default]
    Max,
    /// Add the values. Used for stackable quotas such as extra seats.
    Sum,
    /// Later source replaces earlier.
    Override,
}

/// The input to resolution (`licensing-model.md §2.1`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct EntitlementSpec {
    /// Base tier.
    pub tier: String,
    /// Groups included on top of the tier.
    #[cfg_attr(feature = "serde", serde(default))]
    pub extra_groups: Vec<String>,
    /// Add-on grants.
    #[cfg_attr(feature = "serde", serde(default))]
    pub grants: Vec<Grant>,
    /// Features explicitly removed. Rare, but enterprise contracts need it.
    #[cfg_attr(feature = "serde", serde(default))]
    pub excluded_features: Vec<String>,
    /// Final limit overrides, applied last.
    #[cfg_attr(feature = "serde", serde(default))]
    pub limit_overrides: BTreeMap<String, LimitValue>,
    /// Per-key merge policies. Keys absent here use [`LimitMergePolicy::Max`].
    #[cfg_attr(feature = "serde", serde(default))]
    pub limit_merge: BTreeMap<String, LimitMergePolicy>,
}

/// Resolution failed.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PolicyError {
    /// The catalog itself is unsound.
    Catalog(CatalogError),
    /// The specification names a tier that does not exist.
    UnknownTier(String),
    /// The specification names a group that does not exist.
    UnknownGroup(String),
    /// The specification names a feature that does not exist.
    UnknownFeature(String),
}

impl From<CatalogError> for PolicyError {
    fn from(e: CatalogError) -> Self {
        Self::Catalog(e)
    }
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Catalog(e) => write!(f, "catalog: {e}"),
            Self::UnknownTier(t) => write!(f, "unknown tier `{t}`"),
            Self::UnknownGroup(g) => write!(f, "unknown group `{g}`"),
            Self::UnknownFeature(x) => write!(f, "unknown feature `{x}`"),
        }
    }
}

/// Resolve a specification against a catalog.
///
/// The order is fixed by `licensing-model.md §2.2` and each step matters:
///
/// 1. expand the tier's groups recursively, and its direct features;
/// 2. add `extra_groups`;
/// 3. add grants that are active at `now`;
/// 4. subtract `excluded_features` — **last**, so an exclusion cannot be undone by a grant;
/// 5. merge limits tier → grants → overrides, per the merge policy;
/// 6. emit ordered collections.
pub fn resolve(
    catalog: &Catalog,
    spec: &EntitlementSpec,
    now: i64,
) -> Result<Entitlements, PolicyError> {
    catalog.validate()?;

    let tier = catalog
        .tier(&spec.tier)
        .ok_or_else(|| PolicyError::UnknownTier(spec.tier.clone()))?;

    let mut features: BTreeSet<String> = BTreeSet::new();
    let mut limits: BTreeMap<String, LimitValue> = BTreeMap::new();

    // 1. Tier.
    for gid in &tier.groups {
        collect_group(catalog, gid, &mut features, 0)?;
    }
    for pat in &tier.features {
        add_pattern(catalog, pat, &mut features)?;
    }
    for (k, v) in &tier.limits {
        limits.insert(k.clone(), *v);
    }

    // 2. Extra groups.
    for gid in &spec.extra_groups {
        collect_group(catalog, gid, &mut features, 0)?;
    }

    // 3. Active grants.
    for grant in &spec.grants {
        if !grant.is_active(now) {
            continue;
        }
        match &grant.target {
            GrantTarget::Feature { id } => add_pattern(catalog, id, &mut features)?,
            GrantTarget::Group { id } => collect_group(catalog, id, &mut features, 0)?,
        }
        for (k, v) in &grant.limits {
            merge_limit(&mut limits, k, *v, policy_for(spec, k));
        }
    }

    // 4. Exclusions, applied after everything that could add.
    for ex in &spec.excluded_features {
        if catalog.feature(ex).is_none() {
            return Err(PolicyError::UnknownFeature(ex.clone()));
        }
        features.remove(ex);
    }

    // 5. Explicit overrides, applied last so an operator can always win.
    for (k, v) in &spec.limit_overrides {
        merge_limit(&mut limits, k, *v, policy_for(spec, k));
    }

    Ok(Entitlements {
        features,
        limits,
        tier_id: tier.id.clone(),
        tier_label: tier.label.clone(),
        catalog_version: catalog.version,
        version_scope: None,
        subscription_hint: None,
    })
}

/// Attach the version scope and subscription hint that the credential also carries.
///
/// Kept separate from [`resolve`] so that resolution stays a pure function of catalog and spec,
/// which is what makes its determinism testable in isolation.
#[must_use]
pub fn with_context(
    mut e: Entitlements,
    version_scope: Option<VersionScope>,
    hint: Option<SubscriptionHint>,
) -> Entitlements {
    e.version_scope = version_scope;
    e.subscription_hint = hint;
    e
}

fn policy_for(spec: &EntitlementSpec, key: &str) -> LimitMergePolicy {
    spec.limit_merge.get(key).copied().unwrap_or_default()
}

/// Merge one limit value into the accumulator.
fn merge_limit(
    limits: &mut BTreeMap<String, LimitValue>,
    key: &str,
    incoming: LimitValue,
    policy: LimitMergePolicy,
) {
    let existing = limits.get(key).copied();
    let merged = match (existing, policy) {
        (None, _) => incoming,
        (Some(cur), LimitMergePolicy::Override) => {
            let _ = cur;
            incoming
        }
        // `-1` means unlimited, so it must dominate rather than lose a numeric comparison.
        (Some(cur), LimitMergePolicy::Max) => {
            if cur == copylocker_types::entitlements::LIMIT_UNLIMITED
                || incoming == copylocker_types::entitlements::LIMIT_UNLIMITED
            {
                copylocker_types::entitlements::LIMIT_UNLIMITED
            } else {
                cur.max(incoming)
            }
        }
        (Some(cur), LimitMergePolicy::Sum) => {
            if cur == copylocker_types::entitlements::LIMIT_UNLIMITED
                || incoming == copylocker_types::entitlements::LIMIT_UNLIMITED
            {
                copylocker_types::entitlements::LIMIT_UNLIMITED
            } else {
                cur.saturating_add(incoming)
            }
        }
    };
    limits.insert(key.to_string(), merged);
}

/// Recursively collect a group's features.
///
/// Depth is bounded independently of [`Catalog::validate`] so this function is safe to call even
/// on an unvalidated catalog.
fn collect_group(
    catalog: &Catalog,
    id: &str,
    out: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), PolicyError> {
    if depth > MAX_GROUP_DEPTH {
        return Err(PolicyError::Catalog(CatalogError::DepthExceeded(
            id.to_string(),
        )));
    }
    let g = catalog
        .group(id)
        .ok_or_else(|| PolicyError::UnknownGroup(id.to_string()))?;
    for inc in &g.members.includes {
        collect_group(catalog, inc, out, depth + 1)?;
    }
    for pat in &g.members.features {
        add_pattern(catalog, pat, out)?;
    }
    Ok(())
}

fn add_pattern(
    catalog: &Catalog,
    pattern: &str,
    out: &mut BTreeSet<String>,
) -> Result<(), PolicyError> {
    for id in catalog.expand_pattern(pattern)? {
        out.insert(id);
    }
    Ok(())
}

/// Compare two tiers by rank, for telling upgrades from downgrades.
///
/// Returns `None` when either identifier is unknown.
#[must_use]
pub fn compare_tiers(catalog: &Catalog, a: &str, b: &str) -> Option<core::cmp::Ordering> {
    let ra = catalog.tier(a)?.rank;
    let rb = catalog.tier(b)?.rank;
    Some(ra.cmp(&rb))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::fixtures::sample;
    use copylocker_proto::entitlements as ent_codec;

    const NOW: i64 = 1_800_000_000;

    fn spec(tier: &str) -> EntitlementSpec {
        EntitlementSpec {
            tier: tier.to_string(),
            ..Default::default()
        }
    }

    fn features_of(e: &Entitlements) -> Vec<&str> {
        e.features.iter().map(String::as_str).collect()
    }

    #[test]
    fn a_tier_expands_through_nested_groups() {
        let c = sample();
        let e = resolve(&c, &spec("pro"), NOW).unwrap();
        // pro -> pro-suite -> export-pro -> export-basic
        assert_eq!(
            features_of(&e),
            [
                "ai.assist",
                "export.pdf",
                "export.png",
                "export.svg",
                "render.4k"
            ]
        );
        assert_eq!(e.tier_id, "pro");
        assert_eq!(e.tier_label, "Pro");
        assert_eq!(e.catalog_version, 1);
        assert_eq!(e.limit("max_projects"), Some(100));
    }

    #[test]
    fn direct_tier_features_are_included_alongside_groups() {
        let e = resolve(&sample(), &spec("team"), NOW).unwrap();
        assert!(e.has_feature("team.share"));
        assert!(e.has_feature("ai.assist"));
        assert!(e.is_unlimited("max_projects"));
        assert_eq!(e.limit("max_members"), Some(25));
    }

    #[test]
    fn resolution_is_byte_for_byte_deterministic() {
        // The property the signature depends on.
        let c = sample();
        let mut s = spec("pro");
        s.extra_groups = alloc::vec!["export-basic".to_string()];
        s.grants = alloc::vec![Grant {
            target: GrantTarget::Feature {
                id: "team.share".to_string()
            },
            valid_from: None,
            valid_until: None,
            source: "order-1".to_string(),
            limits: [("max_members".to_string(), 5)].into_iter().collect(),
        }];
        let a = ent_codec::encode(&resolve(&c, &s, NOW).unwrap()).to_canonical();
        let b = ent_codec::encode(&resolve(&c, &s, NOW).unwrap()).to_canonical();
        assert_eq!(a, b);
    }

    #[test]
    fn specification_ordering_does_not_change_the_result() {
        let c = sample();
        let mut a = spec("free");
        a.extra_groups = alloc::vec!["export-pro".to_string(), "pro-suite".to_string()];
        let mut b = spec("free");
        b.extra_groups = alloc::vec!["pro-suite".to_string(), "export-pro".to_string()];
        assert_eq!(resolve(&c, &a, NOW).unwrap(), resolve(&c, &b, NOW).unwrap());
    }

    #[test]
    fn globs_expand_and_never_reach_the_output() {
        let mut c = sample();
        c.tiers[0].features.push("export.*".to_string());
        let e = resolve(&c, &spec("free"), NOW).unwrap();
        assert!(e.has_feature("export.pdf"));
        assert!(
            !e.features.iter().any(|f| f.contains('*')),
            "a wildcard must never be sent to a client"
        );
    }

    #[test]
    fn grants_apply_only_within_their_window() {
        let c = sample();
        let mut s = spec("free");
        s.grants = alloc::vec![Grant {
            target: GrantTarget::Feature {
                id: "ai.assist".to_string()
            },
            valid_from: Some(NOW),
            valid_until: Some(NOW + 100),
            source: "promo".to_string(),
            limits: BTreeMap::new(),
        }];
        assert!(!resolve(&c, &s, NOW - 1).unwrap().has_feature("ai.assist"));
        assert!(
            resolve(&c, &s, NOW).unwrap().has_feature("ai.assist"),
            "valid_from is inclusive"
        );
        assert!(resolve(&c, &s, NOW + 99).unwrap().has_feature("ai.assist"));
        assert!(
            !resolve(&c, &s, NOW + 100).unwrap().has_feature("ai.assist"),
            "valid_until is exclusive"
        );
    }

    #[test]
    fn an_open_ended_grant_is_always_active() {
        let mut s = spec("free");
        s.grants = alloc::vec![Grant {
            target: GrantTarget::Group {
                id: "pro-suite".to_string()
            },
            valid_from: None,
            valid_until: None,
            source: String::new(),
            limits: BTreeMap::new(),
        }];
        assert!(resolve(&sample(), &s, 0).unwrap().has_feature("render.4k"));
        assert!(resolve(&sample(), &s, i64::MAX)
            .unwrap()
            .has_feature("render.4k"));
    }

    #[test]
    fn exclusions_win_over_grants() {
        // Applied last on purpose: an enterprise contract that excludes a feature must not be
        // silently re-enabled by an add-on.
        let mut s = spec("pro");
        s.grants = alloc::vec![Grant {
            target: GrantTarget::Feature {
                id: "ai.assist".to_string()
            },
            valid_from: None,
            valid_until: None,
            source: String::new(),
            limits: BTreeMap::new(),
        }];
        s.excluded_features = alloc::vec!["ai.assist".to_string()];
        let e = resolve(&sample(), &s, NOW).unwrap();
        assert!(!e.has_feature("ai.assist"));
        assert!(
            e.has_feature("render.4k"),
            "only the named feature is removed"
        );
    }

    #[test]
    fn excluding_an_unknown_feature_is_an_error_not_a_silent_no_op() {
        let mut s = spec("pro");
        s.excluded_features = alloc::vec!["typo.feature".to_string()];
        assert_eq!(
            resolve(&sample(), &s, NOW),
            Err(PolicyError::UnknownFeature("typo.feature".to_string()))
        );
    }

    #[test]
    fn limits_default_to_max_so_add_ons_never_shrink_a_quota() {
        let mut s = spec("free"); // max_projects = 3
        s.grants = alloc::vec![Grant {
            target: GrantTarget::Feature {
                id: "export.png".to_string()
            },
            valid_from: None,
            valid_until: None,
            source: String::new(),
            limits: [("max_projects".to_string(), 1)].into_iter().collect(),
        }];
        assert_eq!(
            resolve(&sample(), &s, NOW).unwrap().limit("max_projects"),
            Some(3)
        );
    }

    #[test]
    fn sum_policy_stacks_quotas() {
        let mut s = spec("free");
        s.limit_merge
            .insert("max_projects".to_string(), LimitMergePolicy::Sum);
        s.grants = alloc::vec![
            Grant {
                target: GrantTarget::Feature {
                    id: "export.png".to_string()
                },
                valid_from: None,
                valid_until: None,
                source: String::new(),
                limits: [("max_projects".to_string(), 10)].into_iter().collect(),
            },
            Grant {
                target: GrantTarget::Feature {
                    id: "export.png".to_string()
                },
                valid_from: None,
                valid_until: None,
                source: String::new(),
                limits: [("max_projects".to_string(), 5)].into_iter().collect(),
            },
        ];
        assert_eq!(
            resolve(&sample(), &s, NOW).unwrap().limit("max_projects"),
            Some(18)
        );
    }

    #[test]
    fn override_policy_lets_a_lower_value_win() {
        let mut s = spec("pro"); // 100
        s.limit_merge
            .insert("max_projects".to_string(), LimitMergePolicy::Override);
        s.limit_overrides.insert("max_projects".to_string(), 5);
        assert_eq!(
            resolve(&sample(), &s, NOW).unwrap().limit("max_projects"),
            Some(5)
        );
    }

    #[test]
    fn unlimited_dominates_every_merge_policy() {
        for policy in [LimitMergePolicy::Max, LimitMergePolicy::Sum] {
            let mut s = spec("team"); // max_projects = -1
            s.limit_merge.insert("max_projects".to_string(), policy);
            s.limit_overrides.insert("max_projects".to_string(), 10);
            assert!(
                resolve(&sample(), &s, NOW)
                    .unwrap()
                    .is_unlimited("max_projects"),
                "policy {policy:?} lost the unlimited sentinel"
            );
        }
    }

    #[test]
    fn sum_saturates_rather_than_overflowing() {
        let mut s = spec("free");
        s.limit_merge
            .insert("max_projects".to_string(), LimitMergePolicy::Sum);
        s.limit_overrides
            .insert("max_projects".to_string(), i64::MAX);
        assert_eq!(
            resolve(&sample(), &s, NOW).unwrap().limit("max_projects"),
            Some(i64::MAX)
        );
    }

    #[test]
    fn an_unknown_tier_or_group_is_named_in_the_error() {
        assert_eq!(
            resolve(&sample(), &spec("nope"), NOW),
            Err(PolicyError::UnknownTier("nope".to_string()))
        );
        let mut s = spec("free");
        s.extra_groups = alloc::vec!["nope".to_string()];
        assert_eq!(
            resolve(&sample(), &s, NOW),
            Err(PolicyError::UnknownGroup("nope".to_string()))
        );
    }

    #[test]
    fn a_cyclic_catalog_errors_rather_than_overflowing_the_stack() {
        let mut c = sample();
        c.groups[0].members.includes.push("pro-suite".to_string());
        assert!(matches!(
            resolve(&c, &spec("pro"), NOW),
            Err(PolicyError::Catalog(_))
        ));
    }

    #[test]
    fn tier_ranks_order_upgrades_and_downgrades() {
        use core::cmp::Ordering;
        let c = sample();
        assert_eq!(compare_tiers(&c, "free", "pro"), Some(Ordering::Less));
        assert_eq!(compare_tiers(&c, "team", "pro"), Some(Ordering::Greater));
        assert_eq!(compare_tiers(&c, "pro", "pro"), Some(Ordering::Equal));
        assert_eq!(compare_tiers(&c, "pro", "ghost"), None);
    }

    #[test]
    fn context_attaches_without_disturbing_resolution() {
        let e = resolve(&sample(), &spec("pro"), NOW).unwrap();
        let base_features = e.features.clone();
        let with = with_context(e, Some(VersionScope::ReleasedBefore(NOW)), None);
        assert_eq!(with.features, base_features);
        assert_eq!(with.version_scope, Some(VersionScope::ReleasedBefore(NOW)));
    }

    #[test]
    fn the_resolved_snapshot_survives_the_wire_encoding() {
        let e = resolve(&sample(), &spec("team"), NOW).unwrap();
        let encoded = ent_codec::encode(&e).to_canonical();
        let parsed = copylocker_suite::cbor::decode_canonical(
            &encoded,
            copylocker_suite::cbor::Limits::default(),
        )
        .unwrap();
        assert_eq!(ent_codec::decode(&parsed).unwrap(), e);
    }
}
