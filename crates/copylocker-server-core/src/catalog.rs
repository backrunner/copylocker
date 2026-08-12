//! The entitlement catalog: features, groups, and tiers (`licensing-model.md §2`).
//!
//! # Why feature identifiers can never change
//!
//! `FeatureKey(f) = KDF(SessionRoot, … ‖ feature_id)`. The identifier is an input to the key
//! that unseals that feature's assets. Renaming `export.pdf` to `export.document` does not
//! rename anything — it derives a different key, and every asset ever sealed under the old name
//! becomes permanently unopenable. So the CLI and console hard-block renames of published
//! features, and [`Catalog::validate_evolution`] enforces it here too
//! (`licensing-model.md §2.3`).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use copylocker_types::LimitValue;

/// A single atomic capability.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct Feature {
    /// Identifier. Convention is `<domain>.<capability>`, e.g. `export.pdf`.
    ///
    /// **Immutable once published.**
    pub id: String,
    /// Display label.
    pub label: String,
    /// Optional longer description.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    /// When this feature was deprecated. A deprecated feature still resolves — existing
    /// credentials must keep working — but new tiers should not reference it.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub deprecated_at: Option<i64>,
}

/// What a group contains.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct GroupMembers {
    /// Other groups included wholesale.
    #[cfg_attr(feature = "serde", serde(default))]
    pub includes: Vec<String>,
    /// Feature identifiers, optionally with a trailing `*` glob such as `export.*`.
    ///
    /// Globs are expanded **server-side during resolution**; the wildcard never reaches a
    /// client, because a client that received `export.*` would grant itself features that do
    /// not exist yet (`licensing-model.md §2.3`).
    #[cfg_attr(feature = "serde", serde(default))]
    pub features: Vec<String>,
}

/// A named, reusable set of features.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct FeatureGroup {
    /// Group identifier.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Membership.
    pub members: GroupMembers,
}

/// A purchasable tier.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct Tier {
    /// Tier identifier.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Ordering rank, used to tell an upgrade from a downgrade.
    pub rank: i32,
    /// Groups this tier includes.
    #[cfg_attr(feature = "serde", serde(default))]
    pub groups: Vec<String>,
    /// Features included directly, bypassing groups.
    #[cfg_attr(feature = "serde", serde(default))]
    pub features: Vec<String>,
    /// Numeric limits. `-1` means unlimited.
    #[cfg_attr(feature = "serde", serde(default))]
    pub limits: BTreeMap<String, LimitValue>,
    /// When this tier was archived, if it is no longer sold.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub archived_at: Option<i64>,
}

/// A product's full entitlement catalog at one version.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Catalog {
    /// Product this catalog belongs to.
    pub product_id: String,
    /// Monotonic catalog version, recorded in every issued credential so a past resolution can
    /// be reproduced during a dispute (`licensing-model.md §8`).
    pub version: u32,
    /// All declared features.
    #[cfg_attr(feature = "serde", serde(default))]
    pub features: Vec<Feature>,
    /// All declared groups.
    #[cfg_attr(feature = "serde", serde(default))]
    pub groups: Vec<FeatureGroup>,
    /// All declared tiers.
    #[cfg_attr(feature = "serde", serde(default))]
    pub tiers: Vec<Tier>,
}

/// A structural problem with a catalog.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CatalogError {
    /// Two features, groups, or tiers share an identifier.
    DuplicateId(String),
    /// A group or tier references something that does not exist.
    UnknownReference {
        /// Where the dangling reference lives.
        from: String,
        /// What it points at.
        to: String,
    },
    /// Groups reference each other in a cycle.
    CyclicGroup(String),
    /// Group nesting exceeded the depth limit.
    DepthExceeded(String),
    /// A published feature identifier disappeared or changed.
    ///
    /// This is the immutability violation that would strand sealed assets.
    FeatureIdRemoved(String),
    /// A limit key disappeared, so clients would stop seeing it.
    LimitKeyRemoved(String),
    /// The catalog version did not increase.
    VersionNotAdvanced {
        /// Version of the existing catalog.
        previous: u32,
        /// Version proposed.
        proposed: u32,
    },
    /// A glob pattern was malformed.
    BadGlob(String),
}

impl core::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateId(id) => write!(f, "duplicate identifier `{id}`"),
            Self::UnknownReference { from, to } => {
                write!(f, "`{from}` references unknown `{to}`")
            }
            Self::CyclicGroup(id) => write!(f, "group `{id}` participates in a cycle"),
            Self::DepthExceeded(id) => write!(f, "group `{id}` nests deeper than the limit"),
            Self::FeatureIdRemoved(id) => write!(
                f,
                "feature `{id}` was published and cannot be renamed or removed; \
                 assets sealed under it would become unopenable"
            ),
            Self::LimitKeyRemoved(k) => write!(f, "limit key `{k}` was published and removed"),
            Self::VersionNotAdvanced { previous, proposed } => {
                write!(f, "catalog version must increase: {previous} -> {proposed}")
            }
            Self::BadGlob(p) => write!(f, "malformed glob pattern `{p}`"),
        }
    }
}

/// Maximum group nesting depth (`licensing-model.md §2.2`).
pub const MAX_GROUP_DEPTH: usize = 8;

impl Catalog {
    /// Look up a feature.
    #[must_use]
    pub fn feature(&self, id: &str) -> Option<&Feature> {
        self.features.iter().find(|f| f.id == id)
    }

    /// Look up a group.
    #[must_use]
    pub fn group(&self, id: &str) -> Option<&FeatureGroup> {
        self.groups.iter().find(|g| g.id == id)
    }

    /// Look up a tier.
    #[must_use]
    pub fn tier(&self, id: &str) -> Option<&Tier> {
        self.tiers.iter().find(|t| t.id == id)
    }

    /// Every declared feature identifier.
    #[must_use]
    pub fn feature_ids(&self) -> BTreeSet<String> {
        self.features.iter().map(|f| f.id.clone()).collect()
    }

    /// Expand a feature pattern into concrete identifiers.
    ///
    /// Supports a single trailing `*`. Anything else is rejected rather than interpreted, so a
    /// mistyped pattern fails loudly instead of silently granting nothing.
    pub fn expand_pattern(&self, pattern: &str) -> Result<Vec<String>, CatalogError> {
        let star_count = pattern.matches('*').count();
        match star_count {
            0 => {
                if self.feature(pattern).is_some() {
                    Ok(alloc::vec![pattern.to_string()])
                } else {
                    Err(CatalogError::UnknownReference {
                        from: "pattern".to_string(),
                        to: pattern.to_string(),
                    })
                }
            }
            1 if pattern.ends_with('*') => {
                let prefix = pattern.trim_end_matches('*');
                Ok(self
                    .features
                    .iter()
                    .filter(|f| f.id.starts_with(prefix))
                    .map(|f| f.id.clone())
                    .collect())
            }
            _ => Err(CatalogError::BadGlob(pattern.to_string())),
        }
    }

    /// Check that the catalog is structurally sound.
    ///
    /// Runs before any resolution, so that resolution itself can assume a well-formed graph and
    /// stay a simple traversal.
    pub fn validate(&self) -> Result<(), CatalogError> {
        // Duplicate identifiers.
        let mut seen = BTreeSet::new();
        for f in &self.features {
            if !seen.insert(f.id.clone()) {
                return Err(CatalogError::DuplicateId(f.id.clone()));
            }
        }
        let mut seen_groups = BTreeSet::new();
        for g in &self.groups {
            if !seen_groups.insert(g.id.clone()) {
                return Err(CatalogError::DuplicateId(g.id.clone()));
            }
        }
        let mut seen_tiers = BTreeSet::new();
        for t in &self.tiers {
            if !seen_tiers.insert(t.id.clone()) {
                return Err(CatalogError::DuplicateId(t.id.clone()));
            }
        }

        // References resolve.
        for g in &self.groups {
            for inc in &g.members.includes {
                if self.group(inc).is_none() {
                    return Err(CatalogError::UnknownReference {
                        from: g.id.clone(),
                        to: inc.clone(),
                    });
                }
            }
            for pat in &g.members.features {
                self.expand_pattern(pat).map_err(|e| match e {
                    CatalogError::UnknownReference { to, .. } => CatalogError::UnknownReference {
                        from: g.id.clone(),
                        to,
                    },
                    other => other,
                })?;
            }
        }
        for t in &self.tiers {
            for gid in &t.groups {
                if self.group(gid).is_none() {
                    return Err(CatalogError::UnknownReference {
                        from: t.id.clone(),
                        to: gid.clone(),
                    });
                }
            }
            for pat in &t.features {
                self.expand_pattern(pat).map_err(|e| match e {
                    CatalogError::UnknownReference { to, .. } => CatalogError::UnknownReference {
                        from: t.id.clone(),
                        to,
                    },
                    other => other,
                })?;
            }
        }

        // Cycles and depth. Checked explicitly rather than relying on recursion depth, so a
        // malicious or mistaken catalog produces an error instead of a stack overflow.
        for g in &self.groups {
            self.walk_group(&g.id, &mut Vec::new(), 0)?;
        }
        Ok(())
    }

    /// Depth-first walk detecting cycles and depth violations.
    fn walk_group(
        &self,
        id: &str,
        path: &mut Vec<String>,
        depth: usize,
    ) -> Result<(), CatalogError> {
        if path.iter().any(|p| p == id) {
            return Err(CatalogError::CyclicGroup(id.to_string()));
        }
        if depth > MAX_GROUP_DEPTH {
            return Err(CatalogError::DepthExceeded(id.to_string()));
        }
        let Some(g) = self.group(id) else {
            return Err(CatalogError::UnknownReference {
                from: path.last().cloned().unwrap_or_default(),
                to: id.to_string(),
            });
        };
        path.push(id.to_string());
        for inc in &g.members.includes {
            self.walk_group(inc, path, depth + 1)?;
        }
        path.pop();
        Ok(())
    }

    /// Check that a proposed catalog is a legal successor to this one.
    ///
    /// The immutability rules from `licensing-model.md §2.3`: feature identifiers and limit keys
    /// may never disappear, and the version must advance. Everything else — group membership,
    /// tier composition, limit *values*, labels — is free to change.
    pub fn validate_evolution(&self, proposed: &Catalog) -> Result<(), CatalogError> {
        proposed.validate()?;

        if proposed.version <= self.version {
            return Err(CatalogError::VersionNotAdvanced {
                previous: self.version,
                proposed: proposed.version,
            });
        }

        let new_ids = proposed.feature_ids();
        for f in &self.features {
            if !new_ids.contains(&f.id) {
                return Err(CatalogError::FeatureIdRemoved(f.id.clone()));
            }
        }

        let new_limit_keys: BTreeSet<&String> = proposed
            .tiers
            .iter()
            .flat_map(|t| t.limits.keys())
            .collect();
        for k in self.tiers.iter().flat_map(|t| t.limits.keys()) {
            if !new_limit_keys.contains(k) {
                return Err(CatalogError::LimitKeyRemoved(k.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    fn feature(id: &str) -> Feature {
        Feature {
            id: id.to_string(),
            label: id.to_string(),
            description: None,
            deprecated_at: None,
        }
    }

    /// The example catalog from `licensing-model.md §2.4`.
    pub(crate) fn sample() -> Catalog {
        Catalog {
            product_id: "acme".to_string(),
            version: 1,
            features: alloc::vec![
                feature("export.png"),
                feature("export.pdf"),
                feature("export.svg"),
                feature("ai.assist"),
                feature("render.4k"),
                feature("team.share"),
            ],
            groups: alloc::vec![
                FeatureGroup {
                    id: "export-basic".to_string(),
                    label: "Basic export".to_string(),
                    members: GroupMembers {
                        includes: alloc::vec![],
                        features: alloc::vec!["export.png".to_string()],
                    },
                },
                FeatureGroup {
                    id: "export-pro".to_string(),
                    label: "Pro export".to_string(),
                    members: GroupMembers {
                        includes: alloc::vec!["export-basic".to_string()],
                        features: alloc::vec!["export.pdf".to_string(), "export.svg".to_string()],
                    },
                },
                FeatureGroup {
                    id: "pro-suite".to_string(),
                    label: "Pro suite".to_string(),
                    members: GroupMembers {
                        includes: alloc::vec!["export-pro".to_string()],
                        features: alloc::vec!["ai.assist".to_string(), "render.4k".to_string()],
                    },
                },
            ],
            tiers: alloc::vec![
                Tier {
                    id: "free".to_string(),
                    label: "Free".to_string(),
                    rank: 0,
                    groups: alloc::vec!["export-basic".to_string()],
                    features: alloc::vec![],
                    limits: [("max_projects".to_string(), 3)].into_iter().collect(),
                    archived_at: None,
                },
                Tier {
                    id: "pro".to_string(),
                    label: "Pro".to_string(),
                    rank: 10,
                    groups: alloc::vec!["pro-suite".to_string()],
                    features: alloc::vec![],
                    limits: [("max_projects".to_string(), 100)].into_iter().collect(),
                    archived_at: None,
                },
                Tier {
                    id: "team".to_string(),
                    label: "Team".to_string(),
                    rank: 20,
                    groups: alloc::vec!["pro-suite".to_string()],
                    features: alloc::vec!["team.share".to_string()],
                    limits: [
                        ("max_projects".to_string(), -1),
                        ("max_members".to_string(), 25),
                    ]
                    .into_iter()
                    .collect(),
                    archived_at: None,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::sample;
    use super::*;

    #[test]
    fn the_reference_catalog_validates() {
        sample()
            .validate()
            .expect("reference catalog must be valid");
    }

    #[test]
    fn duplicate_feature_ids_are_rejected() {
        let mut c = sample();
        let dup = c.features[0].clone();
        c.features.push(dup);
        assert_eq!(
            c.validate(),
            Err(CatalogError::DuplicateId("export.png".to_string()))
        );
    }

    #[test]
    fn a_dangling_group_reference_is_rejected() {
        let mut c = sample();
        c.groups[0].members.includes.push("nope".to_string());
        assert_eq!(
            c.validate(),
            Err(CatalogError::UnknownReference {
                from: "export-basic".to_string(),
                to: "nope".to_string(),
            })
        );
    }

    #[test]
    fn a_dangling_feature_reference_is_rejected() {
        let mut c = sample();
        c.tiers[0].features.push("does.not.exist".to_string());
        assert!(matches!(
            c.validate(),
            Err(CatalogError::UnknownReference { .. })
        ));
    }

    #[test]
    fn mutual_group_references_are_detected_not_overflowed() {
        // The stack-overflow scenario from `licensing-model.md §12`.
        let mut c = sample();
        c.groups[0].members.includes.push("pro-suite".to_string());
        assert!(matches!(c.validate(), Err(CatalogError::CyclicGroup(_))));
    }

    #[test]
    fn self_reference_is_detected() {
        let mut c = sample();
        c.groups[0]
            .members
            .includes
            .push("export-basic".to_string());
        assert_eq!(
            c.validate(),
            Err(CatalogError::CyclicGroup("export-basic".to_string()))
        );
    }

    #[test]
    fn nesting_beyond_the_depth_limit_is_rejected() {
        let mut c = Catalog {
            product_id: "p".to_string(),
            version: 1,
            features: alloc::vec![],
            groups: alloc::vec![],
            tiers: alloc::vec![],
        };
        // A chain of MAX_GROUP_DEPTH + 3 groups, each including the next.
        let n = MAX_GROUP_DEPTH + 3;
        for i in 0..n {
            c.groups.push(FeatureGroup {
                id: alloc::format!("g{i}"),
                label: alloc::format!("g{i}"),
                members: GroupMembers {
                    includes: if i + 1 < n {
                        alloc::vec![alloc::format!("g{}", i + 1)]
                    } else {
                        alloc::vec![]
                    },
                    features: alloc::vec![],
                },
            });
        }
        assert!(matches!(c.validate(), Err(CatalogError::DepthExceeded(_))));
    }

    #[test]
    fn globs_expand_to_concrete_features() {
        let c = sample();
        let mut got = c.expand_pattern("export.*").unwrap();
        got.sort();
        assert_eq!(got, ["export.pdf", "export.png", "export.svg"]);
        assert_eq!(c.expand_pattern("export.pdf").unwrap(), ["export.pdf"]);
    }

    #[test]
    fn a_glob_matching_nothing_expands_to_nothing_rather_than_erroring() {
        // An empty expansion is legitimate: a group may anticipate features not yet added.
        assert!(sample().expand_pattern("future.*").unwrap().is_empty());
    }

    #[test]
    fn malformed_globs_are_rejected_rather_than_guessed_at() {
        let c = sample();
        assert!(matches!(
            c.expand_pattern("ex*port.*"),
            Err(CatalogError::BadGlob(_))
        ));
        assert!(matches!(
            c.expand_pattern("*.pdf"),
            Err(CatalogError::BadGlob(_))
        ));
    }

    #[test]
    fn removing_a_published_feature_is_blocked() {
        // The rule that keeps sealed assets openable. References are removed too, so the test
        // isolates the immutability rule rather than tripping the dangling-reference check.
        let old = sample();
        let mut new = sample();
        new.version = 2;
        new.features.retain(|f| f.id != "export.pdf");
        for g in &mut new.groups {
            g.members.features.retain(|f| f != "export.pdf");
        }
        assert_eq!(
            old.validate_evolution(&new),
            Err(CatalogError::FeatureIdRemoved("export.pdf".to_string()))
        );
    }

    #[test]
    fn removing_a_feature_that_is_still_referenced_reports_the_dangling_reference() {
        // Both problems are real; structural soundness is reported first because it is the one
        // that would break resolution outright.
        let old = sample();
        let mut new = sample();
        new.version = 2;
        new.features.retain(|f| f.id != "export.pdf");
        assert!(matches!(
            old.validate_evolution(&new),
            Err(CatalogError::UnknownReference { .. })
        ));
    }

    #[test]
    fn renaming_a_published_feature_is_blocked() {
        let old = sample();
        let mut new = sample();
        new.version = 2;
        new.features[1].id = "export.document".to_string();
        // Group references must be updated too, or validate() fails first; do that so the test
        // isolates the rename rule itself.
        for g in &mut new.groups {
            for f in &mut g.members.features {
                if f == "export.pdf" {
                    *f = "export.document".to_string();
                }
            }
        }
        assert_eq!(
            old.validate_evolution(&new),
            Err(CatalogError::FeatureIdRemoved("export.pdf".to_string()))
        );
    }

    #[test]
    fn adding_features_and_changing_composition_is_allowed() {
        let old = sample();
        let mut new = sample();
        new.version = 2;
        new.features.push(Feature {
            id: "export.webp".to_string(),
            label: "WebP".to_string(),
            description: None,
            deprecated_at: None,
        });
        new.groups[0]
            .members
            .features
            .push("export.webp".to_string());
        new.tiers[1].limits.insert("max_projects".to_string(), 500);
        new.tiers[0].label = "Starter".to_string();
        assert_eq!(old.validate_evolution(&new), Ok(()));
    }

    #[test]
    fn deprecating_a_feature_is_allowed() {
        let old = sample();
        let mut new = sample();
        new.version = 2;
        new.features[1].deprecated_at = Some(1_800_000_000);
        assert_eq!(old.validate_evolution(&new), Ok(()));
    }

    #[test]
    fn removing_a_limit_key_is_blocked() {
        let old = sample();
        let mut new = sample();
        new.version = 2;
        for t in &mut new.tiers {
            t.limits.remove("max_members");
        }
        assert_eq!(
            old.validate_evolution(&new),
            Err(CatalogError::LimitKeyRemoved("max_members".to_string()))
        );
    }

    #[test]
    fn the_version_must_advance() {
        let old = sample();
        let mut new = sample();
        new.version = 1;
        assert_eq!(
            old.validate_evolution(&new),
            Err(CatalogError::VersionNotAdvanced {
                previous: 1,
                proposed: 1
            })
        );
    }
}
