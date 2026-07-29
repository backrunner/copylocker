//! Release registry and version-scope enforcement (`licensing-model.md §4`, ADR-0008).
//!
//! # Where enforcement actually happens
//!
//! Not on the client. `client_info.release_id` is self-reported and forgeable. The real
//! enforcement is that a client outside its licensed version scope **does not receive that
//! release's wrapped KEKs** — and a client that lies about running an older release receives
//! the *old* variant's keys, which its actual binary cannot use, because its variant derives
//! different feature keys. The version cap is enforced by the variant mechanism, not by
//! believing the client (`licensing-model.md §4.2`).

use alloc::string::String;
use alloc::vec::Vec;

use copylocker_types::VersionScope;

/// Lifecycle status of a registered release.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ReleaseStatus {
    /// Supported.
    #[default]
    Active = 0,
    /// Still works, but users should upgrade.
    Deprecated = 1,
    /// Known broken open. Handled per `compromised_action`.
    Compromised = 2,
}

/// What to do about a compromised release.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CompromisedAction {
    /// Tell the user, keep working.
    #[default]
    Warn,
    /// Refuse to refresh until they upgrade.
    ForceUpgrade,
    /// Revoke outright.
    Revoke,
}

impl CompromisedAction {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::ForceUpgrade => "force_upgrade",
            Self::Revoke => "revoke",
        }
    }
}

/// One registered release (`data-model.md §7`).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Release {
    /// Release identifier.
    pub id: String,
    /// Product.
    pub product_id: String,
    /// Semantic version.
    pub app_version: String,
    /// Variant this release's builds derive keys for.
    pub variant_id: u64,
    /// Unique build fingerprint.
    pub build_fingerprint: String,
    /// Release channel.
    pub channel: String,
    /// Lifecycle status.
    pub status: ReleaseStatus,
    /// What to do if compromised.
    #[cfg_attr(feature = "serde", serde(default))]
    pub compromised_action: Option<CompromisedAction>,
    /// Publication time. **The authority for `ReleasedBefore`.**
    pub published_at: i64,
}

/// The release registry for a product.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReleaseRegistry {
    /// Registered releases.
    pub releases: Vec<Release>,
}

impl ReleaseRegistry {
    /// Look up a release.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Release> {
        self.releases.iter().find(|r| r.id == id)
    }

    /// The most recent release satisfying a scope, for the "you can still use N" message.
    #[must_use]
    pub fn highest_allowed(&self, scope: &VersionScope) -> Option<&Release> {
        self.releases
            .iter()
            .filter(|r| self.satisfies(r, scope))
            .max_by_key(|r| r.published_at)
    }

    fn satisfies(&self, release: &Release, scope: &VersionScope) -> bool {
        match scope {
            VersionScope::Unlimited => true,
            // `published_at <= cutoff`: inclusive, so a release published exactly at the cutoff
            // is covered. The boundary is chosen this way because a cutoff is normally derived
            // from a purchase instant, and the version on sale that instant must be included
            // (`licensing-model.md §4.1`).
            VersionScope::ReleasedBefore(cutoff) => release.published_at <= *cutoff,
            VersionScope::Pinned(ids) => ids.contains(&release.id),
            VersionScope::SemverRange(range) => semver_matches(&release.app_version, range),
        }
    }
}

/// What the server decided about a client's reported release.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VersionDecision {
    /// In scope; issue keys for this release's variant.
    InScope {
        /// The variant whose keys to issue.
        variant_id: u64,
    },
    /// The release is not registered at all.
    ///
    /// A build that skipped `copylocker release register` — a release-engineering mistake, and
    /// the error message says so rather than implying piracy (`protocol-spec.md §10.3`, 1007).
    NotRegistered,
    /// Registered but outside the licensed scope. Restricted mode, not a piracy signal.
    OutOfScope {
        /// Highest release the licence does cover.
        highest_allowed: Option<String>,
    },
    /// The release is marked compromised.
    Compromised {
        /// What to do about it.
        action: CompromisedAction,
    },
}

/// Decide what to do with a client's reported release.
///
/// Compromise is checked **before** scope: a build known to be broken open should be handled as
/// such regardless of whether the licence would otherwise cover it.
#[must_use]
pub fn decide(
    registry: &ReleaseRegistry,
    scope: &VersionScope,
    reported_release_id: &str,
) -> VersionDecision {
    let Some(release) = registry.get(reported_release_id) else {
        return VersionDecision::NotRegistered;
    };

    if release.status == ReleaseStatus::Compromised {
        return VersionDecision::Compromised {
            action: release.compromised_action.unwrap_or_default(),
        };
    }

    if registry.satisfies(release, scope) {
        VersionDecision::InScope {
            variant_id: release.variant_id,
        }
    } else {
        VersionDecision::OutOfScope {
            highest_allowed: registry.highest_allowed(scope).map(|r| r.id.clone()),
        }
    }
}

/// A parsed semantic version. Pre-release and build metadata are ignored for range matching.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct SemVer {
    major: u64,
    minor: u64,
    patch: u64,
}

fn parse_semver(s: &str) -> Option<SemVer> {
    // Strip pre-release and build metadata.
    let core = s.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.trim().parse().ok()?;
    let minor = parts.next().unwrap_or("0").trim().parse().unwrap_or(0);
    let patch = parts.next().unwrap_or("0").trim().parse().unwrap_or(0);
    if parts.next().is_some() {
        return None;
    }
    Some(SemVer {
        major,
        minor,
        patch,
    })
}

/// Evaluate a semver range expression.
///
/// Supports `^X.Y.Z`, `~X.Y.Z`, `>=`, `>`, `<=`, `<`, `=`, and space-separated conjunctions such
/// as `">=2.0 <4.0"`. An expression that cannot be parsed evaluates to **false** — a
/// mis-specified range must not silently grant everything.
///
/// `licensing-model.md §4.1` recommends `ReleasedBefore` over this precisely because the
/// semantics of a range are arguable; this exists for licences that already use one.
fn semver_matches(version: &str, range: &str) -> bool {
    let Some(v) = parse_semver(version) else {
        return false;
    };
    let range = range.trim();
    if range.is_empty() || range == "*" {
        return true;
    }
    range.split_whitespace().all(|term| match_term(v, term))
}

fn match_term(v: SemVer, term: &str) -> bool {
    let (op, rest) = if let Some(r) = term.strip_prefix(">=") {
        (">=", r)
    } else if let Some(r) = term.strip_prefix("<=") {
        ("<=", r)
    } else if let Some(r) = term.strip_prefix('>') {
        (">", r)
    } else if let Some(r) = term.strip_prefix('<') {
        ("<", r)
    } else if let Some(r) = term.strip_prefix('^') {
        ("^", r)
    } else if let Some(r) = term.strip_prefix('~') {
        ("~", r)
    } else if let Some(r) = term.strip_prefix('=') {
        ("=", r)
    } else {
        ("=", term)
    };

    let Some(b) = parse_semver(rest) else {
        return false;
    };

    match op {
        ">=" => v >= b,
        "<=" => v <= b,
        ">" => v > b,
        "<" => v < b,
        "=" => v == b,
        // Caret: compatible within the leftmost non-zero component.
        "^" => {
            if b.major > 0 {
                v.major == b.major && v >= b
            } else if b.minor > 0 {
                v.major == 0 && v.minor == b.minor && v >= b
            } else {
                v.major == 0 && v.minor == 0 && v.patch == b.patch
            }
        }
        // Tilde: patch-level changes within the stated minor.
        "~" => v.major == b.major && v.minor == b.minor && v >= b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    const JAN: i64 = 1_767_225_600; // 2026-01-01
    const JUN: i64 = 1_780_272_000; // 2026-06-01
    const DEC: i64 = 1_798_761_600; // 2026-12-31

    fn release(id: &str, version: &str, variant: u64, published: i64) -> Release {
        Release {
            id: id.to_string(),
            product_id: "acme".to_string(),
            app_version: version.to_string(),
            variant_id: variant,
            build_fingerprint: alloc::format!("bf-{id}"),
            channel: "stable".to_string(),
            status: ReleaseStatus::Active,
            compromised_action: None,
            published_at: published,
        }
    }

    fn registry() -> ReleaseRegistry {
        ReleaseRegistry {
            releases: alloc::vec![
                release("rel_1", "3.8.0", 1, JAN),
                release("rel_2", "3.9.0", 2, JUN),
                release("rel_3", "4.0.0", 3, DEC),
            ],
        }
    }

    #[test]
    fn unlimited_scope_accepts_every_registered_release() {
        for id in ["rel_1", "rel_2", "rel_3"] {
            assert!(matches!(
                decide(&registry(), &VersionScope::Unlimited, id),
                VersionDecision::InScope { .. }
            ));
        }
    }

    #[test]
    fn an_unregistered_release_is_reported_as_such() {
        // Distinct from "out of scope": this is a build that skipped registration.
        assert_eq!(
            decide(&registry(), &VersionScope::Unlimited, "rel_unknown"),
            VersionDecision::NotRegistered
        );
    }

    #[test]
    fn released_before_includes_the_boundary_release() {
        // A cutoff derived from a purchase instant must include the version on sale then.
        let scope = VersionScope::ReleasedBefore(JUN);
        assert!(matches!(
            decide(&registry(), &scope, "rel_2"),
            VersionDecision::InScope { .. }
        ));
        assert!(matches!(
            decide(&registry(), &scope, "rel_1"),
            VersionDecision::InScope { .. }
        ));
        assert!(matches!(
            decide(&registry(), &scope, "rel_3"),
            VersionDecision::OutOfScope { .. }
        ));
    }

    #[test]
    fn out_of_scope_names_the_highest_usable_release() {
        // Powers the "you can keep using 3.9" message rather than a bare failure.
        let scope = VersionScope::ReleasedBefore(JUN);
        assert_eq!(
            decide(&registry(), &scope, "rel_3"),
            VersionDecision::OutOfScope {
                highest_allowed: Some("rel_2".to_string())
            }
        );
    }

    #[test]
    fn a_scope_covering_nothing_reports_no_alternative() {
        let scope = VersionScope::ReleasedBefore(JAN - 1);
        assert_eq!(
            decide(&registry(), &scope, "rel_1"),
            VersionDecision::OutOfScope {
                highest_allowed: None
            }
        );
    }

    #[test]
    fn pinned_scope_accepts_only_the_listed_releases() {
        let scope = VersionScope::Pinned(alloc::vec!["rel_2".to_string()]);
        assert!(matches!(
            decide(&registry(), &scope, "rel_2"),
            VersionDecision::InScope { variant_id: 2 }
        ));
        assert!(matches!(
            decide(&registry(), &scope, "rel_1"),
            VersionDecision::OutOfScope { .. }
        ));
    }

    #[test]
    fn in_scope_reports_the_variant_to_issue_keys_for() {
        assert_eq!(
            decide(&registry(), &VersionScope::Unlimited, "rel_2"),
            VersionDecision::InScope { variant_id: 2 }
        );
    }

    #[test]
    fn a_compromised_release_is_handled_before_scope_is_considered() {
        let mut r = registry();
        r.releases[1].status = ReleaseStatus::Compromised;
        r.releases[1].compromised_action = Some(CompromisedAction::ForceUpgrade);
        // Even under an unlimited scope, compromise wins.
        assert_eq!(
            decide(&r, &VersionScope::Unlimited, "rel_2"),
            VersionDecision::Compromised {
                action: CompromisedAction::ForceUpgrade
            }
        );
    }

    #[test]
    fn a_compromised_release_without_an_action_defaults_to_warn() {
        let mut r = registry();
        r.releases[0].status = ReleaseStatus::Compromised;
        assert_eq!(
            decide(&r, &VersionScope::Unlimited, "rel_1"),
            VersionDecision::Compromised {
                action: CompromisedAction::Warn
            }
        );
    }

    #[test]
    fn a_deprecated_release_still_works() {
        let mut r = registry();
        r.releases[0].status = ReleaseStatus::Deprecated;
        assert!(matches!(
            decide(&r, &VersionScope::Unlimited, "rel_1"),
            VersionDecision::InScope { .. }
        ));
    }

    #[test]
    fn lying_about_the_release_yields_the_wrong_variant() {
        // The mechanism that makes the self-reported release_id harmless: claiming rel_1 gets
        // variant 1's keys, which a binary built as variant 3 cannot use.
        let honest = decide(&registry(), &VersionScope::Unlimited, "rel_3");
        let lie = decide(&registry(), &VersionScope::Unlimited, "rel_1");
        assert_eq!(honest, VersionDecision::InScope { variant_id: 3 });
        assert_eq!(lie, VersionDecision::InScope { variant_id: 1 });
        assert_ne!(honest, lie);
    }

    #[test]
    fn caret_ranges_stay_within_the_major_version() {
        assert!(semver_matches("3.9.0", "^3"));
        assert!(semver_matches("3.0.0", "^3"));
        assert!(!semver_matches("4.0.0", "^3"));
        assert!(!semver_matches("2.9.0", "^3"));
        assert!(semver_matches("3.2.1", "^3.2.0"));
        assert!(!semver_matches("3.1.9", "^3.2.0"));
    }

    #[test]
    fn tilde_ranges_stay_within_the_minor_version() {
        assert!(semver_matches("3.2.5", "~3.2.0"));
        assert!(!semver_matches("3.3.0", "~3.2.0"));
    }

    #[test]
    fn conjunctions_require_every_term() {
        assert!(semver_matches("3.0.0", ">=2.0 <4.0"));
        assert!(!semver_matches("4.0.0", ">=2.0 <4.0"));
        assert!(!semver_matches("1.9.0", ">=2.0 <4.0"));
    }

    #[test]
    fn prerelease_and_build_metadata_are_ignored_for_matching() {
        assert!(semver_matches("3.9.0-beta.1", "^3"));
        assert!(semver_matches("3.9.0+build.7", "^3"));
    }

    #[test]
    fn an_unparseable_range_or_version_denies_rather_than_grants() {
        // Fail closed: a typo in a range must not become "everything is licensed".
        assert!(!semver_matches("3.0.0", "not-a-range"));
        assert!(!semver_matches("not-a-version", "^3"));
        assert!(!semver_matches("3.0.0.0", "^3"));
    }

    #[test]
    fn an_empty_or_star_range_matches_everything() {
        assert!(semver_matches("3.0.0", ""));
        assert!(semver_matches("9.9.9", "*"));
    }

    #[test]
    fn semver_ranges_route_through_the_decision_function() {
        let scope = VersionScope::SemverRange("^3".to_string());
        assert!(matches!(
            decide(&registry(), &scope, "rel_2"),
            VersionDecision::InScope { .. }
        ));
        assert!(matches!(
            decide(&registry(), &scope, "rel_3"),
            VersionDecision::OutOfScope { .. }
        ));
    }

    #[test]
    fn compromised_action_names_match_the_wire() {
        assert_eq!(CompromisedAction::Warn.as_str(), "warn");
        assert_eq!(CompromisedAction::ForceUpgrade.as_str(), "force_upgrade");
        assert_eq!(CompromisedAction::Revoke.as_str(), "revoke");
    }
}
