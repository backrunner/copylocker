//! The five-axis policy model (`licensing-model.md §1`, ADR-0009).
//!
//! ```text
//! Policy = Entitlement × Validity × VersionScope × Seats × Mode
//! ```
//!
//! Commercial shapes — trial, perpetual, subscription, version-capped — are **combinations of
//! these axes, not variants of an enum**. A "perpetual licence capped to versions released
//! before a date, one seat, offline-capable" is not a special case needing new code; it is a
//! point in this space.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub use copylocker_types::Mode;
use copylocker_types::VersionScope;

use crate::entitlement::EntitlementSpec;

/// Axis two: how long the licence lasts (`licensing-model.md §3`).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub enum Validity {
    /// Never expires.
    Perpetual,
    /// A fixed term from activation.
    FixedTerm {
        /// Duration in seconds.
        duration_secs: i64,
    },
    /// A recurring subscription.
    Subscription {
        /// Billing period in seconds.
        period_secs: i64,
        /// Grace after a failed payment, during which the app keeps working.
        dunning_grace_secs: i64,
        /// Perpetual fallback terms, if offered.
        #[cfg_attr(feature = "serde", serde(default))]
        fallback: Option<PerpetualFallback>,
    },
    /// A time-limited trial.
    Trial {
        /// Duration in seconds.
        duration_secs: i64,
        /// What a trial is counted against.
        once_per: TrialScope,
        /// Maximum manual extension support may grant.
        #[cfg_attr(feature = "serde", serde(default))]
        extendable_by_secs: Option<i64>,
    },
}

/// What a trial is deduplicated against (`licensing-model.md §3.3`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub enum TrialScope {
    /// One trial per device fingerprint, matched with tolerance so swapping a network card does
    /// not reset it.
    Fingerprint,
    /// One trial per account.
    Account,
    /// One trial per verified email address.
    Email,
}

/// Terms under which a subscription converts to a perpetual licence
/// (`licensing-model.md §5`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct PerpetualFallback {
    /// Consecutive paid months required.
    pub after_months: u32,
    /// What the resulting version cap is measured from.
    pub scope_at: FallbackScopeAt,
}

/// Where the perpetual fallback's version cap is anchored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub enum FallbackScopeAt {
    /// The instant the fallback was earned. The JetBrains-style model.
    EarnedAt,
    /// When the subscription started.
    SubscriptionStart,
}

/// Axis four: seats and transfers.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct SeatSpec {
    /// Concurrent activations allowed.
    pub seats: u32,
    /// Maximum machine transfers within the window, if capped.
    #[cfg_attr(feature = "serde", serde(default))]
    pub max_transfers: Option<u32>,
    /// Length of the transfer window in seconds.
    #[cfg_attr(feature = "serde", serde(default))]
    pub transfer_window_secs: Option<i64>,
    /// Heartbeat interval enabling zombie-seat recovery. `None` disables it.
    #[cfg_attr(feature = "serde", serde(default))]
    pub heartbeat_secs: Option<i64>,
}

impl Default for SeatSpec {
    fn default() -> Self {
        Self {
            seats: 1,
            max_transfers: None,
            transfer_window_secs: None,
            heartbeat_secs: None,
        }
    }
}

/// Runtime tuning that ends up in every credential.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct RuntimeSpec {
    /// How long a credential is good for before an online check is due.
    pub refresh_after_secs: i64,
    /// Extra offline time granted when the network is unavailable at refresh time.
    pub grace_secs: u32,
    /// Minimum fingerprint similarity, `0..=100`, for reusing an activation.
    pub fpr_tolerance: u8,
    /// Whether activation inside a virtual machine is permitted.
    pub allow_vm: bool,
    /// Whether offline licence keys may be issued at all.
    pub allow_olk: bool,
    /// Whether an offline licence key may omit a device binding.
    ///
    /// Defaults to `false`: an unbound key can be copied without limit, and there is no server
    /// in the loop to notice (`protocol-spec.md §8`).
    pub allow_unbound_olk: bool,
    /// `fast` for per-request Ed25519, `pq` to force the hybrid on every ticket.
    pub vt_signature: VtSignature,
    /// How offline clients handle a variant change.
    pub offline_upgrade_policy: OfflineUpgradePolicy,
    /// How many variants of keys to pre-load under `preload_n`.
    pub preload_variants_n: u32,
    /// Whether raw device attributes may be reported, enabling tolerance matching.
    pub report_attrs: bool,
}

/// Which signature protects a validation ticket.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub enum VtSignature {
    /// Ed25519, certified by the PQ-signed epoch certificate. The default
    /// (`protocol-spec.md §5`).
    #[default]
    Fast,
    /// The full PQ hybrid, at roughly 3.3 KB extra per response.
    Pq,
}

/// What an offline client does when its variant is superseded.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub enum OfflineUpgradePolicy {
    /// Require an online check before the new build works.
    #[default]
    RequireOnline,
    /// Pre-issue keys for the next N variants.
    PreloadN,
    /// Keep the variant stable across releases.
    VariantStable,
}

impl Default for RuntimeSpec {
    fn default() -> Self {
        Self {
            refresh_after_secs: 7 * 86_400,
            grace_secs: 14 * 86_400,
            fpr_tolerance: 70,
            allow_vm: true,
            allow_olk: false,
            allow_unbound_olk: false,
            vt_signature: VtSignature::Fast,
            offline_upgrade_policy: OfflineUpgradePolicy::RequireOnline,
            preload_variants_n: 3,
            report_attrs: false,
        }
    }
}

/// A complete policy: one point in the five-axis space.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct Policy {
    /// Policy identifier.
    pub id: String,
    /// Product this policy belongs to.
    pub product_id: String,
    /// Display name.
    pub name: String,
    /// Which preset generated it, for the console's UI.
    #[cfg_attr(feature = "serde", serde(default))]
    pub preset: Option<String>,
    /// Axis one.
    pub entitlement: EntitlementSpec,
    /// Axis two.
    pub validity: Validity,
    /// Axis three.
    pub version_scope: VersionScope,
    /// Axis four.
    pub seats: SeatSpec,
    /// Axis five.
    pub mode: Mode,
    /// Runtime tuning.
    pub runtime: RuntimeSpec,
}

/// A configuration that is legal but likely a mistake.
///
/// These are warnings, not errors: an operator who really wants a ten-year refresh interval may
/// have it, but should be told what they are giving up (`licensing-model.md §11`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PolicyWarning {
    /// Stable identifier for the warning.
    pub id: &'static str,
    /// What is risky and why.
    pub message: String,
}

/// A configuration that cannot work at all.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PolicyDefect {
    /// Seats must be at least one.
    ZeroSeats,
    /// A duration was zero or negative.
    NonPositiveDuration(&'static str),
    /// Tolerance is a percentage.
    ToleranceOutOfRange(u8),
    /// A trial with more than one seat invites rotation abuse
    /// (`licensing-model.md §6`).
    TrialWithMultipleSeats(u32),
    /// Unbound offline keys were allowed without allowing offline keys at all.
    UnboundOlkWithoutOlk,
}

impl core::fmt::Display for PolicyDefect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroSeats => f.write_str("seats must be at least 1"),
            Self::NonPositiveDuration(w) => write!(f, "{w} must be positive"),
            Self::ToleranceOutOfRange(v) => {
                write!(f, "fingerprint tolerance {v} is outside 0..=100")
            }
            Self::TrialWithMultipleSeats(n) => write!(
                f,
                "a trial must be single-seat, got {n}: multiple seats enable trial rotation"
            ),
            Self::UnboundOlkWithoutOlk => f.write_str("allow_unbound_olk requires allow_olk"),
        }
    }
}

impl Policy {
    /// Reject configurations that cannot work.
    pub fn validate(&self) -> Result<(), PolicyDefect> {
        if self.seats.seats == 0 {
            return Err(PolicyDefect::ZeroSeats);
        }
        if self.runtime.fpr_tolerance > 100 {
            return Err(PolicyDefect::ToleranceOutOfRange(
                self.runtime.fpr_tolerance,
            ));
        }
        if self.runtime.refresh_after_secs <= 0 {
            return Err(PolicyDefect::NonPositiveDuration("refresh_after_secs"));
        }
        if self.runtime.allow_unbound_olk && !self.runtime.allow_olk {
            return Err(PolicyDefect::UnboundOlkWithoutOlk);
        }
        match &self.validity {
            Validity::FixedTerm { duration_secs } if *duration_secs <= 0 => {
                return Err(PolicyDefect::NonPositiveDuration("duration_secs"));
            }
            Validity::Subscription { period_secs, .. } if *period_secs <= 0 => {
                return Err(PolicyDefect::NonPositiveDuration("period_secs"));
            }
            Validity::Trial { duration_secs, .. } => {
                if *duration_secs <= 0 {
                    return Err(PolicyDefect::NonPositiveDuration("duration_secs"));
                }
                if self.seats.seats != 1 {
                    return Err(PolicyDefect::TrialWithMultipleSeats(self.seats.seats));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Surface risky-but-legal configurations.
    #[must_use]
    pub fn warnings(&self) -> Vec<PolicyWarning> {
        let mut out = Vec::new();

        // The exposure window after an epoch key compromise is refresh + grace
        // (`crypto-architecture.md §5.3`), so a long refresh directly lengthens it.
        let exposure = self.runtime.refresh_after_secs + i64::from(self.runtime.grace_secs);
        if exposure > 90 * 86_400 {
            out.push(PolicyWarning {
                id: "long_exposure_window",
                message: alloc::format!(
                    "refresh_after + grace is {} days; a revoked credential stays usable that \
                     long, and so does a leaked epoch key",
                    exposure / 86_400
                ),
            });
        }

        // A cancellation cannot propagate faster than the refresh interval.
        if let Validity::Subscription { period_secs, .. } = self.validity {
            if self.runtime.refresh_after_secs > period_secs / 4 {
                out.push(PolicyWarning {
                    id: "refresh_slower_than_billing",
                    message: alloc::format!(
                        "refresh_after ({}d) exceeds a quarter of the billing period ({}d); \
                         cancellations will propagate late",
                        self.runtime.refresh_after_secs / 86_400,
                        period_secs / 86_400
                    ),
                });
            }
        }

        // Perpetual + enforced-online means the vendor has promised to run the server forever
        // (`licensing-model.md §6`).
        if matches!(self.validity, Validity::Perpetual) && self.mode == Mode::EnforcedOnline {
            out.push(PolicyWarning {
                id: "perpetual_requires_forever_server",
                message:
                    "a perpetual licence in enforced-online mode stops working if the licence \
                     server is ever shut down"
                        .to_string(),
            });
        }

        if self.runtime.allow_unbound_olk {
            out.push(PolicyWarning {
                id: "unbound_olk_copyable",
                message: "offline keys without a device binding can be copied without limit"
                    .to_string(),
            });
        }

        if self.runtime.grace_secs == 0 && self.mode == Mode::OfflineHybrid {
            out.push(PolicyWarning {
                id: "no_grace_in_offline_mode",
                message:
                    "grace is zero, so a brief network outage at refresh time locks the user out"
                        .to_string(),
            });
        }

        if self.runtime.fpr_tolerance == 100 {
            out.push(PolicyWarning {
                id: "zero_fingerprint_tolerance",
                message:
                    "a tolerance of 100 requires an exact fingerprint match; ordinary hardware \
                     changes will cost users their seat"
                        .to_string(),
            });
        }

        out
    }

    /// The hard expiry a credential should carry, given when the term started.
    ///
    /// For subscriptions this is `current_period_end + dunning_grace`, **not**
    /// `current_period_end`. Payment settlement is not instantaneous; setting the hard expiry to
    /// the period end locks out a cohort of paying customers every cycle — the most common
    /// self-inflicted wound in subscription software (`licensing-model.md §3.1`).
    #[must_use]
    pub fn expires_at(&self, term_start: i64) -> Option<i64> {
        match &self.validity {
            Validity::Perpetual => None,
            Validity::FixedTerm { duration_secs } => {
                Some(term_start.saturating_add(*duration_secs))
            }
            Validity::Subscription {
                period_secs,
                dunning_grace_secs,
                ..
            } => Some(
                term_start
                    .saturating_add(*period_secs)
                    .saturating_add(*dunning_grace_secs),
            ),
            Validity::Trial { duration_secs, .. } => {
                Some(term_start.saturating_add(*duration_secs))
            }
        }
    }
}

/// Named starting points for common commercial shapes (`licensing-model.md §10`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Preset {
    /// 14-day trial, one seat, one per fingerprint.
    Trial14d,
    /// Perpetual, all versions. The most permissive; use sparingly.
    Perpetual,
    /// Perpetual within one major version.
    PerpetualMajor,
    /// Perpetual with a one-year version cap. The mainstream buy-once model.
    PerpetualFallback,
    /// Monthly subscription.
    SubMonthly,
    /// Annual subscription.
    SubAnnual,
    /// Annual subscription that converts to perpetual after 12 paid months.
    SubAnnualFallback,
    /// 25-seat annual team subscription with heartbeat reclamation.
    TeamSub,
    /// One-year air-gapped enterprise licence with pinned versions.
    ///
    /// This preset intentionally trips the `long_exposure_window` warning: a machine that never
    /// reaches the network cannot revalidate, so a long refresh interval is the whole point.
    /// The warning is still worth emitting, because the operator is accepting a real cost — a
    /// revoked credential stays usable for up to that window.
    EnterpriseAirgap,
    /// Monthly, enforced-online, three seats.
    SaasClient,
    /// One-year educational licence.
    Edu1y,
}

const DAY: i64 = 86_400;
const YEAR: i64 = 365 * DAY;

impl Preset {
    /// Every preset, for exhaustive tests and CLI listings.
    pub const ALL: [Self; 11] = [
        Self::Trial14d,
        Self::Perpetual,
        Self::PerpetualMajor,
        Self::PerpetualFallback,
        Self::SubMonthly,
        Self::SubAnnual,
        Self::SubAnnualFallback,
        Self::TeamSub,
        Self::EnterpriseAirgap,
        Self::SaasClient,
        Self::Edu1y,
    ];

    /// CLI name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trial14d => "trial-14d",
            Self::Perpetual => "perpetual",
            Self::PerpetualMajor => "perpetual-major",
            Self::PerpetualFallback => "perpetual-fallback",
            Self::SubMonthly => "sub-monthly",
            Self::SubAnnual => "sub-annual",
            Self::SubAnnualFallback => "sub-annual-fallback",
            Self::TeamSub => "team-sub",
            Self::EnterpriseAirgap => "enterprise-airgap",
            Self::SaasClient => "saas-client",
            Self::Edu1y => "edu-1y",
        }
    }

    /// Parse a CLI name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }

    /// Build a policy from this preset.
    ///
    /// The result is a **starting point**, not a finished configuration; every field is meant to
    /// be edited afterwards.
    #[must_use]
    pub fn build(self, id: &str, product_id: &str, tier: &str, now: i64) -> Policy {
        let entitlement = EntitlementSpec {
            tier: tier.to_string(),
            ..Default::default()
        };
        let base = Policy {
            id: id.to_string(),
            product_id: product_id.to_string(),
            name: self.as_str().to_string(),
            preset: Some(self.as_str().to_string()),
            entitlement,
            validity: Validity::Perpetual,
            version_scope: VersionScope::Unlimited,
            seats: SeatSpec::default(),
            mode: Mode::OfflineHybrid,
            runtime: RuntimeSpec::default(),
        };

        match self {
            Self::Trial14d => Policy {
                validity: Validity::Trial {
                    duration_secs: 14 * DAY,
                    once_per: TrialScope::Fingerprint,
                    extendable_by_secs: Some(14 * DAY),
                },
                runtime: RuntimeSpec {
                    refresh_after_secs: DAY,
                    grace_secs: (3 * DAY) as u32,
                    ..RuntimeSpec::default()
                },
                ..base
            },
            Self::Perpetual => base,
            Self::PerpetualMajor => Policy {
                version_scope: VersionScope::SemverRange("^1".to_string()),
                ..base
            },
            Self::PerpetualFallback => Policy {
                version_scope: VersionScope::ReleasedBefore(now.saturating_add(YEAR)),
                ..base
            },
            Self::SubMonthly => Policy {
                validity: Validity::Subscription {
                    period_secs: 30 * DAY,
                    dunning_grace_secs: 7 * DAY,
                    fallback: None,
                },
                runtime: RuntimeSpec {
                    // A quarter of the billing period, so a cancellation lands promptly.
                    refresh_after_secs: 7 * DAY,
                    grace_secs: (7 * DAY) as u32,
                    ..RuntimeSpec::default()
                },
                ..base
            },
            Self::SubAnnual => Policy {
                validity: Validity::Subscription {
                    period_secs: YEAR,
                    dunning_grace_secs: 14 * DAY,
                    fallback: None,
                },
                runtime: RuntimeSpec {
                    refresh_after_secs: 30 * DAY,
                    grace_secs: (14 * DAY) as u32,
                    ..RuntimeSpec::default()
                },
                ..base
            },
            Self::SubAnnualFallback => Policy {
                validity: Validity::Subscription {
                    period_secs: YEAR,
                    dunning_grace_secs: 14 * DAY,
                    fallback: Some(PerpetualFallback {
                        after_months: 12,
                        scope_at: FallbackScopeAt::EarnedAt,
                    }),
                },
                runtime: RuntimeSpec {
                    refresh_after_secs: 30 * DAY,
                    grace_secs: (14 * DAY) as u32,
                    ..RuntimeSpec::default()
                },
                ..base
            },
            Self::TeamSub => Policy {
                validity: Validity::Subscription {
                    period_secs: YEAR,
                    dunning_grace_secs: 14 * DAY,
                    fallback: None,
                },
                seats: SeatSpec {
                    seats: 25,
                    heartbeat_secs: Some(6 * 3_600),
                    ..SeatSpec::default()
                },
                runtime: RuntimeSpec {
                    refresh_after_secs: 30 * DAY,
                    grace_secs: (14 * DAY) as u32,
                    ..RuntimeSpec::default()
                },
                ..base
            },
            Self::EnterpriseAirgap => Policy {
                validity: Validity::FixedTerm {
                    duration_secs: YEAR,
                },
                version_scope: VersionScope::Pinned(Vec::new()),
                seats: SeatSpec {
                    seats: 50,
                    ..SeatSpec::default()
                },
                runtime: RuntimeSpec {
                    refresh_after_secs: 180 * DAY,
                    grace_secs: (30 * DAY) as u32,
                    allow_olk: true,
                    offline_upgrade_policy: OfflineUpgradePolicy::PreloadN,
                    ..RuntimeSpec::default()
                },
                ..base
            },
            Self::SaasClient => Policy {
                validity: Validity::Subscription {
                    period_secs: 30 * DAY,
                    dunning_grace_secs: 7 * DAY,
                    fallback: None,
                },
                seats: SeatSpec {
                    seats: 3,
                    heartbeat_secs: Some(3_600),
                    ..SeatSpec::default()
                },
                mode: Mode::EnforcedOnline,
                runtime: RuntimeSpec {
                    refresh_after_secs: 3_600,
                    grace_secs: 3_600,
                    ..RuntimeSpec::default()
                },
                ..base
            },
            Self::Edu1y => Policy {
                validity: Validity::FixedTerm {
                    duration_secs: YEAR,
                },
                runtime: RuntimeSpec {
                    refresh_after_secs: 30 * DAY,
                    grace_secs: (14 * DAY) as u32,
                    ..RuntimeSpec::default()
                },
                ..base
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn policy(preset: Preset) -> Policy {
        preset.build("p1", "acme", "pro", NOW)
    }

    #[test]
    fn every_preset_produces_a_valid_policy() {
        for p in Preset::ALL {
            let pol = policy(p);
            assert_eq!(pol.validate(), Ok(()), "preset {} is invalid", p.as_str());
        }
    }

    #[test]
    fn preset_names_roundtrip() {
        for p in Preset::ALL {
            assert_eq!(Preset::parse(p.as_str()), Some(p));
        }
        assert_eq!(Preset::parse("nope"), None);
    }

    #[test]
    fn presets_match_the_specification_table() {
        assert!(matches!(
            policy(Preset::Trial14d).validity,
            Validity::Trial {
                duration_secs,
                once_per: TrialScope::Fingerprint,
                ..
            } if duration_secs == 14 * DAY
        ));
        assert_eq!(policy(Preset::Trial14d).seats.seats, 1);
        assert_eq!(policy(Preset::TeamSub).seats.seats, 25);
        assert!(policy(Preset::TeamSub).seats.heartbeat_secs.is_some());
        assert_eq!(policy(Preset::SaasClient).mode, Mode::EnforcedOnline);
        assert_eq!(policy(Preset::SaasClient).seats.seats, 3);
        assert!(policy(Preset::EnterpriseAirgap).runtime.allow_olk);
        assert_eq!(
            policy(Preset::EnterpriseAirgap)
                .runtime
                .offline_upgrade_policy,
            OfflineUpgradePolicy::PreloadN
        );
        assert!(matches!(
            policy(Preset::PerpetualFallback).version_scope,
            VersionScope::ReleasedBefore(t) if t == NOW + YEAR
        ));
        assert!(matches!(
            policy(Preset::SubAnnualFallback).validity,
            Validity::Subscription {
                fallback: Some(PerpetualFallback {
                    after_months: 12,
                    ..
                }),
                ..
            }
        ));
    }

    #[test]
    fn subscription_expiry_includes_the_dunning_window() {
        // The self-inflicted-lockout guard: expiry is period_end + dunning, never period_end.
        let p = policy(Preset::SubMonthly);
        let Validity::Subscription {
            period_secs,
            dunning_grace_secs,
            ..
        } = p.validity
        else {
            unreachable!()
        };
        assert_eq!(
            p.expires_at(NOW),
            Some(NOW + period_secs + dunning_grace_secs)
        );
        assert!(p.expires_at(NOW).unwrap() > NOW + period_secs);
    }

    #[test]
    fn perpetual_has_no_expiry() {
        assert_eq!(policy(Preset::Perpetual).expires_at(NOW), None);
    }

    #[test]
    fn expiry_saturates_rather_than_overflowing() {
        let p = policy(Preset::SubAnnual);
        assert_eq!(p.expires_at(i64::MAX), Some(i64::MAX));
    }

    #[test]
    fn subscription_presets_refresh_at_least_four_times_per_period() {
        // Guarantees a cancellation propagates within a quarter of the billing period.
        for preset in [
            Preset::SubMonthly,
            Preset::SubAnnual,
            Preset::SubAnnualFallback,
            Preset::TeamSub,
            Preset::SaasClient,
        ] {
            let p = policy(preset);
            let Validity::Subscription { period_secs, .. } = p.validity else {
                unreachable!()
            };
            assert!(
                p.runtime.refresh_after_secs <= period_secs / 4,
                "{} refreshes too slowly",
                preset.as_str()
            );
        }
    }

    #[test]
    fn only_the_airgap_preset_warns_and_only_about_its_inherent_tradeoff() {
        // A shipped preset that warns is normally a bug in one or the other. The air-gapped
        // preset is the documented exception: a machine that cannot reach the network cannot
        // revalidate, so the long exposure window is the trade being made, not a mistake.
        for p in Preset::ALL {
            let ids: Vec<&str> = policy(p).warnings().into_iter().map(|w| w.id).collect();
            match p {
                Preset::EnterpriseAirgap => {
                    assert_eq!(
                        ids,
                        ["long_exposure_window"],
                        "the airgap preset should warn about exactly one thing"
                    );
                }
                other => assert!(
                    ids.is_empty(),
                    "preset {} warns unexpectedly: {ids:?}",
                    other.as_str()
                ),
            }
        }
    }

    #[test]
    fn zero_seats_is_rejected() {
        let mut p = policy(Preset::Perpetual);
        p.seats.seats = 0;
        assert_eq!(p.validate(), Err(PolicyDefect::ZeroSeats));
    }

    #[test]
    fn a_multi_seat_trial_is_rejected() {
        // Multiple seats on a trial is trial rotation with extra steps.
        let mut p = policy(Preset::Trial14d);
        p.seats.seats = 5;
        assert_eq!(p.validate(), Err(PolicyDefect::TrialWithMultipleSeats(5)));
    }

    #[test]
    fn out_of_range_tolerance_is_rejected() {
        let mut p = policy(Preset::Perpetual);
        p.runtime.fpr_tolerance = 101;
        assert_eq!(p.validate(), Err(PolicyDefect::ToleranceOutOfRange(101)));
    }

    #[test]
    fn unbound_offline_keys_require_offline_keys() {
        let mut p = policy(Preset::Perpetual);
        p.runtime.allow_unbound_olk = true;
        p.runtime.allow_olk = false;
        assert_eq!(p.validate(), Err(PolicyDefect::UnboundOlkWithoutOlk));
    }

    #[test]
    fn non_positive_durations_are_rejected() {
        let mut p = policy(Preset::Edu1y);
        p.validity = Validity::FixedTerm { duration_secs: 0 };
        assert_eq!(
            p.validate(),
            Err(PolicyDefect::NonPositiveDuration("duration_secs"))
        );

        let mut p = policy(Preset::Perpetual);
        p.runtime.refresh_after_secs = -1;
        assert_eq!(
            p.validate(),
            Err(PolicyDefect::NonPositiveDuration("refresh_after_secs"))
        );
    }

    #[test]
    fn a_long_exposure_window_warns() {
        let mut p = policy(Preset::Perpetual);
        p.runtime.refresh_after_secs = 200 * DAY;
        let ids: Vec<_> = p.warnings().into_iter().map(|w| w.id).collect();
        assert!(ids.contains(&"long_exposure_window"));
    }

    #[test]
    fn a_slow_refresh_on_a_subscription_warns() {
        let mut p = policy(Preset::SubMonthly);
        p.runtime.refresh_after_secs = 29 * DAY;
        let ids: Vec<_> = p.warnings().into_iter().map(|w| w.id).collect();
        assert!(ids.contains(&"refresh_slower_than_billing"));
    }

    #[test]
    fn perpetual_plus_enforced_online_warns() {
        let mut p = policy(Preset::Perpetual);
        p.mode = Mode::EnforcedOnline;
        let ids: Vec<_> = p.warnings().into_iter().map(|w| w.id).collect();
        assert!(ids.contains(&"perpetual_requires_forever_server"));
    }

    #[test]
    fn zero_grace_in_offline_mode_warns() {
        let mut p = policy(Preset::Perpetual);
        p.runtime.grace_secs = 0;
        let ids: Vec<_> = p.warnings().into_iter().map(|w| w.id).collect();
        assert!(ids.contains(&"no_grace_in_offline_mode"));
    }

    #[test]
    fn exact_fingerprint_matching_warns() {
        let mut p = policy(Preset::Perpetual);
        p.runtime.fpr_tolerance = 100;
        let ids: Vec<_> = p.warnings().into_iter().map(|w| w.id).collect();
        assert!(ids.contains(&"zero_fingerprint_tolerance"));
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let r = RuntimeSpec::default();
        assert_eq!(r.fpr_tolerance, 70);
        assert!(r.allow_vm);
        assert!(!r.allow_olk);
        assert!(!r.allow_unbound_olk, "unbound keys are copyable");
        assert!(!r.report_attrs, "raw attributes are opt-in");
        assert_eq!(r.vt_signature, VtSignature::Fast);
        assert_eq!(r.preload_variants_n, 3);
        assert_eq!(SeatSpec::default().seats, 1);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn policies_roundtrip_through_the_admin_json_contract() {
        let original = policy(Preset::PerpetualMajor);
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("\"mode\":\"offline_hybrid\""));
        assert!(json.contains("\"kind\":\"semver_range\""));
        let decoded: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }
}
