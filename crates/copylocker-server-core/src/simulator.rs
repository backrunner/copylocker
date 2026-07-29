//! The policy simulator (`licensing-model.md §11`).
//!
//! Five orthogonal axes multiply into a configuration space too large to hold in your head. Get
//! `refresh_after` wrong on a subscription and cancellations propagate months late; get
//! `not_after` wrong and a cohort of paying customers is locked out every billing cycle.
//! Neither mistake announces itself — you find out from support tickets.
//!
//! So a policy can be *run* before it ships. The simulator replays a scenario against the same
//! functions the server uses, and prints a timeline. It doubles as the best regression harness
//! we have: a scenario is an executable assertion about what a configuration means.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use copylocker_types::{Mode, VersionScope};

use crate::catalog::Catalog;
use crate::entitlement::{resolve, PolicyError};
use crate::policy::{FallbackScopeAt, OfflineUpgradePolicy, Policy, TrialScope, Validity};
use crate::subscription::{preview_ending, Subscription, SubscriptionEvent, SubscriptionState};
use crate::version::{decide, ReleaseRegistry, VersionDecision};

/// Something that happens to a licence during a scenario.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum ScenarioStep {
    /// The licence is activated.
    Activate {
        /// When.
        at: i64,
    },
    /// A billing period is paid.
    Renew {
        /// When.
        at: i64,
    },
    /// A payment fails.
    PaymentFails {
        /// When.
        at: i64,
    },
    /// The dunning window closes with no payment.
    DunningLapses {
        /// When.
        at: i64,
    },
    /// The customer cancels, effective at period end.
    Cancel {
        /// When.
        at: i64,
    },
    /// The current period ends.
    PeriodEnds {
        /// When.
        at: i64,
    },
    /// The user tries to run a specific release.
    RunRelease {
        /// When.
        at: i64,
        /// Which release identifier the client reports.
        release_id: String,
    },
}

impl ScenarioStep {
    /// When this step happens.
    #[must_use]
    pub const fn at(&self) -> i64 {
        match self {
            Self::Activate { at }
            | Self::Renew { at }
            | Self::PaymentFails { at }
            | Self::DunningLapses { at }
            | Self::Cancel { at }
            | Self::PeriodEnds { at }
            | Self::RunRelease { at, .. } => *at,
        }
    }
}

const DAY: i64 = 86_400;
const HOUR: i64 = 3_600;
const MINUTE: i64 = 60;

fn format_duration(seconds: i64) -> String {
    if seconds != 0 && seconds % DAY == 0 {
        format!("{}d", seconds / DAY)
    } else if seconds != 0 && seconds % HOUR == 0 {
        format!("{}h", seconds / HOUR)
    } else if seconds != 0 && seconds % MINUTE == 0 {
        format!("{}m", seconds / MINUTE)
    } else {
        format!("{seconds}s")
    }
}

fn format_validity(validity: &Validity) -> String {
    match validity {
        Validity::Perpetual => "perpetual".to_string(),
        Validity::FixedTerm { duration_secs } => {
            format!("fixed_term({})", format_duration(*duration_secs))
        }
        Validity::Subscription {
            period_secs,
            dunning_grace_secs,
            fallback,
        } => {
            let fallback = fallback.map_or_else(
                || "none".to_string(),
                |terms| {
                    let scope = match terms.scope_at {
                        FallbackScopeAt::EarnedAt => "earned_at",
                        FallbackScopeAt::SubscriptionStart => "subscription_start",
                    };
                    format!("{}mo@{scope}", terms.after_months)
                },
            );
            format!(
                "subscription(period={},dunning={},fallback={fallback})",
                format_duration(*period_secs),
                format_duration(*dunning_grace_secs)
            )
        }
        Validity::Trial {
            duration_secs,
            once_per,
            extendable_by_secs,
        } => {
            let once_per = match once_per {
                TrialScope::Fingerprint => "fingerprint",
                TrialScope::Account => "account",
                TrialScope::Email => "email",
            };
            let extendable = extendable_by_secs
                .map(format_duration)
                .unwrap_or_else(|| "none".to_string());
            format!(
                "trial(duration={},once_per={once_per},extendable={extendable})",
                format_duration(*duration_secs)
            )
        }
    }
}

fn format_version_scope(scope: &VersionScope) -> String {
    match scope {
        VersionScope::Unlimited => "unlimited".to_string(),
        VersionScope::SemverRange(range) => format!("semver({range})"),
        VersionScope::ReleasedBefore(cutoff) => format!("released_before({cutoff})"),
        VersionScope::Pinned(releases) => format!("pinned({})", releases.len()),
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::OfflineHybrid => "offline_hybrid",
        Mode::EnforcedOnline => "enforced_online",
    }
}

fn offline_upgrade_name(policy: OfflineUpgradePolicy) -> &'static str {
    match policy {
        OfflineUpgradePolicy::RequireOnline => "require_online",
        OfflineUpgradePolicy::PreloadN => "preload_n",
        OfflineUpgradePolicy::VariantStable => "variant_stable",
    }
}

fn policy_summary(policy: &Policy) -> String {
    let heartbeat = policy
        .seats
        .heartbeat_secs
        .map(format_duration)
        .unwrap_or_else(|| "none".to_string());
    format!(
        "validity={} version_scope={} seats={} mode={} heartbeat={} refresh_after={} grace={} \
         offline_keys={} offline_upgrade={}",
        format_validity(&policy.validity),
        format_version_scope(&policy.version_scope),
        policy.seats.seats,
        mode_name(policy.mode),
        heartbeat,
        format_duration(policy.runtime.refresh_after_secs),
        format_duration(i64::from(policy.runtime.grace_secs)),
        policy.runtime.allow_olk,
        offline_upgrade_name(policy.runtime.offline_upgrade_policy)
    )
}

/// A named sequence of steps.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Scenario {
    /// Scenario name.
    pub name: String,
    /// Steps, applied in order.
    pub steps: Vec<ScenarioStep>,
}

/// One line of simulated timeline.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimelineEntry {
    /// When it happened.
    pub at: i64,
    /// What happened.
    pub event: String,
    /// The consequence.
    pub detail: String,
    /// Whether this is something the operator should look at.
    pub notable: bool,
}

/// The result of a simulation.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Simulation {
    /// Scenario name.
    pub scenario: String,
    /// The timeline.
    pub timeline: Vec<TimelineEntry>,
    /// Subscription state at the end, if the policy has one.
    pub final_subscription_state: Option<SubscriptionState>,
    /// Version cutoff in force at the end, if any.
    pub final_version_cutoff: Option<i64>,
    /// Warnings raised by the policy itself.
    pub policy_warnings: Vec<String>,
}

impl Simulation {
    /// Render as plain text, the form `copylocker policy simulate` prints.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = format!("scenario: {}\n", self.scenario);
        for w in &self.policy_warnings {
            s.push_str(&format!("  ⚠ policy: {w}\n"));
        }
        for e in &self.timeline {
            let mark = if e.notable { "★" } else { " " };
            s.push_str(&format!(
                "{mark} {:>12}  {:<24} {}\n",
                e.at, e.event, e.detail
            ));
        }
        s
    }

    /// Whether any notable event occurred.
    #[must_use]
    pub fn has_notable(&self) -> bool {
        self.timeline.iter().any(|e| e.notable)
    }

    /// Find a timeline entry by event name.
    #[must_use]
    pub fn find(&self, event: &str) -> Option<&TimelineEntry> {
        self.timeline.iter().find(|e| e.event == event)
    }
}

/// Run a scenario against a policy.
///
/// Deliberately calls [`resolve`], [`decide`], and [`Subscription::apply`] — the very functions
/// the live server uses — rather than reimplementing their logic. A simulator that models the
/// server separately would drift from it, and a drifted simulator is worse than none
/// (`licensing-model.md §11`: simulator, CLI, and server must agree).
pub fn simulate(
    policy: &Policy,
    catalog: &Catalog,
    registry: &ReleaseRegistry,
    scenario: &Scenario,
) -> Result<Simulation, PolicyError> {
    let mut timeline = Vec::new();
    let mut subscription: Option<Subscription> = None;
    let mut version_scope = policy.version_scope.clone();
    let mut credential_expiry = None;
    let mut event_seq = 0u32;

    let policy_warnings = policy.warnings().into_iter().map(|w| w.message).collect();

    let (period_secs, dunning_secs, fallback) = match &policy.validity {
        Validity::Subscription {
            period_secs,
            dunning_grace_secs,
            fallback,
        } => (*period_secs, *dunning_grace_secs, *fallback),
        _ => (0, 0, None),
    };

    for step in &scenario.steps {
        let at = step.at();
        match step {
            ScenarioStep::Activate { .. } => {
                let ent = resolve(catalog, &policy.entitlement, at)?;
                let features: Vec<&str> = ent.features.iter().map(String::as_str).collect();
                timeline.push(TimelineEntry {
                    at,
                    event: "activate".to_string(),
                    detail: format!(
                        "tier={} features=[{}] {}",
                        ent.tier_id,
                        features.join(", "),
                        policy_summary(policy)
                    ),
                    notable: false,
                });

                credential_expiry = policy.expires_at(at);
                if let Some(expiry) = credential_expiry {
                    timeline.push(TimelineEntry {
                        at,
                        event: "credential_expiry".to_string(),
                        detail: format!("not_after={expiry}"),
                        notable: false,
                    });
                }

                if period_secs > 0 {
                    subscription = Some(Subscription::new("sim", "sub_sim", at, at + period_secs));
                }
            }

            ScenarioStep::Renew { .. } => {
                let Some(sub) = subscription.as_mut() else {
                    timeline.push(TimelineEntry {
                        at,
                        event: "renew".to_string(),
                        detail: "policy is not a subscription; renewal has no effect".to_string(),
                        notable: true,
                    });
                    continue;
                };
                event_seq += 1;
                let out = sub.apply(
                    &format!("sim_{event_seq}"),
                    &SubscriptionEvent::Renewed {
                        period_start: at,
                        period_end: at + period_secs,
                    },
                    fallback,
                    at,
                    dunning_secs,
                );
                if out.applied {
                    credential_expiry =
                        Some(at.saturating_add(period_secs).saturating_add(dunning_secs));
                }
                timeline.push(TimelineEntry {
                    at,
                    event: "renew".to_string(),
                    detail: format!(
                        "state={:?} continuous_paid_months={} not_after={}",
                        sub.state,
                        sub.continuous_paid_months,
                        credential_expiry
                            .map_or_else(|| "none".to_string(), |expiry| expiry.to_string())
                    ),
                    notable: false,
                });
                if out.fallback_earned {
                    timeline.push(TimelineEntry {
                        at,
                        event: "fallback_earned".to_string(),
                        detail: format!("perpetual fallback vested; version cap anchored at {at}"),
                        notable: true,
                    });
                }
            }

            ScenarioStep::PaymentFails { .. } => {
                if let Some(sub) = subscription.as_mut() {
                    event_seq += 1;
                    sub.apply(
                        &format!("sim_{event_seq}"),
                        &SubscriptionEvent::PaymentFailed,
                        fallback,
                        at,
                        dunning_secs,
                    );
                    timeline.push(TimelineEntry {
                        at,
                        event: "payment_failed".to_string(),
                        detail: format!(
                            "state={:?}; still usable until {}",
                            sub.state,
                            sub.dunning_until.unwrap_or(at)
                        ),
                        notable: true,
                    });
                }
            }

            ScenarioStep::DunningLapses { .. } => {
                if let Some(sub) = subscription.as_mut() {
                    event_seq += 1;
                    let out = sub.apply(
                        &format!("sim_{event_seq}"),
                        &SubscriptionEvent::DunningElapsed,
                        fallback,
                        at,
                        dunning_secs,
                    );
                    timeline.push(TimelineEntry {
                        at,
                        event: "dunning_lapsed".to_string(),
                        detail: format!(
                            "state={:?}{}",
                            sub.state,
                            if out.streak_reset {
                                "; consecutive-payment streak reset to 0"
                            } else {
                                ""
                            }
                        ),
                        notable: true,
                    });
                }
            }

            ScenarioStep::Cancel { .. } => {
                if let Some(sub) = subscription.as_mut() {
                    event_seq += 1;
                    sub.apply(
                        &format!("sim_{event_seq}"),
                        &SubscriptionEvent::CancelAtPeriodEnd,
                        fallback,
                        at,
                        dunning_secs,
                    );
                    let (would_become, cutoff) = preview_ending(sub, fallback);
                    timeline.push(TimelineEntry {
                        at,
                        event: "cancel".to_string(),
                        detail: format!(
                            "state={:?}; at period end will become {:?}{}",
                            sub.state,
                            would_become,
                            cutoff
                                .map(|c| format!(" capped at releases before {c}"))
                                .unwrap_or_default()
                        ),
                        notable: true,
                    });
                }
            }

            ScenarioStep::PeriodEnds { .. } => {
                if let Some(sub) = subscription.as_mut() {
                    event_seq += 1;
                    sub.apply(
                        &format!("sim_{event_seq}"),
                        &SubscriptionEvent::PeriodElapsed,
                        fallback,
                        at,
                        dunning_secs,
                    );
                    if sub.state == SubscriptionState::PerpetualFallback {
                        if let Some(cut) = sub.fallback_version_cutoff(fallback) {
                            version_scope = VersionScope::ReleasedBefore(cut);
                        }
                        credential_expiry = None;
                    }
                    timeline.push(TimelineEntry {
                        at,
                        event: "period_ends".to_string(),
                        detail: format!("state={:?}; scope={version_scope:?}", sub.state),
                        notable: true,
                    });
                }
            }

            ScenarioStep::RunRelease { release_id, .. } => {
                if let Some(sub) = subscription.as_ref() {
                    if !sub.is_usable_at(at) {
                        timeline.push(TimelineEntry {
                            at,
                            event: "run_release".to_string(),
                            detail: format!(
                                "{release_id} cannot run; subscription state {:?} is not usable",
                                sub.state
                            ),
                            notable: true,
                        });
                        continue;
                    }
                }
                let became_perpetual = subscription
                    .as_ref()
                    .is_some_and(|sub| sub.state == SubscriptionState::PerpetualFallback);
                if !became_perpetual && credential_expiry.is_some_and(|expiry| at >= expiry) {
                    let expiry = credential_expiry.unwrap_or(at);
                    timeline.push(TimelineEntry {
                        at,
                        event: "run_release".to_string(),
                        detail: format!(
                            "{release_id} cannot run; credential expired at {expiry}; activate or renew"
                        ),
                        notable: true,
                    });
                    continue;
                }
                let decision = decide(registry, &version_scope, release_id);
                let (detail, notable) = match &decision {
                    VersionDecision::InScope { variant_id } => {
                        (format!("{release_id} runs (variant {variant_id})"), false)
                    }
                    VersionDecision::NotRegistered => (
                        format!(
                            "{release_id} is not registered; run `copylocker release register`"
                        ),
                        true,
                    ),
                    VersionDecision::OutOfScope { highest_allowed } => (
                        format!(
                            "{release_id} is outside the licensed scope — restricted mode. \
                             Highest covered release: {}",
                            highest_allowed.as_deref().unwrap_or("none")
                        ),
                        true,
                    ),
                    VersionDecision::Compromised { action } => (
                        format!(
                            "{release_id} is marked compromised; action={}",
                            action.as_str()
                        ),
                        true,
                    ),
                };
                timeline.push(TimelineEntry {
                    at,
                    event: "run_release".to_string(),
                    detail,
                    notable,
                });
            }
        }
    }

    let final_version_cutoff = match &version_scope {
        VersionScope::ReleasedBefore(c) => Some(*c),
        _ => None,
    };

    Ok(Simulation {
        scenario: scenario.name.clone(),
        timeline,
        final_subscription_state: subscription.map(|s| s.state),
        final_version_cutoff,
        policy_warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::fixtures::sample;
    use crate::policy::Preset;
    use crate::version::{Release, ReleaseStatus};

    const JAN26: i64 = 1_767_225_600; // 2026-01-01
    const MONTH: i64 = 30 * 86_400;
    const YEAR: i64 = 365 * 86_400;

    fn registry() -> ReleaseRegistry {
        ReleaseRegistry {
            releases: alloc::vec![
                Release {
                    id: "rel_19".to_string(),
                    product_id: "acme".to_string(),
                    app_version: "1.9.0".to_string(),
                    variant_id: 19,
                    build_fingerprint: "bf19".to_string(),
                    channel: "stable".to_string(),
                    status: ReleaseStatus::Active,
                    compromised_action: None,
                    published_at: JAN26 - 2 * 86_400,
                },
                Release {
                    id: "rel_20".to_string(),
                    product_id: "acme".to_string(),
                    app_version: "2.0.0".to_string(),
                    variant_id: 20,
                    build_fingerprint: "bf20".to_string(),
                    channel: "stable".to_string(),
                    status: ReleaseStatus::Active,
                    compromised_action: None,
                    published_at: JAN26 - 86_400,
                },
                Release {
                    id: "rel_38".to_string(),
                    product_id: "acme".to_string(),
                    app_version: "3.8.0".to_string(),
                    variant_id: 38,
                    build_fingerprint: "bf38".to_string(),
                    channel: "stable".to_string(),
                    status: ReleaseStatus::Active,
                    compromised_action: None,
                    published_at: JAN26,
                },
                Release {
                    id: "rel_39".to_string(),
                    product_id: "acme".to_string(),
                    app_version: "3.9.0".to_string(),
                    variant_id: 39,
                    build_fingerprint: "bf39".to_string(),
                    channel: "stable".to_string(),
                    status: ReleaseStatus::Active,
                    compromised_action: None,
                    published_at: JAN26 + 350 * 86_400,
                },
                Release {
                    id: "rel_42".to_string(),
                    product_id: "acme".to_string(),
                    app_version: "4.2.0".to_string(),
                    variant_id: 42,
                    build_fingerprint: "bf42".to_string(),
                    channel: "stable".to_string(),
                    status: ReleaseStatus::Active,
                    compromised_action: None,
                    published_at: JAN26 + 2 * YEAR - 60 * 86_400,
                },
            ],
        }
    }

    fn preset_scenario(preset: Preset) -> Scenario {
        let mut steps = alloc::vec![ScenarioStep::Activate { at: JAN26 }];
        match preset {
            Preset::Trial14d => steps.push(ScenarioStep::RunRelease {
                at: JAN26 + 14 * DAY,
                release_id: "rel_38".to_string(),
            }),
            Preset::Perpetual => steps.push(ScenarioStep::RunRelease {
                at: JAN26 + 2 * YEAR,
                release_id: "rel_42".to_string(),
            }),
            Preset::PerpetualMajor => {
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26,
                    release_id: "rel_19".to_string(),
                });
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26,
                    release_id: "rel_20".to_string(),
                });
            }
            Preset::PerpetualFallback => {
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26 + 2 * YEAR,
                    release_id: "rel_39".to_string(),
                });
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26 + 2 * YEAR,
                    release_id: "rel_42".to_string(),
                });
            }
            Preset::SubMonthly => {
                steps.push(ScenarioStep::PaymentFails { at: JAN26 + MONTH });
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26 + MONTH + 7 * DAY - 1,
                    release_id: "rel_38".to_string(),
                });
                steps.push(ScenarioStep::DunningLapses {
                    at: JAN26 + MONTH + 7 * DAY,
                });
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26 + MONTH + 7 * DAY,
                    release_id: "rel_38".to_string(),
                });
            }
            Preset::SubAnnual => {
                steps.push(ScenarioStep::Cancel {
                    at: JAN26 + YEAR - DAY,
                });
                steps.push(ScenarioStep::PeriodEnds { at: JAN26 + YEAR });
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26 + YEAR,
                    release_id: "rel_38".to_string(),
                });
            }
            Preset::SubAnnualFallback => {
                steps.push(ScenarioStep::Renew { at: JAN26 + YEAR });
                steps.push(ScenarioStep::Cancel {
                    at: JAN26 + YEAR + 100 * DAY,
                });
                steps.push(ScenarioStep::PeriodEnds {
                    at: JAN26 + 2 * YEAR,
                });
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26 + 2 * YEAR + DAY,
                    release_id: "rel_42".to_string(),
                });
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26 + 2 * YEAR + DAY,
                    release_id: "rel_39".to_string(),
                });
            }
            Preset::TeamSub | Preset::EnterpriseAirgap => {
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26,
                    release_id: "rel_38".to_string(),
                });
            }
            Preset::SaasClient => {
                steps.push(ScenarioStep::PaymentFails { at: JAN26 + MONTH });
                steps.push(ScenarioStep::RunRelease {
                    at: JAN26 + MONTH + HOUR - 1,
                    release_id: "rel_38".to_string(),
                });
            }
            Preset::Edu1y => steps.push(ScenarioStep::RunRelease {
                at: JAN26 + YEAR,
                release_id: "rel_38".to_string(),
            }),
        }
        Scenario {
            name: format!("preset {}", preset.as_str()),
            steps,
        }
    }

    fn run_entries(simulation: &Simulation) -> Vec<&TimelineEntry> {
        simulation
            .timeline
            .iter()
            .filter(|entry| entry.event == "run_release")
            .collect()
    }

    #[test]
    fn every_preset_passes_its_simulator_scenario() {
        for preset in Preset::ALL {
            let tier = match preset {
                Preset::Trial14d => "free",
                Preset::TeamSub => "team",
                _ => "pro",
            };
            let policy = preset.build("p", "acme", tier, JAN26);
            let scenario = preset_scenario(preset);
            let simulation = simulate(&policy, &sample(), &registry(), &scenario)
                .expect("preset simulation must succeed");
            let rendered = simulation.render();
            let activation = simulation
                .find("activate")
                .expect("every scenario activates");
            let runs = run_entries(&simulation);

            assert!(
                rendered.contains(&format!("scenario: preset {}", preset.as_str())),
                "{} lost its scenario name: {rendered}",
                preset.as_str()
            );
            assert!(
                activation.detail.contains(&format!("tier={tier}")),
                "{} did not resolve its entitlement: {}",
                preset.as_str(),
                activation.detail
            );

            match preset {
                Preset::Trial14d => {
                    assert!(activation.detail.contains(
                        "validity=trial(duration=14d,once_per=fingerprint,extendable=14d)"
                    ));
                    assert!(activation.detail.contains("seats=1"));
                    assert!(simulation.find("credential_expiry").is_some());
                    assert!(runs[0].detail.contains("credential expired"));
                }
                Preset::Perpetual => {
                    assert!(activation.detail.contains("validity=perpetual"));
                    assert!(activation.detail.contains("version_scope=unlimited"));
                    assert!(simulation.find("credential_expiry").is_none());
                    assert!(runs[0].detail.contains("rel_42 runs"));
                }
                Preset::PerpetualMajor => {
                    assert!(activation.detail.contains("version_scope=semver(^1)"));
                    assert!(runs[0].detail.contains("rel_19 runs"));
                    assert!(runs[1].detail.contains("outside the licensed scope"));
                    assert!(runs[1].detail.contains("rel_19"));
                }
                Preset::PerpetualFallback => {
                    assert_eq!(simulation.final_version_cutoff, Some(JAN26 + YEAR));
                    assert!(runs[0].detail.contains("rel_39 runs"));
                    assert!(runs[1].detail.contains("outside the licensed scope"));
                    assert!(runs[1].detail.contains("rel_39"));
                }
                Preset::SubMonthly => {
                    assert!(activation
                        .detail
                        .contains("subscription(period=30d,dunning=7d,fallback=none)"));
                    assert!(simulation
                        .find("payment_failed")
                        .is_some_and(|entry| entry.detail.contains("still usable until")));
                    assert!(runs[0].detail.contains("rel_38 runs"));
                    assert!(runs[1].detail.contains("state Suspended"));
                    assert_eq!(
                        simulation.final_subscription_state,
                        Some(SubscriptionState::Suspended)
                    );
                }
                Preset::SubAnnual => {
                    assert!(activation
                        .detail
                        .contains("subscription(period=365d,dunning=14d,fallback=none)"));
                    assert_eq!(
                        simulation.final_subscription_state,
                        Some(SubscriptionState::Expired)
                    );
                    assert!(runs[0].detail.contains("state Expired"));
                }
                Preset::SubAnnualFallback => {
                    assert!(activation.detail.contains("fallback=12mo@earned_at"));
                    assert!(simulation.find("fallback_earned").is_some());
                    assert!(simulation
                        .find("renew")
                        .is_some_and(|entry| entry.detail.contains("continuous_paid_months=12")));
                    assert_eq!(
                        simulation.final_subscription_state,
                        Some(SubscriptionState::PerpetualFallback)
                    );
                    assert_eq!(simulation.final_version_cutoff, Some(JAN26 + YEAR));
                    assert!(runs[0].detail.contains("outside the licensed scope"));
                    assert!(runs[1].detail.contains("rel_39 runs"));
                }
                Preset::TeamSub => {
                    assert!(activation.detail.contains("seats=25"));
                    assert!(activation.detail.contains("heartbeat=6h"));
                    assert_eq!(
                        simulation.final_subscription_state,
                        Some(SubscriptionState::Active)
                    );
                    assert!(runs[0].detail.contains("rel_38 runs"));
                }
                Preset::EnterpriseAirgap => {
                    assert!(activation.detail.contains("validity=fixed_term(365d)"));
                    assert!(activation.detail.contains("version_scope=pinned(0)"));
                    assert!(activation.detail.contains("seats=50"));
                    assert!(activation.detail.contains("offline_keys=true"));
                    assert!(activation.detail.contains("offline_upgrade=preload_n"));
                    assert_eq!(simulation.policy_warnings.len(), 1);
                    assert!(runs[0].detail.contains("outside the licensed scope"));
                }
                Preset::SaasClient => {
                    assert!(activation.detail.contains("seats=3"));
                    assert!(activation.detail.contains("mode=enforced_online"));
                    assert!(activation.detail.contains("heartbeat=1h"));
                    assert!(activation.detail.contains("refresh_after=1h grace=1h"));
                    assert_eq!(
                        simulation.final_subscription_state,
                        Some(SubscriptionState::PastDue)
                    );
                    assert!(runs[0].detail.contains("rel_38 runs"));
                }
                Preset::Edu1y => {
                    assert!(activation.detail.contains("validity=fixed_term(365d)"));
                    assert!(simulation.find("credential_expiry").is_some());
                    assert!(runs[0].detail.contains("credential expired"));
                }
            }
        }
    }

    /// The worked example from `licensing-model.md §11`: buy an annual subscription with a
    /// perpetual fallback, cancel after 18 months, end up version-capped.
    #[test]
    fn the_documented_fallback_scenario_reproduces() {
        let policy = Preset::SubAnnualFallback.build("p", "acme", "pro", JAN26);
        let scenario = Scenario {
            name: "sub-annual-fallback, cancel in year two".to_string(),
            steps: alloc::vec![
                ScenarioStep::Activate { at: JAN26 },
                // One completed annual billing cycle earns twelve paid months.
                ScenarioStep::Renew { at: JAN26 + YEAR },
                ScenarioStep::Cancel {
                    at: JAN26 + YEAR + 150 * 86_400
                },
                ScenarioStep::PeriodEnds {
                    at: JAN26 + 2 * YEAR
                },
                // 4.2 was published after the fallback vested.
                ScenarioStep::RunRelease {
                    at: JAN26 + 2 * YEAR + 86_400,
                    release_id: "rel_42".to_string()
                },
                // 3.9 was published before it, so it still runs.
                ScenarioStep::RunRelease {
                    at: JAN26 + 2 * YEAR + 86_400,
                    release_id: "rel_39".to_string()
                },
            ],
        };

        let sim = simulate(&policy, &sample(), &registry(), &scenario).unwrap();

        assert!(
            sim.find("fallback_earned").is_some(),
            "twelve paid months must vest the fallback"
        );
        assert_eq!(
            sim.final_subscription_state,
            Some(SubscriptionState::PerpetualFallback)
        );

        let runs: Vec<&TimelineEntry> = sim
            .timeline
            .iter()
            .filter(|e| e.event == "run_release")
            .collect();
        assert_eq!(runs.len(), 2);
        assert!(
            runs[0].detail.contains("outside the licensed scope"),
            "4.2 is newer than the cap: {}",
            runs[0].detail
        );
        assert!(
            runs[0].detail.contains("rel_39"),
            "the user must be told which version they can still run"
        );
        assert!(runs[1].detail.contains("runs"), "3.9 must still work");
    }

    #[test]
    fn a_trial_expires_without_a_subscription() {
        let policy = Preset::Trial14d.build("p", "acme", "free", JAN26);
        let scenario = Scenario {
            name: "trial".to_string(),
            steps: alloc::vec![ScenarioStep::Activate { at: JAN26 }],
        };
        let sim = simulate(&policy, &sample(), &registry(), &scenario).unwrap();
        assert_eq!(sim.final_subscription_state, None);
        let expiry = sim.find("credential_expiry").expect("trials expire");
        assert!(expiry.detail.contains(&format!("{}", JAN26 + 14 * 86_400)));
    }

    #[test]
    fn a_perpetual_licence_has_no_expiry_line() {
        let policy = Preset::Perpetual.build("p", "acme", "pro", JAN26);
        let scenario = Scenario {
            name: "perpetual".to_string(),
            steps: alloc::vec![ScenarioStep::Activate { at: JAN26 }],
        };
        let sim = simulate(&policy, &sample(), &registry(), &scenario).unwrap();
        assert!(sim.find("credential_expiry").is_none());
    }

    #[test]
    fn cancelling_before_vesting_expires_rather_than_going_perpetual() {
        let policy = Preset::SubAnnualFallback.build("p", "acme", "pro", JAN26);
        let scenario = Scenario {
            name: "early cancel".to_string(),
            steps: alloc::vec![
                ScenarioStep::Activate { at: JAN26 },
                ScenarioStep::Cancel {
                    at: JAN26 + 60 * 86_400
                },
                ScenarioStep::PeriodEnds { at: JAN26 + YEAR },
            ],
        };
        let sim = simulate(&policy, &sample(), &registry(), &scenario).unwrap();
        assert_eq!(
            sim.final_subscription_state,
            Some(SubscriptionState::Expired)
        );
        assert!(sim.find("fallback_earned").is_none());
    }

    #[test]
    fn dunning_keeps_the_licence_usable_and_says_until_when() {
        let policy = Preset::SubMonthly.build("p", "acme", "pro", JAN26);
        let scenario = Scenario {
            name: "dunning".to_string(),
            steps: alloc::vec![
                ScenarioStep::Activate { at: JAN26 },
                ScenarioStep::PaymentFails {
                    at: JAN26 + 30 * 86_400
                },
            ],
        };
        let sim = simulate(&policy, &sample(), &registry(), &scenario).unwrap();
        let e = sim.find("payment_failed").expect("must be recorded");
        assert!(e.detail.contains("still usable until"));
        assert!(e.notable);
    }

    #[test]
    fn an_unregistered_release_is_flagged_with_the_fix() {
        let policy = Preset::Perpetual.build("p", "acme", "pro", JAN26);
        let scenario = Scenario {
            name: "unregistered".to_string(),
            steps: alloc::vec![
                ScenarioStep::Activate { at: JAN26 },
                ScenarioStep::RunRelease {
                    at: JAN26,
                    release_id: "rel_ghost".to_string()
                },
            ],
        };
        let sim = simulate(&policy, &sample(), &registry(), &scenario).unwrap();
        let e = sim.find("run_release").unwrap();
        assert!(e.notable);
        assert!(
            e.detail.contains("copylocker release register"),
            "the message must name the fix, not imply piracy"
        );
    }

    #[test]
    fn a_compromised_release_reports_the_configured_action() {
        let mut reg = registry();
        let release = reg
            .releases
            .iter_mut()
            .find(|release| release.id == "rel_42")
            .expect("fixture release must exist");
        release.status = ReleaseStatus::Compromised;
        release.compromised_action = Some(crate::version::CompromisedAction::ForceUpgrade);
        let policy = Preset::Perpetual.build("p", "acme", "pro", JAN26);
        let scenario = Scenario {
            name: "compromised".to_string(),
            steps: alloc::vec![ScenarioStep::RunRelease {
                at: JAN26,
                release_id: "rel_42".to_string()
            }],
        };
        let sim = simulate(&policy, &sample(), &reg, &scenario).unwrap();
        assert!(sim
            .find("run_release")
            .unwrap()
            .detail
            .contains("force_upgrade"));
    }

    #[test]
    fn renewing_a_non_subscription_policy_is_flagged_as_a_configuration_error() {
        let policy = Preset::Perpetual.build("p", "acme", "pro", JAN26);
        let scenario = Scenario {
            name: "bad".to_string(),
            steps: alloc::vec![
                ScenarioStep::Activate { at: JAN26 },
                ScenarioStep::Renew { at: JAN26 + 86_400 },
            ],
        };
        let sim = simulate(&policy, &sample(), &registry(), &scenario).unwrap();
        assert!(sim.find("renew").unwrap().notable);
    }

    #[test]
    fn policy_warnings_surface_in_the_simulation() {
        let mut policy = Preset::SubMonthly.build("p", "acme", "pro", JAN26);
        policy.runtime.refresh_after_secs = 29 * 86_400;
        let scenario = Scenario {
            name: "warned".to_string(),
            steps: alloc::vec![ScenarioStep::Activate { at: JAN26 }],
        };
        let sim = simulate(&policy, &sample(), &registry(), &scenario).unwrap();
        assert!(!sim.policy_warnings.is_empty());
        assert!(sim.render().contains("⚠ policy:"));
    }

    #[test]
    fn a_broken_catalog_surfaces_as_an_error_rather_than_a_misleading_timeline() {
        let mut cat = sample();
        cat.groups[0].members.includes.push("pro-suite".to_string());
        let policy = Preset::Perpetual.build("p", "acme", "pro", JAN26);
        let scenario = Scenario {
            name: "bad catalog".to_string(),
            steps: alloc::vec![ScenarioStep::Activate { at: JAN26 }],
        };
        assert!(simulate(&policy, &cat, &registry(), &scenario).is_err());
    }

    #[test]
    fn rendering_marks_notable_lines() {
        let policy = Preset::SubMonthly.build("p", "acme", "pro", JAN26);
        let scenario = Scenario {
            name: "render".to_string(),
            steps: alloc::vec![
                ScenarioStep::Activate { at: JAN26 },
                ScenarioStep::PaymentFails { at: JAN26 + 86_400 },
            ],
        };
        let sim = simulate(&policy, &sample(), &registry(), &scenario).unwrap();
        let text = sim.render();
        assert!(text.contains("scenario: render"));
        assert!(text.contains('★'));
        assert!(sim.has_notable());
    }
}
