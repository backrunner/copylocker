//! Subscription lifecycle and perpetual fallback (`licensing-model.md §3.2` and `§5`).
//!
//! ```text
//!         ┌──────────── renew ──────────────────────┐
//!         ▼                                          │
//!   active ──payment_failed──▶ past_due ──dunning──▶ suspended
//!     │  │                        │                     │
//!     │  └──payment_ok────────────┘                     │
//!     │                                                 │
//!   cancel_at_period_end                          reactivate
//!     │                                                 │
//!     ▼                                                 ▼
//!   canceling ──period_end──▶ ended ──(earned)──▶ perpetual_fallback
//!                               └──(otherwise)──▶ expired
//! ```
//!
//! Every transition is driven by a payment webhook, and webhooks are **replayed**: out of order,
//! more than once, and sometimes years late. So every function here is idempotent, and
//! `fallback_earned_at` is write-once — a replayed renewal must not re-award or re-date a
//! perpetual fallback (`licensing-model.md §5.2`).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::policy::{FallbackScopeAt, PerpetualFallback};

const BILLING_MONTH_SECS: i64 = 30 * 86_400;

/// Lifecycle state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SubscriptionState {
    /// Paid and current.
    Active,
    /// A payment failed; still usable inside the dunning window.
    PastDue,
    /// Cancelled, paid through the period end.
    Canceling,
    /// Dunning elapsed with no payment.
    Suspended,
    /// The final period ended.
    Ended,
    /// Ended without an earned fallback.
    Expired,
    /// Ended with an earned fallback; now a perpetual licence with a version cap.
    PerpetualFallback,
}

impl SubscriptionState {
    /// Whether the application should keep working in this state.
    ///
    /// `PastDue` is usable on purpose: that is what the dunning window is for. Locking someone
    /// out the instant a card expires is both hostile and bad for recovery rates.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::PastDue | Self::Canceling | Self::PerpetualFallback
        )
    }

    /// Whether this state can never change again.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Expired | Self::PerpetualFallback)
    }

    /// The hint value sent to clients, where one applies.
    #[must_use]
    pub const fn to_hint(self) -> Option<copylocker_types::SubscriptionState> {
        use copylocker_types::SubscriptionState as Hint;
        match self {
            Self::Active => Some(Hint::Active),
            Self::PastDue => Some(Hint::PastDue),
            Self::Canceling => Some(Hint::Canceling),
            Self::Suspended => Some(Hint::Suspended),
            Self::Ended | Self::Expired | Self::PerpetualFallback => None,
        }
    }
}

/// A payment provider event.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SubscriptionEvent {
    /// A billing period was paid.
    Renewed {
        /// Start of the new period.
        period_start: i64,
        /// End of the new period.
        period_end: i64,
    },
    /// A charge failed.
    PaymentFailed,
    /// A previously failed charge succeeded.
    PaymentRecovered,
    /// The customer cancelled, effective at the period end.
    CancelAtPeriodEnd,
    /// The customer un-cancelled.
    CancelReverted,
    /// The current period elapsed.
    PeriodElapsed,
    /// The dunning window elapsed without payment.
    DunningElapsed,
    /// The subscription was reactivated after suspension.
    Reactivated {
        /// Start of the new period.
        period_start: i64,
        /// End of the new period.
        period_end: i64,
    },
    /// A refund or fraud determination revoked an earned fallback.
    FallbackRevoked,
    /// A refund was reported and the licence enters a review window before revocation.
    RefundReported,
}

/// A subscription's stored state (`data-model.md §6`).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Subscription {
    /// Payment provider name.
    pub provider: String,
    /// The provider's identifier for this subscription.
    pub external_id: String,
    /// Lifecycle state.
    pub state: SubscriptionState,
    /// Start of the current paid period.
    pub current_period_start: i64,
    /// End of the current paid period.
    pub current_period_end: i64,
    /// When the dunning window closes, if a payment has failed.
    #[cfg_attr(feature = "serde", serde(default))]
    pub dunning_until: Option<i64>,
    /// Consecutive paid months. Reset to zero by a lapse.
    pub continuous_paid_months: u32,
    /// When the perpetual fallback was earned. **Write-once.**
    #[cfg_attr(feature = "serde", serde(default))]
    pub fallback_earned_at: Option<i64>,
    /// When the customer cancelled.
    #[cfg_attr(feature = "serde", serde(default))]
    pub canceled_at: Option<i64>,
    /// Last modification time.
    pub updated_at: i64,
    /// Provider event identifiers already applied, for deduplication.
    ///
    /// In production this lives in the `billing_events` table; it is carried here so the state
    /// machine itself can be tested for idempotence.
    #[cfg_attr(feature = "serde", serde(default))]
    pub processed_events: Vec<String>,
}

/// What changed as a result of applying an event.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TransitionOutcome {
    /// Whether the event was applied, as opposed to deduplicated or rejected.
    pub applied: bool,
    /// Whether an older event was ignored to avoid rolling state backward.
    pub stale: bool,
    /// The state before, when applied.
    pub from: Option<SubscriptionState>,
    /// The state after.
    pub to: Option<SubscriptionState>,
    /// Whether the perpetual fallback was earned by this event.
    pub fallback_earned: bool,
    /// Whether the consecutive-payment counter was reset.
    pub streak_reset: bool,
}

impl Subscription {
    /// Start a new active subscription.
    #[must_use]
    pub fn new(provider: &str, external_id: &str, period_start: i64, period_end: i64) -> Self {
        Self {
            provider: provider.to_string(),
            external_id: external_id.to_string(),
            state: SubscriptionState::Active,
            current_period_start: period_start,
            current_period_end: period_end,
            dunning_until: None,
            continuous_paid_months: 0,
            fallback_earned_at: None,
            canceled_at: None,
            updated_at: period_start,
            processed_events: Vec::new(),
        }
    }

    /// Whether the app should work right now.
    ///
    /// Distinct from [`SubscriptionState::is_usable`] because `PastDue` is only usable *inside*
    /// the dunning window; past it, the state machine has simply not been told yet.
    #[must_use]
    pub fn is_usable_at(&self, now: i64) -> bool {
        match self.state {
            SubscriptionState::PastDue => self.dunning_until.is_none_or(|d| now < d),
            other => other.is_usable(),
        }
    }

    /// Apply a provider event.
    ///
    /// `event_id` deduplicates: replaying an event that has already been applied is a no-op that
    /// reports `applied: false`. This is not an optimisation — providers genuinely resend, and
    /// double-counting a renewal would award a perpetual fallback early.
    pub fn apply(
        &mut self,
        event_id: &str,
        event: &SubscriptionEvent,
        fallback: Option<PerpetualFallback>,
        now: i64,
        dunning_grace_secs: i64,
    ) -> TransitionOutcome {
        if self.processed_events.iter().any(|e| e == event_id) {
            return TransitionOutcome::default();
        }
        // Payment providers may deliver old events after newer ones. Security revocations are
        // the exception: a late refund or fraud decision must still remove an earned fallback.
        if now < self.updated_at
            && !matches!(
                event,
                SubscriptionEvent::FallbackRevoked | SubscriptionEvent::RefundReported
            )
        {
            self.processed_events.push(event_id.to_string());
            return TransitionOutcome {
                stale: true,
                ..Default::default()
            };
        }
        // A terminal state absorbs everything except an explicit fallback revocation.
        if self.state.is_terminal()
            && !matches!(
                event,
                SubscriptionEvent::FallbackRevoked | SubscriptionEvent::RefundReported
            )
        {
            self.processed_events.push(event_id.to_string());
            return TransitionOutcome::default();
        }

        let from = self.state;
        let mut out = TransitionOutcome {
            applied: true,
            from: Some(from),
            to: Some(from),
            ..Default::default()
        };

        match event {
            SubscriptionEvent::Renewed {
                period_start,
                period_end,
            }
            | SubscriptionEvent::Reactivated {
                period_start,
                period_end,
            } => {
                self.current_period_start = *period_start;
                self.current_period_end = *period_end;
                self.dunning_until = None;
                // A renewal after a lapse restarts the streak; the `Suspended` transition
                // already zeroed it.
                self.continuous_paid_months = self
                    .continuous_paid_months
                    .saturating_add(paid_months(*period_start, *period_end));
                // `Canceling` must survive a renewal event: the customer asked to stop, and a
                // provider-side renewal should not silently un-cancel them.
                self.state = if from == SubscriptionState::Canceling {
                    SubscriptionState::Canceling
                } else {
                    SubscriptionState::Active
                };

                if let Some(f) = fallback {
                    if self.fallback_earned_at.is_none()
                        && self.continuous_paid_months >= f.after_months
                    {
                        // Write-once: this is what makes replayed webhooks safe.
                        self.fallback_earned_at = Some(now);
                        out.fallback_earned = true;
                    }
                }
            }
            SubscriptionEvent::PaymentFailed => {
                if from == SubscriptionState::Active || from == SubscriptionState::Canceling {
                    self.state = SubscriptionState::PastDue;
                    self.dunning_until = Some(now.saturating_add(dunning_grace_secs));
                }
            }
            SubscriptionEvent::PaymentRecovered => {
                if from == SubscriptionState::PastDue {
                    self.state = if self.canceled_at.is_some() {
                        SubscriptionState::Canceling
                    } else {
                        SubscriptionState::Active
                    };
                    self.dunning_until = None;
                }
            }
            SubscriptionEvent::CancelAtPeriodEnd => {
                if matches!(from, SubscriptionState::Active | SubscriptionState::PastDue) {
                    self.state = SubscriptionState::Canceling;
                    self.canceled_at = Some(now);
                }
            }
            SubscriptionEvent::CancelReverted => {
                if from == SubscriptionState::Canceling {
                    self.state = SubscriptionState::Active;
                    self.canceled_at = None;
                }
            }
            SubscriptionEvent::PeriodElapsed => {
                if from == SubscriptionState::Canceling {
                    self.state = self.settle_ending();
                }
            }
            SubscriptionEvent::DunningElapsed => {
                if from == SubscriptionState::PastDue {
                    self.state = SubscriptionState::Suspended;
                    // An interruption breaks the streak (`licensing-model.md §5.1`). An
                    // already-earned fallback is untouched: it was earned.
                    if self.continuous_paid_months != 0 {
                        out.streak_reset = true;
                    }
                    self.continuous_paid_months = 0;
                }
            }
            SubscriptionEvent::FallbackRevoked => {
                // The refund and fraud path. Deliberately able to act on a terminal state.
                self.fallback_earned_at = None;
                if from == SubscriptionState::PerpetualFallback {
                    self.state = SubscriptionState::Expired;
                }
            }
            SubscriptionEvent::RefundReported => {
                self.dunning_until = None;
                self.state = if from == SubscriptionState::PerpetualFallback {
                    SubscriptionState::Expired
                } else {
                    SubscriptionState::Suspended
                };
            }
        }

        // A suspended subscription that reaches its period end is over.
        if self.state == SubscriptionState::Suspended
            && matches!(event, SubscriptionEvent::PeriodElapsed)
        {
            self.state = self.settle_ending();
        }

        self.updated_at = self.updated_at.max(now);
        self.processed_events.push(event_id.to_string());
        out.to = Some(self.state);
        out
    }

    /// Decide what an ending subscription becomes.
    fn settle_ending(&self) -> SubscriptionState {
        if self.fallback_earned_at.is_some() {
            SubscriptionState::PerpetualFallback
        } else {
            SubscriptionState::Expired
        }
    }

    /// The version cap a perpetual fallback confers, if earned.
    ///
    /// `EarnedAt` caps at the moment the fallback vested, so the customer keeps every version
    /// released while they were paying — and nothing after (`licensing-model.md §5`).
    #[must_use]
    pub fn fallback_version_cutoff(&self, fallback: Option<PerpetualFallback>) -> Option<i64> {
        let earned = self.fallback_earned_at?;
        match fallback?.scope_at {
            FallbackScopeAt::EarnedAt => Some(earned),
            FallbackScopeAt::SubscriptionStart => Some(self.current_period_start),
        }
    }

    /// Progress toward the fallback, for the in-app "N more months" message.
    #[must_use]
    pub fn fallback_progress(&self, fallback: Option<PerpetualFallback>) -> Option<(u32, u32)> {
        let f = fallback?;
        Some((self.continuous_paid_months, f.after_months))
    }

    /// Build the client-facing hint.
    #[must_use]
    pub fn hint(
        &self,
        fallback: Option<PerpetualFallback>,
    ) -> Option<copylocker_types::SubscriptionHint> {
        let state = self.state.to_hint()?;
        let progress = self.fallback_progress(fallback);
        Some(copylocker_types::SubscriptionHint {
            state,
            current_period_end: self.current_period_end,
            fallback_progress_months: progress.map(|(a, _)| a),
            fallback_required_months: progress.map(|(_, b)| b),
        })
    }
}

fn paid_months(period_start: i64, period_end: i64) -> u32 {
    let period_secs = period_end.saturating_sub(period_start).max(0);
    let months = period_secs / BILLING_MONTH_SECS;
    u32::try_from(months).unwrap_or(u32::MAX).max(1)
}

/// Preview what would happen if the subscription ended right now.
///
/// Backs `copylocker license preview-fallback`, so support can answer "what do I keep if I
/// cancel today?" without changing anything (`licensing-model.md §5.2`).
#[must_use]
pub fn preview_ending(
    sub: &Subscription,
    fallback: Option<PerpetualFallback>,
) -> (SubscriptionState, Option<i64>) {
    let end_state = sub.settle_ending();
    let cutoff = if end_state == SubscriptionState::PerpetualFallback {
        sub.fallback_version_cutoff(fallback)
    } else {
        None
    };
    (end_state, cutoff)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MONTH: i64 = 30 * 86_400;
    const START: i64 = 1_800_000_000;
    const DUNNING: i64 = 7 * 86_400;

    fn fallback_12() -> Option<PerpetualFallback> {
        Some(PerpetualFallback {
            after_months: 12,
            scope_at: FallbackScopeAt::EarnedAt,
        })
    }

    fn sub() -> Subscription {
        Subscription::new("stripe", "sub_123", START, START + MONTH)
    }

    /// Drive `n` successful renewals with distinct event ids.
    fn renew_n(s: &mut Subscription, n: u32, fb: Option<PerpetualFallback>) {
        for i in 0..n {
            let at = START + MONTH * i64::from(i + 1);
            s.apply(
                &alloc::format!("evt_renew_{i}"),
                &SubscriptionEvent::Renewed {
                    period_start: at,
                    period_end: at + MONTH,
                },
                fb,
                at,
                DUNNING,
            );
        }
    }

    #[test]
    fn a_new_subscription_is_active_and_usable() {
        let s = sub();
        assert_eq!(s.state, SubscriptionState::Active);
        assert!(s.is_usable_at(START));
    }

    #[test]
    fn payment_failure_enters_dunning_and_stays_usable() {
        // The whole point of dunning: a failed card must not lock the customer out instantly.
        let mut s = sub();
        s.apply(
            "e1",
            &SubscriptionEvent::PaymentFailed,
            None,
            START,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::PastDue);
        assert_eq!(s.dunning_until, Some(START + DUNNING));
        assert!(s.is_usable_at(START + DUNNING - 1));
        assert!(!s.is_usable_at(START + DUNNING), "dunning end is exclusive");
    }

    #[test]
    fn recovering_payment_returns_to_active() {
        let mut s = sub();
        s.apply(
            "e1",
            &SubscriptionEvent::PaymentFailed,
            None,
            START,
            DUNNING,
        );
        s.apply(
            "e2",
            &SubscriptionEvent::PaymentRecovered,
            None,
            START + 100,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::Active);
        assert_eq!(s.dunning_until, None);
    }

    #[test]
    fn recovering_payment_after_cancelling_returns_to_canceling_not_active() {
        let mut s = sub();
        s.apply(
            "e1",
            &SubscriptionEvent::CancelAtPeriodEnd,
            None,
            START,
            DUNNING,
        );
        s.apply(
            "e2",
            &SubscriptionEvent::PaymentFailed,
            None,
            START,
            DUNNING,
        );
        s.apply(
            "e3",
            &SubscriptionEvent::PaymentRecovered,
            None,
            START,
            DUNNING,
        );
        assert_eq!(
            s.state,
            SubscriptionState::Canceling,
            "recovering a payment must not silently un-cancel"
        );
    }

    #[test]
    fn dunning_expiry_suspends_and_stops_being_usable() {
        let mut s = sub();
        s.apply(
            "e1",
            &SubscriptionEvent::PaymentFailed,
            None,
            START,
            DUNNING,
        );
        s.apply(
            "e2",
            &SubscriptionEvent::DunningElapsed,
            None,
            START + DUNNING,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::Suspended);
        assert!(!s.is_usable_at(START + DUNNING));
    }

    #[test]
    fn cancelling_keeps_the_subscription_usable_until_the_period_ends() {
        let mut s = sub();
        s.apply(
            "e1",
            &SubscriptionEvent::CancelAtPeriodEnd,
            None,
            START,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::Canceling);
        assert!(s.is_usable_at(START + MONTH - 1));
        s.apply(
            "e2",
            &SubscriptionEvent::PeriodElapsed,
            None,
            START + MONTH,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::Expired);
        assert!(!s.is_usable_at(START + MONTH));
    }

    #[test]
    fn cancelling_can_be_reverted() {
        let mut s = sub();
        s.apply(
            "e1",
            &SubscriptionEvent::CancelAtPeriodEnd,
            None,
            START,
            DUNNING,
        );
        s.apply(
            "e2",
            &SubscriptionEvent::CancelReverted,
            None,
            START,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::Active);
        assert_eq!(s.canceled_at, None);
    }

    #[test]
    fn a_renewal_does_not_un_cancel() {
        let mut s = sub();
        s.apply(
            "e1",
            &SubscriptionEvent::CancelAtPeriodEnd,
            None,
            START,
            DUNNING,
        );
        s.apply(
            "e2",
            &SubscriptionEvent::Renewed {
                period_start: START + MONTH,
                period_end: START + 2 * MONTH,
            },
            None,
            START + MONTH,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::Canceling);
    }

    #[test]
    fn twelve_paid_months_earn_the_fallback_exactly_once() {
        let mut s = sub();
        renew_n(&mut s, 12, fallback_12());
        assert_eq!(s.continuous_paid_months, 12);
        let earned = s.fallback_earned_at.expect("fallback must be earned");

        // Another renewal must not move the earned timestamp.
        s.apply(
            "evt_renew_later",
            &SubscriptionEvent::Renewed {
                period_start: START + 13 * MONTH,
                period_end: START + 14 * MONTH,
            },
            fallback_12(),
            START + 13 * MONTH,
            DUNNING,
        );
        assert_eq!(
            s.fallback_earned_at,
            Some(earned),
            "earned_at is write-once"
        );
    }

    #[test]
    fn one_annual_renewal_counts_as_twelve_paid_months() {
        let mut s = Subscription::new("stripe", "sub_annual", START, START + 365 * 86_400);
        let out = s.apply(
            "annual_renewal",
            &SubscriptionEvent::Renewed {
                period_start: START + 365 * 86_400,
                period_end: START + 2 * 365 * 86_400,
            },
            fallback_12(),
            START + 365 * 86_400,
            DUNNING,
        );

        assert_eq!(s.continuous_paid_months, 12);
        assert_eq!(s.fallback_earned_at, Some(START + 365 * 86_400));
        assert!(out.fallback_earned);
    }

    #[test]
    fn eleven_months_do_not_earn_the_fallback() {
        let mut s = sub();
        renew_n(&mut s, 11, fallback_12());
        assert_eq!(s.fallback_earned_at, None);
    }

    #[test]
    fn a_lapse_resets_the_streak() {
        let mut s = sub();
        renew_n(&mut s, 11, fallback_12());
        assert_eq!(s.continuous_paid_months, 11);

        s.apply(
            "fail",
            &SubscriptionEvent::PaymentFailed,
            fallback_12(),
            START + 11 * MONTH,
            DUNNING,
        );
        let out = s.apply(
            "dunning",
            &SubscriptionEvent::DunningElapsed,
            fallback_12(),
            START + 11 * MONTH + DUNNING,
            DUNNING,
        );
        assert!(out.streak_reset);
        assert_eq!(s.continuous_paid_months, 0);
        assert_eq!(s.fallback_earned_at, None);
    }

    #[test]
    fn an_earned_fallback_survives_a_later_lapse() {
        // Earned is earned; a subsequent lapse ends the subscription but keeps the perpetual
        // grant.
        let mut s = sub();
        renew_n(&mut s, 12, fallback_12());
        let earned = s.fallback_earned_at;

        s.apply(
            "fail",
            &SubscriptionEvent::PaymentFailed,
            fallback_12(),
            START + 12 * MONTH,
            DUNNING,
        );
        s.apply(
            "dunning",
            &SubscriptionEvent::DunningElapsed,
            fallback_12(),
            START + 12 * MONTH + DUNNING,
            DUNNING,
        );
        assert_eq!(s.fallback_earned_at, earned);

        s.apply(
            "period",
            &SubscriptionEvent::PeriodElapsed,
            fallback_12(),
            START + 13 * MONTH,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::PerpetualFallback);
        assert!(s.is_usable_at(i64::MAX));
    }

    #[test]
    fn cancelling_after_earning_the_fallback_yields_a_perpetual_licence() {
        // The `sub-annual-fallback` scenario from `licensing-model.md §11`.
        let mut s = sub();
        renew_n(&mut s, 12, fallback_12());
        s.apply(
            "cancel",
            &SubscriptionEvent::CancelAtPeriodEnd,
            fallback_12(),
            START + 12 * MONTH,
            DUNNING,
        );
        s.apply(
            "end",
            &SubscriptionEvent::PeriodElapsed,
            fallback_12(),
            START + 13 * MONTH,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::PerpetualFallback);
        assert_eq!(
            s.fallback_version_cutoff(fallback_12()),
            s.fallback_earned_at
        );
    }

    #[test]
    fn every_event_is_byte_stable_across_three_replays() {
        // Each case starts in a state where the first delivery changes durable state. This keeps
        // the test from passing merely because an event happened to be inapplicable.
        let mut past_due = sub();
        past_due.apply(
            "setup_failed",
            &SubscriptionEvent::PaymentFailed,
            fallback_12(),
            START + 1,
            DUNNING,
        );

        let mut canceling = sub();
        canceling.apply(
            "setup_cancel",
            &SubscriptionEvent::CancelAtPeriodEnd,
            fallback_12(),
            START + 1,
            DUNNING,
        );

        let mut suspended = past_due.clone();
        suspended.apply(
            "setup_dunning",
            &SubscriptionEvent::DunningElapsed,
            fallback_12(),
            START + DUNNING + 1,
            DUNNING,
        );

        let mut perpetual = sub();
        perpetual.state = SubscriptionState::PerpetualFallback;
        perpetual.fallback_earned_at = Some(START);

        let cases = [
            (
                "renewed",
                sub(),
                SubscriptionEvent::Renewed {
                    period_start: START + MONTH,
                    period_end: START + 2 * MONTH,
                },
                START + MONTH,
            ),
            (
                "payment_failed",
                sub(),
                SubscriptionEvent::PaymentFailed,
                START + 1,
            ),
            (
                "payment_recovered",
                past_due.clone(),
                SubscriptionEvent::PaymentRecovered,
                START + 2,
            ),
            (
                "cancel_at_period_end",
                sub(),
                SubscriptionEvent::CancelAtPeriodEnd,
                START + 1,
            ),
            (
                "cancel_reverted",
                canceling.clone(),
                SubscriptionEvent::CancelReverted,
                START + 2,
            ),
            (
                "period_elapsed",
                canceling,
                SubscriptionEvent::PeriodElapsed,
                START + MONTH,
            ),
            (
                "dunning_elapsed",
                past_due,
                SubscriptionEvent::DunningElapsed,
                START + DUNNING + 1,
            ),
            (
                "reactivated",
                suspended,
                SubscriptionEvent::Reactivated {
                    period_start: START + 2 * MONTH,
                    period_end: START + 3 * MONTH,
                },
                START + 2 * MONTH,
            ),
            (
                "fallback_revoked",
                perpetual,
                SubscriptionEvent::FallbackRevoked,
                START + 1,
            ),
            (
                "refund_reported",
                sub(),
                SubscriptionEvent::RefundReported,
                START + 1,
            ),
        ];

        for (name, mut subscription, event, now) in cases {
            let before = alloc::format!("{subscription:?}").into_bytes();
            let first = subscription.apply("subject", &event, fallback_12(), now, DUNNING);
            assert!(first.applied, "{name}: first delivery was not applied");

            let snapshot = subscription.clone();
            let snapshot_bytes = alloc::format!("{snapshot:?}").into_bytes();
            assert_ne!(
                before, snapshot_bytes,
                "{name}: first delivery did not change durable state"
            );

            for replay in 1..=3 {
                let again = subscription.apply("subject", &event, fallback_12(), now, DUNNING);
                assert!(!again.applied, "{name}: replay {replay} was applied");
                assert_eq!(
                    alloc::format!("{subscription:?}").into_bytes(),
                    snapshot_bytes,
                    "{name}: replay {replay} changed the state bytes"
                );
                assert_eq!(
                    subscription, snapshot,
                    "{name}: replay {replay} changed state"
                );
            }
        }
    }

    #[test]
    fn an_out_of_order_event_cannot_roll_state_backward() {
        let mut s = sub();
        s.apply(
            "newer_renewal",
            &SubscriptionEvent::Renewed {
                period_start: START + 2 * MONTH,
                period_end: START + 3 * MONTH,
            },
            fallback_12(),
            START + 2 * MONTH,
            DUNNING,
        );
        let snapshot = s.clone();

        let stale = s.apply(
            "older_failure",
            &SubscriptionEvent::PaymentFailed,
            fallback_12(),
            START + MONTH,
            DUNNING,
        );

        assert!(!stale.applied);
        assert!(stale.stale);
        assert_eq!(s.state, SubscriptionState::Active);
        assert_eq!(s.current_period_start, snapshot.current_period_start);
        assert_eq!(s.current_period_end, snapshot.current_period_end);
        assert_eq!(s.updated_at, snapshot.updated_at);
        assert!(s
            .processed_events
            .iter()
            .any(|event| event == "older_failure"));
    }

    #[test]
    fn a_late_fallback_revocation_is_never_ignored_as_stale() {
        let mut s = sub();
        renew_n(&mut s, 12, fallback_12());
        let latest_update = s.updated_at;

        let revoked = s.apply(
            "older_refund",
            &SubscriptionEvent::FallbackRevoked,
            fallback_12(),
            START,
            DUNNING,
        );

        assert!(revoked.applied);
        assert!(!revoked.stale);
        assert_eq!(s.fallback_earned_at, None);
        assert_eq!(s.updated_at, latest_update);
    }

    #[test]
    fn replaying_renewals_cannot_award_the_fallback_early() {
        // The failure this idempotence exists to prevent.
        let mut s = sub();
        for _ in 0..20 {
            s.apply(
                "evt_same",
                &SubscriptionEvent::Renewed {
                    period_start: START + MONTH,
                    period_end: START + 2 * MONTH,
                },
                fallback_12(),
                START + MONTH,
                DUNNING,
            );
        }
        assert_eq!(s.continuous_paid_months, 1);
        assert_eq!(s.fallback_earned_at, None);
    }

    #[test]
    fn a_refund_revokes_an_earned_fallback() {
        let mut s = sub();
        renew_n(&mut s, 12, fallback_12());
        s.apply(
            "end",
            &SubscriptionEvent::PeriodElapsed,
            fallback_12(),
            START + 13 * MONTH,
            DUNNING,
        );
        // Reaching `PerpetualFallback` requires having cancelled first; force the state to
        // exercise revocation from it directly.
        s.state = SubscriptionState::PerpetualFallback;
        s.apply(
            "refund",
            &SubscriptionEvent::FallbackRevoked,
            fallback_12(),
            START + 14 * MONTH,
            DUNNING,
        );
        assert_eq!(s.fallback_earned_at, None);
        assert_eq!(s.state, SubscriptionState::Expired);
        assert!(!s.is_usable_at(START + 14 * MONTH));
    }

    #[test]
    fn a_refund_report_suspends_during_the_review_window() {
        let mut s = sub();
        let out = s.apply(
            "refund_reported",
            &SubscriptionEvent::RefundReported,
            fallback_12(),
            START + 1,
            DUNNING,
        );

        assert!(out.applied);
        assert_eq!(s.state, SubscriptionState::Suspended);
        assert!(!s.is_usable_at(START + 1));
    }

    #[test]
    fn a_suspended_subscription_can_be_reactivated() {
        let mut s = sub();
        s.apply("f", &SubscriptionEvent::PaymentFailed, None, START, DUNNING);
        s.apply(
            "d",
            &SubscriptionEvent::DunningElapsed,
            None,
            START + DUNNING,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::Suspended);
        s.apply(
            "r",
            &SubscriptionEvent::Reactivated {
                period_start: START + 2 * MONTH,
                period_end: START + 3 * MONTH,
            },
            None,
            START + 2 * MONTH,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::Active);
        assert_eq!(s.continuous_paid_months, 1, "the streak restarts from zero");
    }

    #[test]
    fn terminal_states_absorb_further_events() {
        let mut s = sub();
        s.apply(
            "c",
            &SubscriptionEvent::CancelAtPeriodEnd,
            None,
            START,
            DUNNING,
        );
        s.apply(
            "p",
            &SubscriptionEvent::PeriodElapsed,
            None,
            START + MONTH,
            DUNNING,
        );
        assert_eq!(s.state, SubscriptionState::Expired);
        let out = s.apply(
            "renew_after_death",
            &SubscriptionEvent::Renewed {
                period_start: START + 2 * MONTH,
                period_end: START + 3 * MONTH,
            },
            None,
            START + 2 * MONTH,
            DUNNING,
        );
        assert!(!out.applied);
        assert_eq!(s.state, SubscriptionState::Expired);
    }

    #[test]
    fn preview_reports_what_cancelling_now_would_yield() {
        let mut s = sub();
        renew_n(&mut s, 11, fallback_12());
        assert_eq!(
            preview_ending(&s, fallback_12()),
            (SubscriptionState::Expired, None)
        );

        renew_n(&mut s, 12, fallback_12());
        let (state, cutoff) = preview_ending(&s, fallback_12());
        assert_eq!(state, SubscriptionState::PerpetualFallback);
        assert_eq!(cutoff, s.fallback_earned_at);
    }

    #[test]
    fn the_client_hint_reports_progress_toward_the_fallback() {
        let mut s = sub();
        renew_n(&mut s, 9, fallback_12());
        let h = s.hint(fallback_12()).expect("active subs get a hint");
        assert_eq!(h.state, copylocker_types::SubscriptionState::Active);
        assert_eq!(h.fallback_progress_months, Some(9));
        assert_eq!(h.fallback_required_months, Some(12));
        assert_eq!(h.current_period_end, s.current_period_end);
    }

    #[test]
    fn ended_states_produce_no_hint() {
        let mut s = sub();
        s.state = SubscriptionState::Expired;
        assert!(s.hint(fallback_12()).is_none());
    }

    #[test]
    fn subscription_start_scoping_caps_at_the_period_start() {
        let mut s = sub();
        let fb = Some(PerpetualFallback {
            after_months: 12,
            scope_at: FallbackScopeAt::SubscriptionStart,
        });
        renew_n(&mut s, 12, fb);
        assert_eq!(s.fallback_version_cutoff(fb), Some(s.current_period_start));
    }

    #[test]
    fn every_state_is_reachable_and_classified() {
        for st in [
            SubscriptionState::Active,
            SubscriptionState::PastDue,
            SubscriptionState::Canceling,
            SubscriptionState::PerpetualFallback,
        ] {
            assert!(st.is_usable(), "{st:?} should be usable");
        }
        for st in [
            SubscriptionState::Suspended,
            SubscriptionState::Ended,
            SubscriptionState::Expired,
        ] {
            assert!(!st.is_usable(), "{st:?} should not be usable");
        }
        assert!(SubscriptionState::Expired.is_terminal());
        assert!(SubscriptionState::PerpetualFallback.is_terminal());
        assert!(!SubscriptionState::Active.is_terminal());
    }
}
