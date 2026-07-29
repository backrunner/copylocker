//! The client state machine (`system-architecture.md §6`).
//!
//! Written as an exhaustive `match` over `(state, event)` with **no wildcard arms**. Adding a
//! state or an event then breaks the build until every new combination has been considered,
//! which is the point: the dangerous transitions here are the ones nobody thought about
//! (`20-client-core.md §1.2`).
//!
//! # The transition table
//!
//! | Event | Active | NeedsRevalidation | Grace | Locked |
//! |---|---|---|---|---|
//! | validation ok | → Active | → Active | → Active | → Active |
//! | kill order | → Revoked (wipe) | → Revoked | → Revoked | → Revoked |
//! | signature invalid | → Tampered | → Tampered | → Tampered | → Tampered |
//! | network failed | — | → Grace | — | — |
//! | reached refresh_after | → NeedsRevalidation | — | — | — |
//! | reached grace deadline | → Locked | → Locked | → Locked | — |
//! | clock rollback | → NeedsRevalidation | — | — | — |

use alloc::vec::Vec;

use copylocker_types::{KillReason, LicenseState, StateReason, Verdict};

use crate::clock::{ClockState, ClockVerdict, DEFAULT_ROLLBACK_THRESHOLD};
use crate::error::{FatalError, TransientError};

/// Deadlines the state machine reasons about, taken from the stored credential.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Deadlines {
    /// When an online validation becomes due.
    pub refresh_after: i64,
    /// When the grace window closes.
    pub grace_deadline: i64,
    /// Hard expiry; `0` means unlimited.
    pub not_after: i64,
}

impl Deadlines {
    /// Whether a refresh is due at `now`.
    #[must_use]
    pub const fn refresh_due(&self, now: i64) -> bool {
        now >= self.refresh_after
    }

    /// Whether the credential has run out entirely at `now`.
    #[must_use]
    pub const fn hard_expired(&self, now: i64) -> bool {
        self.not_after != 0 && now >= self.not_after
    }

    /// Whether the grace window has closed at `now`.
    #[must_use]
    pub const fn grace_exhausted(&self, now: i64) -> bool {
        now >= self.grace_deadline || self.hard_expired(now)
    }
}

/// Something that happened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Event {
    /// Periodic tick.
    Tick,
    /// The network became available.
    NetworkAvailable,
    /// The application resumed from suspend.
    AppResumed {
        /// Monotonic milliseconds spent suspended.
        monotonic_gap_ms: u64,
    },
    /// A credential was loaded from storage.
    CredentialLoaded,
    /// An activation completed and was verified.
    ActivationVerified,
    /// A validation ticket was received and verified.
    TicketVerified,
    /// A valid validation ticket denied productive use without indicating tampering.
    TicketDenied(Verdict),
    /// A verified kill order was received.
    KillOrderVerified(KillReason),
    /// A request failed for transient reasons.
    NetworkFailed(TransientError),
    /// A cryptographic, chain, or integrity check failed.
    VerificationFailed(FatalError),
    /// The user asked to deactivate.
    UserDeactivate,
}

/// Something the host must do.
///
/// The core performs no I/O itself; it returns intentions and the shell carries them out. That
/// is what keeps the whole state machine deterministic and replayable
/// (`20-client-core.md §1`).
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Effect {
    /// Persist the given opaque blob.
    Persist(Vec<u8>),
    /// Send a validation request.
    SendValidation,
    /// Erase every stored credential and derived key.
    WipeAll,
    /// The state changed.
    StateChanged(LicenseState, StateReason),
    /// Wake the client at this instant.
    ScheduleWake {
        /// When.
        at: i64,
    },
}

/// Tuning for the state machine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CoreConfig {
    /// Rollbacks tolerated before locking when offline.
    pub rollback_threshold: u32,
    /// Minimum seconds between opportunistic validations, so instrumented call sites cannot
    /// stampede the server (`20-client-core.md §1.4`).
    pub min_validation_interval_secs: i64,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            rollback_threshold: DEFAULT_ROLLBACK_THRESHOLD,
            min_validation_interval_secs: 60,
        }
    }
}

/// The client state machine.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StateMachine {
    state: LicenseState,
    clock: ClockState,
    deadlines: Deadlines,
    config: CoreConfig,
    last_validation_attempt: i64,
    has_credential: bool,
}

impl StateMachine {
    /// Start with no credential.
    #[must_use]
    pub fn new(config: CoreConfig, seed_time: i64) -> Self {
        Self {
            state: LicenseState::Unlicensed,
            clock: ClockState::new(seed_time),
            deadlines: Deadlines::default(),
            config,
            last_validation_attempt: i64::MIN,
            has_credential: false,
        }
    }

    /// Current state.
    ///
    /// ⚠️ **Advisory only. Do NOT gate features on this value — use a feature key.**
    /// A `bool` or enum comparison is one patched instruction; deriving a key that actually
    /// decrypts something is not (ADR-0004).
    #[must_use]
    pub const fn state(&self) -> LicenseState {
        self.state
    }

    /// Clock guard state.
    #[must_use]
    pub const fn clock(&self) -> &ClockState {
        &self.clock
    }

    /// Mutable clock guard, for merging state loaded from redundant storage.
    pub fn clock_mut(&mut self) -> &mut ClockState {
        &mut self.clock
    }

    /// Current deadlines.
    #[must_use]
    pub const fn deadlines(&self) -> Deadlines {
        self.deadlines
    }

    /// Install deadlines from a freshly verified credential or ticket.
    pub fn set_deadlines(&mut self, d: Deadlines) {
        self.deadlines = d;
    }

    /// Whether a credential is held.
    #[must_use]
    pub const fn has_credential(&self) -> bool {
        self.has_credential
    }

    /// Handle an event.
    ///
    /// `wall_clock` is passed in rather than read: the core has no clock of its own, which is
    /// what makes every transition reproducible in a test and drivable by a fuzzer.
    pub fn handle(&mut self, event: Event, wall_clock: i64) -> Vec<Effect> {
        let mut effects = Vec::new();

        // The clock guard runs first for time-driven events. A rollback must be caught before
        // any deadline is evaluated, or the rolled-back reading would be used.
        let now = match event {
            Event::Tick | Event::AppResumed { .. } => {
                match self.clock.check(wall_clock) {
                    ClockVerdict::Rollback { .. } | ClockVerdict::ImplausibleJump { .. } => {
                        // Rule 2: force a revalidation. Rule 3: if rollbacks keep coming and we
                        // cannot reach the server, lock (`20-client-core.md §1.3`).
                        if self
                            .clock
                            .exceeds_rollback_threshold(self.config.rollback_threshold)
                        {
                            return self
                                .transition(LicenseState::Locked, StateReason::ClockRollback);
                        }
                        if self.state == LicenseState::Active {
                            let mut e = self.transition(
                                LicenseState::NeedsRevalidation,
                                StateReason::ClockRollback,
                            );
                            e.push(Effect::SendValidation);
                            return e;
                        }
                        self.clock.effective_now(wall_clock)
                    }
                    ClockVerdict::Ok => self.clock.effective_now(wall_clock),
                }
            }
            _ => self.clock.effective_now(wall_clock),
        };

        match (self.state, event) {
            // --- Unlicensed ---
            (LicenseState::Unlicensed, Event::CredentialLoaded)
            | (LicenseState::Unlicensed, Event::ActivationVerified) => {
                self.has_credential = true;
                effects.extend(self.transition(LicenseState::Active, StateReason::Activated));
                effects.push(Effect::ScheduleWake {
                    at: self.deadlines.refresh_after,
                });
            }
            (LicenseState::Unlicensed, Event::VerificationFailed(_)) => {
                effects
                    .extend(self.transition(LicenseState::Tampered, StateReason::IntegrityFailure));
            }
            (LicenseState::Unlicensed, Event::Tick)
            | (LicenseState::Unlicensed, Event::NetworkAvailable)
            | (LicenseState::Unlicensed, Event::AppResumed { .. })
            | (LicenseState::Unlicensed, Event::NetworkFailed(_))
            | (LicenseState::Unlicensed, Event::TicketVerified)
            | (LicenseState::Unlicensed, Event::TicketDenied(_))
            | (LicenseState::Unlicensed, Event::UserDeactivate) => {}
            (LicenseState::Unlicensed, Event::KillOrderVerified(r)) => {
                effects.extend(self.revoke(r));
            }

            // --- Activating ---
            (LicenseState::Activating, Event::ActivationVerified) => {
                self.has_credential = true;
                effects.extend(self.transition(LicenseState::Active, StateReason::Activated));
                effects.push(Effect::ScheduleWake {
                    at: self.deadlines.refresh_after,
                });
            }
            (LicenseState::Activating, Event::NetworkFailed(_)) => {
                effects.extend(
                    self.transition(LicenseState::Unlicensed, StateReason::NetworkUnavailable),
                );
            }
            (LicenseState::Activating, Event::VerificationFailed(_)) => {
                effects
                    .extend(self.transition(LicenseState::Tampered, StateReason::IntegrityFailure));
            }
            (LicenseState::Activating, Event::KillOrderVerified(r)) => {
                effects.extend(self.revoke(r));
            }
            (LicenseState::Activating, Event::Tick)
            | (LicenseState::Activating, Event::NetworkAvailable)
            | (LicenseState::Activating, Event::AppResumed { .. })
            | (LicenseState::Activating, Event::CredentialLoaded)
            | (LicenseState::Activating, Event::TicketVerified)
            | (LicenseState::Activating, Event::TicketDenied(_)) => {}
            (LicenseState::Activating, Event::UserDeactivate) => {
                effects.extend(self.wipe(StateReason::UserRequested));
            }

            // --- Active ---
            (LicenseState::Active, Event::Tick)
            | (LicenseState::Active, Event::AppResumed { .. }) => {
                if self.deadlines.hard_expired(now) {
                    effects.extend(
                        self.transition(LicenseState::Locked, StateReason::CredentialExpired),
                    );
                } else if self.deadlines.refresh_due(now) {
                    effects.extend(
                        self.transition(LicenseState::NeedsRevalidation, StateReason::RefreshDue),
                    );
                    effects.push(Effect::SendValidation);
                    self.last_validation_attempt = now;
                }
            }
            (LicenseState::Active, Event::NetworkAvailable) => {
                if self.should_opportunistically_validate(now) {
                    effects.push(Effect::SendValidation);
                    self.last_validation_attempt = now;
                }
            }
            (LicenseState::Active, Event::TicketVerified) => {
                effects.extend(self.accept_ticket());
            }
            (LicenseState::Active, Event::TicketDenied(verdict)) => {
                effects.extend(self.deny_ticket(verdict));
            }
            // A network failure while still inside the refresh window changes nothing: there is
            // no need to validate yet, so there is nothing to fail.
            (LicenseState::Active, Event::NetworkFailed(_)) => {}
            (LicenseState::Active, Event::KillOrderVerified(r)) => {
                effects.extend(self.revoke(r));
            }
            (LicenseState::Active, Event::VerificationFailed(_)) => {
                effects.extend(self.tamper());
            }
            (LicenseState::Active, Event::UserDeactivate) => {
                effects.extend(self.wipe(StateReason::UserRequested));
            }
            (LicenseState::Active, Event::CredentialLoaded)
            | (LicenseState::Active, Event::ActivationVerified) => {}

            // --- NeedsRevalidation ---
            (LicenseState::NeedsRevalidation, Event::TicketVerified) => {
                effects.extend(self.accept_ticket());
            }
            (LicenseState::NeedsRevalidation, Event::TicketDenied(verdict)) => {
                effects.extend(self.deny_ticket(verdict));
            }
            (LicenseState::NeedsRevalidation, Event::NetworkFailed(_)) => {
                // The fail-open branch: a transient failure buys the grace window.
                if self.deadlines.grace_exhausted(now) {
                    effects
                        .extend(self.transition(LicenseState::Locked, StateReason::GraceExhausted));
                } else {
                    effects.extend(
                        self.transition(LicenseState::Grace, StateReason::NetworkUnavailable),
                    );
                    effects.push(Effect::ScheduleWake {
                        at: self.deadlines.grace_deadline,
                    });
                }
            }
            (LicenseState::NeedsRevalidation, Event::Tick)
            | (LicenseState::NeedsRevalidation, Event::AppResumed { .. }) => {
                if self.deadlines.grace_exhausted(now) {
                    effects
                        .extend(self.transition(LicenseState::Locked, StateReason::GraceExhausted));
                }
            }
            (LicenseState::NeedsRevalidation, Event::NetworkAvailable) => {
                effects.push(Effect::SendValidation);
                self.last_validation_attempt = now;
            }
            (LicenseState::NeedsRevalidation, Event::KillOrderVerified(r)) => {
                effects.extend(self.revoke(r));
            }
            (LicenseState::NeedsRevalidation, Event::VerificationFailed(_)) => {
                effects.extend(self.tamper());
            }
            (LicenseState::NeedsRevalidation, Event::UserDeactivate) => {
                effects.extend(self.wipe(StateReason::UserRequested));
            }
            (LicenseState::NeedsRevalidation, Event::CredentialLoaded)
            | (LicenseState::NeedsRevalidation, Event::ActivationVerified) => {}

            // --- Grace ---
            (LicenseState::Grace, Event::TicketVerified) => {
                effects.extend(self.accept_ticket());
            }
            (LicenseState::Grace, Event::TicketDenied(verdict)) => {
                effects.extend(self.deny_ticket(verdict));
            }
            (LicenseState::Grace, Event::Tick)
            | (LicenseState::Grace, Event::AppResumed { .. }) => {
                if self.deadlines.grace_exhausted(now) {
                    effects
                        .extend(self.transition(LicenseState::Locked, StateReason::GraceExhausted));
                }
            }
            (LicenseState::Grace, Event::NetworkAvailable) => {
                effects.push(Effect::SendValidation);
                self.last_validation_attempt = now;
            }
            // Already in grace; another failure changes nothing but the clock.
            (LicenseState::Grace, Event::NetworkFailed(_)) => {}
            (LicenseState::Grace, Event::KillOrderVerified(r)) => {
                effects.extend(self.revoke(r));
            }
            (LicenseState::Grace, Event::VerificationFailed(_)) => {
                effects.extend(self.tamper());
            }
            (LicenseState::Grace, Event::UserDeactivate) => {
                effects.extend(self.wipe(StateReason::UserRequested));
            }
            (LicenseState::Grace, Event::CredentialLoaded)
            | (LicenseState::Grace, Event::ActivationVerified) => {}

            // --- Locked ---
            (LicenseState::Locked, Event::TicketVerified) => {
                // Recoverable: a successful online check restores service.
                effects.extend(self.accept_ticket());
            }
            (LicenseState::Locked, Event::TicketDenied(verdict)) => {
                effects.extend(self.deny_ticket(verdict));
            }
            (LicenseState::Locked, Event::NetworkAvailable) => {
                effects.push(Effect::SendValidation);
                self.last_validation_attempt = now;
            }
            (LicenseState::Locked, Event::KillOrderVerified(r)) => {
                effects.extend(self.revoke(r));
            }
            (LicenseState::Locked, Event::VerificationFailed(_)) => {
                effects.extend(self.tamper());
            }
            (LicenseState::Locked, Event::UserDeactivate) => {
                effects.extend(self.wipe(StateReason::UserRequested));
            }
            (LicenseState::Locked, Event::Tick)
            | (LicenseState::Locked, Event::AppResumed { .. })
            | (LicenseState::Locked, Event::NetworkFailed(_))
            | (LicenseState::Locked, Event::CredentialLoaded)
            | (LicenseState::Locked, Event::ActivationVerified) => {}

            // --- Revoked ---
            // Terminal until the user activates afresh. A revoked client must not be able to
            // talk its way back with a ticket.
            (LicenseState::Revoked, Event::ActivationVerified) => {
                self.has_credential = true;
                effects.extend(self.transition(LicenseState::Active, StateReason::Activated));
            }
            (LicenseState::Revoked, Event::Tick)
            | (LicenseState::Revoked, Event::NetworkAvailable)
            | (LicenseState::Revoked, Event::AppResumed { .. })
            | (LicenseState::Revoked, Event::CredentialLoaded)
            | (LicenseState::Revoked, Event::TicketVerified)
            | (LicenseState::Revoked, Event::TicketDenied(_))
            | (LicenseState::Revoked, Event::NetworkFailed(_))
            | (LicenseState::Revoked, Event::VerificationFailed(_))
            | (LicenseState::Revoked, Event::KillOrderVerified(_))
            | (LicenseState::Revoked, Event::UserDeactivate) => {}

            // --- Tampered ---
            // Terminal. Only a fresh activation clears it, and even that requires the integrity
            // problem to have been resolved first.
            (LicenseState::Tampered, Event::ActivationVerified) => {
                self.has_credential = true;
                effects.extend(self.transition(LicenseState::Active, StateReason::Activated));
            }
            (LicenseState::Tampered, Event::Tick)
            | (LicenseState::Tampered, Event::NetworkAvailable)
            | (LicenseState::Tampered, Event::AppResumed { .. })
            | (LicenseState::Tampered, Event::CredentialLoaded)
            | (LicenseState::Tampered, Event::TicketVerified)
            | (LicenseState::Tampered, Event::TicketDenied(_))
            | (LicenseState::Tampered, Event::NetworkFailed(_))
            | (LicenseState::Tampered, Event::VerificationFailed(_))
            | (LicenseState::Tampered, Event::KillOrderVerified(_))
            | (LicenseState::Tampered, Event::UserDeactivate) => {}
        }

        effects
    }

    /// Whether a Feature Key may be derived right now.
    ///
    /// Advisory for callers; the authoritative check happens inside key derivation itself.
    #[must_use]
    pub const fn permits_key_derivation(&self) -> bool {
        self.has_credential && self.state.permits_key_derivation()
    }

    /// Whether an opportunistic validation is due, respecting the minimum interval.
    #[must_use]
    pub fn should_opportunistically_validate(&self, now: i64) -> bool {
        if self.deadlines.refresh_due(now) {
            return true;
        }
        now.saturating_sub(self.last_validation_attempt) >= self.config.min_validation_interval_secs
            && self.state != LicenseState::Active
    }

    /// Note that a validation was attempted, for interval throttling.
    pub fn note_validation_attempt(&mut self, now: i64) {
        self.last_validation_attempt = now;
    }

    fn transition(&mut self, to: LicenseState, reason: StateReason) -> Vec<Effect> {
        if self.state == to {
            return Vec::new();
        }
        self.state = to;
        alloc::vec![Effect::StateChanged(to, reason)]
    }

    fn accept_ticket(&mut self) -> Vec<Effect> {
        let mut e = self.transition(LicenseState::Active, StateReason::Validated);
        e.push(Effect::ScheduleWake {
            at: self.deadlines.refresh_after,
        });
        e
    }

    fn deny_ticket(&mut self, verdict: Verdict) -> Vec<Effect> {
        let reason = match verdict {
            Verdict::Ok => StateReason::Validated,
            Verdict::NeedsReactivation => StateReason::ReactivationRequired,
            Verdict::VersionOutOfScope => StateReason::VersionOutOfScope,
        };
        self.transition(LicenseState::Locked, reason)
    }

    fn revoke(&mut self, reason: KillReason) -> Vec<Effect> {
        self.has_credential = false;
        let mut e = alloc::vec![Effect::WipeAll];
        self.state = LicenseState::Revoked;
        e.push(Effect::StateChanged(
            LicenseState::Revoked,
            StateReason::KillOrder(reason),
        ));
        e
    }

    fn tamper(&mut self) -> Vec<Effect> {
        self.has_credential = false;
        let mut e = alloc::vec![Effect::WipeAll];
        self.state = LicenseState::Tampered;
        e.push(Effect::StateChanged(
            LicenseState::Tampered,
            StateReason::IntegrityFailure,
        ));
        e
    }

    fn wipe(&mut self, reason: StateReason) -> Vec<Effect> {
        self.has_credential = false;
        self.state = LicenseState::Unlicensed;
        alloc::vec![
            Effect::WipeAll,
            Effect::StateChanged(LicenseState::Unlicensed, reason),
        ]
    }
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000;
    const REFRESH: i64 = 7 * 86_400;
    const GRACE: i64 = 14 * 86_400;

    fn deadlines() -> Deadlines {
        Deadlines {
            refresh_after: T0 + REFRESH,
            grace_deadline: T0 + REFRESH + GRACE,
            not_after: T0 + 365 * 86_400,
        }
    }

    /// A machine holding a fresh credential.
    fn active() -> StateMachine {
        let mut m = StateMachine::new(CoreConfig::default(), T0);
        m.set_deadlines(deadlines());
        m.handle(Event::CredentialLoaded, T0);
        assert_eq!(m.state(), LicenseState::Active);
        m
    }

    fn states(effects: &[Effect]) -> Vec<LicenseState> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::StateChanged(s, _) => Some(*s),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn loading_a_credential_activates_and_schedules_the_next_check() {
        let mut m = StateMachine::new(CoreConfig::default(), T0);
        m.set_deadlines(deadlines());
        let e = m.handle(Event::CredentialLoaded, T0);
        assert_eq!(states(&e), [LicenseState::Active]);
        assert!(e.contains(&Effect::ScheduleWake { at: T0 + REFRESH }));
        assert!(m.permits_key_derivation());
    }

    #[test]
    fn reaching_the_refresh_deadline_requests_a_validation() {
        let mut m = active();
        assert!(m.handle(Event::Tick, T0 + REFRESH - 1).is_empty());
        let e = m.handle(Event::Tick, T0 + REFRESH);
        assert_eq!(states(&e), [LicenseState::NeedsRevalidation]);
        assert!(e.contains(&Effect::SendValidation));
        assert!(
            m.permits_key_derivation(),
            "a pending refresh must not stop the app working"
        );
    }

    #[test]
    fn a_network_failure_before_the_refresh_is_due_changes_nothing() {
        let mut m = active();
        assert!(m
            .handle(Event::NetworkFailed(TransientError::Offline), T0 + 100)
            .is_empty());
        assert_eq!(m.state(), LicenseState::Active);
    }

    #[test]
    fn a_network_failure_at_refresh_time_opens_the_grace_window() {
        // The fail-open path.
        let mut m = active();
        m.handle(Event::Tick, T0 + REFRESH);
        let e = m.handle(Event::NetworkFailed(TransientError::Offline), T0 + REFRESH);
        assert_eq!(states(&e), [LicenseState::Grace]);
        assert!(e.contains(&Effect::ScheduleWake {
            at: T0 + REFRESH + GRACE
        }));
        assert!(m.permits_key_derivation(), "grace means keep working");
    }

    #[test]
    fn a_server_error_is_treated_exactly_like_being_offline() {
        // The rule that keeps an outage from becoming a mass lockout.
        for err in [
            TransientError::Offline,
            TransientError::Timeout,
            TransientError::ServerError(500),
            TransientError::ServerError(503),
            TransientError::TransportFailure,
            TransientError::RateLimited { retry_after: 60 },
        ] {
            let mut m = active();
            m.handle(Event::Tick, T0 + REFRESH);
            m.handle(Event::NetworkFailed(err), T0 + REFRESH);
            assert_eq!(m.state(), LicenseState::Grace, "{err:?} must fail open");
            assert!(m.permits_key_derivation());
        }
    }

    #[test]
    fn the_grace_window_eventually_locks() {
        let mut m = active();
        m.handle(Event::Tick, T0 + REFRESH);
        m.handle(Event::NetworkFailed(TransientError::Offline), T0 + REFRESH);
        assert!(m.handle(Event::Tick, T0 + REFRESH + GRACE - 1).is_empty());
        let e = m.handle(Event::Tick, T0 + REFRESH + GRACE);
        assert_eq!(states(&e), [LicenseState::Locked]);
        assert!(!m.permits_key_derivation());
    }

    #[test]
    fn a_successful_validation_restores_service_from_any_recoverable_state() {
        for setup in [
            LicenseState::NeedsRevalidation,
            LicenseState::Grace,
            LicenseState::Locked,
        ] {
            let mut m = active();
            // Drive to the target state.
            m.handle(Event::Tick, T0 + REFRESH);
            if setup != LicenseState::NeedsRevalidation {
                m.handle(Event::NetworkFailed(TransientError::Offline), T0 + REFRESH);
            }
            if setup == LicenseState::Locked {
                m.handle(Event::Tick, T0 + REFRESH + GRACE);
            }
            assert_eq!(m.state(), setup);

            m.set_deadlines(Deadlines {
                refresh_after: T0 + 2 * REFRESH,
                grace_deadline: T0 + 2 * REFRESH + GRACE,
                not_after: T0 + 365 * 86_400,
            });
            let e = m.handle(Event::TicketVerified, T0 + REFRESH + GRACE);
            assert_eq!(states(&e), [LicenseState::Active], "from {setup:?}");
            assert!(m.permits_key_derivation());
        }
    }

    #[test]
    fn a_denied_ticket_locks_without_treating_the_client_as_tampered() {
        for (verdict, reason) in [
            (
                Verdict::NeedsReactivation,
                StateReason::ReactivationRequired,
            ),
            (Verdict::VersionOutOfScope, StateReason::VersionOutOfScope),
        ] {
            let mut machine = active();
            let effects = machine.handle(Event::TicketDenied(verdict), T0 + 1);
            assert!(effects.contains(&Effect::StateChanged(LicenseState::Locked, reason)));
            assert!(!effects.contains(&Effect::WipeAll));
            assert!(machine.has_credential());
            assert!(!machine.permits_key_derivation());

            machine.handle(Event::TicketVerified, T0 + 2);
            assert_eq!(machine.state(), LicenseState::Active);
            assert!(machine.permits_key_derivation());
        }
    }

    #[test]
    fn a_locked_client_cannot_reach_active_without_going_online() {
        // The invariant from `20-client-core.md §5`.
        let mut m = active();
        m.handle(Event::Tick, T0 + REFRESH);
        m.handle(Event::NetworkFailed(TransientError::Offline), T0 + REFRESH);
        m.handle(Event::Tick, T0 + REFRESH + GRACE);
        assert_eq!(m.state(), LicenseState::Locked);

        for offline_event in [
            Event::Tick,
            Event::AppResumed {
                monotonic_gap_ms: 1_000,
            },
            Event::NetworkFailed(TransientError::Offline),
            Event::CredentialLoaded,
        ] {
            m.handle(offline_event, T0 + REFRESH + GRACE + 1);
            assert_eq!(
                m.state(),
                LicenseState::Locked,
                "{offline_event:?} must not unlock"
            );
        }
    }

    #[test]
    fn a_kill_order_wipes_immediately_from_every_state() {
        // The blast-radius requirement: revocation is instant and unconditional.
        for setup in [
            LicenseState::Active,
            LicenseState::NeedsRevalidation,
            LicenseState::Grace,
            LicenseState::Locked,
        ] {
            let mut m = active();
            m.handle(Event::Tick, T0 + REFRESH);
            if setup != LicenseState::NeedsRevalidation && setup != LicenseState::Active {
                m.handle(Event::NetworkFailed(TransientError::Offline), T0 + REFRESH);
            }
            if setup == LicenseState::Locked {
                m.handle(Event::Tick, T0 + REFRESH + GRACE);
            }
            if setup == LicenseState::Active {
                // Re-make a clean active machine.
                m = active();
            }

            let e = m.handle(Event::KillOrderVerified(KillReason::Refund), T0 + REFRESH);
            assert!(e.contains(&Effect::WipeAll), "from {setup:?}");
            assert_eq!(m.state(), LicenseState::Revoked);
            assert!(!m.permits_key_derivation());
        }
    }

    #[test]
    fn a_revoked_client_cannot_be_talked_back_with_a_ticket() {
        let mut m = active();
        m.handle(Event::KillOrderVerified(KillReason::Fraud), T0);
        assert_eq!(m.state(), LicenseState::Revoked);
        m.handle(Event::TicketVerified, T0 + 1);
        assert_eq!(
            m.state(),
            LicenseState::Revoked,
            "only a fresh activation clears revocation"
        );
        m.handle(Event::ActivationVerified, T0 + 2);
        assert_eq!(m.state(), LicenseState::Active);
    }

    #[test]
    fn a_verification_failure_fails_closed_from_every_state() {
        for setup in [LicenseState::Active, LicenseState::Grace] {
            let mut m = active();
            if setup == LicenseState::Grace {
                m.handle(Event::Tick, T0 + REFRESH);
                m.handle(Event::NetworkFailed(TransientError::Offline), T0 + REFRESH);
            }
            let e = m.handle(
                Event::VerificationFailed(FatalError::SignatureInvalid),
                T0 + REFRESH,
            );
            assert!(e.contains(&Effect::WipeAll), "from {setup:?}");
            assert_eq!(m.state(), LicenseState::Tampered);
            assert!(!m.permits_key_derivation());
        }
    }

    #[test]
    fn tampered_is_terminal_except_for_a_fresh_activation() {
        let mut m = active();
        m.handle(Event::VerificationFailed(FatalError::ChainInvalid), T0);
        for e in [
            Event::Tick,
            Event::NetworkAvailable,
            Event::TicketVerified,
            Event::CredentialLoaded,
        ] {
            m.handle(e, T0 + 1);
            assert_eq!(m.state(), LicenseState::Tampered);
        }
        m.handle(Event::ActivationVerified, T0 + 2);
        assert_eq!(m.state(), LicenseState::Active);
    }

    #[test]
    fn a_clock_rollback_forces_a_revalidation_rather_than_extending_anything() {
        let mut m = active();
        let e = m.handle(Event::Tick, T0 - 365 * 86_400);
        assert_eq!(states(&e), [LicenseState::NeedsRevalidation]);
        assert!(e.contains(&Effect::SendValidation));
        assert_eq!(m.clock().rollback_events(), 1);
    }

    #[test]
    fn repeated_rollbacks_eventually_lock() {
        let mut m = active();
        for _ in 0..=DEFAULT_ROLLBACK_THRESHOLD {
            m.handle(Event::Tick, T0 - 365 * 86_400);
        }
        assert_eq!(m.state(), LicenseState::Locked);
    }

    #[test]
    fn a_hard_expiry_locks_even_with_grace_remaining() {
        let mut m = StateMachine::new(CoreConfig::default(), T0);
        m.set_deadlines(Deadlines {
            refresh_after: T0 + 10_000,
            grace_deadline: T0 + 100_000,
            not_after: T0 + 500,
        });
        m.handle(Event::CredentialLoaded, T0);
        let e = m.handle(Event::Tick, T0 + 500);
        assert_eq!(states(&e), [LicenseState::Locked]);
    }

    #[test]
    fn an_unlimited_credential_never_hard_expires() {
        let d = Deadlines {
            refresh_after: T0 + 10,
            grace_deadline: T0 + 20,
            not_after: 0,
        };
        assert!(!d.hard_expired(i64::MAX));
    }

    #[test]
    fn network_availability_triggers_a_check_when_one_is_pending() {
        let mut m = active();
        m.handle(Event::Tick, T0 + REFRESH);
        m.handle(Event::NetworkFailed(TransientError::Offline), T0 + REFRESH);
        let e = m.handle(Event::NetworkAvailable, T0 + REFRESH + 10);
        assert!(e.contains(&Effect::SendValidation));
    }

    #[test]
    fn network_availability_does_not_stampede_while_active_and_current() {
        // Instrumented call sites fire often; the interval guard keeps them from flooding.
        let mut m = active();
        assert!(m.handle(Event::NetworkAvailable, T0 + 10).is_empty());
    }

    #[test]
    fn deactivation_wipes_and_returns_to_unlicensed() {
        let mut m = active();
        let e = m.handle(Event::UserDeactivate, T0 + 1);
        assert!(e.contains(&Effect::WipeAll));
        assert_eq!(m.state(), LicenseState::Unlicensed);
        assert!(!m.permits_key_derivation());
    }

    #[test]
    fn no_event_sequence_reaches_active_from_locked_without_a_ticket() {
        // Property test over every event, replayed from a locked state.
        let mut m = active();
        m.handle(Event::Tick, T0 + REFRESH);
        m.handle(Event::NetworkFailed(TransientError::Offline), T0 + REFRESH);
        m.handle(Event::Tick, T0 + REFRESH + GRACE);
        assert_eq!(m.state(), LicenseState::Locked);

        let events = [
            Event::Tick,
            Event::NetworkAvailable,
            Event::AppResumed {
                monotonic_gap_ms: 5_000,
            },
            Event::CredentialLoaded,
            Event::NetworkFailed(TransientError::Timeout),
            Event::NetworkFailed(TransientError::ServerError(500)),
        ];
        // Replay a long pseudo-random sequence.
        let mut idx = 0usize;
        for step in 0..500u32 {
            idx = (idx * 31 + step as usize) % events.len();
            // Indices are modulo the array length.
            #[allow(clippy::indexing_slicing)]
            m.handle(events[idx], T0 + REFRESH + GRACE + i64::from(step));
            assert_ne!(
                m.state(),
                LicenseState::Active,
                "reached Active without a verified ticket at step {step}"
            );
        }
    }

    #[test]
    fn a_wiped_machine_never_permits_key_derivation_regardless_of_state() {
        let mut m = active();
        m.handle(Event::KillOrderVerified(KillReason::SeatReclaimed), T0);
        // Even forcing the advisory state back does not restore key derivation, because the
        // credential is gone.
        assert!(!m.has_credential());
        assert!(!m.permits_key_derivation());
    }

    #[test]
    fn effects_are_deterministic_for_a_replayed_sequence() {
        // The replay requirement from `20-client-core.md §5`.
        let run = || {
            let mut m = active();
            let mut all = Vec::new();
            all.extend(m.handle(Event::Tick, T0 + REFRESH));
            all.extend(m.handle(Event::NetworkFailed(TransientError::Offline), T0 + REFRESH));
            all.extend(m.handle(Event::Tick, T0 + REFRESH + GRACE));
            all.extend(m.handle(Event::TicketVerified, T0 + REFRESH + GRACE + 1));
            (m, all)
        };
        let (m1, e1) = run();
        let (m2, e2) = run();
        assert_eq!(e1, e2);
        assert_eq!(m1, m2);
    }
}
