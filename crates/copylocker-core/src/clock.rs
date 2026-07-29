//! Clock guard (`protocol-spec.md §11`, `20-client-core.md §1.3`).
//!
//! Setting the system clock back is the cheapest attack on any time-limited licence, and it
//! needs no tooling. The defence is a persisted high-water mark: every deadline is computed
//! against `max(wall_clock, last_seen_max)`, so moving the clock backwards **cannot extend
//! anything**. It can only make the client think a refresh is overdue, which fails safe.

/// What the clock check concluded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClockVerdict {
    /// The clock looks sane.
    Ok,
    /// The clock moved backwards past the tolerated skew.
    Rollback {
        /// How far back, in seconds.
        delta: i64,
    },
    /// The clock jumped implausibly far forward relative to elapsed monotonic time.
    ///
    /// Not fatal by itself — a laptop resuming from suspend legitimately jumps — but it forces
    /// a revalidation rather than being trusted.
    ImplausibleJump {
        /// How far forward, in seconds.
        delta: i64,
    },
}

/// Tolerated backwards drift before a reading counts as a rollback.
///
/// Wide enough to absorb an NTP correction or a timezone-confused RTC, narrow enough that it
/// buys an attacker nothing useful.
pub const SKEW_TOLERANCE_SECS: i64 = 300;

/// Forward jump, relative to elapsed monotonic time, that counts as implausible.
pub const FORWARD_JUMP_TOLERANCE_SECS: i64 = 86_400;

/// Persisted clock state.
///
/// Stored inside the AEAD-protected blob alongside the credential, so tampering with it breaks
/// the seal rather than silently resetting the high-water mark
/// (`20-client-core.md §2.2`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ClockState {
    /// The greatest wall-clock reading ever observed. Monotonic; never decreases.
    last_seen_max: i64,
    /// Server time from the most recent validation ticket. Authoritative when present.
    last_server_time: i64,
    /// Cumulative rollback observations.
    rollback_events: u32,
}

impl ClockState {
    /// Start from a known-good instant, normally the credential's issuance time.
    #[must_use]
    pub const fn new(seed: i64) -> Self {
        Self {
            last_seen_max: seed,
            last_server_time: seed,
            rollback_events: 0,
        }
    }

    /// Restore a state previously authenticated by the secure store.
    ///
    /// `last_server_time` may be older than the local high-water mark, but never newer. Returning
    /// `None` for that impossible ordering keeps malformed persistence out of deadline logic.
    #[must_use]
    pub const fn from_persisted(
        last_seen_max: i64,
        last_server_time: i64,
        rollback_events: u32,
    ) -> Option<Self> {
        if last_server_time > last_seen_max {
            return None;
        }
        Some(Self {
            last_seen_max,
            last_server_time,
            rollback_events,
        })
    }

    /// The high-water mark.
    #[must_use]
    pub const fn last_seen_max(&self) -> i64 {
        self.last_seen_max
    }

    /// The most recent authoritative server time.
    #[must_use]
    pub const fn last_server_time(&self) -> i64 {
        self.last_server_time
    }

    /// How many rollbacks have been observed.
    #[must_use]
    pub const fn rollback_events(&self) -> u32 {
        self.rollback_events
    }

    /// The time to use for **every** deadline computation.
    ///
    /// Never the raw wall clock. Taking the maximum is what makes a backwards clock unable to
    /// extend a grace window or postpone an expiry (`20-client-core.md §1.3`, rule 1).
    #[must_use]
    pub const fn effective_now(&self, wall_clock: i64) -> i64 {
        if wall_clock > self.last_seen_max {
            wall_clock
        } else {
            self.last_seen_max
        }
    }

    /// Check a wall-clock reading and advance the high-water mark.
    pub fn check(&mut self, wall_clock: i64) -> ClockVerdict {
        if wall_clock.saturating_add(SKEW_TOLERANCE_SECS) < self.last_seen_max {
            self.rollback_events = self.rollback_events.saturating_add(1);
            return ClockVerdict::Rollback {
                delta: self.last_seen_max.saturating_sub(wall_clock),
            };
        }
        if wall_clock > self.last_seen_max {
            self.last_seen_max = wall_clock;
        }
        ClockVerdict::Ok
    }

    /// Cross-check the wall clock against elapsed monotonic time within one session.
    ///
    /// Catches the case where a process runs for ten minutes but the wall clock advances ten
    /// days. The monotonic clock cannot be set by the user, so a large divergence is evidence
    /// of tampering — or of a suspend/resume, which is why it forces a check rather than a lock.
    pub fn check_against_monotonic(
        &mut self,
        wall_clock: i64,
        monotonic_elapsed_secs: i64,
        session_start_wall: i64,
    ) -> ClockVerdict {
        let verdict = self.check(wall_clock);
        if verdict != ClockVerdict::Ok {
            return verdict;
        }
        let wall_elapsed = wall_clock.saturating_sub(session_start_wall);
        let divergence = wall_elapsed.saturating_sub(monotonic_elapsed_secs);
        if divergence > FORWARD_JUMP_TOLERANCE_SECS {
            return ClockVerdict::ImplausibleJump { delta: divergence };
        }
        ClockVerdict::Ok
    }

    /// Record authoritative server time from a validation ticket.
    ///
    /// Server time is trusted absolutely: it is the only clock in the system an attacker cannot
    /// touch (`protocol-spec.md §11`).
    pub fn observe_server_time(&mut self, server_time: i64) {
        self.last_server_time = server_time;
        if server_time > self.last_seen_max {
            self.last_seen_max = server_time;
        }
    }

    /// Merge a copy of this state read from another storage location.
    ///
    /// The client writes clock state to several places. On load it merges, taking the maximum,
    /// so deleting one file does not reset the high-water mark
    /// (`protocol-spec.md §11`).
    pub fn merge(&mut self, other: &Self) {
        if other.last_seen_max > self.last_seen_max {
            self.last_seen_max = other.last_seen_max;
        }
        if other.last_server_time > self.last_server_time {
            self.last_server_time = other.last_server_time;
        }
        self.rollback_events = self.rollback_events.max(other.rollback_events);
    }

    /// Whether repeated rollbacks warrant locking, per policy.
    #[must_use]
    pub const fn exceeds_rollback_threshold(&self, threshold: u32) -> bool {
        self.rollback_events > threshold
    }
}

/// Default rollback tolerance before the client locks (`20-client-core.md §1.3`, rule 3).
pub const DEFAULT_ROLLBACK_THRESHOLD: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;
    const YEAR: i64 = 365 * DAY;

    #[test]
    fn a_forward_clock_advances_the_high_water_mark() {
        let mut c = ClockState::new(T0);
        assert_eq!(c.check(T0 + 100), ClockVerdict::Ok);
        assert_eq!(c.last_seen_max(), T0 + 100);
    }

    #[test]
    fn small_backward_drift_is_tolerated_without_advancing() {
        // NTP corrections and sloppy RTCs are normal; they must not look like an attack.
        let mut c = ClockState::new(T0);
        assert_eq!(c.check(T0 - SKEW_TOLERANCE_SECS + 1), ClockVerdict::Ok);
        assert_eq!(c.rollback_events(), 0);
        assert_eq!(c.last_seen_max(), T0, "the mark must not move backwards");
    }

    #[test]
    fn a_one_day_rollback_is_detected() {
        let mut c = ClockState::new(T0);
        assert_eq!(c.check(T0 - DAY), ClockVerdict::Rollback { delta: DAY });
        assert_eq!(c.rollback_events(), 1);
    }

    #[test]
    fn a_one_year_rollback_is_detected_and_extends_nothing() {
        // The acceptance criterion from `roadmap.md` M2.
        let mut c = ClockState::new(T0);
        assert_eq!(c.check(T0 - YEAR), ClockVerdict::Rollback { delta: YEAR });
        // And crucially, deadline arithmetic still uses the high-water mark.
        assert_eq!(
            c.effective_now(T0 - YEAR),
            T0,
            "a rolled-back clock must not extend any deadline"
        );
    }

    #[test]
    fn effective_now_never_goes_below_the_high_water_mark() {
        let mut c = ClockState::new(T0);
        c.check(T0 + 1000);
        for wall in [T0 - YEAR, T0, T0 + 999] {
            assert_eq!(c.effective_now(wall), T0 + 1000);
        }
        assert_eq!(c.effective_now(T0 + 2000), T0 + 2000);
    }

    #[test]
    fn repeated_rollbacks_accumulate_toward_the_lock_threshold() {
        let mut c = ClockState::new(T0);
        for _ in 0..4 {
            c.check(T0 - YEAR);
        }
        assert_eq!(c.rollback_events(), 4);
        assert!(c.exceeds_rollback_threshold(DEFAULT_ROLLBACK_THRESHOLD));
        assert!(!c.exceeds_rollback_threshold(10));
    }

    #[test]
    fn deleting_one_storage_copy_does_not_reset_the_mark() {
        // The redundancy rule: merge takes the maximum across locations.
        let mut fresh = ClockState::new(T0);
        let persisted = {
            let mut c = ClockState::new(T0);
            c.check(T0 + 10 * YEAR);
            c.check(T0 - YEAR); // one rollback recorded
            c
        };
        fresh.merge(&persisted);
        assert_eq!(fresh.last_seen_max(), T0 + 10 * YEAR);
        assert_eq!(fresh.rollback_events(), 1);
    }

    #[test]
    fn merging_never_lowers_anything() {
        let mut c = ClockState::new(T0);
        c.check(T0 + 1000);
        c.merge(&ClockState::new(T0 - YEAR));
        assert_eq!(c.last_seen_max(), T0 + 1000);
    }

    #[test]
    fn server_time_advances_the_mark_and_is_recorded() {
        let mut c = ClockState::new(T0);
        c.observe_server_time(T0 + 5000);
        assert_eq!(c.last_server_time(), T0 + 5000);
        assert_eq!(c.last_seen_max(), T0 + 5000);
    }

    #[test]
    fn server_time_behind_the_mark_is_recorded_without_lowering_it() {
        // A ticket from a slightly-behind server is normal and must not rewind the guard.
        let mut c = ClockState::new(T0);
        c.check(T0 + 1000);
        c.observe_server_time(T0 + 500);
        assert_eq!(c.last_server_time(), T0 + 500);
        assert_eq!(c.last_seen_max(), T0 + 1000);
    }

    #[test]
    fn persisted_state_restores_exactly_and_rejects_impossible_ordering() {
        let restored = ClockState::from_persisted(9_000, 8_000, 3).unwrap();
        assert_eq!(restored.last_seen_max(), 9_000);
        assert_eq!(restored.last_server_time(), 8_000);
        assert_eq!(restored.rollback_events(), 3);
        assert!(ClockState::from_persisted(7_999, 8_000, 3).is_none());
    }

    #[test]
    fn a_wall_clock_racing_ahead_of_monotonic_time_is_flagged() {
        // Ten minutes of process time, ten days of wall clock.
        let mut c = ClockState::new(T0);
        let verdict = c.check_against_monotonic(T0 + 10 * DAY, 600, T0);
        assert!(matches!(verdict, ClockVerdict::ImplausibleJump { .. }));
    }

    #[test]
    fn ordinary_elapsed_time_passes_the_monotonic_cross_check() {
        let mut c = ClockState::new(T0);
        assert_eq!(
            c.check_against_monotonic(T0 + 600, 600, T0),
            ClockVerdict::Ok
        );
    }

    #[test]
    fn a_rollback_takes_priority_over_the_monotonic_check() {
        let mut c = ClockState::new(T0);
        assert!(matches!(
            c.check_against_monotonic(T0 - YEAR, 10, T0),
            ClockVerdict::Rollback { .. }
        ));
    }

    #[test]
    fn extreme_values_do_not_overflow() {
        // `overflow-checks` stays on in release builds, so this would be a live crash.
        let mut c = ClockState::new(i64::MAX);
        assert!(matches!(c.check(i64::MIN), ClockVerdict::Rollback { .. }));
        assert_eq!(c.effective_now(i64::MIN), i64::MAX);

        let mut c2 = ClockState::new(i64::MIN);
        assert_eq!(c2.check(i64::MAX), ClockVerdict::Ok);
        assert_eq!(
            c2.check_against_monotonic(i64::MAX, i64::MAX, i64::MIN),
            ClockVerdict::Ok
        );
    }
}
