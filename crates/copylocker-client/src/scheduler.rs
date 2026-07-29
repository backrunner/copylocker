use std::time::Duration;

use crate::SchedulerConfig;

const JITTER_BASE: u64 = 8_500;
const JITTER_SPAN: u64 = 3_001;
const JITTER_SCALE: u64 = 10_000;

#[derive(Debug)]
pub(crate) struct SchedulerState {
    next_attempt_at: Option<i64>,
    last_attempt_at: Option<i64>,
    consecutive_failures: u8,
    startup_pending: bool,
}

impl SchedulerState {
    pub(crate) const fn new(has_credential: bool) -> Self {
        Self {
            next_attempt_at: None,
            last_attempt_at: None,
            consecutive_failures: 0,
            startup_pending: has_credential,
        }
    }

    pub(crate) fn should_attempt(
        &mut self,
        now: i64,
        has_credential: bool,
        online_hint: bool,
        core_requested: bool,
        minimum_interval_secs: i64,
    ) -> bool {
        if !has_credential {
            self.disable();
            return false;
        }
        let hint_due = online_hint
            && self
                .last_attempt_at
                .is_none_or(|last| now.saturating_sub(last) >= minimum_interval_secs);
        let timer_due = self.next_attempt_at.is_some_and(|next| now >= next);
        if self.startup_pending || core_requested || hint_due || timer_due {
            self.startup_pending = false;
            self.mark_attempt(now);
            return true;
        }
        false
    }

    pub(crate) fn mark_attempt(&mut self, now: i64) {
        self.last_attempt_at = Some(now);
    }

    pub(crate) fn record_success(
        &mut self,
        now: i64,
        interval_start: i64,
        nominal_deadline: i64,
        sample: u64,
    ) {
        self.consecutive_failures = 0;
        self.startup_pending = false;
        let interval_secs = nominal_deadline.saturating_sub(interval_start).max(1) as u64;
        let jittered = jitter(Duration::from_secs(interval_secs), sample);
        let jittered_secs = i64::try_from(jittered.as_secs()).unwrap_or(i64::MAX);
        self.next_attempt_at = Some(
            interval_start
                .saturating_add(jittered_secs)
                .max(now.saturating_add(1)),
        );
    }

    pub(crate) fn record_failure(
        &mut self,
        now: i64,
        config: SchedulerConfig,
        retry_after: Option<Duration>,
        sample: u64,
    ) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let exponent = u32::from(self.consecutive_failures.saturating_sub(1).min(6));
        let multiplier = 1_u32 << exponent;
        let exponential = config.base_retry.saturating_mul(multiplier);
        let requested = retry_after.unwrap_or(Duration::ZERO);
        let bounded = exponential.max(requested).min(config.max_retry);
        let delay = jitter(bounded, sample);
        let delay_secs = i64::try_from(delay.as_secs().max(1)).unwrap_or(i64::MAX);
        self.next_attempt_at = Some(now.saturating_add(delay_secs));
    }

    pub(crate) fn next_delay(&self, now: i64, poll_interval: Duration) -> Duration {
        if self.startup_pending || self.next_attempt_at.is_some_and(|next| next <= now) {
            return Duration::ZERO;
        }
        let until_attempt = self.next_attempt_at.map_or(poll_interval, |next| {
            Duration::from_secs(u64::try_from(next.saturating_sub(now)).unwrap_or(u64::MAX))
        });
        poll_interval.min(until_attempt)
    }

    pub(crate) fn disable(&mut self) {
        self.next_attempt_at = None;
        self.consecutive_failures = 0;
        self.startup_pending = false;
    }
}

pub(crate) fn jitter(base: Duration, sample: u64) -> Duration {
    let factor = JITTER_BASE + sample % JITTER_SPAN;
    let millis = base.as_millis().saturating_mul(u128::from(factor)) / u128::from(JITTER_SCALE);
    let millis = u64::try_from(millis).unwrap_or(u64::MAX);
    Duration::from_millis(millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SchedulerConfig {
        SchedulerConfig {
            base_retry: Duration::from_secs(30),
            max_retry: Duration::from_secs(6 * 60 * 60),
            poll_interval: Duration::from_secs(30),
        }
    }

    #[test]
    fn jitter_covers_the_documented_range() {
        let base = Duration::from_secs(10_000);
        assert_eq!(jitter(base, 0), Duration::from_secs(8_500));
        assert_eq!(jitter(base, 3_000), Duration::from_secs(11_500));
    }

    #[test]
    fn retries_double_and_cap_at_six_hours() {
        let mut state = SchedulerState::new(false);
        let cfg = config();
        let mut delays = Vec::new();
        for _ in 0..12 {
            state.record_failure(1_000, cfg, None, 1_500);
            delays.push(state.next_attempt_at.unwrap() - 1_000);
        }
        assert_eq!(&delays[..4], &[30, 60, 120, 240]);
        assert_eq!(*delays.last().unwrap(), 1_920);

        let capped = SchedulerConfig {
            base_retry: Duration::from_secs(3_600),
            ..cfg
        };
        state.record_failure(2_000, capped, None, 1_500);
        assert!(state.next_attempt_at.unwrap() - 2_000 <= 6 * 60 * 60);
    }

    #[test]
    fn hints_respect_the_minimum_interval() {
        let mut state = SchedulerState::new(true);
        assert!(state.should_attempt(100, true, false, false, 60));
        assert!(!state.should_attempt(120, true, true, false, 60));
        assert!(state.should_attempt(160, true, true, false, 60));
    }

    #[test]
    fn success_jitters_the_refresh_interval() {
        let mut state = SchedulerState::new(false);
        state.record_success(1_000, 1_000, 2_000, 0);
        assert_eq!(state.next_attempt_at, Some(1_850));
        state.record_success(1_000, 1_000, 2_000, 3_000);
        assert_eq!(state.next_attempt_at, Some(2_150));
    }
}
