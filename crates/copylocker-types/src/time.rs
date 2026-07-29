//! Time window arithmetic.
//!
//! `crypto-architecture.md §8` calls out "time comparison using `>` where `>=` was meant" as a
//! recurring source of boundary bugs. The fix is a single shared helper with one documented
//! convention, used by every validity check in the workspace.

use core::fmt;

/// A half-open instant range `[not_before, not_after)`, in Unix seconds (UTC).
///
/// **Convention**: `not_before` is inclusive, `not_after` is exclusive. A credential whose
/// `not_after` is exactly `now` has expired. `not_after == 0` means "no upper bound", matching
/// the `MachineCredential.not_after` encoding in `protocol-spec.md §4` where `0` = unlimited.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TimeWindow {
    not_before: i64,
    not_after: i64,
}

impl TimeWindow {
    /// Sentinel for `not_after` meaning "never expires" (`protocol-spec.md §4`, field 11).
    pub const UNLIMITED: i64 = 0;

    /// Build a window. `not_after == 0` is the unlimited sentinel.
    #[must_use]
    pub const fn new(not_before: i64, not_after: i64) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    /// A window that has already started and never ends.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self::new(i64::MIN, Self::UNLIMITED)
    }

    /// Start of the window (inclusive).
    #[must_use]
    pub const fn not_before(&self) -> i64 {
        self.not_before
    }

    /// End of the window (exclusive); `0` means unlimited.
    #[must_use]
    pub const fn not_after(&self) -> i64 {
        self.not_after
    }

    /// Whether the window has an upper bound at all.
    #[must_use]
    pub const fn is_unlimited(&self) -> bool {
        self.not_after == Self::UNLIMITED
    }

    /// `not_before <= now < not_after` (with `not_after == 0` treated as `+inf`).
    #[must_use]
    pub const fn contains(&self, now: i64) -> bool {
        if now < self.not_before {
            return false;
        }
        self.is_unlimited() || now < self.not_after
    }

    /// Whether `now` is at or past the (exclusive) end.
    #[must_use]
    pub const fn is_expired(&self, now: i64) -> bool {
        !self.is_unlimited() && now >= self.not_after
    }

    /// Whether `now` precedes the (inclusive) start.
    #[must_use]
    pub const fn is_not_yet_valid(&self, now: i64) -> bool {
        now < self.not_before
    }

    /// Seconds remaining until expiry, saturating at zero. `None` when unlimited.
    #[must_use]
    pub const fn remaining(&self, now: i64) -> Option<i64> {
        if self.is_unlimited() {
            return None;
        }
        let left = self.not_after.saturating_sub(now);
        Some(if left < 0 { 0 } else { left })
    }

    /// A window that is well-formed: unlimited, or `not_before < not_after`.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        self.is_unlimited() || self.not_before < self.not_after
    }
}

impl fmt::Debug for TimeWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_unlimited() {
            write!(f, "TimeWindow([{}, ∞))", self.not_before)
        } else {
            write!(f, "TimeWindow([{}, {}))", self.not_before, self.not_after)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_are_start_inclusive_end_exclusive() {
        let w = TimeWindow::new(100, 200);
        assert!(!w.contains(99));
        assert!(w.contains(100), "not_before is inclusive");
        assert!(w.contains(199));
        assert!(!w.contains(200), "not_after is exclusive");
        assert!(w.is_expired(200));
        assert!(!w.is_expired(199));
    }

    #[test]
    fn zero_not_after_means_unlimited() {
        let w = TimeWindow::new(100, TimeWindow::UNLIMITED);
        assert!(w.is_unlimited());
        assert!(w.contains(i64::MAX));
        assert!(!w.is_expired(i64::MAX));
        assert_eq!(w.remaining(i64::MAX), None);
        // The lower bound still applies.
        assert!(!w.contains(99));
    }

    #[test]
    fn remaining_saturates_at_zero() {
        let w = TimeWindow::new(0, 100);
        assert_eq!(w.remaining(40), Some(60));
        assert_eq!(w.remaining(100), Some(0));
        assert_eq!(w.remaining(10_000), Some(0));
    }

    #[test]
    fn remaining_does_not_overflow_on_extremes() {
        let w = TimeWindow::new(i64::MIN, i64::MAX);
        assert_eq!(w.remaining(i64::MIN), Some(i64::MAX));
    }

    #[test]
    fn inverted_windows_are_rejected_by_well_formed() {
        assert!(!TimeWindow::new(200, 100).is_well_formed());
        assert!(TimeWindow::new(100, 200).is_well_formed());
        assert!(TimeWindow::new(100, TimeWindow::UNLIMITED).is_well_formed());
    }
}
