//! Conformance results.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use copylocker_types::SuiteId;

/// One conformance check.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Check {
    /// Stable dotted identifier, e.g. `sig.cross_domain_replay_fails`.
    pub id: String,
    /// What property the check establishes, in one sentence.
    pub description: String,
    /// Whether it held.
    pub passed: bool,
}

/// The outcome of running the conformance harness against one suite.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConformanceReport {
    suite_name: String,
    suite_id: SuiteId,
    checks: Vec<Check>,
}

impl ConformanceReport {
    /// Start an empty report.
    #[must_use]
    pub fn new(suite_name: &str, suite_id: SuiteId) -> Self {
        Self {
            suite_name: suite_name.to_string(),
            suite_id,
            checks: Vec::new(),
        }
    }

    /// Record a check.
    pub fn check(&mut self, id: &str, description: &str, passed: bool) {
        self.checks.push(Check {
            id: id.to_string(),
            description: description.to_string(),
            passed,
        });
    }

    /// Record a check with a sub-name, for parameterised checks.
    pub fn check_named(&mut self, id: &str, variant: &str, description: &str, passed: bool) {
        let mut full = String::from(id);
        full.push('[');
        full.push_str(variant);
        full.push(']');
        self.checks.push(Check {
            id: full,
            description: description.to_string(),
            passed,
        });
    }

    /// Record an outright failure, used when a precondition could not even be set up.
    pub fn fail(&mut self, id: &str, description: &str) {
        self.check(id, description, false);
    }

    /// Every check recorded.
    #[must_use]
    pub fn checks(&self) -> &[Check] {
        &self.checks
    }

    /// Total number of checks.
    #[must_use]
    pub fn total(&self) -> usize {
        self.checks.len()
    }

    /// Number that failed.
    #[must_use]
    pub fn failures(&self) -> usize {
        self.checks.iter().filter(|c| !c.passed).count()
    }

    /// Whether every check passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failures() == 0
    }

    /// A human-readable summary. Lists only failures, since a passing run needs no detail.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "suite {} ({}): {}/{} checks passed",
            self.suite_name,
            self.suite_id,
            self.total() - self.failures(),
            self.total()
        );
        for c in self.checks.iter().filter(|c| !c.passed) {
            let _ = write!(s, "\n  FAIL {} — {}", c.id, c.description);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_report_passes_vacuously() {
        let r = ConformanceReport::new("X", SuiteId::from_u32(1));
        assert!(r.passed());
        assert_eq!(r.total(), 0);
    }

    #[test]
    fn summary_lists_only_failures() {
        let mut r = ConformanceReport::new("X", SuiteId::from_u32(1));
        r.check("a.ok", "fine", true);
        r.check("b.bad", "broken", false);
        r.check_named("c.param", "case1", "parameterised", false);
        assert!(!r.passed());
        assert_eq!(r.failures(), 2);
        let s = r.summary();
        assert!(s.contains("1/3 checks passed"));
        assert!(s.contains("FAIL b.bad"));
        assert!(s.contains("FAIL c.param[case1]"));
        assert!(!s.contains("a.ok"));
    }
}
