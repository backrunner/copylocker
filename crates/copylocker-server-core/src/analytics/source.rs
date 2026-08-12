//! Exact-vs-HLL source labeling (`90-analytics-telemetry.md §4.3, §8`).
//!
//! Small deployments get exact distinct counts straight from the machine rows; large ones
//! get HLL estimates. The UI must always say which one it is looking at, so every query
//! response carries a [`QueryMeta`] — and the Worker picks the path with [`source_for`]
//! instead of re-deriving the threshold.

/// Below this many machine rows the exact path is used (`90-analytics-telemetry.md §4.3`).
pub const EXACT_PATH_MAX_MACHINE_ROWS: u64 = 1_000_000;

/// Which computation path produced a distinct-count series.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub enum Source {
    /// Computed exactly from machine rows.
    Exact,
    /// Estimated by merging HLL sketches.
    Hll,
}

/// Pick the computation path for a deployment with `machine_rows` rows in `machines`.
#[must_use]
pub fn source_for(machine_rows: u64) -> Source {
    if machine_rows < EXACT_PATH_MAX_MACHINE_ROWS {
        Source::Exact
    } else {
        Source::Hll
    }
}

/// Query-result metadata: where the numbers came from, how far off they can be, and how
/// many buckets k-anonymity hid (`90-analytics-telemetry.md §8`).
#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-rs",
    ts(export, export_to = "../../../packages/admin-sdk/bindings/")
)]
pub struct QueryMeta {
    /// Computation path.
    pub source: Source,
    /// Worst-case relative error in percent: `0.0` for exact, [`super::HLL_ERROR_PCT`] for HLL.
    pub error_pct: f64,
    /// Buckets suppressed by k-anonymity.
    pub suppressed_buckets: u64,
}

impl QueryMeta {
    /// Build metadata for a query answered via `source`, after suppressing
    /// `suppressed_buckets` buckets.
    #[must_use]
    pub fn new(source: Source, suppressed_buckets: u64) -> Self {
        let error_pct = match source {
            Source::Exact => 0.0,
            Source::Hll => super::HLL_ERROR_PCT,
        };
        Self {
            source,
            error_pct,
            suppressed_buckets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_threshold_matches_the_design() {
        assert_eq!(source_for(0), Source::Exact);
        assert_eq!(source_for(EXACT_PATH_MAX_MACHINE_ROWS - 1), Source::Exact);
        assert_eq!(source_for(EXACT_PATH_MAX_MACHINE_ROWS), Source::Hll);
        assert_eq!(source_for(u64::MAX), Source::Hll);
    }

    #[test]
    fn error_pct_follows_the_source() {
        let exact = QueryMeta::new(Source::Exact, 2);
        assert_eq!(exact.error_pct, 0.0);
        assert_eq!(exact.suppressed_buckets, 2);
        let hll = QueryMeta::new(Source::Hll, 0);
        assert_eq!(hll.error_pct, 0.81);
    }
}
