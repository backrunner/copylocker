//! k-anonymity suppression (`90-analytics-telemetry.md §4, §12`).
//!
//! No bucket smaller than five distinct machines ever leaves the server: below that, a
//! bucket can single out individuals. Suppression happens after computation, on the pure
//! bucket series, so the Worker needs no judgment of its own.

use alloc::string::String;
use alloc::vec::Vec;

/// Minimum distinct-machine count for a bucket to be reportable.
pub const K_ANONYMITY_MIN: u64 = 5;

/// One computed bucket of a series: its label, its distinct-machine count (the value the
/// k-anonymity rule judges), and whatever payload the query produced.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Bucket<T> {
    /// Bucket label, e.g. an encoded [`crate::analytics::CubeKey`] or a group-by value.
    pub key: String,
    /// Distinct machines contributing to this bucket.
    pub distinct_machines: u64,
    /// The bucket's computed payload (counts, histograms, ...), carried through untouched.
    pub value: T,
}

/// The result of [`suppress_buckets`]: the reportable series plus what was hidden.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Suppression<T> {
    /// Buckets at or above the threshold, in input order.
    pub surviving: Vec<Bucket<T>>,
    /// Keys of the suppressed buckets, for `meta.suppressed_buckets` accounting.
    pub suppressed_keys: Vec<String>,
}

impl<T> Suppression<T> {
    /// How many buckets were suppressed.
    #[must_use]
    pub fn suppressed_count(&self) -> u64 {
        self.suppressed_keys.len() as u64
    }
}

/// Drop every bucket with fewer than `min_distinct` distinct machines. Pass
/// [`K_ANONYMITY_MIN`] unless a stricter floor is required.
pub fn suppress_buckets<T>(buckets: Vec<Bucket<T>>, min_distinct: u64) -> Suppression<T> {
    let mut surviving = Vec::new();
    let mut suppressed_keys = Vec::new();
    for bucket in buckets {
        if bucket.distinct_machines < min_distinct {
            suppressed_keys.push(bucket.key);
        } else {
            surviving.push(bucket);
        }
    }
    Suppression {
        surviving,
        suppressed_keys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(key: &str, distinct: u64) -> Bucket<u64> {
        Bucket {
            key: String::from(key),
            distinct_machines: distinct,
            value: distinct * 10,
        }
    }

    #[test]
    fn a_bucket_of_four_is_suppressed_but_five_survives() {
        // The §12 test row.
        let out = suppress_buckets(
            alloc::vec![bucket("tiny", 4), bucket("just-enough", 5)],
            K_ANONYMITY_MIN,
        );
        assert_eq!(out.surviving.len(), 1);
        assert_eq!(out.surviving[0].key, "just-enough");
        assert_eq!(out.surviving[0].value, 50);
        assert_eq!(out.suppressed_keys, ["tiny"]);
        assert_eq!(out.suppressed_count(), 1);
    }

    #[test]
    fn suppression_preserves_order_and_reports_every_hidden_bucket() {
        let out = suppress_buckets(
            alloc::vec![
                bucket("a", 0),
                bucket("b", K_ANONYMITY_MIN),
                bucket("c", 1),
                bucket("d", 100),
            ],
            K_ANONYMITY_MIN,
        );
        let keys: Vec<&str> = out.surviving.iter().map(|b| b.key.as_str()).collect();
        assert_eq!(keys, ["b", "d"]);
        assert_eq!(out.suppressed_keys, ["a", "c"]);
    }
}
