//! HyperLogLog sketches for distinct-machine counting (`90-analytics-telemetry.md §4`).
//!
//! Fixed precision `p = 14`: 16,384 u8 registers, theoretical relative error
//! `1.04 / sqrt(2^14) ≈ 0.81%` ([`HLL_ERROR_PCT`]). Small cardinalities use linear
//! counting, the standard HLL bias correction, so small buckets stay near-exact.
//!
//! A sketch contains only hashed, register-quantized counts — no machine ids — so it
//! holds no personal data and survives GDPR deletion of the underlying machine rows
//! (`90-analytics-telemetry.md §4.1, §11`).

use alloc::vec::Vec;

/// HLL precision parameter. Fixed at 14 per the design; not configurable.
pub const HLL_PRECISION: u8 = 14;

/// Number of registers, `2^HLL_PRECISION`.
pub const HLL_REGISTERS: usize = 1 << HLL_PRECISION;

/// Theoretical relative error of a p=14 sketch, in percent.
pub const HLL_ERROR_PCT: f64 = 0.81;

/// Version byte prepended to the serialized form, so the BLOB format can evolve.
pub const SKETCH_VERSION: u8 = 1;

/// Exact length of a serialized sketch: version byte + dense register array.
pub const SKETCH_BYTES: usize = 1 + HLL_REGISTERS;

/// A p=14 HyperLogLog sketch over 64-bit hashes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HllSketch {
    /// Dense register array, always exactly [`HLL_REGISTERS`] long.
    registers: Vec<u8>,
}

/// Why a serialized sketch was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SketchError {
    /// Blob length was not exactly [`SKETCH_BYTES`].
    BadLength {
        /// Length seen.
        got: usize,
    },
    /// Version byte is not [`SKETCH_VERSION`].
    UnsupportedVersion {
        /// Version seen.
        got: u8,
    },
}

impl core::fmt::Display for SketchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLength { got } => {
                write!(f, "sketch blob is {got} bytes; expected {SKETCH_BYTES}")
            }
            Self::UnsupportedVersion { got } => {
                write!(f, "sketch blob version {got}; expected {SKETCH_VERSION}")
            }
        }
    }
}

impl Default for HllSketch {
    fn default() -> Self {
        Self::new()
    }
}

impl HllSketch {
    /// An empty sketch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registers: alloc::vec![0u8; HLL_REGISTERS],
        }
    }

    /// Add one machine-id-like value. Idempotent: adding the same value twice changes
    /// nothing, so a re-run of a day rollup cannot inflate the sketch.
    ///
    /// The value should already be pseudonymous (`HMAC(analytics_pepper, machine_id)`,
    /// `90-analytics-telemetry.md §4.2`); this function hashes again only for register
    /// placement and rank extraction.
    pub fn add(&mut self, value: &[u8]) {
        let h = hash64(value);
        let idx = (h >> (64 - HLL_PRECISION)) as usize;
        // The remaining (64 - p) bits carry the rank. The sentinel caps the rank at
        // (64 - p) + 1 when those bits are all zero.
        let w = (h << HLL_PRECISION) | (1u64 << (HLL_PRECISION - 1));
        let rank = (w.leading_zeros() + 1) as u8;
        if let Some(reg) = self.registers.get_mut(idx) {
            if rank > *reg {
                *reg = rank;
            }
        }
    }

    /// Merge another sketch into this one (register-wise maximum). The result is exactly
    /// the sketch that would have been produced by adding both inputs to one sketch, so
    /// merging per-day sketches gives the whole-window estimate.
    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.registers.iter_mut().zip(other.registers.iter()) {
            if *b > *a {
                *a = *b;
            }
        }
    }

    /// Estimated distinct count, with linear counting for small cardinalities.
    #[must_use]
    pub fn cardinality(&self) -> u64 {
        let m = HLL_REGISTERS as f64;
        // alpha_m for m = 2^14 (HLL++ form, exact for m >= 128).
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let mut sum = 0.0f64;
        let mut zeros = 0u64;
        for &r in &self.registers {
            sum += exp2_neg(r);
            if r == 0 {
                zeros += 1;
            }
        }
        let raw = alpha * m * m / sum;
        let estimate = if raw <= 2.5 * m && zeros > 0 {
            // Linear counting: near-exact in the small range.
            m * ln(m / zeros as f64)
        } else {
            raw
        };
        // The estimate is always non-negative, so adding 0.5 and truncating rounds.
        (estimate + 0.5) as u64
    }

    /// Serialize for the `analytics_hll.sketch` BLOB column: one version byte followed
    /// by the dense register array ([`SKETCH_BYTES`] total).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SKETCH_BYTES);
        out.push(SKETCH_VERSION);
        out.extend_from_slice(&self.registers);
        out
    }

    /// Deserialize, rejecting malformed blobs (wrong length or version) without panicking.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SketchError> {
        if bytes.len() != SKETCH_BYTES {
            return Err(SketchError::BadLength { got: bytes.len() });
        }
        let (&version, registers) = bytes
            .split_first()
            .ok_or(SketchError::BadLength { got: 0 })?;
        if version != SKETCH_VERSION {
            return Err(SketchError::UnsupportedVersion { got: version });
        }
        Ok(Self {
            registers: registers.to_vec(),
        })
    }
}

/// A deterministic 64-bit hash: FNV-1a over the input with a splitmix64 finalizer for
/// avalanche. Sketch inputs are already HMAC outputs (uniform) per the design, so this
/// only needs to spread register indices and ranks; it is not a cryptographic boundary.
fn hash64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^= h >> 30;
    h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

/// Exact `2^-r` via the IEEE-754 exponent field. Ranks never exceed `(64 - p) + 1 = 51`,
/// far below the 1023 limit, so the result is always a normal number. `core` has no
/// float math, and this is exact where a computed power would only be close.
fn exp2_neg(r: u8) -> f64 {
    f64::from_bits((1023 - u64::from(r)) << 52)
}

/// Natural logarithm for `x > 0`. `core` has no `f64::ln`, and linear counting only
/// needs `ln(m / V)` for `m / V` in `(1, 2.5]`, so a small argument-reduced atanh series
/// (accurate to ~1e-15 relative over that range, and far beyond) replaces the libm call.
fn ln(x: f64) -> f64 {
    // Decompose x = m * 2^e with m in [2^-1/2, 2^1/2) for fast convergence.
    let bits = x.to_bits();
    let e = ((bits >> 52) & 0x7ff) as i64 - 1023;
    let mant = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | (1023u64 << 52));
    let (m, e) = if mant > core::f64::consts::SQRT_2 {
        (mant * 0.5, e + 1)
    } else {
        (mant, e)
    };
    // ln(m) = 2 * (z + z^3/3 + z^5/5 + ...) with z = (m-1)/(m+1), |z| < 0.172.
    let z = (m - 1.0) / (m + 1.0);
    let z2 = z * z;
    let mut term = z;
    let mut sum = 0.0f64;
    for k in 0..12u32 {
        sum += term / f64::from(2 * k + 1);
        term *= z2;
    }
    #[allow(clippy::cast_precision_loss)] // e is in [-1022, 1024], exact in f64.
    let e = e as f64;
    e * core::f64::consts::LN_2 + 2.0 * sum
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;

    /// A deterministic machine-id-like key: splitmix64 of the index, as bytes.
    fn machine_id(i: u64) -> [u8; 8] {
        let mut x = i.wrapping_add(0x9e37_79b9_7f4a_7c15);
        x ^= x >> 30;
        x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^= x >> 31;
        x.to_le_bytes()
    }

    #[test]
    fn the_core_only_ln_is_accurate() {
        // Reference values for the range linear counting exercises, plus edges.
        for (x, want) in [
            (1.0f64, 0.0f64),
            (core::f64::consts::E, 1.0),
            (2.0, core::f64::consts::LN_2),
            (2.5, 0.916_290_731_874_155),
            (1.0001, 0.000_099_995_000_333_308),
        ] {
            let got = ln(x);
            assert!(
                (got - want).abs() < 1e-12,
                "ln({x}) = {got}, expected {want}"
            );
        }
    }

    #[test]
    fn exp2_neg_is_exact() {
        assert_eq!(exp2_neg(0), 1.0);
        assert_eq!(exp2_neg(1), 0.5);
        assert_eq!(exp2_neg(51), 4.440_892_098_500_626e-16);
    }

    #[test]
    fn estimates_agree_with_exact_counts_within_one_percent() {
        for n in [100u64, 1_000, 10_000, 50_000] {
            let mut sketch = HllSketch::new();
            for i in 0..n {
                sketch.add(&machine_id(i));
            }
            let est = sketch.cardinality();
            let err = (est as f64 - n as f64).abs() / n as f64 * 100.0;
            std::println!("n={n}: estimate={est}, err={err:.3}%");
            assert!(
                err <= 1.0,
                "n={n}: estimate {est} is off by {err:.3}% (limit 1%)"
            );
        }
    }

    #[test]
    fn adding_is_idempotent() {
        let mut sketch = HllSketch::new();
        sketch.add(b"machine-1");
        let once = sketch.cardinality();
        for _ in 0..10 {
            sketch.add(b"machine-1");
        }
        assert_eq!(sketch.cardinality(), once);
    }

    #[test]
    fn merging_daily_sketches_equals_one_window_sketch() {
        // A 30-day window; each day sees 5,000 machines from an overlapping sliding band
        // of a 20,000-machine pool, so days share members.
        const DAYS: u64 = 30;
        let mut merged = HllSketch::new();
        let mut whole = HllSketch::new();
        for day in 0..DAYS {
            let mut daily = HllSketch::new();
            let start = (day * 500) % 16_000;
            for j in start..start + 5_000 {
                let id = machine_id(j);
                daily.add(&id);
                whole.add(&id);
            }
            merged.merge(&daily);
        }
        // Register-wise max means merge is exact, not approximate.
        assert_eq!(merged, whole);
        // And the union estimate tracks the true distinct count of the window.
        // Day 29 starts at 14_500, so the union is [0, 14_500 + 5_000).
        let true_distinct = 14_500u64 + 5_000;
        let est = merged.cardinality();
        let err = (est as f64 - true_distinct as f64).abs() / true_distinct as f64 * 100.0;
        assert!(
            err <= 1.0,
            "merged estimate {est} vs true {true_distinct}: {err:.3}% off"
        );
    }

    #[test]
    fn serialization_round_trips() {
        let mut sketch = HllSketch::new();
        for i in 0..1_000u64 {
            sketch.add(&machine_id(i));
        }
        let bytes = sketch.to_bytes();
        assert_eq!(bytes.len(), SKETCH_BYTES);
        let back = HllSketch::from_bytes(&bytes).unwrap();
        assert_eq!(back, sketch);
        assert_eq!(back.cardinality(), sketch.cardinality());
    }

    #[test]
    fn an_empty_sketch_serializes_and_estimates_zero() {
        let sketch = HllSketch::new();
        assert_eq!(sketch.cardinality(), 0);
        let back = HllSketch::from_bytes(&sketch.to_bytes()).unwrap();
        assert_eq!(back.cardinality(), 0);
    }

    #[test]
    fn malformed_blobs_are_rejected_without_panicking() {
        assert_eq!(
            HllSketch::from_bytes(&[]),
            Err(SketchError::BadLength { got: 0 })
        );
        assert_eq!(
            HllSketch::from_bytes(&alloc::vec![0u8; SKETCH_BYTES - 1]),
            Err(SketchError::BadLength {
                got: SKETCH_BYTES - 1
            })
        );
        assert_eq!(
            HllSketch::from_bytes(&alloc::vec![0u8; SKETCH_BYTES + 1]),
            Err(SketchError::BadLength {
                got: SKETCH_BYTES + 1
            })
        );
        let mut wrong_version = alloc::vec![0u8; SKETCH_BYTES];
        wrong_version[0] = SKETCH_VERSION + 1;
        assert_eq!(
            HllSketch::from_bytes(&wrong_version),
            Err(SketchError::UnsupportedVersion {
                got: SKETCH_VERSION + 1
            })
        );
    }
}
