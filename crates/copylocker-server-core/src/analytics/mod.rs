//! The analytics compute layer for milestone M6 (`90-analytics-telemetry.md`).
//!
//! Everything here is a pure function or value type: no I/O, no clock, no storage. The
//! Worker feeds in machine rows and telemetry blocks decoded from the wire and persists
//! sketches to D1; this module decides *what* to compute and *how* to bound it.
//!
//! Trust model (`90-analytics-telemetry.md §1, §6`): T0 metrics are derived from signed
//! credential usage and are *trusted*; T1 metrics are client self-reports and *untrusted*,
//! so they must pass through [`clip::clip_telemetry`] before they may touch a store.

pub mod catalog;
pub mod clip;
pub mod cube;
pub mod hll;
pub mod kanon;
pub mod source;

pub use catalog::{metric_by_id, metrics, MetricDefinition, MetricTier};
pub use clip::{
    clip_telemetry, consent_allows, ClipEvent, ClippedTelemetry, TelemetryValues, DAYS_ACTIVE_CAP,
    FEATURE_HITS_CAP, HISTOGRAM_BUCKET_CAP, MAX_FEATURE_KEY_LEN, SESSION_COUNT_CAP,
    SESSION_DURATION_BUCKETS,
};
pub use cube::{CubeKey, CubeKeyError, CUBE_COUNT, MAX_CUBE_KEY_LEN, MAX_DIM_VALUE_LEN};
pub use hll::{
    HllSketch, SketchError, HLL_ERROR_PCT, HLL_PRECISION, HLL_REGISTERS, SKETCH_BYTES,
    SKETCH_VERSION,
};
pub use kanon::{suppress_buckets, Bucket, Suppression, K_ANONYMITY_MIN};
pub use source::{source_for, QueryMeta, Source, EXACT_PATH_MAX_MACHINE_ROWS};
