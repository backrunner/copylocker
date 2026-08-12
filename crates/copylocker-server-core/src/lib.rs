//! Server-side domain logic, with no Cloudflare dependency.
//!
//! Everything the license server decides lives here as pure functions and traits. Storage,
//! signing, and the clock arrive through traits, so the whole server can be driven from an
//! in-memory harness on a developer's machine — which is what makes seat-race tests, property
//! tests, and fuzzing possible at all (`10-server-worker.md §8`).
//!
//! # Error discipline
//!
//! [`ClientFault`] and [`ServerFault`] are separate types with no conversion between them.
//! A client fault becomes a 4xx and the client fails closed; a server fault becomes a 5xx and
//! the client fails **open** into its grace window. Merging them into one enum is how outages
//! turn into mass lockouts (`10-server-worker.md §4`).

// The host-only `ts-rs` feature (admin-sdk binding generation) links std because the
// ts-rs derive emits std-prelude code. Every other build stays no_std + alloc.
#![cfg_attr(not(feature = "ts-rs"), no_std)]
#![forbid(unsafe_code)]
// In tests, unwrap/expect are assertion shorthand. Production code keeps the workspace denies.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

extern crate alloc;

pub mod activate;
pub mod analytics;
pub mod anomaly;
pub mod catalog;
pub mod deactivate;
pub mod entitlement;
pub mod error;
pub mod fingerprint_match;
pub mod heartbeat;
pub mod policy;
pub mod revoke;
pub mod simulator;
pub mod store;
pub mod subscription;
pub mod validate;
pub mod version;

pub use activate::{commit_seat, reserve_seat, ActivateInput, Reservation};
pub use catalog::{Catalog, Feature, FeatureGroup, GroupMembers, Tier};
pub use deactivate::{deactivate, DeactivatePlan};
pub use entitlement::{
    resolve, EntitlementSpec, Grant, GrantTarget, LimitMergePolicy, PolicyError,
};
pub use error::{ClientFault, ServerFault};
pub use heartbeat::{heartbeat, reclaim_zombies, HeartbeatPlan};
pub use policy::{Mode, Policy, Preset, RuntimeSpec, SeatSpec, Validity};
pub use revoke::{revoke, RevokeError, RevokePlan, RevokeTarget};
pub use store::{
    ActivationRecord, ActivationStatus, Clock, Issuer, LicenseRecord, LicenseStatus, ProofVerifier,
    Storage,
};
pub use subscription::{Subscription, SubscriptionEvent, SubscriptionState};
pub use validate::{validate, TicketPlan, ValidateInput, ValidateOutcome};
pub use version::VersionDecision;
