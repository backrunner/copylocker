//! Shared data types for CopyLocker.
//!
//! Per [`00-crate-layout.md §3`], this crate holds **pure data types only**: no I/O, no
//! cryptography, no policy decisions. It is `no_std + alloc` so that it can be linked into
//! the browser WASM core and the Cloudflare Worker alike.
//!
//! The only "logic" admitted here is [`TimeWindow::contains`], which exists precisely so that
//! the whole codebase shares one inclusive/exclusive boundary convention
//! (`crypto-architecture.md §8`, "time comparison with `>` instead of `>=`" pitfall).

// The host-only `ts-rs` feature (admin-sdk binding generation) links std because the
// ts-rs derive emits std-prelude code. Every other build stays no_std + alloc.
#![cfg_attr(not(feature = "ts-rs"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod entitlements;
pub mod ids;
pub mod state;
pub mod time;

pub use entitlements::{
    Entitlements, LimitValue, SubscriptionHint, SubscriptionState, VersionScope,
};
pub use ids::{Digest, EpochId, Fingerprint, LicenseId, MachineId, ProductId, SuiteId};
pub use state::{
    ArtifactKind, KillReason, LicenseState, Mode, SecurityLevel, StateReason, Verdict,
};
pub use time::TimeWindow;

/// Wire protocol version implemented by this build (`protocol-spec.md`).
pub const PROTO_VER: u8 = 1;

/// Maximum accepted CBOR nesting depth on any parsing entry point
/// (`protocol-spec.md §10.1`).
pub const MAX_CBOR_DEPTH: u8 = 16;

/// Maximum accepted request body size for client-facing endpoints, in bytes
/// (`protocol-spec.md §10.1`).
pub const MAX_BODY_BYTES: usize = 16 * 1024;
