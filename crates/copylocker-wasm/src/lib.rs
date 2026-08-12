//! Browser WASM core for the CopyLocker web SDK (`40-web-sdk-wasm-ts.md`).
//!
//! The crate exposes exactly one opaque entry point to JavaScript: [`ClSession::step`]
//! (wasm32 only). Every operation — activation, validation, snapshot persistence, state
//! queries, and derivation of the "half-baked" key material `M` — is a CBOR map whose `op`
//! field selects the behaviour, so the WASM export surface carries no semantic names an
//! attacker can grep for. Errors are numeric codes only (NFR-SEC-011).
//!
//! All verification semantics replicate the desktop client (`copylocker-client`): pinned-root
//! certificate chain verification, KEM unsealing of the credential secret, `KeyMaterial::bind`,
//! the eight ticket checks, monotonic revocation/security-floor watermarks, and the shared
//! state machine from `copylocker-core`. The TypeScript shell owns transport, timers, and
//! storage; this core owns cryptography and state.
//!
//! The platform-independent logic lives in [`session`]; the `wasm-bindgen` wrapper is a thin
//! shell compiled only for `wasm32`, so `cargo test -p copylocker-wasm` exercises the full
//! protocol on the host.

// In tests, unwrap/expect are assertion shorthand. Production code keeps the workspace denies.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod codes;
pub mod rng;
pub mod session;

pub use rng::{GetrandomRng, SessionRng};
pub use session::Session;

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(target_arch = "wasm32")]
pub use wasm::ClSession;
