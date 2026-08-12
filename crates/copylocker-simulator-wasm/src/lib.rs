//! The console/browser shell over the policy simulator (`licensing-model.md §11`).
//!
//! The admin console's Simulator page must produce output identical to
//! `copylocker policy simulate` and to the live server, so this crate wraps
//! [`copylocker_server_core::simulator::simulate`] — the very function the CLI
//! calls — instead of reimplementing anything. The wasm shell is one opaque
//! entry point: a JSON [`SimulationRequest`] in, a JSON
//! [`copylocker_server_core::simulator::Simulation`] (or an error string) out.
//!
//! Unlike `copylocker-wasm` (the client SDK core), this shell runs inside the
//! vendor-facing admin console, so errors are allowed to carry human-readable
//! text; NFR-SEC-011's numeric-codes-only rule targets client-side SDKs.

#![forbid(unsafe_code)]

mod sim;

pub use sim::{simulate_json, SimulationRequest, MAX_REQUEST_BYTES};

#[cfg(target_arch = "wasm32")]
mod wasm;
