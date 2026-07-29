//! CopyLocker client domain core (`20-client-core.md`).
//!
//! Pure domain logic with **no I/O, no clock, no randomness**: everything external arrives as a
//! parameter. That constraint is what makes the client 100% deterministically testable — every
//! state transition, clock trick, and key derivation in this crate runs identically on a
//! developer laptop, in CI, and under a fuzzer (`20-client-core.md §1`).
//!
//! Layers above (`copylocker-client`, the Tauri/Electron/WASM shells) supply transport, storage,
//! timers, and entropy, and carry out the [`Effect`]s this core returns.
//!
//! # The two rules that shape this API
//!
//! 1. **No function returns `bool` for a licence check** (ADR-0004). The productive check is
//!    [`KeyMaterial::feature_key`]: it yields a key that decrypts something, or an error.
//! 2. **Transient and fatal failures are different types** with no conversion between them
//!    (`20-client-core.md §1.1`), so the fail-open path cannot be reached by a crypto failure.

#![no_std]
#![forbid(unsafe_code)]
// In tests, unwrap/expect are assertion shorthand. Production code keeps the workspace denies.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

extern crate alloc;

pub mod clock;
pub mod error;
pub mod keys;
pub mod state;
pub mod ticket;

pub use clock::{ClockState, ClockVerdict, DEFAULT_ROLLBACK_THRESHOLD};
pub use error::{CoreError, FatalError, TransientError};
pub use keys::{KeyMaterial, SessionKind};
pub use state::{CoreConfig, Deadlines, Effect, Event, StateMachine};
pub use ticket::{check_ticket, TicketChecks};
