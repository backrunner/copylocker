//! Randomness plumbing for the session (`crypto-architecture.md §7`).
//!
//! [`CryptoRng`] is infallible by contract, but real entropy sources can fail. This module
//! adapts a fallible source by latching the failure: the buffer is zeroed, the caller checks
//! [`SessionRng::failed`] after the operation, and the tainted key material is never used.
//! This mirrors `CryptoRngAdapter` in `copylocker-client`.

use copylocker_suite::CryptoRng;

/// A `CryptoRng` whose failures can be observed after the fact.
///
/// Callers must `reset()` before an operation and check `failed()` after it; on failure the
/// produced material must be discarded. Implementations must be cryptographically secure
/// sources — never anything seedable from attacker-influenced input on a production path.
pub trait SessionRng: CryptoRng {
    /// Whether any fill since the last [`SessionRng::reset`] failed.
    fn failed(&self) -> bool;
    /// Clear the failure latch before starting a new operation.
    fn reset(&mut self);
}

/// The production source: the OS CSPRNG natively, WebCrypto `getRandomValues` on wasm32
/// (via `getrandom`'s `wasm_js` backend).
#[derive(Debug, Default)]
pub struct GetrandomRng {
    failed: bool,
}

impl GetrandomRng {
    /// A fresh source with a clear failure latch.
    #[must_use]
    pub const fn new() -> Self {
        Self { failed: false }
    }
}

impl SessionRng for GetrandomRng {
    fn failed(&self) -> bool {
        self.failed
    }

    fn reset(&mut self) {
        self.failed = false;
    }
}

impl CryptoRng for GetrandomRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if getrandom::fill(dest).is_err() {
            dest.fill(0);
            self.failed = true;
        }
    }
}
