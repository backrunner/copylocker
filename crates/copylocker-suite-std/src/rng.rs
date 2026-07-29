//! Bridge between CopyLocker's object-safe [`CryptoRng`] and the `rand_core` traits that the
//! upstream primitive crates require.
//!
//! `crypto-architecture.md §8` requires that the randomness source be passed in explicitly
//! rather than taken from a library default, so that "which CSPRNG did this key come from" is
//! answerable by reading the call site.

use core::convert::Infallible;

use copylocker_suite::CryptoRng;
use rand_core::{TryCryptoRng, TryRng};

/// Adapts `&mut dyn CryptoRng` into something the `rand_core`-based crates accept.
pub struct RandCoreBridge<'a> {
    inner: &'a mut dyn CryptoRng,
}

impl core::fmt::Debug for RandCoreBridge<'_> {
    /// Never renders internal state: for a seeded test RNG that state *is* the key stream.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RandCoreBridge")
    }
}

impl<'a> RandCoreBridge<'a> {
    /// Wrap a randomness source.
    pub fn new(inner: &'a mut dyn CryptoRng) -> Self {
        Self { inner }
    }
}

impl TryRng for RandCoreBridge<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.inner.fill_bytes(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.inner.fill_bytes(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.inner.fill_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for RandCoreBridge<'_> {}

/// Adapts a `rand_core` generator into CopyLocker's [`CryptoRng`].
///
/// This is the direction used at the edges: the host supplies `OsRng` (desktop) or the Workers
/// runtime's `crypto.getRandomValues`, and the whole library sees only the narrow trait.
pub struct FromRandCore<R>(pub R);

impl<R: rand_core::CryptoRng> CryptoRng for FromRandCore<R> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
}

impl<R> core::fmt::Debug for FromRandCore<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FromRandCore")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{Rng, SeedableRng};

    #[test]
    fn bridge_round_trips_between_the_two_trait_families() {
        let inner = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        let mut ours = FromRandCore(inner);
        let mut bridged = RandCoreBridge::new(&mut ours);
        let mut a = [0u8; 32];
        bridged.fill_bytes(&mut a);

        // The same seed must reproduce the same stream through the same path.
        let inner2 = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        let mut ours2 = FromRandCore(inner2);
        let mut bridged2 = RandCoreBridge::new(&mut ours2);
        let mut b = [0u8; 32];
        bridged2.fill_bytes(&mut b);

        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
