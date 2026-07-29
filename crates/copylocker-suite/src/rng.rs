//! Randomness contract.
//!
//! `crypto-architecture.md §7` forbids both home-grown PRNGs and any deterministic RNG
//! reachable from a production path. The contract here is deliberately minimal and
//! object-safe: callers pass `&mut dyn CryptoRng`, so the concrete source (OS CSPRNG,
//! `crypto.getRandomValues`, or a seeded test RNG behind `#[cfg(test)]`) is chosen at the edge
//! and never inferred by a library default.

/// A cryptographically secure randomness source.
///
/// Implementing this type is an assertion that the source is suitable for key generation.
/// Do not implement it for anything seedable from a value an attacker can influence.
pub trait CryptoRng {
    /// Fill `dest` entirely with random bytes.
    ///
    /// Implementations must either succeed or panic-free abort at the edge; a partial fill is a
    /// contract violation. Sources that can fail should be wrapped so the failure surfaces
    /// before this call.
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

impl<T: CryptoRng + ?Sized> CryptoRng for &mut T {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        (**self).fill_bytes(dest);
    }
}

/// Convenience: draw a fixed-width array.
pub fn random_array<const N: usize>(rng: &mut dyn CryptoRng) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}
