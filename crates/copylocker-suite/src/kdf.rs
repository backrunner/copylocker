//! Key derivation slot.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Secret};

/// A pseudo-random key: the output of extract, the input to expand.
#[derive(ZeroizeOnDrop)]
pub struct Prk([u8; 64]);

impl Default for Prk {
    fn default() -> Self {
        Self([0u8; Self::MAX_LEN])
    }
}

impl Prk {
    /// Maximum PRK width. HKDF-SHA-512 fills all 64 bytes; narrower hashes fill a prefix and
    /// record the used length via [`Prk::len`].
    pub const MAX_LEN: usize = 64;

    /// Build from raw bytes, truncating or zero-padding to the buffer width.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut out = [0u8; Self::MAX_LEN];
        let n = b.len().min(Self::MAX_LEN);
        // Both slices are bounded by `n`, which is `min`-clamped to the buffer width.
        #[allow(clippy::indexing_slicing)]
        out[..n].copy_from_slice(&b[..n]);
        Self(out)
    }

    /// Borrow the full buffer.
    #[must_use]
    pub const fn expose(&self) -> &[u8; Self::MAX_LEN] {
        &self.0
    }

    /// Width of the buffer.
    #[must_use]
    pub const fn len(&self) -> usize {
        Self::MAX_LEN
    }

    /// Always `false`; present to satisfy the `len`/`is_empty` lint pairing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl Zeroize for Prk {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for Prk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Prk(<redacted>)")
    }
}

/// An extract-then-expand key derivation function.
pub trait KeyDerivation {
    /// Extract a PRK from possibly-non-uniform input keying material.
    fn extract(salt: &[u8], ikm: &[u8]) -> Prk;

    /// Expand a PRK into `out`, bound to `info`.
    fn expand(prk: &Prk, info: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;

    /// Expand bound to a *sequence* of info parts.
    ///
    /// The parts are length-prefixed before concatenation, which keeps the binding injective:
    /// without prefixes, `["ab", "c"]` and `["a", "bc"]` would derive the same key. Every
    /// multi-part derivation in the key hierarchy (`crypto-architecture.md §6`) goes through
    /// here for exactly that reason.
    fn expand_parts(prk: &Prk, parts: &[&[u8]], out: &mut [u8]) -> Result<(), CryptoError> {
        let mut info = alloc::vec::Vec::new();
        for p in parts {
            let len = u32::try_from(p.len()).map_err(|_| CryptoError::OutputTooLong)?;
            info.extend_from_slice(&len.to_be_bytes());
            info.extend_from_slice(p);
        }
        Self::expand(prk, &info, out)
    }

    /// Convenience: derive a 32-byte key from a PRK and a sequence of info parts.
    fn derive_key(prk: &Prk, parts: &[&[u8]]) -> Result<Secret<[u8; 32]>, CryptoError> {
        let mut k = Secret::zeroed();
        Self::expand_parts(prk, parts, k.expose_mut())?;
        Ok(k)
    }

    /// Convenience: extract-then-expand in one step.
    fn derive_from(
        salt: &[u8],
        ikm: &[u8],
        parts: &[&[u8]],
    ) -> Result<Secret<[u8; 32]>, CryptoError> {
        let prk = Self::extract(salt, ikm);
        Self::derive_key(&prk, parts)
    }

    /// Stretch a low-entropy secret (a password, a short code) into key material.
    ///
    /// This is a *different primitive* from [`KeyDerivation::extract`]: HKDF assumes its input
    /// already has entropy, so feeding it a password provides no work factor. CL-STD-1 fills
    /// this with Argon2id (`crypto-architecture.md §3`).
    fn stretch(salt: &[u8], low_entropy: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;
}
