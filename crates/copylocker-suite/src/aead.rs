//! Authenticated encryption slot.

use alloc::vec::Vec;

use crate::{CryptoError, CryptoRng};

/// An AEAD.
///
/// CL-STD-1 uses XChaCha20-Poly1305: constant-time without hardware support (WASM has no
/// AES-NI) and with a nonce wide enough to generate randomly forever, which removes the need
/// for a counter that multi-device deployments cannot safely maintain
/// (`crypto-architecture.md §3.3`).
pub trait AeadScheme {
    /// Key length in bytes.
    const KEY_LEN: usize;
    /// Nonce length in bytes.
    const NONCE_LEN: usize;
    /// Authentication tag length in bytes.
    const TAG_LEN: usize;

    /// Whether a randomly generated nonce is safe for this scheme.
    ///
    /// `true` requires a nonce wide enough that birthday collisions are negligible (192 bits for
    /// XChaCha20). A scheme with a 96-bit nonce must return `false`, and callers must then
    /// maintain a counter.
    const RANDOM_NONCE_SAFE: bool;

    /// Encrypt and authenticate. Output is ciphertext ‖ tag.
    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Verify and decrypt.
    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Draw a fresh nonce.
    ///
    /// Only callable on schemes where random nonces are sound; the default panics-free path is
    /// to return an error instead, so a mis-parameterised suite fails loudly at runtime rather
    /// than silently reusing nonces.
    fn random_nonce(rng: &mut dyn CryptoRng) -> Result<Vec<u8>, CryptoError> {
        if !Self::RANDOM_NONCE_SAFE {
            return Err(CryptoError::BadLength);
        }
        let mut n = alloc::vec![0u8; Self::NONCE_LEN];
        rng.fill_bytes(&mut n);
        Ok(n)
    }

    /// Seal with a freshly drawn nonce, returning `nonce ‖ ciphertext ‖ tag`.
    ///
    /// This is the shape stored on disk and on the wire: the nonce always travels with the
    /// ciphertext, so there is no separate nonce-management burden on callers
    /// (`crypto-architecture.md §8`).
    fn seal_with_nonce(
        key: &[u8],
        aad: &[u8],
        pt: &[u8],
        rng: &mut dyn CryptoRng,
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Self::random_nonce(rng)?;
        let mut out = Vec::with_capacity(nonce.len() + pt.len() + Self::TAG_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&Self::seal(key, &nonce, aad, pt)?);
        Ok(out)
    }

    /// Inverse of [`AeadScheme::seal_with_nonce`].
    fn open_with_nonce(key: &[u8], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if blob.len() < Self::NONCE_LEN + Self::TAG_LEN {
            return Err(CryptoError::BadLength);
        }
        let (nonce, ct) = blob.split_at(Self::NONCE_LEN);
        Self::open(key, nonce, aad, ct)
    }
}
