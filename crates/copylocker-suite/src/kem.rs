//! Key encapsulation slot.

use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, CryptoRng};

/// An encapsulation ciphertext.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Ciphertext(pub Vec<u8>);

impl Ciphertext {
    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Ciphertext {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

/// A 32-byte KEM shared secret.
///
/// Wiped on drop and never rendered; the only way to read it is [`SharedSecret::expose`].
#[derive(Default, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Width in bytes.
    pub const LEN: usize = 32;

    /// Wrap raw bytes.
    #[must_use]
    pub const fn new(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// Borrow the secret bytes.
    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// A key encapsulation mechanism.
///
/// CL-STD-1 fills this slot with X-Wing, a *specified* hybrid combiner with a security proof,
/// rather than an ad-hoc concatenation — designing a KEM combiner in-house is exactly the kind
/// of thing `crypto-architecture.md §1` rules out.
pub trait KeyEncapsulation {
    /// Private key. Must wipe itself on drop.
    type DecapKey: Zeroize;
    /// Public key. `Debug` for the same reason as verifying keys: public material is loggable.
    type EncapKey: Clone + PartialEq + core::fmt::Debug;

    /// Encoded encapsulation key length.
    const EK_LEN: usize;
    /// Encoded decapsulation key (seed) length.
    const DK_LEN: usize;
    /// Ciphertext length.
    const CT_LEN: usize;

    /// Generate a fresh key pair.
    fn keygen(rng: &mut dyn CryptoRng) -> (Self::DecapKey, Self::EncapKey);

    /// Derive the public key from a private key.
    fn encap_key(dk: &Self::DecapKey) -> Self::EncapKey;

    /// Encapsulate to `ek`, producing a ciphertext and the shared secret.
    fn encap(
        ek: &Self::EncapKey,
        rng: &mut dyn CryptoRng,
    ) -> Result<(Ciphertext, SharedSecret), CryptoError>;

    /// Recover the shared secret from a ciphertext.
    ///
    /// Note that ML-KEM (and therefore X-Wing) is *implicitly rejecting*: a wrong ciphertext
    /// yields an unrelated shared secret rather than an error. Callers must not treat `Ok` as
    /// proof of anything — the AEAD unwrap that follows is what actually authenticates
    /// (`crypto-architecture.md §6`, step ②).
    fn decap(dk: &Self::DecapKey, ct: &Ciphertext) -> Result<SharedSecret, CryptoError>;

    /// Serialise an encapsulation key for the wire.
    fn encode_ek(ek: &Self::EncapKey) -> Vec<u8>;

    /// Parse an encapsulation key from the wire.
    fn decode_ek(bytes: &[u8]) -> Result<Self::EncapKey, CryptoError>;

    /// Serialise a decapsulation key. Callers must protect the output.
    fn encode_dk(dk: &Self::DecapKey) -> Vec<u8>;

    /// Parse a decapsulation key.
    fn decode_dk(bytes: &[u8]) -> Result<Self::DecapKey, CryptoError>;
}
