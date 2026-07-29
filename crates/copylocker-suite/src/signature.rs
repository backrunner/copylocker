//! Signature slot.

use alloc::vec::Vec;

use copylocker_types::SecurityLevel;
use zeroize::Zeroize;

use crate::{CryptoError, CryptoRng, DomainCtx};

/// An opaque signature blob.
///
/// For hybrid schemes this is the length-prefixed concatenation of both components
/// (`crypto-architecture.md §3.1`); the layout is the scheme's business, not the caller's.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Signature(pub Vec<u8>);

impl Signature {
    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the signature is empty (always invalid).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Signature {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

/// A digital signature scheme.
///
/// # Hybrid discipline
///
/// For a PQ/T hybrid implementation, `verify` **must** require both components to pass. There
/// must be no code path that accepts a single component — not behind a feature flag, not behind
/// a config option (FR-CRY-004). A single-component pass is reported as
/// [`CryptoError::HybridStripDetected`] so the caller can log the attack, and is still a
/// failure.
pub trait SignatureScheme {
    /// Private key type. Must wipe itself on drop.
    type SigningKey: Zeroize;
    /// Public key type. `Debug` is required because public keys are safe to log and callers
    /// embed them in diagnostic structures.
    type VerifyingKey: Clone + PartialEq + core::fmt::Debug;

    /// Upper bound on signature length, for buffer sizing and wire limits.
    const SIG_MAX_LEN: usize;
    /// Encoded verifying key length.
    const VK_LEN: usize;
    /// Encoded signing key (seed) length.
    const SK_LEN: usize;

    /// Generate a fresh key pair.
    ///
    /// The RNG is passed explicitly rather than taken from a library default, so that the
    /// randomness source is always an auditable choice (`crypto-architecture.md §8`).
    fn generate(rng: &mut dyn CryptoRng) -> (Self::SigningKey, Self::VerifyingKey);

    /// Derive the verifying key from a signing key.
    fn verifying_key(sk: &Self::SigningKey) -> Self::VerifyingKey;

    /// Sign `msg` under domain context `ctx`.
    fn sign(
        sk: &Self::SigningKey,
        ctx: DomainCtx<'_>,
        msg: &[u8],
    ) -> Result<Signature, CryptoError>;

    /// Verify `sig` over `msg` under domain context `ctx`.
    ///
    /// Returns `Ok(())` only on full success.
    fn verify(
        vk: &Self::VerifyingKey,
        ctx: DomainCtx<'_>,
        msg: &[u8],
        sig: &Signature,
    ) -> Result<(), CryptoError>;

    /// Serialise a verifying key for the wire.
    fn encode_vk(vk: &Self::VerifyingKey) -> Vec<u8>;

    /// Parse a verifying key from the wire.
    fn decode_vk(bytes: &[u8]) -> Result<Self::VerifyingKey, CryptoError>;

    /// Serialise a signing key. Callers are responsible for protecting the output.
    fn encode_sk(sk: &Self::SigningKey) -> Vec<u8>;

    /// Parse a signing key.
    fn decode_sk(bytes: &[u8]) -> Result<Self::SigningKey, CryptoError>;

    /// The claimed security level, used for `security_floor` monotonicity checks.
    fn security_level() -> SecurityLevel;

    /// Whether this scheme resists a cryptographically relevant quantum computer.
    ///
    /// `false` for the classical fast-path scheme used for per-request `ValidationTicket`
    /// signatures, whose limited blast radius is analysed in `protocol-spec.md §5`.
    fn is_post_quantum() -> bool;
}
