//! Device binding slot.

use alloc::vec::Vec;

use copylocker_types::{Digest, Fingerprint};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, SharedSecret};

/// Evidence about the running environment, mixed into the key schedule.
///
/// The point is that a credential lifted onto another machine — or into a patched build on the
/// same machine — derives different keys and therefore cannot unseal anything
/// (`crypto-architecture.md §6`, step ③).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct EnvEvidence {
    /// Digest of the executing module: the main binary's `.text` on Tauri, the `.node` plus
    /// `app.asar` on Electron, the WASM binary on the web.
    pub module_digest: Digest,
    /// Build fingerprint injected at build time, tying keys to one specific build.
    pub build_fingerprint: Vec<u8>,
    /// Additional platform-specific evidence, ordered by the caller and length-prefixed on use.
    pub extra: Vec<Vec<u8>>,
}

impl EnvEvidence {
    /// Evidence parts in canonical order, for hashing.
    #[must_use]
    pub fn parts(&self) -> Vec<&[u8]> {
        let mut v: Vec<&[u8]> = Vec::with_capacity(2 + self.extra.len());
        v.push(self.module_digest.as_bytes());
        v.push(&self.build_fingerprint);
        for e in &self.extra {
            v.push(e);
        }
        v
    }
}

/// A shared secret that has been bound to a device and environment.
///
/// Distinct type from [`SharedSecret`] on purpose: the type system then prevents deriving a
/// session root straight from the unbound KEM output, which would silently drop device binding.
#[derive(Default, ZeroizeOnDrop)]
pub struct BoundSecret([u8; 32]);

impl BoundSecret {
    /// Width in bytes.
    pub const LEN: usize = 32;

    /// Wrap raw bytes.
    #[must_use]
    pub const fn new(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// Borrow the bound secret.
    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Zeroize for BoundSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for BoundSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BoundSecret(<redacted>)")
    }
}

/// Mixes fingerprint and environment evidence into the key schedule.
///
/// This slot is the main lever a private suite pulls (`80-private-suite.md`): the transform can
/// be arbitrarily idiosyncratic without changing anything above it. Crucially, the private
/// variant buys *cost asymmetry*, not confidentiality — the system must remain unforgeable even
/// with the transform fully published.
pub trait DeviceBinder {
    /// Bind a KEM shared secret to a device.
    fn bind(
        secret: &SharedSecret,
        fp: &Fingerprint,
        env: &EnvEvidence,
    ) -> Result<BoundSecret, CryptoError>;
}
