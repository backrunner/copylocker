//! Crypto-agility slot contracts (ADR-0001, `crypto-architecture.md §2`).
//!
//! This crate defines **only traits and the small value types they exchange**. It never depends
//! on a concrete suite; the dependency arrow points the other way. A vendor swaps CL-STD-1 for
//! a private suite by changing one type alias, because everything above this layer is generic
//! over [`CryptoSuite`].
//!
//! # Stability
//!
//! Semantic versioning here is deliberately conservative: any trait change is breaking and
//! forces every out-of-tree suite to be updated in lockstep. New capabilities should arrive as
//! **new traits with default implementations**, not as changes to existing ones
//! (`00-crate-layout.md §3`).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod aead;
pub mod artifact;
pub mod binder;
pub mod cbor;
pub mod device;
pub mod domain;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod rng;
pub mod secret;
pub mod signature;

pub use aead::AeadScheme;
pub use artifact::{Artifact, ArtifactCodec};
pub use binder::{BoundSecret, DeviceBinder, EnvEvidence};
pub use device::{AttrKey, AttrValue, DeviceAttrs, EnvClass, FingerprintScheme};
pub use domain::DomainCtx;
pub use error::{CodecError, CryptoError};
pub use hash::{HashScheme, StreamingHash};
pub use kdf::{KeyDerivation, Prk};
pub use kem::{Ciphertext, KeyEncapsulation, SharedSecret};
pub use rng::CryptoRng;
pub use secret::Secret;
pub use signature::{Signature, SignatureScheme};

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use copylocker_types::SuiteId;

/// Per-vendor parameters mixed into a suite instance.
///
/// For CL-STD-1 this carries only the fingerprint salt. A private suite
/// (`80-private-suite.md`) additionally derives its key-schedule tweaks from here, which is what
/// makes two vendors' deployments non-interchangeable without changing the algorithms.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct VendorParams {
    /// Per-vendor fingerprint salt. Never leaves the server in plaintext.
    pub fpr_salt: Vec<u8>,
    /// Opaque additional parameters, suite-defined.
    pub extra: BTreeMap<String, Vec<u8>>,
}

impl VendorParams {
    /// Build from a fingerprint salt alone, which is all CL-STD-1 needs.
    #[must_use]
    pub fn from_salt(fpr_salt: Vec<u8>) -> Self {
        Self {
            fpr_salt,
            extra: BTreeMap::new(),
        }
    }
}

impl core::fmt::Debug for VendorParams {
    /// Deliberately opaque: `fpr_salt` is secret material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VendorParams")
            .field("fpr_salt", &"<redacted>")
            .field("extra_keys", &self.extra.len())
            .finish()
    }
}

/// The full slot assignment for one crypto suite.
///
/// A suite is a *type-level* bundle: every slot is an associated type, so choosing a suite is a
/// compile-time decision with no dynamic dispatch on the hot path.
pub trait CryptoSuite: Send + Sync + 'static {
    /// Four-byte identifier written into every artifact header and covered by signatures and
    /// AEAD AAD alike.
    const SUITE_ID: SuiteId;

    /// Wire protocol version this suite speaks.
    const PROTO_VER: u8;

    /// Human-readable suite name, e.g. `"CL-STD-1"`.
    const NAME: &'static str;

    /// Signature slot.
    type Sig: SignatureScheme;
    /// Key encapsulation slot.
    type Kem: KeyEncapsulation;
    /// Authenticated encryption slot.
    type Aead: AeadScheme;
    /// Key derivation slot.
    type Kdf: KeyDerivation;
    /// Hash slot.
    type Hash: HashScheme;
    /// Fingerprint slot.
    type Fpr: FingerprintScheme;
    /// Artifact encoding slot.
    type Codec: ArtifactCodec;
    /// Device binding slot.
    type Binder: DeviceBinder;

    /// Instantiate the suite with vendor-specific parameters.
    fn with_vendor_params(p: &VendorParams) -> Self;

    /// The vendor parameters this instance was built with.
    fn vendor_params(&self) -> &VendorParams;
}
