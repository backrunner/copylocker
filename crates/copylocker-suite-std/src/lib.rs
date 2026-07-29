//! CL-STD-1 — the open reference crypto suite (`crypto-architecture.md §3`).
//!
//! | Slot | Algorithm |
//! |---|---|
//! | Signature | `Hybrid(Ed25519, ML-DSA-65)` |
//! | Fast signature | Ed25519 (per-request tickets only) |
//! | KEM | X-Wing (X25519 + ML-KEM-768) |
//! | AEAD | XChaCha20-Poly1305 |
//! | KDF | HKDF-SHA-512, Argon2id for low-entropy input |
//! | Hash | SHA-256 (protocol), BLAKE3 (manifests) |
//! | Fingerprint | HMAC-SHA-256 over canonical attributes |
//! | Codec | Deterministic CBOR |
//! | Binder | `HKDF(secret ‖ fp ‖ H(env))` |
//!
//! Everything here composes standard primitives from audited crates. Nothing in this crate
//! invents an algorithm; the one construction assembled locally, X-Wing, follows a published
//! specification byte for byte.

#![no_std]
#![forbid(unsafe_code)]
// In tests, unwrap/expect are assertion shorthand. Production code keeps the workspace denies.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

extern crate alloc;

pub mod aead;
pub mod binder;
pub mod codec;
pub mod fingerprint;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod rng;
pub mod sig;

pub use aead::XChaCha20Poly1305Aead;
pub use binder::HkdfBinder;
pub use codec::CanonicalCborCodec;
pub use fingerprint::HmacFingerprint;
pub use hash::{Blake3Scheme, Sha256Scheme};
pub use kdf::HkdfSha512;
pub use kem::XWingKem;
pub use rng::{FromRandCore, RandCoreBridge};
pub use sig::{FastSig, HybridSig};

use copylocker_suite::{CryptoSuite, VendorParams};
use copylocker_types::SuiteId;

/// The CL-STD-1 suite identifier.
pub const CL_STD_1_SUITE_ID: SuiteId = SuiteId::from_u32(0x0100_0001);

/// CL-STD-1.
#[derive(Clone, Debug)]
pub struct ClStd1 {
    params: VendorParams,
}

impl CryptoSuite for ClStd1 {
    const SUITE_ID: SuiteId = CL_STD_1_SUITE_ID;
    const PROTO_VER: u8 = copylocker_types::PROTO_VER;
    const NAME: &'static str = "CL-STD-1";

    type Sig = HybridSig;
    type Kem = XWingKem;
    type Aead = XChaCha20Poly1305Aead;
    type Kdf = HkdfSha512;
    type Hash = Sha256Scheme;
    type Fpr = HmacFingerprint;
    type Codec = CanonicalCborCodec;
    type Binder = HkdfBinder;

    fn with_vendor_params(p: &VendorParams) -> Self {
        Self { params: p.clone() }
    }

    fn vendor_params(&self) -> &VendorParams {
        &self.params
    }
}

/// A deterministic RNG for tests and for the CLI's `--deterministic` mode.
///
/// `crypto-architecture.md §7` forbids a seedable RNG on any production path. This helper is
/// therefore gated to `cfg(test)` plus the explicitly named `deterministic-rng` feature, so
/// reaching for it requires an intentional, greppable opt-in.
#[cfg(any(test, feature = "deterministic-rng"))]
pub fn test_rng(seed: u64) -> FromRandCore<rand_chacha::ChaCha20Rng> {
    use rand_core::SeedableRng;
    FromRandCore(rand_chacha::ChaCha20Rng::seed_from_u64(seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_suite::{AeadScheme, KeyEncapsulation, SignatureScheme};

    #[test]
    fn suite_identity_is_as_specified() {
        assert_eq!(ClStd1::SUITE_ID.to_u32(), 0x0100_0001);
        assert_eq!(ClStd1::PROTO_VER, 1);
        assert_eq!(ClStd1::NAME, "CL-STD-1");
    }

    #[test]
    fn passes_the_public_suite_conformance_contract() {
        copylocker_suite_testkit::assert_conformant::<ClStd1>();
    }

    #[test]
    fn vendor_params_are_carried() {
        let p = VendorParams::from_salt(alloc::vec![1, 2, 3]);
        let s = ClStd1::with_vendor_params(&p);
        assert_eq!(s.vendor_params().fpr_salt, alloc::vec![1, 2, 3]);
    }

    #[test]
    fn vendor_params_debug_redacts_the_salt() {
        let p = VendorParams::from_salt(alloc::vec![0xde, 0xad]);
        let rendered = alloc::format!("{p:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("222"), "salt bytes must not appear");
    }

    #[test]
    fn declared_slot_parameters_are_self_consistent() {
        assert_eq!(<ClStd1 as CryptoSuite>::Aead::KEY_LEN, 32);
        assert_eq!(<ClStd1 as CryptoSuite>::Aead::NONCE_LEN, 24);
        assert!(<ClStd1 as CryptoSuite>::Sig::is_post_quantum());
        assert_eq!(<ClStd1 as CryptoSuite>::Kem::EK_LEN, 1216);
    }

    /// End-to-end exercise of the key hierarchy in `crypto-architecture.md §6`:
    /// encapsulate a credential secret to a device, bind it, derive a session root, then a
    /// feature key.
    #[test]
    fn full_feature_key_derivation_chain() {
        use copylocker_suite::{DeviceBinder, EnvEvidence, KeyDerivation};
        use copylocker_types::{Digest, Fingerprint};

        let mut rng = test_rng(42);
        let (device_dk, device_ek) = XWingKem::keygen(&mut rng);

        // Server side: encapsulate to the device.
        let (kem_ct, ss_server) = XWingKem::encap(&device_ek, &mut rng).unwrap();
        // Client side: recover the same secret.
        let ss_client = XWingKem::decap(&device_dk, &kem_ct).unwrap();
        assert_eq!(ss_server.expose(), ss_client.expose());

        let fp = Fingerprint::from_vec(alloc::vec![7; 32]);
        let env = EnvEvidence {
            module_digest: Digest([3; 32]),
            build_fingerprint: b"build-2026.07".to_vec(),
            extra: alloc::vec![],
        };
        let bound = HkdfBinder::bind(&ss_client, &fp, &env).unwrap();

        let prk = HkdfSha512::extract(b"copylocker/sr/v1", bound.expose());
        let session_root = HkdfSha512::derive_key(&prk, &[b"server-nonce", b"epoch-id"]).unwrap();

        let fk_prk = HkdfSha512::extract(b"copylocker/fk/v1", session_root.as_slice());
        let fk_pdf = HkdfSha512::derive_key(&fk_prk, &[b"acme", b"export.pdf"]).unwrap();
        let fk_svg = HkdfSha512::derive_key(&fk_prk, &[b"acme", b"export.svg"]).unwrap();

        // Distinct features must yield distinct keys, or sealing one asset would unseal another.
        assert!(!fk_pdf.ct_eq(&fk_svg));

        // And a different device cannot arrive at the same feature key.
        let other_fp = Fingerprint::from_vec(alloc::vec![8; 32]);
        let other_bound = HkdfBinder::bind(&ss_client, &other_fp, &env).unwrap();
        let other_prk = HkdfSha512::extract(b"copylocker/sr/v1", other_bound.expose());
        let other_root =
            HkdfSha512::derive_key(&other_prk, &[b"server-nonce", b"epoch-id"]).unwrap();
        assert!(!session_root.ct_eq(&other_root));
    }
}
