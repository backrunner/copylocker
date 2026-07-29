//! The signature envelope (`protocol-spec.md §1`).
//!
//! ```cddl
//! envelope = {
//!   0: uint,          ; proto_ver
//!   1: bytes .size 4, ; suite_id
//!   2: uint,          ; artifact_kind
//!   3: bytes,         ; tbs — the inner artifact's canonical CBOR
//!   4: bytes,         ; sig
//!   5: ? bytes,       ; epoch_cert_ref — 8-byte epoch_id
//! }
//! ```
//!
//! The signature covers `tbs` under a domain context derived from `artifact_kind`, `suite_id`,
//! and `product_id`. Because the kind is *inside* the signed context rather than merely
//! alongside it, a body signed as one artifact cannot be re-labelled as another.

use alloc::vec::Vec;

use copylocker_suite::cbor::{decode_canonical, CborValue, MapBuilder};
use copylocker_suite::{Artifact, CodecError, DomainCtx, Signature, SignatureScheme};
use copylocker_types::{ArtifactKind, EpochId, SuiteId, PROTO_VER};

use crate::field;
use crate::{ProtoError, BULK_LIMITS};

/// A signed artifact as it travels on the wire or sits on disk.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Envelope {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite used to produce the signature.
    pub suite_id: SuiteId,
    /// Which artifact the body is.
    pub kind: ArtifactKind,
    /// Canonical encoding of the artifact body.
    pub tbs: Vec<u8>,
    /// The signature over `tbs`.
    pub sig: Vec<u8>,
    /// Epoch whose key signed this, so the client can select the right certificate.
    pub epoch_ref: Option<EpochId>,
}

impl Envelope {
    /// Sign an artifact, producing an envelope.
    pub fn seal<S: SignatureScheme, A: Artifact>(
        artifact: &A,
        suite_id: SuiteId,
        product_id: &str,
        epoch_ref: Option<EpochId>,
        sk: &S::SigningKey,
    ) -> Result<Self, ProtoError> {
        let tbs = artifact.to_canonical()?;
        let ctx = DomainCtx::new(A::KIND, suite_id, product_id);
        let sig = S::sign(sk, ctx, &tbs)?;
        Ok(Self {
            proto_ver: PROTO_VER,
            suite_id,
            kind: A::KIND,
            tbs,
            sig: sig.0,
            epoch_ref,
        })
    }

    /// Verify the signature and decode the body.
    ///
    /// The checks run in this order for a reason: version and suite first (cheap rejects), then
    /// the artifact kind, and only then the signature. Verifying first would let an attacker
    /// spend our CPU on arbitrary bodies.
    pub fn open<S: SignatureScheme, A: Artifact>(
        &self,
        product_id: &str,
        vk: &S::VerifyingKey,
    ) -> Result<A, ProtoError> {
        if self.proto_ver != PROTO_VER {
            return Err(ProtoError::UnsupportedProtoVersion(self.proto_ver));
        }
        if self.kind != A::KIND {
            return Err(ProtoError::ArtifactKindMismatch);
        }
        let ctx = DomainCtx::new(A::KIND, self.suite_id, product_id);
        S::verify(vk, ctx, &self.tbs, &Signature(self.sig.clone()))?;
        Ok(A::from_canonical(&self.tbs)?)
    }

    /// Decode the body **without** checking the signature.
    ///
    /// Only for inspection tooling — the CLI's `inspect` command and the console's audit views.
    /// Never call this on a verification path; the name is deliberately alarming.
    pub fn peek_unverified<A: Artifact>(&self) -> Result<A, ProtoError> {
        if self.kind != A::KIND {
            return Err(ProtoError::ArtifactKindMismatch);
        }
        Ok(A::from_canonical(&self.tbs)?)
    }

    /// Encode to canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Uint(self.kind as u64));
        b.put(3, CborValue::Bytes(self.tbs.clone()));
        b.put(4, CborValue::Bytes(self.sig.clone()));
        b.put_opt(
            5,
            self.epoch_ref
                .map(|e| CborValue::Bytes(e.as_bytes().to_vec())),
        );
        b.finish()
    }

    /// Decode from canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let v = decode_canonical(bytes, BULK_LIMITS)?;
        if v.as_map().is_none() {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        let kind_raw = field::u8_field(&v, 2)?;
        Ok(Self {
            proto_ver: field::u8_field(&v, 0)?,
            suite_id: field::suite_id(&v, 1)?,
            kind: ArtifactKind::from_u8(kind_raw)
                .ok_or(ProtoError::Codec(CodecError::UnknownDiscriminant))?,
            tbs: field::bytes(&v, 3)?,
            sig: field::bytes(&v, 4)?,
            epoch_ref: match field::opt(&v, 5) {
                None => None,
                Some(_) => Some(EpochId(field::fixed::<8>(&v, 5)?)),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::fixtures;
    use crate::artifacts::{KillOrder, MachineCredential};
    use copylocker_suite::CryptoRng;
    use copylocker_suite_std::HybridSig;

    /// A seeded RNG, adequate for tests.
    struct TestRng(rand_chacha::ChaCha20Rng);

    impl CryptoRng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            use rand_core::Rng;
            self.0.fill_bytes(dest);
        }
    }

    fn rng(seed: u64) -> TestRng {
        use rand_core::SeedableRng;
        TestRng(rand_chacha::ChaCha20Rng::seed_from_u64(seed))
    }

    const SUITE: SuiteId = SuiteId::from_u32(0x0100_0001);

    #[test]
    fn seal_open_roundtrip() {
        let mut r = rng(1);
        let (sk, vk) = HybridSig::generate(&mut r);
        let mc = fixtures::machine_credential();
        let env =
            Envelope::seal::<HybridSig, _>(&mc, SUITE, "acme", Some(mc.epoch_id), &sk).unwrap();
        let opened: MachineCredential = env.open::<HybridSig, _>("acme", &vk).unwrap();
        assert_eq!(opened, mc);
    }

    #[test]
    fn envelope_bytes_roundtrip() {
        let mut r = rng(2);
        let (sk, _) = HybridSig::generate(&mut r);
        let mc = fixtures::machine_credential();
        let env =
            Envelope::seal::<HybridSig, _>(&mc, SUITE, "acme", Some(mc.epoch_id), &sk).unwrap();
        let bytes = env.encode();
        let decoded = Envelope::decode(&bytes).unwrap();
        assert_eq!(decoded, env);
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn a_body_signed_as_one_kind_cannot_be_relabelled_as_another() {
        // The core domain-separation property, at the envelope level.
        let mut r = rng(3);
        let (sk, vk) = HybridSig::generate(&mut r);
        let ko = fixtures::kill_order();
        let mut env = Envelope::seal::<HybridSig, _>(&ko, SUITE, "acme", None, &sk).unwrap();

        // Relabel it as a machine credential and try to open it as one.
        env.kind = ArtifactKind::MachineCred;
        assert!(env
            .open::<HybridSig, MachineCredential>("acme", &vk)
            .is_err());

        // Even opening it as its true type now fails, because the declared kind disagrees.
        assert_eq!(
            env.open::<HybridSig, KillOrder>("acme", &vk),
            Err(ProtoError::ArtifactKindMismatch)
        );
    }

    #[test]
    fn a_signature_from_another_product_does_not_verify() {
        let mut r = rng(4);
        let (sk, vk) = HybridSig::generate(&mut r);
        let ko = fixtures::kill_order();
        let env = Envelope::seal::<HybridSig, _>(&ko, SUITE, "acme", None, &sk).unwrap();
        assert!(env
            .open::<HybridSig, KillOrder>("other-product", &vk)
            .is_err());
    }

    #[test]
    fn tampering_with_the_body_is_caught() {
        let mut r = rng(5);
        let (sk, vk) = HybridSig::generate(&mut r);
        let ko = fixtures::kill_order();
        let mut env = Envelope::seal::<HybridSig, _>(&ko, SUITE, "acme", None, &sk).unwrap();
        env.tbs[10] ^= 0xff;
        assert!(env.open::<HybridSig, KillOrder>("acme", &vk).is_err());
    }

    #[test]
    fn a_wrong_protocol_version_is_rejected_before_verification() {
        let mut r = rng(6);
        let (sk, vk) = HybridSig::generate(&mut r);
        let ko = fixtures::kill_order();
        let mut env = Envelope::seal::<HybridSig, _>(&ko, SUITE, "acme", None, &sk).unwrap();
        env.proto_ver = 99;
        assert_eq!(
            env.open::<HybridSig, KillOrder>("acme", &vk),
            Err(ProtoError::UnsupportedProtoVersion(99))
        );
    }

    #[test]
    fn peek_ignores_the_signature_but_still_checks_the_kind() {
        let mut r = rng(7);
        let (sk, _) = HybridSig::generate(&mut r);
        let ko = fixtures::kill_order();
        let mut env = Envelope::seal::<HybridSig, _>(&ko, SUITE, "acme", None, &sk).unwrap();
        env.sig = alloc::vec![0; env.sig.len()];
        assert_eq!(env.peek_unverified::<KillOrder>().unwrap(), ko);
        assert_eq!(
            env.peek_unverified::<MachineCredential>(),
            Err(ProtoError::ArtifactKindMismatch)
        );
    }

    #[test]
    fn unknown_artifact_kind_is_rejected_on_decode() {
        let mut r = rng(8);
        let (sk, _) = HybridSig::generate(&mut r);
        let ko = fixtures::kill_order();
        let env = Envelope::seal::<HybridSig, _>(&ko, SUITE, "acme", None, &sk).unwrap();
        let mut v = decode_canonical(&env.encode(), BULK_LIMITS).unwrap();
        if let CborValue::Map(ref mut entries) = v {
            for (k, val) in entries.iter_mut() {
                if k.as_uint() == Some(2) {
                    *val = CborValue::Uint(200);
                }
            }
        }
        assert_eq!(
            Envelope::decode(&v.to_canonical()),
            Err(ProtoError::Codec(CodecError::UnknownDiscriminant))
        );
    }

    #[test]
    fn truncated_envelopes_error_without_panicking() {
        let mut r = rng(9);
        let (sk, _) = HybridSig::generate(&mut r);
        let ko = fixtures::kill_order();
        let bytes = Envelope::seal::<HybridSig, _>(&ko, SUITE, "acme", None, &sk)
            .unwrap()
            .encode();
        for cut in 0..bytes.len() {
            assert!(Envelope::decode(&bytes[..cut]).is_err());
        }
    }
}
