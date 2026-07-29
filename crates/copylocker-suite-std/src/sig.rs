//! Signature slots: the PQ/T hybrid used for durable artifacts, and the classical fast path
//! used for per-request tickets.

use alloc::vec::Vec;

use copylocker_suite::{CryptoError, CryptoRng, DomainCtx, HashScheme, Signature, SignatureScheme};
use copylocker_types::SecurityLevel;
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hash::Sha256Scheme;

/// ML-DSA parameter set, selected by feature flag.
mod pq {
    #[cfg(feature = "pq-ml-dsa-44")]
    pub(super) use ml_dsa::MlDsa44 as Params;
    #[cfg(feature = "pq-ml-dsa-65")]
    pub(super) use ml_dsa::MlDsa65 as Params;
    #[cfg(feature = "pq-ml-dsa-87")]
    pub(super) use ml_dsa::MlDsa87 as Params;

    /// Encoded verifying-key length for the selected parameter set (FIPS-204 Table 2).
    #[cfg(feature = "pq-ml-dsa-44")]
    pub(super) const VK_LEN: usize = 1312;
    #[cfg(feature = "pq-ml-dsa-65")]
    pub(super) const VK_LEN: usize = 1952;
    #[cfg(feature = "pq-ml-dsa-87")]
    pub(super) const VK_LEN: usize = 2592;

    /// Encoded signature length for the selected parameter set.
    #[cfg(feature = "pq-ml-dsa-44")]
    pub(super) const SIG_LEN: usize = 2420;
    #[cfg(feature = "pq-ml-dsa-65")]
    pub(super) const SIG_LEN: usize = 3309;
    #[cfg(feature = "pq-ml-dsa-87")]
    pub(super) const SIG_LEN: usize = 4627;

    /// NIST category claimed by the selected parameter set.
    #[cfg(feature = "pq-ml-dsa-44")]
    pub(super) const LEVEL: copylocker_types::SecurityLevel =
        copylocker_types::SecurityLevel::Category1;
    #[cfg(feature = "pq-ml-dsa-65")]
    pub(super) const LEVEL: copylocker_types::SecurityLevel =
        copylocker_types::SecurityLevel::Category3;
    #[cfg(feature = "pq-ml-dsa-87")]
    pub(super) const LEVEL: copylocker_types::SecurityLevel =
        copylocker_types::SecurityLevel::Category5;
}

#[cfg(not(any(
    feature = "pq-ml-dsa-44",
    feature = "pq-ml-dsa-65",
    feature = "pq-ml-dsa-87"
)))]
compile_error!(
    "copylocker-suite-std requires exactly one ML-DSA parameter set feature: \
     pq-ml-dsa-44, pq-ml-dsa-65, or pq-ml-dsa-87"
);

#[cfg(any(
    all(feature = "pq-ml-dsa-44", feature = "pq-ml-dsa-65"),
    all(feature = "pq-ml-dsa-44", feature = "pq-ml-dsa-87"),
    all(feature = "pq-ml-dsa-65", feature = "pq-ml-dsa-87")
))]
compile_error!(
    "copylocker-suite-std accepts only one ML-DSA parameter set feature at a time; \
     enabling several would make SUITE_ID ambiguous"
);

/// Label binding the hybrid to-be-signed construction. Protocol-visible and frozen.
const HYBRID_TBS_LABEL: &[u8] = b"copylocker/hybrid-sig/v1";

/// Ed25519 seed length.
const ED_SK_LEN: usize = 32;
/// Ed25519 public key length.
const ED_VK_LEN: usize = 32;
/// Ed25519 signature length.
const ED_SIG_LEN: usize = 64;
/// ML-DSA seed length (`ξ` in FIPS-204).
const PQ_SK_SEED_LEN: usize = 32;

/// Build the message both components sign.
///
/// ```text
/// M' = HYBRID_TBS_LABEL ‖ u32be(len(ctx)) ‖ ctx ‖ SHA-256(msg)
/// ```
///
/// Signing a *bound* digest rather than the raw message is what makes the two components
/// inseparable: a signature harvested from one context cannot be replayed into another, because
/// the context is inside what was signed, not merely alongside it
/// (`crypto-architecture.md §3.1`).
fn hybrid_tbs(ctx: DomainCtx<'_>, msg: &[u8]) -> Vec<u8> {
    let ctx_bytes = ctx.to_bytes();
    let digest = Sha256Scheme::hash(msg);
    let mut out =
        Vec::with_capacity(HYBRID_TBS_LABEL.len() + 4 + ctx_bytes.len() + digest.as_bytes().len());
    out.extend_from_slice(HYBRID_TBS_LABEL);
    out.extend_from_slice(&(ctx_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&ctx_bytes);
    out.extend_from_slice(digest.as_bytes());
    out
}

/// Private key for the hybrid scheme: two independent seeds.
#[derive(ZeroizeOnDrop)]
pub struct HybridSigningKey {
    pq_seed: [u8; PQ_SK_SEED_LEN],
    ed_seed: [u8; ED_SK_LEN],
}

impl Zeroize for HybridSigningKey {
    fn zeroize(&mut self) {
        self.pq_seed.zeroize();
        self.ed_seed.zeroize();
    }
}

impl core::fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HybridSigningKey(<redacted>)")
    }
}

/// Public key for the hybrid scheme.
#[derive(Clone, PartialEq, Debug)]
pub struct HybridVerifyingKey {
    pq: ml_dsa::VerifyingKey<pq::Params>,
    ed: EdVerifyingKey,
}

/// `Hybrid(Ed25519, ML-DSA)`.
///
/// # Both components, always
///
/// Verification requires **both** signatures to check out. There is no downgrade path, no
/// feature flag, and no configuration that accepts one component (FR-CRY-004). When exactly one
/// verifies, the result is [`CryptoError::HybridStripDetected`] — still a failure, but a
/// distinguishable one so the caller can record the attack attempt
/// (`crypto-architecture.md §3.1`).
///
/// # Determinism
///
/// Both components sign deterministically: Ed25519 by construction, ML-DSA via the FIPS-204
/// deterministic variant. That removes any dependence on RNG quality at signing time and makes
/// the suite's KAT vectors reproducible.
#[derive(Clone, Copy, Debug, Default)]
pub struct HybridSig;

impl HybridSig {
    fn ed_signing_key(sk: &HybridSigningKey) -> EdSigningKey {
        EdSigningKey::from_bytes(&sk.ed_seed)
    }

    /// The signing operations live on the *expanded* key in `ml-dsa`; expansion from the seed is
    /// deterministic, so this stays a pure function of the stored seed.
    fn pq_signing_key(sk: &HybridSigningKey) -> ml_dsa::ExpandedSigningKey<pq::Params> {
        ml_dsa::ExpandedSigningKey::<pq::Params>::from_seed(&sk.pq_seed.into())
    }
}

impl SignatureScheme for HybridSig {
    type SigningKey = HybridSigningKey;
    type VerifyingKey = HybridVerifyingKey;

    // 4-byte length prefix before each component.
    const SIG_MAX_LEN: usize = 4 + pq::SIG_LEN + 4 + ED_SIG_LEN;
    const VK_LEN: usize = pq::VK_LEN + ED_VK_LEN;
    const SK_LEN: usize = PQ_SK_SEED_LEN + ED_SK_LEN;

    fn generate(rng: &mut dyn CryptoRng) -> (Self::SigningKey, Self::VerifyingKey) {
        let mut pq_seed = [0u8; PQ_SK_SEED_LEN];
        let mut ed_seed = [0u8; ED_SK_LEN];
        rng.fill_bytes(&mut pq_seed);
        rng.fill_bytes(&mut ed_seed);
        let sk = HybridSigningKey { pq_seed, ed_seed };
        let vk = Self::verifying_key(&sk);
        (sk, vk)
    }

    fn verifying_key(sk: &Self::SigningKey) -> Self::VerifyingKey {
        HybridVerifyingKey {
            pq: Self::pq_signing_key(sk).verifying_key(),
            ed: Self::ed_signing_key(sk).verifying_key(),
        }
    }

    fn sign(
        sk: &Self::SigningKey,
        ctx: DomainCtx<'_>,
        msg: &[u8],
    ) -> Result<Signature, CryptoError> {
        let tbs = hybrid_tbs(ctx, msg);

        // The domain context is already inside `tbs`, so the ML-DSA context string is empty.
        // Putting it in both places would be redundant and would run into ML-DSA's 255-byte
        // context limit for long product identifiers.
        let pq_sig = Self::pq_signing_key(sk)
            .sign_deterministic(&tbs, &[])
            .map_err(|_| CryptoError::Invalid)?;
        let pq_bytes = pq_sig.encode();
        let ed_bytes = Self::ed_signing_key(sk).sign(&tbs).to_bytes();

        let mut out = Vec::with_capacity(Self::SIG_MAX_LEN);
        out.extend_from_slice(&(pq_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&pq_bytes);
        out.extend_from_slice(&(ed_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&ed_bytes);
        Ok(Signature(out))
    }

    fn verify(
        vk: &Self::VerifyingKey,
        ctx: DomainCtx<'_>,
        msg: &[u8],
        sig: &Signature,
    ) -> Result<(), CryptoError> {
        let (pq_bytes, ed_bytes) = split_hybrid(sig.as_bytes())?;
        let tbs = hybrid_tbs(ctx, msg);

        let pq_ok = decode_pq_sig(pq_bytes)
            .map(|s| vk.pq.verify_with_context(&tbs, &[], &s))
            .unwrap_or(false);

        let ed_ok = ed25519_dalek::Signature::from_slice(ed_bytes)
            .ok()
            // `verify_strict` rejects small-order public keys and non-canonical `s`, closing
            // the malleability gap that plain `verify` leaves open.
            .map(|s| vk.ed.verify_strict(&tbs, &s).is_ok())
            .unwrap_or(false);

        match (pq_ok, ed_ok) {
            (true, true) => Ok(()),
            // Exactly one component verifying means someone is stripping the other.
            (true, false) | (false, true) => Err(CryptoError::HybridStripDetected),
            (false, false) => Err(CryptoError::Invalid),
        }
    }

    fn encode_vk(vk: &Self::VerifyingKey) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::VK_LEN);
        out.extend_from_slice(&vk.pq.encode());
        out.extend_from_slice(vk.ed.as_bytes());
        out
    }

    fn decode_vk(bytes: &[u8]) -> Result<Self::VerifyingKey, CryptoError> {
        if bytes.len() != Self::VK_LEN {
            return Err(CryptoError::BadLength);
        }
        let (pq_raw, ed_raw) = bytes.split_at(pq::VK_LEN);
        let pq_arr = ml_dsa::EncodedVerifyingKey::<pq::Params>::try_from(pq_raw)
            .map_err(|_| CryptoError::BadLength)?;
        let ed_arr: [u8; ED_VK_LEN] = ed_raw.try_into().map_err(|_| CryptoError::BadLength)?;
        Ok(HybridVerifyingKey {
            pq: ml_dsa::VerifyingKey::<pq::Params>::decode(&pq_arr),
            ed: EdVerifyingKey::from_bytes(&ed_arr).map_err(|_| CryptoError::Invalid)?,
        })
    }

    fn encode_sk(sk: &Self::SigningKey) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SK_LEN);
        out.extend_from_slice(&sk.pq_seed);
        out.extend_from_slice(&sk.ed_seed);
        out
    }

    fn decode_sk(bytes: &[u8]) -> Result<Self::SigningKey, CryptoError> {
        if bytes.len() != Self::SK_LEN {
            return Err(CryptoError::BadLength);
        }
        let (pq_raw, ed_raw) = bytes.split_at(PQ_SK_SEED_LEN);
        Ok(HybridSigningKey {
            pq_seed: pq_raw.try_into().map_err(|_| CryptoError::BadLength)?,
            ed_seed: ed_raw.try_into().map_err(|_| CryptoError::BadLength)?,
        })
    }

    fn security_level() -> SecurityLevel {
        pq::LEVEL
    }

    fn is_post_quantum() -> bool {
        true
    }
}

/// Split `len ‖ pq ‖ len ‖ ed`, rejecting anything that does not consume the buffer exactly.
fn split_hybrid(sig: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    fn read_prefixed(b: &[u8]) -> Option<(&[u8], &[u8])> {
        let (len_raw, rest) = b.split_at_checked(4)?;
        let len = u32::from_be_bytes(len_raw.try_into().ok()?) as usize;
        let (body, tail) = rest.split_at_checked(len)?;
        Some((body, tail))
    }
    let (pq, rest) = read_prefixed(sig).ok_or(CryptoError::BadLength)?;
    let (ed, tail) = read_prefixed(rest).ok_or(CryptoError::BadLength)?;
    if !tail.is_empty() {
        return Err(CryptoError::BadLength);
    }
    Ok((pq, ed))
}

fn decode_pq_sig(bytes: &[u8]) -> Option<ml_dsa::Signature<pq::Params>> {
    let arr = ml_dsa::EncodedSignature::<pq::Params>::try_from(bytes).ok()?;
    ml_dsa::Signature::<pq::Params>::decode(&arr)
}

/// Ed25519-only signing key.
#[derive(ZeroizeOnDrop)]
pub struct FastSigningKey([u8; ED_SK_LEN]);

impl Zeroize for FastSigningKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for FastSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FastSigningKey(<redacted>)")
    }
}

/// Ed25519, the per-request fast path for `ValidationTicket` and `KillOrder`.
///
/// # Why a classical algorithm is acceptable here
///
/// Signing every validation with ML-DSA would cost more CPU than a Worker request budget
/// allows. The mitigation is structural rather than cryptographic: the PQ hybrid protects the
/// *key chain* (the `EpochCert` that certifies this Ed25519 key), while Ed25519 carries the
/// high-frequency per-request load. Forging a ticket lets an attacker extend the life of a
/// credential that already exists; it cannot create one, because a `MachineCredential` needs
/// the PQ signing key *and* a KEM encapsulation to the device
/// (`protocol-spec.md §5`).
///
/// Vendors who need end-to-end PQ set `policy.vt_signature = "pq"` and pay the CPU and
/// bandwidth cost.
#[derive(Clone, Copy, Debug, Default)]
pub struct FastSig;

impl SignatureScheme for FastSig {
    type SigningKey = FastSigningKey;
    type VerifyingKey = EdVerifyingKey;

    const SIG_MAX_LEN: usize = ED_SIG_LEN;
    const VK_LEN: usize = ED_VK_LEN;
    const SK_LEN: usize = ED_SK_LEN;

    fn generate(rng: &mut dyn CryptoRng) -> (Self::SigningKey, Self::VerifyingKey) {
        let mut seed = [0u8; ED_SK_LEN];
        rng.fill_bytes(&mut seed);
        let vk = EdSigningKey::from_bytes(&seed).verifying_key();
        (FastSigningKey(seed), vk)
    }

    fn verifying_key(sk: &Self::SigningKey) -> Self::VerifyingKey {
        EdSigningKey::from_bytes(&sk.0).verifying_key()
    }

    fn sign(
        sk: &Self::SigningKey,
        ctx: DomainCtx<'_>,
        msg: &[u8],
    ) -> Result<Signature, CryptoError> {
        let tbs = hybrid_tbs(ctx, msg);
        let s = EdSigningKey::from_bytes(&sk.0).sign(&tbs);
        Ok(Signature(s.to_bytes().to_vec()))
    }

    fn verify(
        vk: &Self::VerifyingKey,
        ctx: DomainCtx<'_>,
        msg: &[u8],
        sig: &Signature,
    ) -> Result<(), CryptoError> {
        let tbs = hybrid_tbs(ctx, msg);
        let s = ed25519_dalek::Signature::from_slice(sig.as_bytes())
            .map_err(|_| CryptoError::BadLength)?;
        vk.verify_strict(&tbs, &s).map_err(|_| CryptoError::Invalid)
    }

    fn encode_vk(vk: &Self::VerifyingKey) -> Vec<u8> {
        vk.as_bytes().to_vec()
    }

    fn decode_vk(bytes: &[u8]) -> Result<Self::VerifyingKey, CryptoError> {
        let arr: [u8; ED_VK_LEN] = bytes.try_into().map_err(|_| CryptoError::BadLength)?;
        EdVerifyingKey::from_bytes(&arr).map_err(|_| CryptoError::Invalid)
    }

    fn encode_sk(sk: &Self::SigningKey) -> Vec<u8> {
        sk.0.to_vec()
    }

    fn decode_sk(bytes: &[u8]) -> Result<Self::SigningKey, CryptoError> {
        Ok(FastSigningKey(
            bytes.try_into().map_err(|_| CryptoError::BadLength)?,
        ))
    }

    fn security_level() -> SecurityLevel {
        SecurityLevel::Category1
    }

    fn is_post_quantum() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng;
    use copylocker_types::{ArtifactKind, SuiteId};

    const SUITE: SuiteId = SuiteId::from_u32(0x0100_0001);

    fn ctx(kind: ArtifactKind) -> DomainCtx<'static> {
        DomainCtx::new(kind, SUITE, "acme-editor")
    }

    #[test]
    fn hybrid_signs_and_verifies() {
        let mut rng = test_rng(1);
        let (sk, vk) = HybridSig::generate(&mut rng);
        let sig = HybridSig::sign(&sk, ctx(ArtifactKind::MachineCred), b"payload").unwrap();
        assert!(HybridSig::verify(&vk, ctx(ArtifactKind::MachineCred), b"payload", &sig).is_ok());
    }

    #[test]
    fn declared_lengths_match_reality() {
        let mut rng = test_rng(2);
        let (sk, vk) = HybridSig::generate(&mut rng);
        assert_eq!(HybridSig::encode_vk(&vk).len(), HybridSig::VK_LEN);
        assert_eq!(HybridSig::encode_sk(&sk).len(), HybridSig::SK_LEN);
        let sig = HybridSig::sign(&sk, ctx(ArtifactKind::EpochCert), b"m").unwrap();
        assert_eq!(sig.len(), HybridSig::SIG_MAX_LEN);
    }

    #[test]
    fn cross_domain_replay_fails() {
        let mut rng = test_rng(3);
        let (sk, vk) = HybridSig::generate(&mut rng);
        let sig = HybridSig::sign(&sk, ctx(ArtifactKind::ValidationTicket), b"m").unwrap();
        // A ticket signature must not verify as a kill order.
        assert!(HybridSig::verify(&vk, ctx(ArtifactKind::KillOrder), b"m", &sig).is_err());
    }

    #[test]
    fn cross_product_replay_fails() {
        let mut rng = test_rng(4);
        let (sk, vk) = HybridSig::generate(&mut rng);
        let a = DomainCtx::new(ArtifactKind::MachineCred, SUITE, "product-a");
        let b = DomainCtx::new(ArtifactKind::MachineCred, SUITE, "product-b");
        let sig = HybridSig::sign(&sk, a, b"m").unwrap();
        assert!(HybridSig::verify(&vk, b, b"m", &sig).is_err());
    }

    #[test]
    fn stripping_the_pq_component_is_detected() {
        let mut rng = test_rng(5);
        let (sk, vk) = HybridSig::generate(&mut rng);
        let sig = HybridSig::sign(&sk, ctx(ArtifactKind::MachineCred), b"m").unwrap();
        let (pq, ed) = split_hybrid(sig.as_bytes()).unwrap();

        // Corrupt only the PQ half; the Ed25519 half still verifies.
        let mut broken_pq = pq.to_vec();
        broken_pq[0] ^= 0xff;
        let mut forged = Vec::new();
        forged.extend_from_slice(&(broken_pq.len() as u32).to_be_bytes());
        forged.extend_from_slice(&broken_pq);
        forged.extend_from_slice(&(ed.len() as u32).to_be_bytes());
        forged.extend_from_slice(ed);

        assert_eq!(
            HybridSig::verify(
                &vk,
                ctx(ArtifactKind::MachineCred),
                b"m",
                &Signature(forged)
            ),
            Err(CryptoError::HybridStripDetected)
        );
    }

    #[test]
    fn stripping_the_classical_component_is_detected() {
        let mut rng = test_rng(6);
        let (sk, vk) = HybridSig::generate(&mut rng);
        let sig = HybridSig::sign(&sk, ctx(ArtifactKind::MachineCred), b"m").unwrap();
        let (pq, ed) = split_hybrid(sig.as_bytes()).unwrap();

        let mut broken_ed = ed.to_vec();
        broken_ed[0] ^= 0xff;
        let mut forged = Vec::new();
        forged.extend_from_slice(&(pq.len() as u32).to_be_bytes());
        forged.extend_from_slice(pq);
        forged.extend_from_slice(&(broken_ed.len() as u32).to_be_bytes());
        forged.extend_from_slice(&broken_ed);

        assert_eq!(
            HybridSig::verify(
                &vk,
                ctx(ArtifactKind::MachineCred),
                b"m",
                &Signature(forged)
            ),
            Err(CryptoError::HybridStripDetected)
        );
    }

    #[test]
    fn truncated_or_padded_signatures_are_rejected() {
        let mut rng = test_rng(7);
        let (sk, vk) = HybridSig::generate(&mut rng);
        let sig = HybridSig::sign(&sk, ctx(ArtifactKind::MachineCred), b"m").unwrap();

        let mut padded = sig.as_bytes().to_vec();
        padded.push(0);
        assert_eq!(
            HybridSig::verify(
                &vk,
                ctx(ArtifactKind::MachineCred),
                b"m",
                &Signature(padded)
            ),
            Err(CryptoError::BadLength),
            "trailing bytes must not be ignored"
        );

        let truncated = sig.as_bytes()[..sig.len() - 1].to_vec();
        assert_eq!(
            HybridSig::verify(
                &vk,
                ctx(ArtifactKind::MachineCred),
                b"m",
                &Signature(truncated)
            ),
            Err(CryptoError::BadLength)
        );

        assert_eq!(
            HybridSig::verify(
                &vk,
                ctx(ArtifactKind::MachineCred),
                b"m",
                &Signature(Vec::new())
            ),
            Err(CryptoError::BadLength)
        );
    }

    #[test]
    fn wrong_message_fails_on_both_components() {
        let mut rng = test_rng(8);
        let (sk, vk) = HybridSig::generate(&mut rng);
        let sig = HybridSig::sign(&sk, ctx(ArtifactKind::MachineCred), b"m").unwrap();
        assert_eq!(
            HybridSig::verify(&vk, ctx(ArtifactKind::MachineCred), b"m2", &sig),
            Err(CryptoError::Invalid)
        );
    }

    #[test]
    fn keys_roundtrip_through_encoding() {
        let mut rng = test_rng(9);
        let (sk, vk) = HybridSig::generate(&mut rng);
        let sk2 = HybridSig::decode_sk(&HybridSig::encode_sk(&sk)).unwrap();
        let vk2 = HybridSig::decode_vk(&HybridSig::encode_vk(&vk)).unwrap();
        assert_eq!(vk2, vk);
        let sig = HybridSig::sign(&sk2, ctx(ArtifactKind::MachineCred), b"m").unwrap();
        assert!(HybridSig::verify(&vk2, ctx(ArtifactKind::MachineCred), b"m", &sig).is_ok());
    }

    #[test]
    fn signing_is_deterministic() {
        let mut rng = test_rng(10);
        let (sk, _) = HybridSig::generate(&mut rng);
        let a = HybridSig::sign(&sk, ctx(ArtifactKind::MachineCred), b"m").unwrap();
        let b = HybridSig::sign(&sk, ctx(ArtifactKind::MachineCred), b"m").unwrap();
        assert_eq!(a, b, "KAT vectors depend on deterministic signing");
    }

    #[test]
    fn wrong_key_fails() {
        let mut rng = test_rng(11);
        let (sk, _) = HybridSig::generate(&mut rng);
        let (_, other_vk) = HybridSig::generate(&mut rng);
        let sig = HybridSig::sign(&sk, ctx(ArtifactKind::MachineCred), b"m").unwrap();
        assert!(HybridSig::verify(&other_vk, ctx(ArtifactKind::MachineCred), b"m", &sig).is_err());
    }

    #[test]
    fn fast_scheme_signs_verifies_and_separates_domains() {
        let mut rng = test_rng(12);
        let (sk, vk) = FastSig::generate(&mut rng);
        let sig = FastSig::sign(&sk, ctx(ArtifactKind::ValidationTicket), b"vt").unwrap();
        assert_eq!(sig.len(), FastSig::SIG_MAX_LEN);
        assert!(FastSig::verify(&vk, ctx(ArtifactKind::ValidationTicket), b"vt", &sig).is_ok());
        assert!(FastSig::verify(&vk, ctx(ArtifactKind::KillOrder), b"vt", &sig).is_err());
        assert!(FastSig::verify(&vk, ctx(ArtifactKind::ValidationTicket), b"x", &sig).is_err());
    }

    #[test]
    fn fast_scheme_is_flagged_classical() {
        assert!(!FastSig::is_post_quantum());
        assert!(HybridSig::is_post_quantum());
    }

    #[test]
    fn fast_keys_roundtrip() {
        let mut rng = test_rng(13);
        let (sk, vk) = FastSig::generate(&mut rng);
        let sk2 = FastSig::decode_sk(&FastSig::encode_sk(&sk)).unwrap();
        let vk2 = FastSig::decode_vk(&FastSig::encode_vk(&vk)).unwrap();
        assert_eq!(FastSig::verifying_key(&sk2), vk2);
    }
}
