//! Root → epoch → artifact certificate chain (`crypto-architecture.md §5.1`).
//!
//! The client must verify the **whole** chain, every time. A client that verifies only the
//! artifact and trusts a cached epoch key has no protection against a compromised or expired
//! epoch, which is precisely the scenario epoch rotation exists to contain.

use alloc::vec::Vec;

use copylocker_suite::{Artifact, CryptoError, DomainCtx, HashScheme, Signature, SignatureScheme};
use copylocker_types::{ArtifactKind, Digest, EpochId};

use crate::artifacts::EpochCert;
use crate::envelope::Envelope;
use crate::ProtoError;

/// The root public keys compiled into a client build.
///
/// Two are pinned, not one: `current` signs today's epoch certificates, `next` is pre-placed so
/// that rotating the root later does not brick clients that shipped before the rotation
/// (`crypto-architecture.md §5.2`). Activating `next` is purely a server-side change.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PinnedRoots {
    /// Digest of the currently active root verifying key.
    pub current: Digest,
    /// Digest of the pre-placed successor root verifying key.
    pub next: Option<Digest>,
}

impl PinnedRoots {
    /// Pin a single root. Acceptable for development; production builds should pin a successor
    /// too, or rotation will require shipping a new client to every user at once.
    #[must_use]
    pub fn single(current: Digest) -> Self {
        Self {
            current,
            next: None,
        }
    }

    /// Pin a root and its pre-placed successor.
    #[must_use]
    pub fn with_next(current: Digest, next: Digest) -> Self {
        Self {
            current,
            next: Some(next),
        }
    }

    /// Whether a digest matches one of the pinned roots.
    #[must_use]
    pub fn accepts(&self, d: &Digest) -> bool {
        self.current == *d || self.next.as_ref() == Some(d)
    }
}

/// Local knowledge of which epochs have been revoked, and how recent that knowledge is.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RevocationState {
    /// Highest revocation sequence the client has seen. Monotonic: accepting a lower value
    /// would roll the client back to a state where a revoked credential still passes.
    pub epoch: u64,
    /// Epochs known to be revoked.
    pub revoked_epochs: Vec<EpochId>,
}

impl RevocationState {
    /// Whether a signing epoch is known-revoked.
    #[must_use]
    pub fn is_epoch_revoked(&self, id: &EpochId) -> bool {
        self.revoked_epochs.contains(id)
    }

    /// Merge a newer revocation view, rejecting rollbacks.
    pub fn advance(&mut self, to_epoch: u64, revoked: Vec<EpochId>) -> Result<(), ProtoError> {
        if to_epoch < self.epoch {
            return Err(ProtoError::MonotonicityViolation);
        }
        self.epoch = to_epoch;
        for e in revoked {
            if !self.revoked_epochs.contains(&e) {
                self.revoked_epochs.push(e);
            }
        }
        Ok(())
    }
}

/// A verified trust chain: pinned roots plus the epoch certificates validated against them.
#[derive(Clone, Debug)]
pub struct VerifiedChain<S: SignatureScheme> {
    roots: PinnedRoots,
    /// Epoch certificates that passed root verification, with their parsed verifying keys.
    epochs: Vec<VerifiedEpoch<S>>,
    revocation: RevocationState,
}

/// One epoch certificate that has been verified against a pinned root.
#[derive(Clone, Debug)]
pub struct VerifiedEpoch<S: SignatureScheme> {
    /// The certificate body.
    pub cert: EpochCert,
    /// Parsed verifying key for durable artifacts.
    pub vk: S::VerifyingKey,
}

impl<S: SignatureScheme> VerifiedChain<S> {
    /// Start an empty chain with the given pinned roots.
    #[must_use]
    pub fn new(roots: PinnedRoots) -> Self {
        Self {
            roots,
            epochs: Vec::new(),
            revocation: RevocationState::default(),
        }
    }

    /// The pinned roots.
    #[must_use]
    pub fn roots(&self) -> &PinnedRoots {
        &self.roots
    }

    /// Current revocation knowledge.
    #[must_use]
    pub fn revocation(&self) -> &RevocationState {
        &self.revocation
    }

    /// Mutable access to revocation knowledge, for merging a `RevocationBatch`.
    pub fn revocation_mut(&mut self) -> &mut RevocationState {
        &mut self.revocation
    }

    /// Verify an epoch certificate against the pinned roots and add it to the chain.
    ///
    /// The steps follow `crypto-architecture.md §5.1` in order:
    ///
    /// 1. the certificate's declared issuer must hit a pinned root — checked *before* any
    ///    signature work, so an attacker cannot make us verify against a key of their choosing;
    /// 2. the supplied root key must actually be the one named;
    /// 3. the root signature must verify;
    /// 4. the certificate must be inside its validity window;
    /// 5. the epoch must not be known-revoked.
    pub fn add_epoch<H: HashScheme>(
        &mut self,
        env: &Envelope,
        product_id: &str,
        root_vk: &S::VerifyingKey,
        now: i64,
    ) -> Result<(), ProtoError> {
        let cert: EpochCert = env.peek_unverified()?;

        if !self.roots.accepts(&cert.issuer_vk_digest) {
            return Err(ProtoError::RootPinMismatch);
        }
        let supplied = H::hash(&S::encode_vk(root_vk));
        if supplied != cert.issuer_vk_digest {
            return Err(ProtoError::RootPinMismatch);
        }

        let ctx = DomainCtx::new(ArtifactKind::EpochCert, cert.suite_id, product_id);
        S::verify(root_vk, ctx, &env.tbs, &Signature(env.sig.clone()))?;

        if !cert.window().contains(now) {
            return Err(ProtoError::OutsideValidityWindow);
        }
        if self.revocation.is_epoch_revoked(&cert.epoch_id) {
            return Err(ProtoError::EpochRevoked);
        }

        let vk = S::decode_vk(&cert.vk)?;
        // Replacing an existing entry keeps re-fetching `/v1/keys` idempotent.
        self.epochs.retain(|e| e.cert.epoch_id != cert.epoch_id);
        self.epochs.push(VerifiedEpoch { cert, vk });
        Ok(())
    }

    /// Look up a verified epoch.
    #[must_use]
    pub fn epoch(&self, id: &EpochId) -> Option<&VerifiedEpoch<S>> {
        self.epochs.iter().find(|e| e.cert.epoch_id == *id)
    }

    /// Every verified epoch currently held.
    #[must_use]
    pub fn epochs(&self) -> &[VerifiedEpoch<S>] {
        &self.epochs
    }

    /// Verify an artifact signed by one of the chain's epochs.
    ///
    /// Re-checks the epoch's validity window and revocation status at verification time, not
    /// just when the certificate was added: an epoch can expire or be revoked while a
    /// long-running process holds the chain in memory.
    pub fn verify_artifact<A: Artifact>(
        &self,
        env: &Envelope,
        product_id: &str,
        now: i64,
    ) -> Result<A, ProtoError> {
        let epoch_id = env.epoch_ref.ok_or(ProtoError::UnknownEpoch)?;
        let epoch = self.epoch(&epoch_id).ok_or(ProtoError::UnknownEpoch)?;

        if self.revocation.is_epoch_revoked(&epoch_id) {
            return Err(ProtoError::EpochRevoked);
        }
        if !epoch.cert.window().contains(now) {
            return Err(ProtoError::OutsideValidityWindow);
        }
        env.open::<S, A>(product_id, &epoch.vk)
    }

    /// Verify an artifact signed by the epoch's classical fast key.
    ///
    /// Used for `ValidationTicket` and `KillOrder`, whose per-request signing cost rules out the
    /// PQ hybrid (`protocol-spec.md §5`). The fast key is itself certified by the PQ-signed
    /// epoch certificate, so the chain of trust remains post-quantum.
    pub fn verify_artifact_fast<F: SignatureScheme, A: Artifact>(
        &self,
        env: &Envelope,
        product_id: &str,
        now: i64,
    ) -> Result<A, ProtoError> {
        let epoch_id = env.epoch_ref.ok_or(ProtoError::UnknownEpoch)?;
        let epoch = self.epoch(&epoch_id).ok_or(ProtoError::UnknownEpoch)?;

        if self.revocation.is_epoch_revoked(&epoch_id) {
            return Err(ProtoError::EpochRevoked);
        }
        if !epoch.cert.window().contains(now) {
            return Err(ProtoError::OutsideValidityWindow);
        }
        let vk = F::decode_vk(&epoch.cert.vk_fast)
            .map_err(|_| ProtoError::Crypto(CryptoError::Invalid))?;
        env.open::<F, A>(product_id, &vk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{fixtures, KillOrder, MachineCredential};
    use copylocker_suite::CryptoRng;
    use copylocker_suite_std::{FastSig, HybridSig, Sha256Scheme};
    use copylocker_types::SuiteId;

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
    const NOW: i64 = 5_000;

    struct Fixture {
        chain: VerifiedChain<HybridSig>,
        epoch_sk: <HybridSig as SignatureScheme>::SigningKey,
        fast_sk: <FastSig as SignatureScheme>::SigningKey,
        epoch_id: EpochId,
    }

    /// Build a root, an epoch under it, and a chain that has accepted the epoch.
    fn fixture() -> Fixture {
        let mut r = rng(1);
        let (root_sk, root_vk) = HybridSig::generate(&mut r);
        let (epoch_sk, epoch_vk) = HybridSig::generate(&mut r);
        let (fast_sk, fast_vk) = FastSig::generate(&mut r);

        let root_digest = Sha256Scheme::hash(&HybridSig::encode_vk(&root_vk));
        let cert = EpochCert {
            vk: HybridSig::encode_vk(&epoch_vk),
            vk_fast: FastSig::encode_vk(&fast_vk),
            issuer_vk_digest: root_digest,
            ..fixtures::epoch_cert()
        };
        let env =
            Envelope::seal::<HybridSig, _>(&cert, SUITE, "acme", Some(cert.epoch_id), &root_sk)
                .unwrap();

        let mut chain = VerifiedChain::<HybridSig>::new(PinnedRoots::single(root_digest));
        chain
            .add_epoch::<Sha256Scheme>(&env, "acme", &root_vk, NOW)
            .expect("epoch must be accepted");

        Fixture {
            chain,
            epoch_sk,
            fast_sk,
            epoch_id: cert.epoch_id,
        }
    }

    #[test]
    fn a_credential_signed_by_a_chained_epoch_verifies() {
        let f = fixture();
        let mc = fixtures::machine_credential();
        let env = Envelope::seal::<HybridSig, _>(&mc, SUITE, "acme", Some(f.epoch_id), &f.epoch_sk)
            .unwrap();
        let out: MachineCredential = f.chain.verify_artifact(&env, "acme", NOW).unwrap();
        assert_eq!(out, mc);
    }

    #[test]
    fn an_epoch_certificate_from_an_unpinned_root_is_refused() {
        let mut r = rng(2);
        let (attacker_sk, attacker_vk) = HybridSig::generate(&mut r);
        let (_, epoch_vk) = HybridSig::generate(&mut r);
        let (_, fast_vk) = FastSig::generate(&mut r);

        let attacker_digest = Sha256Scheme::hash(&HybridSig::encode_vk(&attacker_vk));
        let cert = EpochCert {
            vk: HybridSig::encode_vk(&epoch_vk),
            vk_fast: FastSig::encode_vk(&fast_vk),
            issuer_vk_digest: attacker_digest,
            ..fixtures::epoch_cert()
        };
        let env = Envelope::seal::<HybridSig, _>(&cert, SUITE, "acme", None, &attacker_sk).unwrap();

        // The chain pins a different root. The attacker's certificate is internally consistent
        // and correctly signed — it just is not signed by anyone we trust.
        let mut chain = VerifiedChain::<HybridSig>::new(PinnedRoots::single(Digest([0xaa; 32])));
        assert_eq!(
            chain.add_epoch::<Sha256Scheme>(&env, "acme", &attacker_vk, NOW),
            Err(ProtoError::RootPinMismatch)
        );
    }

    #[test]
    fn a_root_key_that_does_not_match_the_named_digest_is_refused() {
        // Guards against being handed a certificate that names a pinned root but supplies a
        // different key to verify with.
        let mut r = rng(3);
        let (root_sk, root_vk) = HybridSig::generate(&mut r);
        let (_, other_vk) = HybridSig::generate(&mut r);
        let (_, epoch_vk) = HybridSig::generate(&mut r);
        let (_, fast_vk) = FastSig::generate(&mut r);

        let root_digest = Sha256Scheme::hash(&HybridSig::encode_vk(&root_vk));
        let cert = EpochCert {
            vk: HybridSig::encode_vk(&epoch_vk),
            vk_fast: FastSig::encode_vk(&fast_vk),
            issuer_vk_digest: root_digest,
            ..fixtures::epoch_cert()
        };
        let env = Envelope::seal::<HybridSig, _>(&cert, SUITE, "acme", None, &root_sk).unwrap();

        let mut chain = VerifiedChain::<HybridSig>::new(PinnedRoots::single(root_digest));
        assert_eq!(
            chain.add_epoch::<Sha256Scheme>(&env, "acme", &other_vk, NOW),
            Err(ProtoError::RootPinMismatch)
        );
    }

    #[test]
    fn an_expired_epoch_certificate_is_refused() {
        let mut r = rng(4);
        let (root_sk, root_vk) = HybridSig::generate(&mut r);
        let (_, epoch_vk) = HybridSig::generate(&mut r);
        let (_, fast_vk) = FastSig::generate(&mut r);
        let root_digest = Sha256Scheme::hash(&HybridSig::encode_vk(&root_vk));
        let cert = EpochCert {
            vk: HybridSig::encode_vk(&epoch_vk),
            vk_fast: FastSig::encode_vk(&fast_vk),
            issuer_vk_digest: root_digest,
            not_before: 1_000,
            not_after: 2_000,
            ..fixtures::epoch_cert()
        };
        let env = Envelope::seal::<HybridSig, _>(&cert, SUITE, "acme", None, &root_sk).unwrap();
        let mut chain = VerifiedChain::<HybridSig>::new(PinnedRoots::single(root_digest));
        assert_eq!(
            chain.add_epoch::<Sha256Scheme>(&env, "acme", &root_vk, 2_000),
            Err(ProtoError::OutsideValidityWindow),
            "not_after is exclusive"
        );
        assert!(chain
            .add_epoch::<Sha256Scheme>(&env, "acme", &root_vk, 1_999)
            .is_ok());
    }

    #[test]
    fn an_artifact_referencing_an_unknown_epoch_is_refused() {
        let f = fixture();
        let mc = fixtures::machine_credential();
        let env = Envelope::seal::<HybridSig, _>(
            &mc,
            SUITE,
            "acme",
            Some(EpochId([0xff; 8])),
            &f.epoch_sk,
        )
        .unwrap();
        assert_eq!(
            f.chain
                .verify_artifact::<MachineCredential>(&env, "acme", NOW)
                .err(),
            Some(ProtoError::UnknownEpoch)
        );
    }

    #[test]
    fn an_artifact_with_no_epoch_reference_is_refused() {
        let f = fixture();
        let mc = fixtures::machine_credential();
        let env = Envelope::seal::<HybridSig, _>(&mc, SUITE, "acme", None, &f.epoch_sk).unwrap();
        assert_eq!(
            f.chain
                .verify_artifact::<MachineCredential>(&env, "acme", NOW)
                .err(),
            Some(ProtoError::UnknownEpoch)
        );
    }

    #[test]
    fn revoking_an_epoch_invalidates_artifacts_it_already_signed() {
        // The recovery path for a leaked epoch key: existing credentials stop verifying as soon
        // as the client learns of the revocation (`crypto-architecture.md §5.3`).
        let mut f = fixture();
        let mc = fixtures::machine_credential();
        let env = Envelope::seal::<HybridSig, _>(&mc, SUITE, "acme", Some(f.epoch_id), &f.epoch_sk)
            .unwrap();
        assert!(f
            .chain
            .verify_artifact::<MachineCredential>(&env, "acme", NOW)
            .is_ok());

        f.chain
            .revocation_mut()
            .advance(99, alloc::vec![f.epoch_id])
            .unwrap();

        assert_eq!(
            f.chain
                .verify_artifact::<MachineCredential>(&env, "acme", NOW)
                .err(),
            Some(ProtoError::EpochRevoked)
        );
    }

    #[test]
    fn revocation_state_refuses_to_move_backwards() {
        let mut st = RevocationState::default();
        st.advance(10, alloc::vec![]).unwrap();
        assert_eq!(
            st.advance(9, alloc::vec![]),
            Err(ProtoError::MonotonicityViolation)
        );
        // Equal is fine: re-delivering the same batch must be idempotent.
        assert!(st.advance(10, alloc::vec![]).is_ok());
        assert_eq!(st.epoch, 10);
    }

    #[test]
    fn revocation_merge_is_idempotent() {
        let mut st = RevocationState::default();
        let e = EpochId([7; 8]);
        st.advance(1, alloc::vec![e]).unwrap();
        st.advance(2, alloc::vec![e]).unwrap();
        assert_eq!(st.revoked_epochs.len(), 1);
    }

    #[test]
    fn the_fast_path_verifies_tickets_under_the_certified_ed25519_key() {
        let f = fixture();
        let ko = fixtures::kill_order();
        let env =
            Envelope::seal::<FastSig, _>(&ko, SUITE, "acme", Some(f.epoch_id), &f.fast_sk).unwrap();
        let out: KillOrder = f
            .chain
            .verify_artifact_fast::<FastSig, _>(&env, "acme", NOW)
            .unwrap();
        assert_eq!(out, ko);
    }

    #[test]
    fn a_fast_signed_artifact_does_not_verify_on_the_hybrid_path() {
        let f = fixture();
        let ko = fixtures::kill_order();
        let env =
            Envelope::seal::<FastSig, _>(&ko, SUITE, "acme", Some(f.epoch_id), &f.fast_sk).unwrap();
        assert!(f
            .chain
            .verify_artifact::<KillOrder>(&env, "acme", NOW)
            .is_err());
    }

    #[test]
    fn adding_the_same_epoch_twice_is_idempotent() {
        let mut r = rng(1);
        let (root_sk, root_vk) = HybridSig::generate(&mut r);
        let (_, epoch_vk) = HybridSig::generate(&mut r);
        let (_, fast_vk) = FastSig::generate(&mut r);
        let root_digest = Sha256Scheme::hash(&HybridSig::encode_vk(&root_vk));
        let cert = EpochCert {
            vk: HybridSig::encode_vk(&epoch_vk),
            vk_fast: FastSig::encode_vk(&fast_vk),
            issuer_vk_digest: root_digest,
            ..fixtures::epoch_cert()
        };
        let env = Envelope::seal::<HybridSig, _>(&cert, SUITE, "acme", None, &root_sk).unwrap();
        let mut chain = VerifiedChain::<HybridSig>::new(PinnedRoots::single(root_digest));
        chain
            .add_epoch::<Sha256Scheme>(&env, "acme", &root_vk, NOW)
            .unwrap();
        chain
            .add_epoch::<Sha256Scheme>(&env, "acme", &root_vk, NOW)
            .unwrap();
        assert_eq!(chain.epochs().len(), 1);
    }

    #[test]
    fn a_pre_placed_successor_root_is_accepted() {
        // Root rotation without shipping a new client.
        let mut r = rng(5);
        let (next_sk, next_vk) = HybridSig::generate(&mut r);
        let (_, epoch_vk) = HybridSig::generate(&mut r);
        let (_, fast_vk) = FastSig::generate(&mut r);
        let next_digest = Sha256Scheme::hash(&HybridSig::encode_vk(&next_vk));
        let cert = EpochCert {
            vk: HybridSig::encode_vk(&epoch_vk),
            vk_fast: FastSig::encode_vk(&fast_vk),
            issuer_vk_digest: next_digest,
            ..fixtures::epoch_cert()
        };
        let env = Envelope::seal::<HybridSig, _>(&cert, SUITE, "acme", None, &next_sk).unwrap();
        let mut chain = VerifiedChain::<HybridSig>::new(PinnedRoots::with_next(
            Digest([0xaa; 32]),
            next_digest,
        ));
        assert!(chain
            .add_epoch::<Sha256Scheme>(&env, "acme", &next_vk, NOW)
            .is_ok());
    }
}
