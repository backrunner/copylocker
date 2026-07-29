use core::marker::PhantomData;

use copylocker_core::FatalError;
use copylocker_proto::{Envelope, EpochCert, Keyset, PinnedRoots, VerifiedChain};
use copylocker_suite::{CryptoSuite, HashScheme, SignatureScheme};
use copylocker_types::{Digest, EpochId, PROTO_VER};

struct RootVerifier<V> {
    digest: Digest,
    key: V,
}

pub(crate) struct TrustAnchors<S: CryptoSuite> {
    current: RootVerifier<<S::Sig as SignatureScheme>::VerifyingKey>,
    next: Option<RootVerifier<<S::Sig as SignatureScheme>::VerifyingKey>>,
    pins: PinnedRoots,
    suite: PhantomData<S>,
}

impl<S: CryptoSuite> TrustAnchors<S> {
    pub(crate) fn decode(current: &[u8], next: Option<&[u8]>) -> Result<Self, FatalError> {
        let current = decode_root::<S>(current)?;
        let next = next.map(decode_root::<S>).transpose()?;
        let pins = match next.as_ref() {
            Some(successor) => PinnedRoots::with_next(current.digest, successor.digest),
            None => PinnedRoots::single(current.digest),
        };
        Ok(Self {
            current,
            next,
            pins,
            suite: PhantomData,
        })
    }

    pub(crate) fn verify_keyset(
        &self,
        keyset: &Keyset,
        product_id: &str,
        now: i64,
        known_revocation_epoch: u64,
        revoked_epochs: &[EpochId],
    ) -> Result<VerifiedChain<S::Sig>, FatalError> {
        if keyset.proto_ver != PROTO_VER {
            return Err(FatalError::CredentialCorrupt);
        }
        if keyset.revocation_epoch < known_revocation_epoch {
            return Err(FatalError::RevocationRollback);
        }

        let mut chain = VerifiedChain::new(self.pins.clone());
        chain
            .revocation_mut()
            .advance(known_revocation_epoch, revoked_epochs.to_vec())
            .map_err(FatalError::from)?;

        for encoded in &keyset.epoch_certificates {
            let envelope = Envelope::decode(encoded).map_err(FatalError::from)?;
            let certificate = envelope
                .peek_unverified::<EpochCert>()
                .map_err(FatalError::from)?;
            if certificate.product_scope.as_deref() != Some(product_id) {
                continue;
            }
            if envelope.proto_ver != PROTO_VER
                || envelope.suite_id != S::SUITE_ID
                || envelope.epoch_ref.is_some()
                || certificate.proto_ver != PROTO_VER
                || certificate.suite_id != S::SUITE_ID
                || certificate.not_after <= certificate.not_before
            {
                return Err(FatalError::CredentialCorrupt);
            }
            if !certificate.window().contains(now) {
                continue;
            }
            let root = self
                .root_for(&certificate.issuer_vk_digest)
                .ok_or(FatalError::ChainInvalid)?;
            chain
                .add_epoch::<S::Hash>(&envelope, product_id, root, now)
                .map_err(FatalError::from)?;
        }
        Ok(chain)
    }

    fn root_for(&self, digest: &Digest) -> Option<&<S::Sig as SignatureScheme>::VerifyingKey> {
        if self.current.digest == *digest {
            return Some(&self.current.key);
        }
        self.next
            .as_ref()
            .filter(|next| next.digest == *digest)
            .map(|next| &next.key)
    }
}

fn decode_root<S: CryptoSuite>(
    encoded: &[u8],
) -> Result<RootVerifier<<S::Sig as SignatureScheme>::VerifyingKey>, FatalError> {
    let key = S::Sig::decode_vk(encoded).map_err(|_| FatalError::ChainInvalid)?;
    let digest = S::Hash::hash(encoded);
    Ok(RootVerifier { digest, key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_proto::EpochCert;
    use copylocker_suite::{Artifact, CryptoSuite};
    use copylocker_suite_std::{ClStd1, FastSig, HybridSig};
    use copylocker_types::{ArtifactKind, SuiteId};

    const NOW: i64 = 10_000;

    fn signed_keyset() -> (Vec<u8>, Keyset, EpochId) {
        let mut rng = copylocker_suite_std::test_rng(41);
        let (root_sk, root_vk) = HybridSig::generate(&mut rng);
        let (_, epoch_vk) = HybridSig::generate(&mut rng);
        let (_, fast_vk) = FastSig::generate(&mut rng);
        let root_bytes = HybridSig::encode_vk(&root_vk);
        let epoch_id = EpochId([7; 8]);
        let cert = EpochCert {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            epoch_id,
            vk: HybridSig::encode_vk(&epoch_vk),
            vk_fast: FastSig::encode_vk(&fast_vk),
            not_before: NOW - 100,
            not_after: NOW + 100,
            product_scope: Some(String::from("acme")),
            issuer_vk_digest: <ClStd1 as CryptoSuite>::Hash::hash(&root_bytes),
        };
        let envelope = Envelope::seal::<HybridSig, _>(
            &cert,
            SuiteId::from_u32(0x0100_0001),
            "acme",
            None,
            &root_sk,
        )
        .unwrap();
        (
            root_bytes,
            Keyset {
                proto_ver: PROTO_VER,
                epoch_certificates: vec![envelope.encode()],
                revocation_epoch: 3,
            },
            epoch_id,
        )
    }

    #[test]
    fn root_signed_current_epoch_is_accepted() {
        let (root, keyset, epoch_id) = signed_keyset();
        let anchors = TrustAnchors::<ClStd1>::decode(&root, None).unwrap();
        let chain = anchors.verify_keyset(&keyset, "acme", NOW, 2, &[]).unwrap();
        assert!(chain.epoch(&epoch_id).is_some());
        assert_eq!(
            chain.revocation().epoch,
            2,
            "the unsigned keyset cursor is only a fetch hint"
        );
    }

    #[test]
    fn revocation_watermark_cannot_move_backwards() {
        let (root, keyset, _) = signed_keyset();
        let anchors = TrustAnchors::<ClStd1>::decode(&root, None).unwrap();
        assert_eq!(
            anchors.verify_keyset(&keyset, "acme", NOW, 4, &[]).err(),
            Some(FatalError::RevocationRollback)
        );
    }

    #[test]
    fn revoked_epoch_is_not_reintroduced_by_the_keyset() {
        let (root, keyset, epoch_id) = signed_keyset();
        let anchors = TrustAnchors::<ClStd1>::decode(&root, None).unwrap();
        assert_eq!(
            anchors
                .verify_keyset(&keyset, "acme", NOW, 3, &[epoch_id])
                .err(),
            Some(FatalError::EpochRevoked)
        );
    }

    #[test]
    fn certificate_for_another_product_is_ignored() {
        let (root, keyset, epoch_id) = signed_keyset();
        let anchors = TrustAnchors::<ClStd1>::decode(&root, None).unwrap();
        let chain = anchors
            .verify_keyset(&keyset, "other", NOW, 0, &[])
            .unwrap();
        assert!(chain.epoch(&epoch_id).is_none());
    }

    #[test]
    fn artifact_kind_constant_remains_epoch_certificate() {
        assert_eq!(EpochCert::KIND, ArtifactKind::EpochCert);
    }
}
