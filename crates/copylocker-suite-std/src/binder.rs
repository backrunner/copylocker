//! Device binding: HKDF over the shared secret, fingerprint, and environment evidence.

use copylocker_suite::{
    BoundSecret, CryptoError, DeviceBinder, EnvEvidence, HashScheme, KeyDerivation, SharedSecret,
};
use copylocker_types::Fingerprint;

use crate::hash::Sha256Scheme;
use crate::kdf::HkdfSha512;

/// Salt for the binding derivation. Protocol-visible and frozen.
const BIND_SALT: &[u8] = b"copylocker/bind/v1";

/// `BoundSecret = HKDF(CredentialSecret ‖ fp ‖ H(env))` (`crypto-architecture.md §6`, step ③).
///
/// This is the slot a private suite most wants to replace: making the transform idiosyncratic
/// raises the cost of writing a universal patch. It buys **cost asymmetry, not
/// confidentiality** — the system stays unforgeable even with this function fully published
/// (`open-closed-boundary.md`).
#[derive(Clone, Copy, Debug, Default)]
pub struct HkdfBinder;

impl DeviceBinder for HkdfBinder {
    fn bind(
        secret: &SharedSecret,
        fp: &Fingerprint,
        env: &EnvEvidence,
    ) -> Result<BoundSecret, CryptoError> {
        let env_digest = Sha256Scheme::hash_parts(&env.parts());
        let key = HkdfSha512::derive_from(
            BIND_SALT,
            secret.expose(),
            &[fp.as_bytes(), env_digest.as_bytes()],
        )?;
        Ok(BoundSecret::new(*key.expose()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use copylocker_types::Digest;

    fn evidence(tag: u8) -> EnvEvidence {
        EnvEvidence {
            module_digest: Digest([tag; 32]),
            build_fingerprint: vec![tag, tag],
            extra: vec![],
        }
    }

    #[test]
    fn binding_is_deterministic() {
        let ss = SharedSecret::new([9u8; 32]);
        let fp = Fingerprint::from_vec(vec![1, 2, 3]);
        let a = HkdfBinder::bind(&ss, &fp, &evidence(1)).unwrap();
        let b = HkdfBinder::bind(&ss, &fp, &evidence(1)).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn a_different_fingerprint_yields_a_different_secret() {
        // The machine-binding property: same credential, different device, different keys.
        let ss = SharedSecret::new([9u8; 32]);
        let a = HkdfBinder::bind(&ss, &Fingerprint::from_vec(vec![1]), &evidence(1)).unwrap();
        let b = HkdfBinder::bind(&ss, &Fingerprint::from_vec(vec![2]), &evidence(1)).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn a_patched_build_yields_a_different_secret() {
        // The integrity property: modifying the binary changes the module digest, so the
        // patched build derives keys that cannot unseal anything.
        let ss = SharedSecret::new([9u8; 32]);
        let fp = Fingerprint::from_vec(vec![1]);
        let a = HkdfBinder::bind(&ss, &fp, &evidence(1)).unwrap();
        let b = HkdfBinder::bind(&ss, &fp, &evidence(2)).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn extra_evidence_participates() {
        let ss = SharedSecret::new([9u8; 32]);
        let fp = Fingerprint::from_vec(vec![1]);
        let mut with_extra = evidence(1);
        with_extra.extra.push(vec![0xaa]);
        assert_ne!(
            HkdfBinder::bind(&ss, &fp, &evidence(1)).unwrap().expose(),
            HkdfBinder::bind(&ss, &fp, &with_extra).unwrap().expose()
        );
    }
}
