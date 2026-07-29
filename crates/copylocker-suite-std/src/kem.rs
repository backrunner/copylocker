//! X-Wing adapter over RustCrypto's specification-tested implementation.
//!
//! CopyLocker owns only the narrow suite-trait adapter and the seed wrapper needed by its
//! zeroization contract. Key expansion, ML-KEM/X25519 composition, the combiner, and wire layout
//! are delegated to `x-wing`, whose upstream tests replay the draft RFC vectors.

use alloc::vec::Vec;

use copylocker_suite::{Ciphertext, CryptoError, CryptoRng, KeyEncapsulation, SharedSecret};
use x_wing::{Decapsulate as _, Decapsulator as _, Encapsulate as _, KeyExport as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::RandCoreBridge;

/// X-Wing decapsulation key: the 32-byte seed defined by the specification.
#[derive(ZeroizeOnDrop)]
pub struct XWingDecapKey([u8; x_wing::DECAPSULATION_KEY_SIZE]);

impl Zeroize for XWingDecapKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for XWingDecapKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XWingDecapKey(<redacted>)")
    }
}

/// Validated X-Wing encapsulation key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct XWingEncapKey(x_wing::EncapsulationKey);

/// X-Wing (X25519 + ML-KEM-768), draft 06.
#[derive(Clone, Copy, Debug, Default)]
pub struct XWingKem;

impl KeyEncapsulation for XWingKem {
    type DecapKey = XWingDecapKey;
    type EncapKey = XWingEncapKey;

    const EK_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;
    const DK_LEN: usize = x_wing::DECAPSULATION_KEY_SIZE;
    const CT_LEN: usize = x_wing::CIPHERTEXT_SIZE;

    fn keygen(rng: &mut dyn CryptoRng) -> (Self::DecapKey, Self::EncapKey) {
        let mut seed = [0u8; x_wing::DECAPSULATION_KEY_SIZE];
        rng.fill_bytes(&mut seed);
        let dk = XWingDecapKey(seed);
        let ek = Self::encap_key(&dk);
        (dk, ek)
    }

    fn encap_key(dk: &Self::DecapKey) -> Self::EncapKey {
        let upstream = x_wing::DecapsulationKey::from(dk.0);
        XWingEncapKey(upstream.encapsulation_key().clone())
    }

    fn encap(
        ek: &Self::EncapKey,
        rng: &mut dyn CryptoRng,
    ) -> Result<(Ciphertext, SharedSecret), CryptoError> {
        let mut bridge = RandCoreBridge::new(rng);
        let (ciphertext, shared) = ek.0.encapsulate_with_rng(&mut bridge);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&shared);
        Ok((Ciphertext(ciphertext.to_vec()), SharedSecret::new(secret)))
    }

    fn decap(dk: &Self::DecapKey, ct: &Ciphertext) -> Result<SharedSecret, CryptoError> {
        let ciphertext =
            x_wing::Ciphertext::try_from(ct.as_bytes()).map_err(|_| CryptoError::BadLength)?;
        let upstream = x_wing::DecapsulationKey::from(dk.0);
        let shared = upstream.decapsulate(&ciphertext);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&shared);
        Ok(SharedSecret::new(secret))
    }

    fn encode_ek(ek: &Self::EncapKey) -> Vec<u8> {
        ek.0.to_bytes().to_vec()
    }

    fn decode_ek(bytes: &[u8]) -> Result<Self::EncapKey, CryptoError> {
        x_wing::EncapsulationKey::try_from(bytes)
            .map(XWingEncapKey)
            .map_err(|_| CryptoError::Invalid)
    }

    fn encode_dk(dk: &Self::DecapKey) -> Vec<u8> {
        dk.0.to_vec()
    }

    fn decode_dk(bytes: &[u8]) -> Result<Self::DecapKey, CryptoError> {
        Ok(XWingDecapKey(
            bytes.try_into().map_err(|_| CryptoError::BadLength)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng;

    #[test]
    fn encap_decap_agree() {
        let mut rng = test_rng(1);
        let (dk, ek) = XWingKem::keygen(&mut rng);
        let (ct, ss_sender) = XWingKem::encap(&ek, &mut rng).unwrap();
        assert_eq!(ct.as_bytes().len(), XWingKem::CT_LEN);
        let ss_receiver = XWingKem::decap(&dk, &ct).unwrap();
        assert_eq!(ss_sender.expose(), ss_receiver.expose());
    }

    #[test]
    fn declared_lengths_match_reality() {
        let mut rng = test_rng(2);
        let (dk, ek) = XWingKem::keygen(&mut rng);
        assert_eq!(XWingKem::encode_ek(&ek).len(), XWingKem::EK_LEN);
        assert_eq!(XWingKem::encode_dk(&dk).len(), XWingKem::DK_LEN);
        assert_eq!(XWingKem::EK_LEN, 1216);
        assert_eq!(XWingKem::CT_LEN, 1120);
    }

    #[test]
    fn key_derivation_from_seed_is_deterministic() {
        let seed = [7u8; 32];
        let dk = XWingKem::decode_dk(&seed).unwrap();
        let a = XWingKem::encode_ek(&XWingKem::encap_key(&dk));
        let b = XWingKem::encode_ek(&XWingKem::encap_key(&dk));
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_key_yields_a_different_secret() {
        let mut rng = test_rng(3);
        let (_, ek) = XWingKem::keygen(&mut rng);
        let (other_dk, _) = XWingKem::keygen(&mut rng);
        let (ct, ss_sender) = XWingKem::encap(&ek, &mut rng).unwrap();
        let ss_other = XWingKem::decap(&other_dk, &ct).unwrap();
        assert_ne!(ss_sender.expose(), ss_other.expose());
    }

    #[test]
    fn tampered_ciphertext_yields_a_different_secret() {
        let mut rng = test_rng(4);
        let (dk, ek) = XWingKem::keygen(&mut rng);
        let (ct, ss) = XWingKem::encap(&ek, &mut rng).unwrap();
        let mut bad = ct.as_bytes().to_vec();
        bad[0] ^= 1;
        let ss_bad = XWingKem::decap(&dk, &Ciphertext(bad)).unwrap();
        assert_ne!(ss.expose(), ss_bad.expose());
    }

    #[test]
    fn wrong_length_inputs_are_rejected() {
        let mut rng = test_rng(5);
        let (dk, _) = XWingKem::keygen(&mut rng);
        assert!(matches!(
            XWingKem::decap(&dk, &Ciphertext(alloc::vec![0u8; 10])),
            Err(CryptoError::BadLength)
        ));
        assert!(XWingKem::decode_ek(&[0u8; 10]).is_err());
        assert!(matches!(
            XWingKem::decode_dk(&[0u8; 10]),
            Err(CryptoError::BadLength)
        ));
    }

    #[test]
    fn keys_roundtrip() {
        let mut rng = test_rng(6);
        let (dk, ek) = XWingKem::keygen(&mut rng);
        let ek2 = XWingKem::decode_ek(&XWingKem::encode_ek(&ek)).unwrap();
        let dk2 = XWingKem::decode_dk(&XWingKem::encode_dk(&dk)).unwrap();
        assert_eq!(ek, ek2);
        let (ct, ss) = XWingKem::encap(&ek2, &mut rng).unwrap();
        assert_eq!(XWingKem::decap(&dk2, &ct).unwrap().expose(), ss.expose());
    }

    #[test]
    fn two_encapsulations_to_one_key_differ() {
        let mut rng = test_rng(7);
        let (_, ek) = XWingKem::keygen(&mut rng);
        let (ct1, ss1) = XWingKem::encap(&ek, &mut rng).unwrap();
        let (ct2, ss2) = XWingKem::encap(&ek, &mut rng).unwrap();
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_ne!(ss1.expose(), ss2.expose());
    }
}
