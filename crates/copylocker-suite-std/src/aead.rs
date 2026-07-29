//! XChaCha20-Poly1305 AEAD slot.

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use copylocker_suite::{AeadScheme, CryptoError};

/// XChaCha20-Poly1305.
///
/// Chosen over AES-GCM because WASM has no AES-NI — ChaCha is both faster there and naturally
/// constant-time — and because a 192-bit nonce can be drawn at random indefinitely, which
/// removes the counter that multi-device deployments cannot coordinate
/// (`crypto-architecture.md §3.3`).
#[derive(Clone, Copy, Debug, Default)]
pub struct XChaCha20Poly1305Aead;

impl AeadScheme for XChaCha20Poly1305Aead {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 24;
    const TAG_LEN: usize = 16;
    const RANDOM_NONCE_SAFE: bool = true;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != Self::KEY_LEN || nonce.len() != Self::NONCE_LEN {
            return Err(CryptoError::BadLength);
        }
        let key = key.try_into().map_err(|_| CryptoError::BadLength)?;
        let nonce: &XNonce = nonce.try_into().map_err(|_| CryptoError::BadLength)?;
        XChaCha20Poly1305::new(key)
            .encrypt(nonce, Payload { msg: pt, aad })
            .map_err(|_| CryptoError::Invalid)
    }

    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != Self::KEY_LEN || nonce.len() != Self::NONCE_LEN {
            return Err(CryptoError::BadLength);
        }
        if ct.len() < Self::TAG_LEN {
            return Err(CryptoError::BadLength);
        }
        let key = key.try_into().map_err(|_| CryptoError::BadLength)?;
        let nonce: &XNonce = nonce.try_into().map_err(|_| CryptoError::BadLength)?;
        XChaCha20Poly1305::new(key)
            .decrypt(nonce, Payload { msg: ct, aad })
            .map_err(|_| CryptoError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng;

    const KEY: [u8; 32] = [0x42; 32];
    const NONCE: [u8; 24] = [0x24; 24];

    #[test]
    fn seal_open_roundtrip() {
        let ct = XChaCha20Poly1305Aead::seal(&KEY, &NONCE, b"aad", b"secret").unwrap();
        assert_eq!(ct.len(), b"secret".len() + 16);
        let pt = XChaCha20Poly1305Aead::open(&KEY, &NONCE, b"aad", &ct).unwrap();
        assert_eq!(pt, b"secret");
    }

    #[test]
    fn wrong_aad_fails() {
        let ct = XChaCha20Poly1305Aead::seal(&KEY, &NONCE, b"aad", b"secret").unwrap();
        assert_eq!(
            XChaCha20Poly1305Aead::open(&KEY, &NONCE, b"other", &ct),
            Err(CryptoError::Invalid)
        );
    }

    #[test]
    fn any_single_bit_flip_fails() {
        let ct = XChaCha20Poly1305Aead::seal(&KEY, &NONCE, b"aad", b"secret message").unwrap();
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 1;
            assert_eq!(
                XChaCha20Poly1305Aead::open(&KEY, &NONCE, b"aad", &bad),
                Err(CryptoError::Invalid),
                "flip at byte {i} must be caught"
            );
        }
    }

    #[test]
    fn wrong_key_or_nonce_fails() {
        let ct = XChaCha20Poly1305Aead::seal(&KEY, &NONCE, b"", b"x").unwrap();
        assert!(XChaCha20Poly1305Aead::open(&[0x43; 32], &NONCE, b"", &ct).is_err());
        assert!(XChaCha20Poly1305Aead::open(&KEY, &[0x25; 24], b"", &ct).is_err());
    }

    #[test]
    fn bad_lengths_are_rejected_before_use() {
        assert_eq!(
            XChaCha20Poly1305Aead::seal(&[0u8; 31], &NONCE, b"", b""),
            Err(CryptoError::BadLength)
        );
        assert_eq!(
            XChaCha20Poly1305Aead::seal(&KEY, &[0u8; 12], b"", b""),
            Err(CryptoError::BadLength)
        );
        assert_eq!(
            XChaCha20Poly1305Aead::open(&KEY, &NONCE, b"", &[0u8; 4]),
            Err(CryptoError::BadLength)
        );
    }

    #[test]
    fn nonce_prefixed_helper_roundtrips_and_varies() {
        let mut rng = test_rng(1);
        let a = XChaCha20Poly1305Aead::seal_with_nonce(&KEY, b"aad", b"payload", &mut rng).unwrap();
        let b = XChaCha20Poly1305Aead::seal_with_nonce(&KEY, b"aad", b"payload", &mut rng).unwrap();
        assert_ne!(a, b, "each seal must draw a fresh nonce");
        assert_eq!(
            XChaCha20Poly1305Aead::open_with_nonce(&KEY, b"aad", &a).unwrap(),
            b"payload"
        );
        assert_eq!(
            XChaCha20Poly1305Aead::open_with_nonce(&KEY, b"aad", &b).unwrap(),
            b"payload"
        );
    }
}
