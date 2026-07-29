//! HKDF-SHA-512 for key derivation, Argon2id for low-entropy stretching.

use copylocker_suite::{CryptoError, KeyDerivation, Prk};
use hkdf::Hkdf;
use sha2::Sha512;

/// Argon2id parameters (`crypto-architecture.md §3`): 64 MiB, 3 passes, 1 lane.
mod argon2_params {
    /// Memory cost in KiB.
    pub(super) const M_COST: u32 = 64 * 1024;
    /// Iteration count.
    pub(super) const T_COST: u32 = 3;
    /// Parallelism.
    pub(super) const P_COST: u32 = 1;
}

/// HKDF-SHA-512, with Argon2id filling the low-entropy stretching slot.
#[derive(Clone, Copy, Debug, Default)]
pub struct HkdfSha512;

impl KeyDerivation for HkdfSha512 {
    fn extract(salt: &[u8], ikm: &[u8]) -> Prk {
        let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
        Prk::from_bytes(&prk)
    }

    fn expand(prk: &Prk, info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        // HKDF-Expand is capped at 255 * HashLen octets.
        if out.len() > 255 * 64 {
            return Err(CryptoError::OutputTooLong);
        }
        let hk = Hkdf::<Sha512>::from_prk(prk.expose()).map_err(|_| CryptoError::BadLength)?;
        hk.expand(info, out).map_err(|_| CryptoError::OutputTooLong)
    }

    fn stretch(salt: &[u8], low_entropy: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        // Argon2 requires a salt of at least 8 bytes; shorter salts are a caller bug, not
        // something to silently pad.
        if salt.len() < 8 {
            return Err(CryptoError::BadLength);
        }
        let params = argon2::Params::new(
            argon2_params::M_COST,
            argon2_params::T_COST,
            argon2_params::P_COST,
            Some(out.len()),
        )
        .map_err(|_| CryptoError::BadLength)?;
        let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        a2.hash_password_into(low_entropy, salt, out)
            .map_err(|_| CryptoError::BadLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn rfc5869_style_determinism() {
        let a = HkdfSha512::extract(b"salt", b"ikm");
        let b = HkdfSha512::extract(b"salt", b"ikm");
        let mut ka = [0u8; 32];
        let mut kb = [0u8; 32];
        HkdfSha512::expand(&a, b"info", &mut ka).unwrap();
        HkdfSha512::expand(&b, b"info", &mut kb).unwrap();
        assert_eq!(ka, kb);
        assert_ne!(ka, [0u8; 32]);
    }

    #[test]
    fn different_salt_info_or_ikm_diverge() {
        let base = HkdfSha512::derive_from(b"salt", b"ikm", &[b"a"]).unwrap();
        let other_salt = HkdfSha512::derive_from(b"salt2", b"ikm", &[b"a"]).unwrap();
        let other_ikm = HkdfSha512::derive_from(b"salt", b"ikm2", &[b"a"]).unwrap();
        let other_info = HkdfSha512::derive_from(b"salt", b"ikm", &[b"b"]).unwrap();
        assert!(!base.ct_eq(&other_salt));
        assert!(!base.ct_eq(&other_ikm));
        assert!(!base.ct_eq(&other_info));
    }

    #[test]
    fn multipart_info_is_length_prefixed() {
        // Without prefixes, ["ab","c"] and ["a","bc"] would collide.
        let prk = HkdfSha512::extract(b"s", b"i");
        let a = HkdfSha512::derive_key(&prk, &[b"ab", b"c"]).unwrap();
        let b = HkdfSha512::derive_key(&prk, &[b"a", b"bc"]).unwrap();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn oversized_expansion_is_rejected_rather_than_truncated() {
        let prk = HkdfSha512::extract(b"s", b"i");
        let mut huge = vec![0u8; 255 * 64 + 1];
        assert_eq!(
            HkdfSha512::expand(&prk, b"", &mut huge),
            Err(CryptoError::OutputTooLong)
        );
    }

    #[test]
    fn argon2id_stretch_is_deterministic_and_salt_bound() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        HkdfSha512::stretch(b"saltsalt", b"weak-password", &mut a).unwrap();
        HkdfSha512::stretch(b"saltsalt", b"weak-password", &mut b).unwrap();
        HkdfSha512::stretch(b"saltsalu", b"weak-password", &mut c).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn short_argon2_salt_is_an_error_not_a_silent_pad() {
        let mut out = [0u8; 32];
        assert_eq!(
            HkdfSha512::stretch(b"short", b"pw", &mut out),
            Err(CryptoError::BadLength)
        );
    }
}
