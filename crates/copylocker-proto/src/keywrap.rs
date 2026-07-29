//! Credential-secret sealing and per-feature KEK wrapping (ADR-0013).
//!
//! These byte layouts are shared by the issuer and every client. Keeping their AAD construction
//! here prevents the two sides from independently interpreting prose such as `mc_header || fp`.

use alloc::string::String;
use alloc::vec::Vec;

use copylocker_suite::cbor::{CborValue, MapBuilder};
use copylocker_suite::{
    AeadScheme, CryptoError, CryptoRng, CryptoSuite, KeyDerivation, Secret, SharedSecret,
};
use copylocker_types::{EpochId, Fingerprint, LicenseId, MachineId, SuiteId};
use zeroize::Zeroizing;

/// CredentialSecret and asset KEKs are always 256 bits in protocol version 1.
pub const WRAPPED_SECRET_LEN: usize = 32;
/// HKDF salt for turning the X-Wing shared secret into the credential-wrap AEAD key.
pub const CREDENTIAL_WRAP_SALT: &[u8] = b"copylocker/cs-wrap/v1";
const CREDENTIAL_AAD_LABEL: &str = "copylocker/cs-aad/v1";
const KEK_AAD_LABEL: &str = "copylocker/kek-aad/v1";

/// Public fields bound to an encrypted CredentialSecret.
#[derive(Clone, Copy, Debug)]
pub struct CredentialSealContext<'a> {
    /// Protocol version.
    pub proto_ver: u8,
    /// Negotiated suite.
    pub suite_id: SuiteId,
    /// Product scope.
    pub product_id: &'a str,
    /// License identity.
    pub license_id: LicenseId,
    /// Activation identity.
    pub machine_id: MachineId,
    /// Fingerprint to which the credential is issued.
    pub fingerprint: &'a Fingerprint,
    /// KEM ciphertext carried beside `sealed_cs` in the MachineCredential.
    pub kem_ct: &'a [u8],
    /// Fixed nonce for the offline session root.
    pub offline_nonce: &'a [u8; 32],
    /// Issuing epoch.
    pub epoch_id: EpochId,
    /// Release variant for which the credential is issued.
    pub variant_id: u64,
}

impl CredentialSealContext<'_> {
    /// Canonical CBOR AAD, frozen by ADR-0013.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Text(String::from(CREDENTIAL_AAD_LABEL)));
        b.put(1, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(2, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(3, CborValue::Text(String::from(self.product_id)));
        b.put(4, CborValue::Bytes(self.license_id.as_bytes().to_vec()));
        b.put(5, CborValue::Bytes(self.machine_id.as_bytes().to_vec()));
        b.put(6, CborValue::Bytes(self.fingerprint.as_bytes().to_vec()));
        b.put(7, CborValue::Bytes(self.kem_ct.to_vec()));
        b.put(8, CborValue::Bytes(self.offline_nonce.to_vec()));
        b.put(9, CborValue::Bytes(self.epoch_id.as_bytes().to_vec()));
        b.put(10, CborValue::Uint(self.variant_id));
        b.build().to_canonical()
    }
}

/// Derive the AEAD key used by `sealed_cs`.
pub fn credential_wrap_key<S: CryptoSuite>(
    kem_shared_secret: &SharedSecret,
    context: &CredentialSealContext<'_>,
) -> Result<Secret<Vec<u8>>, CryptoError> {
    let prk = S::Kdf::extract(CREDENTIAL_WRAP_SALT, kem_shared_secret.expose());
    let mut key = Secret::new(alloc::vec![0u8; S::Aead::KEY_LEN]);
    S::Kdf::expand_parts(
        &prk,
        &[
            context.suite_id.as_bytes(),
            context.product_id.as_bytes(),
            context.license_id.as_bytes(),
            context.machine_id.as_bytes(),
        ],
        key.expose_mut(),
    )?;
    Ok(key)
}

/// Seal a 32-byte CredentialSecret as `nonce || ciphertext || tag`.
pub fn seal_credential_secret<S: CryptoSuite>(
    kem_shared_secret: &SharedSecret,
    context: &CredentialSealContext<'_>,
    credential_secret: &Secret<[u8; WRAPPED_SECRET_LEN]>,
    rng: &mut dyn CryptoRng,
) -> Result<Vec<u8>, CryptoError> {
    let key = credential_wrap_key::<S>(kem_shared_secret, context)?;
    S::Aead::seal_with_nonce(
        key.expose(),
        &context.aad(),
        credential_secret.as_slice(),
        rng,
    )
}

/// Open `sealed_cs`, enforcing the exact 32-byte plaintext contract.
pub fn open_credential_secret<S: CryptoSuite>(
    kem_shared_secret: &SharedSecret,
    context: &CredentialSealContext<'_>,
    sealed: &[u8],
) -> Result<Secret<[u8; WRAPPED_SECRET_LEN]>, CryptoError> {
    ensure_wrapped_len::<S>(sealed)?;
    let key = credential_wrap_key::<S>(kem_shared_secret, context)?;
    let plaintext = Zeroizing::new(S::Aead::open_with_nonce(
        key.expose(),
        &context.aad(),
        sealed,
    )?);
    let bytes = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadLength)?;
    Ok(Secret::new(bytes))
}

/// Whether a KEK was wrapped for the offline credential or the current online ticket.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KekWrapKind {
    /// MachineCredential field 21, derived from `offline_nonce`.
    Offline = 0,
    /// ValidationTicket field 15, derived from `server_nonce`.
    Online = 1,
}

/// Public fields bound to a per-feature wrapped asset KEK.
#[derive(Clone, Copy, Debug)]
pub struct KekWrapContext<'a> {
    /// Protocol version.
    pub proto_ver: u8,
    /// Negotiated suite.
    pub suite_id: SuiteId,
    /// Product scope.
    pub product_id: &'a str,
    /// License identity.
    pub license_id: LicenseId,
    /// Activation identity.
    pub machine_id: MachineId,
    /// Issuing epoch.
    pub epoch_id: EpochId,
    /// Release variant whose FeatureKey wraps the KEK.
    pub variant_id: u64,
    /// Entitled feature identifier.
    pub feature_id: &'a str,
    /// Online or offline wrapping.
    pub kind: KekWrapKind,
    /// `offline_nonce` for offline or the ticket's `server_nonce` for online.
    pub session_nonce: &'a [u8; 32],
}

impl KekWrapContext<'_> {
    /// Canonical CBOR AAD, frozen by ADR-0013.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Text(String::from(KEK_AAD_LABEL)));
        b.put(1, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(2, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(3, CborValue::Text(String::from(self.product_id)));
        b.put(4, CborValue::Bytes(self.license_id.as_bytes().to_vec()));
        b.put(5, CborValue::Bytes(self.machine_id.as_bytes().to_vec()));
        b.put(6, CborValue::Bytes(self.epoch_id.as_bytes().to_vec()));
        b.put(7, CborValue::Uint(self.variant_id));
        b.put(8, CborValue::Text(String::from(self.feature_id)));
        b.put(9, CborValue::Uint(self.kind as u64));
        b.put(10, CborValue::Bytes(self.session_nonce.to_vec()));
        b.build().to_canonical()
    }
}

/// Wrap a 32-byte asset KEK as `nonce || ciphertext || tag`.
pub fn seal_kek<S: CryptoSuite>(
    feature_key: &[u8],
    context: &KekWrapContext<'_>,
    kek: &Secret<[u8; WRAPPED_SECRET_LEN]>,
    rng: &mut dyn CryptoRng,
) -> Result<Vec<u8>, CryptoError> {
    S::Aead::seal_with_nonce(feature_key, &context.aad(), kek.as_slice(), rng)
}

/// Open a wrapped asset KEK, enforcing the exact 32-byte plaintext contract.
pub fn open_kek<S: CryptoSuite>(
    feature_key: &[u8],
    context: &KekWrapContext<'_>,
    wrapped: &[u8],
) -> Result<Secret<[u8; WRAPPED_SECRET_LEN]>, CryptoError> {
    ensure_wrapped_len::<S>(wrapped)?;
    let plaintext = Zeroizing::new(S::Aead::open_with_nonce(
        feature_key,
        &context.aad(),
        wrapped,
    )?);
    let bytes = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::BadLength)?;
    Ok(Secret::new(bytes))
}

fn ensure_wrapped_len<S: CryptoSuite>(blob: &[u8]) -> Result<(), CryptoError> {
    let expected = S::Aead::NONCE_LEN
        .checked_add(WRAPPED_SECRET_LEN)
        .and_then(|n| n.checked_add(S::Aead::TAG_LEN))
        .ok_or(CryptoError::BadLength)?;
    if blob.len() != expected {
        return Err(CryptoError::BadLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_suite::CryptoRng;
    use copylocker_suite_std::ClStd1;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{Rng, SeedableRng};

    struct TestRng(ChaCha20Rng);

    impl CryptoRng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest);
        }
    }

    fn rng() -> TestRng {
        TestRng(ChaCha20Rng::seed_from_u64(7))
    }

    fn credential_context<'a>(
        fingerprint: &'a Fingerprint,
        kem_ct: &'a [u8],
        offline_nonce: &'a [u8; 32],
    ) -> CredentialSealContext<'a> {
        CredentialSealContext {
            proto_ver: 1,
            suite_id: ClStd1::SUITE_ID,
            product_id: "acme",
            license_id: LicenseId([1; 16]),
            machine_id: MachineId([2; 16]),
            fingerprint,
            kem_ct,
            offline_nonce,
            epoch_id: EpochId([3; 8]),
            variant_id: 4,
        }
    }

    #[test]
    fn credential_secret_roundtrips_and_has_fixed_wire_length() {
        let fingerprint = Fingerprint::from_vec(alloc::vec![5; 32]);
        let kem_ct = alloc::vec![6; 1088];
        let nonce = [7; 32];
        let context = credential_context(&fingerprint, &kem_ct, &nonce);
        let shared = SharedSecret::new([8; 32]);
        let secret = Secret::new([9; 32]);
        let sealed =
            seal_credential_secret::<ClStd1>(&shared, &context, &secret, &mut rng()).unwrap();
        assert_eq!(sealed.len(), 72);
        let opened = open_credential_secret::<ClStd1>(&shared, &context, &sealed).unwrap();
        assert!(secret.ct_eq(&opened));
    }

    #[test]
    fn credential_aad_tampering_fails() {
        let fingerprint = Fingerprint::from_vec(alloc::vec![5; 32]);
        let other_fingerprint = Fingerprint::from_vec(alloc::vec![0xff; 32]);
        let kem_ct = alloc::vec![6; 1088];
        let nonce = [7; 32];
        let context = credential_context(&fingerprint, &kem_ct, &nonce);
        let other = credential_context(&other_fingerprint, &kem_ct, &nonce);
        let shared = SharedSecret::new([8; 32]);
        let secret = Secret::new([9; 32]);
        let sealed =
            seal_credential_secret::<ClStd1>(&shared, &context, &secret, &mut rng()).unwrap();
        assert!(open_credential_secret::<ClStd1>(&shared, &other, &sealed).is_err());
    }

    #[test]
    fn kek_context_separates_online_offline_feature_and_variant() {
        let nonce = [7; 32];
        let base = KekWrapContext {
            proto_ver: 1,
            suite_id: ClStd1::SUITE_ID,
            product_id: "acme",
            license_id: LicenseId([1; 16]),
            machine_id: MachineId([2; 16]),
            epoch_id: EpochId([3; 8]),
            variant_id: 4,
            feature_id: "export.pdf",
            kind: KekWrapKind::Offline,
            session_nonce: &nonce,
        };
        let key = Secret::new([8; 32]);
        let kek = Secret::new([9; 32]);
        let wrapped = seal_kek::<ClStd1>(key.as_slice(), &base, &kek, &mut rng()).unwrap();
        assert_eq!(wrapped.len(), 72);
        assert!(kek.ct_eq(&open_kek::<ClStd1>(key.as_slice(), &base, &wrapped).unwrap()));

        let online = KekWrapContext {
            kind: KekWrapKind::Online,
            ..base
        };
        assert!(open_kek::<ClStd1>(key.as_slice(), &online, &wrapped).is_err());
        let other_feature = KekWrapContext {
            feature_id: "sync.cloud",
            ..base
        };
        assert!(open_kek::<ClStd1>(key.as_slice(), &other_feature, &wrapped).is_err());
        let other_variant = KekWrapContext {
            variant_id: 5,
            ..base
        };
        assert!(open_kek::<ClStd1>(key.as_slice(), &other_variant, &wrapped).is_err());
    }
}
