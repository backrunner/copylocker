//! Versioned sealed-asset container shared by build tooling and clients.

use alloc::string::String;
use alloc::vec::Vec;

use copylocker_suite::cbor::{decode_canonical, CborValue, Limits, MapBuilder};
use copylocker_suite::{AeadScheme, CodecError, CryptoError, CryptoRng, CryptoSuite, Secret};
use copylocker_types::SuiteId;

use crate::{field, ProtoError};

/// Sealed-asset schema version implemented by this release.
pub const SEALED_ASSET_SCHEMA_V1: u64 = 1;
/// Hard bound for the complete encoded container. Larger assets require the future chunked format.
pub const MAX_SEALED_ASSET_BYTES: usize = 64 * 1024 * 1024;
const MAX_ASSET_ID_BYTES: usize = 1_024;
const ASSET_AAD_LABEL: &str = "copylocker/asset-aad/v1";
const ASSET_LIMITS: Limits = Limits {
    max_depth: copylocker_types::MAX_CBOR_DEPTH,
    max_items: 32,
    max_string: MAX_SEALED_ASSET_BYTES,
};

/// One whole-file encrypted asset.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SealedAsset {
    /// Container schema.
    pub schema: u64,
    /// Crypto suite used for the payload AEAD.
    pub suite_id: SuiteId,
    /// Product scope.
    pub product_id: String,
    /// Release variant whose wrapped KEK opens this payload.
    pub variant_id: u64,
    /// Entitlement feature that owns the KEK.
    pub feature_id: String,
    /// Stable build-time asset identifier.
    pub asset_id: String,
    /// `nonce || ciphertext || tag` under the asset KEK.
    pub ciphertext: Vec<u8>,
}

impl SealedAsset {
    /// Construct and encrypt one bounded whole-file asset.
    pub fn seal<S: CryptoSuite>(
        product_id: impl Into<String>,
        variant_id: u64,
        feature_id: impl Into<String>,
        asset_id: impl Into<String>,
        plaintext: &[u8],
        kek: &Secret<[u8; 32]>,
        rng: &mut dyn CryptoRng,
    ) -> Result<Self, CryptoError> {
        let mut asset = Self {
            schema: SEALED_ASSET_SCHEMA_V1,
            suite_id: S::SUITE_ID,
            product_id: product_id.into(),
            variant_id,
            feature_id: feature_id.into(),
            asset_id: asset_id.into(),
            ciphertext: Vec::new(),
        };
        if !asset.identifiers_are_valid() {
            return Err(CryptoError::Invalid);
        }
        let ciphertext_len = plaintext
            .len()
            .checked_add(S::Aead::NONCE_LEN)
            .and_then(|length| length.checked_add(S::Aead::TAG_LEN))
            .ok_or(CryptoError::BadLength)?;
        if asset
            .encoded_len_with_ciphertext(ciphertext_len)
            .is_none_or(|length| length > MAX_SEALED_ASSET_BYTES)
        {
            return Err(CryptoError::BadLength);
        }
        asset.ciphertext = S::Aead::seal_with_nonce(kek.as_slice(), &asset.aad(), plaintext, rng)?;
        if asset
            .encoded_len_with_ciphertext(asset.ciphertext.len())
            .is_none_or(|length| length > MAX_SEALED_ASSET_BYTES)
        {
            return Err(CryptoError::BadLength);
        }
        Ok(asset)
    }

    /// Authenticate and decrypt the asset payload.
    pub fn open<S: CryptoSuite>(&self, kek: &Secret<[u8; 32]>) -> Result<Vec<u8>, CryptoError> {
        if self.schema != SEALED_ASSET_SCHEMA_V1
            || self.suite_id != S::SUITE_ID
            || !self.identifiers_are_valid()
            || self
                .encoded_len_with_ciphertext(self.ciphertext.len())
                .is_none_or(|length| length > MAX_SEALED_ASSET_BYTES)
        {
            return Err(CryptoError::Invalid);
        }
        S::Aead::open_with_nonce(kek.as_slice(), &self.aad(), &self.ciphertext)
    }

    /// Canonical wire encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(self.schema));
        builder.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        builder.put(2, CborValue::Text(self.product_id.clone()));
        builder.put(3, CborValue::Uint(self.variant_id));
        builder.put(4, CborValue::Text(self.feature_id.clone()));
        builder.put(5, CborValue::Text(self.asset_id.clone()));
        builder.put(6, CborValue::Bytes(self.ciphertext.clone()));
        builder.finish()
    }

    /// Decode a bounded canonical container.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > MAX_SEALED_ASSET_BYTES {
            return Err(ProtoError::Codec(CodecError::TooLong));
        }
        let value = decode_canonical(bytes, ASSET_LIMITS)?;
        if value.as_map().is_none() {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        let asset = Self {
            schema: field::uint(&value, 0)?,
            suite_id: field::suite_id(&value, 1)?,
            product_id: field::text(&value, 2)?,
            variant_id: field::uint(&value, 3)?,
            feature_id: field::text(&value, 4)?,
            asset_id: field::text(&value, 5)?,
            ciphertext: field::bytes(&value, 6)?,
        };
        if asset.schema != SEALED_ASSET_SCHEMA_V1
            || !asset.identifiers_are_valid()
            || asset.ciphertext.len() > MAX_SEALED_ASSET_BYTES
        {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        Ok(asset)
    }

    /// Canonical AEAD associated data.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Text(String::from(ASSET_AAD_LABEL)));
        builder.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        builder.put(2, CborValue::Text(self.product_id.clone()));
        builder.put(3, CborValue::Uint(self.variant_id));
        builder.put(4, CborValue::Text(self.feature_id.clone()));
        builder.put(5, CborValue::Text(self.asset_id.clone()));
        builder.finish()
    }

    fn identifiers_are_valid(&self) -> bool {
        [&self.product_id, &self.feature_id, &self.asset_id]
            .into_iter()
            .all(|value| {
                !value.is_empty()
                    && value.len() <= MAX_ASSET_ID_BYTES
                    && !value.as_bytes().contains(&0)
            })
    }

    fn encoded_len_with_ciphertext(&self, ciphertext_len: usize) -> Option<usize> {
        // The map and its integer keys 0..=6 each occupy one byte in canonical CBOR.
        [
            Some(1 + 7),
            Some(cbor_uint_len(self.schema)),
            cbor_blob_len(self.suite_id.as_bytes().len()),
            cbor_blob_len(self.product_id.len()),
            Some(cbor_uint_len(self.variant_id)),
            cbor_blob_len(self.feature_id.len()),
            cbor_blob_len(self.asset_id.len()),
            cbor_blob_len(ciphertext_len),
        ]
        .into_iter()
        .try_fold(0usize, |total, part| total.checked_add(part?))
    }
}

fn cbor_uint_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn cbor_blob_len(length: usize) -> Option<usize> {
    let head: usize = match length {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    };
    head.checked_add(length)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use copylocker_suite_std::ClStd1;

    #[test]
    fn asset_round_trips_and_all_metadata_is_authenticated() {
        let mut rng = copylocker_suite_std::test_rng(44);
        let key = Secret::new([7; 32]);
        let asset = SealedAsset::seal::<ClStd1>(
            "product",
            3,
            "feature",
            "asset.bin",
            b"payload",
            &key,
            &mut rng,
        )
        .unwrap();
        let decoded = SealedAsset::decode(&asset.encode()).unwrap();
        assert_eq!(decoded.open::<ClStd1>(&key).unwrap(), b"payload");

        for changed in [
            {
                let mut value = decoded.clone();
                value.product_id.push('x');
                value
            },
            {
                let mut value = decoded.clone();
                value.variant_id += 1;
                value
            },
            {
                let mut value = decoded.clone();
                value.feature_id.push('x');
                value
            },
            {
                let mut value = decoded.clone();
                value.asset_id.push('x');
                value
            },
        ] {
            assert!(changed.open::<ClStd1>(&key).is_err());
        }
    }

    #[test]
    fn the_container_limit_includes_cbor_metadata_and_aead_overhead() {
        let mut asset = SealedAsset {
            schema: SEALED_ASSET_SCHEMA_V1,
            suite_id: ClStd1::SUITE_ID,
            product_id: String::from("product"),
            variant_id: 3,
            feature_id: String::from("feature"),
            asset_id: String::from("asset.bin"),
            ciphertext: Vec::new(),
        };
        for ciphertext_len in [0, 23, 24, 255, 256, 65_535, 65_536] {
            asset.ciphertext = vec![0; ciphertext_len];
            assert_eq!(
                asset.encoded_len_with_ciphertext(ciphertext_len).unwrap(),
                asset.encode().len()
            );
        }

        let aead_overhead =
            <ClStd1 as CryptoSuite>::Aead::NONCE_LEN + <ClStd1 as CryptoSuite>::Aead::TAG_LEN;
        let mut max_plaintext = MAX_SEALED_ASSET_BYTES - aead_overhead;
        while asset
            .encoded_len_with_ciphertext(max_plaintext + aead_overhead)
            .unwrap()
            > MAX_SEALED_ASSET_BYTES
        {
            max_plaintext -= 1;
        }
        assert_eq!(
            asset
                .encoded_len_with_ciphertext(max_plaintext + aead_overhead)
                .unwrap(),
            MAX_SEALED_ASSET_BYTES
        );
        assert!(
            asset
                .encoded_len_with_ciphertext(max_plaintext + aead_overhead + 1)
                .unwrap()
                > MAX_SEALED_ASSET_BYTES
        );
    }

    #[test]
    fn malformed_or_oversized_containers_are_rejected() {
        assert!(SealedAsset::decode(&[]).is_err());
        assert!(SealedAsset::decode(&vec![0; MAX_SEALED_ASSET_BYTES + 1]).is_err());
    }
}
