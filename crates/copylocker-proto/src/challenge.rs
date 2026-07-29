//! Opaque feature-challenge messages used across native and Web host boundaries.
//!
//! The host-visible operation deliberately returns derived key material rather than a boolean
//! licence verdict (ADR-0004). Both messages use a small, versioned canonical-CBOR envelope so
//! bindings can forward bytes without exposing a structured verification object.

use alloc::string::String;
use alloc::vec::Vec;

use copylocker_suite::cbor::{decode_canonical, CborValue, Limits, MapBuilder};
use copylocker_suite::CodecError;

use crate::{field, ProtoError};

/// Feature-challenge schema implemented by this release.
pub const FEATURE_CHALLENGE_SCHEMA_V1: u64 = 1;
/// Maximum encoded challenge request size accepted at a host boundary.
pub const MAX_FEATURE_CHALLENGE_BYTES: usize = 64 * 1024;
/// Maximum feature identifier length.
pub const MAX_FEATURE_ID_BYTES: usize = 1_024;
/// Maximum caller-provided challenge length.
pub const MAX_CHALLENGE_BYTES: usize = 60 * 1024;
/// Width of the derived response material.
pub const FEATURE_RESPONSE_LEN: usize = 32;

const CHALLENGE_LIMITS: Limits = Limits {
    max_depth: 2,
    max_items: 3,
    max_string: MAX_CHALLENGE_BYTES,
};

/// A caller nonce bound to one entitled feature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeatureChallenge {
    /// Schema version.
    pub schema: u64,
    /// Feature whose productive key material must answer the challenge.
    pub feature_id: String,
    /// Opaque caller nonce or transcript hash.
    pub challenge: Vec<u8>,
}

impl FeatureChallenge {
    /// Construct a version-one request.
    pub fn new(feature_id: impl Into<String>, challenge: Vec<u8>) -> Result<Self, ProtoError> {
        let value = Self {
            schema: FEATURE_CHALLENGE_SCHEMA_V1,
            feature_id: feature_id.into(),
            challenge,
        };
        value.validate()?;
        Ok(value)
    }

    /// Encode as canonical CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(self.schema));
        builder.put(1, CborValue::Text(self.feature_id.clone()));
        builder.put(2, CborValue::Bytes(self.challenge.clone()));
        builder.finish()
    }

    /// Decode a bounded, canonical request.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > MAX_FEATURE_CHALLENGE_BYTES {
            return Err(ProtoError::Codec(CodecError::TooLong));
        }
        let value = decode_canonical(bytes, CHALLENGE_LIMITS)?;
        if value.as_map().is_none_or(|entries| entries.len() != 3) {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        let challenge = Self {
            schema: field::uint(&value, 0)?,
            feature_id: field::text(&value, 1)?,
            challenge: field::bytes(&value, 2)?,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    fn validate(&self) -> Result<(), ProtoError> {
        if self.schema != FEATURE_CHALLENGE_SCHEMA_V1
            || self.feature_id.is_empty()
            || self.feature_id.len() > MAX_FEATURE_ID_BYTES
            || self.feature_id.as_bytes().contains(&0)
            || self.challenge.is_empty()
            || self.challenge.len() > MAX_CHALLENGE_BYTES
        {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        Ok(())
    }
}

/// Opaque, domain-separated material returned for a feature challenge.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeatureResponse {
    /// Schema version.
    pub schema: u64,
    /// Material for the host's second derivation step.
    pub material: [u8; FEATURE_RESPONSE_LEN],
}

impl FeatureResponse {
    /// Construct a version-one response.
    #[must_use]
    pub const fn new(material: [u8; FEATURE_RESPONSE_LEN]) -> Self {
        Self {
            schema: FEATURE_CHALLENGE_SCHEMA_V1,
            material,
        }
    }

    /// Encode as canonical CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(self.schema));
        builder.put(1, CborValue::Bytes(self.material.to_vec()));
        builder.finish()
    }

    /// Decode a canonical response.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let value = decode_canonical(
            bytes,
            Limits {
                max_depth: 2,
                max_items: 2,
                max_string: FEATURE_RESPONSE_LEN,
            },
        )?;
        if value.as_map().is_none_or(|entries| entries.len() != 2) {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        let response = Self {
            schema: field::uint(&value, 0)?,
            material: field::fixed(&value, 1)?,
        };
        if response.schema != FEATURE_CHALLENGE_SCHEMA_V1 {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn challenge_and_response_round_trip_canonically() {
        let challenge = FeatureChallenge::new("export.pdf", vec![7; 32]).unwrap();
        assert_eq!(
            FeatureChallenge::decode(&challenge.encode()).unwrap(),
            challenge
        );

        let response = FeatureResponse::new([9; FEATURE_RESPONSE_LEN]);
        assert_eq!(
            FeatureResponse::decode(&response.encode()).unwrap(),
            response
        );
    }

    #[test]
    fn requests_are_strictly_bounded_and_have_no_extension_fields() {
        assert!(FeatureChallenge::new("", vec![1]).is_err());
        assert!(FeatureChallenge::new("feature", Vec::new()).is_err());
        assert!(FeatureChallenge::new("f", vec![0; MAX_CHALLENGE_BYTES + 1]).is_err());

        let mut extended = MapBuilder::new();
        extended.put(0, CborValue::Uint(FEATURE_CHALLENGE_SCHEMA_V1));
        extended.put(1, CborValue::Text(String::from("feature")));
        extended.put(2, CborValue::Bytes(vec![1]));
        extended.put(3, CborValue::Uint(0));
        assert!(FeatureChallenge::decode(&extended.finish()).is_err());
    }

    #[test]
    fn every_truncation_is_rejected_without_panicking() {
        let encoded = FeatureChallenge::new("feature", vec![3; 32])
            .unwrap()
            .encode();
        for end in 0..encoded.len() {
            assert!(FeatureChallenge::decode(&encoded[..end]).is_err());
        }
    }
}
