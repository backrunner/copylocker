//! Unsigned service response bodies (`protocol-spec.md §10.2`).
//!
//! Signed artifacts still travel in [`crate::Envelope`]. These small wrappers model the
//! service-level CBOR maps around key discovery, errors, and acknowledgements so clients do not
//! need to parse wire data with ad-hoc indexing.

use alloc::string::String;
use alloc::vec::Vec;

use copylocker_suite::cbor::{decode_canonical, CborValue, MapBuilder};
use copylocker_suite::CodecError;

use crate::field;
use crate::{ProtoError, BULK_LIMITS, CLIENT_LIMITS};

/// Maximum complete `/v1/keys` response accepted by a client.
pub const MAX_KEYSET_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of Epoch certificates published by one keyset.
pub const MAX_KEYSET_CERTIFICATES: usize = 1_000;
/// Maximum encoded size of one enveloped Epoch certificate.
pub const MAX_EPOCH_CERTIFICATE_BYTES: usize = 64 * 1024;

/// `GET /v1/keys` response.
///
/// The container itself is not a trust anchor. Every certificate inside it still has to verify
/// against a root key compiled into the client, and `revocation_epoch` is checked against the
/// protected local high-water mark.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Keyset {
    /// Protocol version.
    pub proto_ver: u8,
    /// Canonical encodings of root-signed [`crate::EpochCert`] envelopes.
    pub epoch_certificates: Vec<Vec<u8>>,
    /// Latest published revocation sequence.
    pub revocation_epoch: u64,
}

impl Keyset {
    /// Encode to deterministic CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        builder.put(
            1,
            CborValue::Array(
                self.epoch_certificates
                    .iter()
                    .cloned()
                    .map(CborValue::Bytes)
                    .collect(),
            ),
        );
        builder.put(2, CborValue::Uint(self.revocation_epoch));
        builder.finish()
    }

    /// Decode a bounded deterministic-CBOR keyset.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > MAX_KEYSET_BYTES {
            return Err(ProtoError::Codec(CodecError::TooLong));
        }
        let value = decode_canonical(bytes, BULK_LIMITS)?;
        let certificates = field::req(&value, 1)?
            .as_array()
            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(1)))?;
        if certificates.len() > MAX_KEYSET_CERTIFICATES {
            return Err(ProtoError::Codec(CodecError::TooLong));
        }
        let mut epoch_certificates = Vec::with_capacity(certificates.len());
        for certificate in certificates {
            let encoded = certificate
                .as_bytes()
                .ok_or(ProtoError::Codec(CodecError::TypeMismatch(1)))?;
            if encoded.len() > MAX_EPOCH_CERTIFICATE_BYTES {
                return Err(ProtoError::Codec(CodecError::TooLong));
            }
            epoch_certificates.push(encoded.to_vec());
        }
        Ok(Self {
            proto_ver: field::u8_field(&value, 0)?,
            epoch_certificates,
            revocation_epoch: field::uint(&value, 2)?,
        })
    }
}

/// CBOR error body returned by client-facing endpoints.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProtocolErrorResponse {
    /// Stable numeric protocol error code.
    pub code: u64,
    /// Optional non-sensitive user-facing detail.
    pub message: Option<String>,
    /// Optional server-requested delay in seconds.
    pub retry_after: Option<u32>,
}

impl ProtocolErrorResponse {
    /// Decode a bounded deterministic-CBOR error body.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > copylocker_types::MAX_BODY_BYTES {
            return Err(ProtoError::Codec(CodecError::TooLong));
        }
        let value = decode_canonical(bytes, CLIENT_LIMITS)?;
        let retry_after = field::opt_uint(&value, 2)?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ProtoError::FieldOutOfRange(2))?;
        Ok(Self {
            code: field::uint(&value, 0)?,
            message: field::opt_text(&value, 1)?,
            retry_after,
        })
    }
}

/// A freshly issued or rotated Mode E account session
/// (`POST /v1/account/login` and `/v1/account/refresh`).
///
/// Both tokens are bearer secrets. The server stores only their hashes; the client must keep
/// them in protected storage and must never log them.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountSession {
    /// Short-lived token presented as the activation credential.
    pub account_token: [u8; crate::requests::ACCOUNT_TOKEN_LEN],
    /// Longer-lived token used to rotate the session.
    pub refresh_token: [u8; crate::requests::ACCOUNT_TOKEN_LEN],
    /// Access token expiry (Unix seconds).
    pub expires_at: i64,
    /// Refresh token expiry (Unix seconds).
    pub refresh_expires_at: i64,
}

impl AccountSession {
    /// Encode as canonical CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Bytes(self.account_token.to_vec()));
        builder.put(1, CborValue::Bytes(self.refresh_token.to_vec()));
        builder.put(2, CborValue::int(self.expires_at));
        builder.put(3, CborValue::int(self.refresh_expires_at));
        builder.finish()
    }

    /// Decode a bounded deterministic-CBOR session.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > copylocker_types::MAX_BODY_BYTES {
            return Err(ProtoError::Codec(CodecError::TooLong));
        }
        let value = decode_canonical(bytes, CLIENT_LIMITS)?;
        if value.as_map().is_none_or(|entries| entries.len() != 4) {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        Ok(Self {
            account_token: field::fixed::<{ crate::requests::ACCOUNT_TOKEN_LEN }>(&value, 0)?,
            refresh_token: field::fixed::<{ crate::requests::ACCOUNT_TOKEN_LEN }>(&value, 1)?,
            expires_at: field::int(&value, 2)?,
            refresh_expires_at: field::int(&value, 3)?,
        })
    }
}

impl core::fmt::Debug for AccountSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AccountSession")
            .field("account_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

/// `{ 0: true }` response used by deactivation and similar commands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AckResponse {
    /// Whether the server committed the operation.
    pub ok: bool,
}

impl AckResponse {
    /// Decode a bounded deterministic-CBOR acknowledgement.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > copylocker_types::MAX_BODY_BYTES {
            return Err(ProtoError::Codec(CodecError::TooLong));
        }
        let value = decode_canonical(bytes, CLIENT_LIMITS)?;
        let ok = field::req(&value, 0)?
            .as_bool()
            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(0)))?;
        Ok(Self { ok })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyset_round_trips() {
        let keyset = Keyset {
            proto_ver: 1,
            epoch_certificates: alloc::vec![alloc::vec![1, 2, 3], alloc::vec![4, 5]],
            revocation_epoch: 42,
        };
        assert_eq!(Keyset::decode(&keyset.encode()).unwrap(), keyset);
    }

    #[test]
    fn oversized_keyset_members_are_rejected() {
        let keyset = Keyset {
            proto_ver: 1,
            epoch_certificates: alloc::vec![alloc::vec![0; MAX_EPOCH_CERTIFICATE_BYTES + 1]],
            revocation_epoch: 0,
        };
        assert!(matches!(
            Keyset::decode(&keyset.encode()),
            Err(ProtoError::Codec(CodecError::TooLong))
        ));
    }

    #[test]
    fn protocol_error_fields_decode() {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(5_000));
        builder.put(1, CborValue::Text(String::from("retry later")));
        builder.put(2, CborValue::Uint(7));
        assert_eq!(
            ProtocolErrorResponse::decode(&builder.finish()).unwrap(),
            ProtocolErrorResponse {
                code: 5_000,
                message: Some(String::from("retry later")),
                retry_after: Some(7),
            }
        );
    }

    #[test]
    fn acknowledgement_requires_a_boolean() {
        let mut valid = MapBuilder::new();
        valid.put(0, CborValue::Bool(true));
        assert_eq!(
            AckResponse::decode(&valid.finish()).unwrap(),
            AckResponse { ok: true }
        );

        let mut invalid = MapBuilder::new();
        invalid.put(0, CborValue::Uint(1));
        assert!(AckResponse::decode(&invalid.finish()).is_err());
    }

    #[test]
    fn account_session_round_trips_without_leaking_tokens() {
        let session = AccountSession {
            account_token: [1; crate::requests::ACCOUNT_TOKEN_LEN],
            refresh_token: [2; crate::requests::ACCOUNT_TOKEN_LEN],
            expires_at: 1_700_003_600,
            refresh_expires_at: 1_702_592_000,
        };
        assert_eq!(AccountSession::decode(&session.encode()).unwrap(), session);
        let rendered = alloc::format!("{session:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("account_token: ["));

        let mut extra = MapBuilder::new();
        extra.put(0, CborValue::Bytes(alloc::vec![1; 32]));
        extra.put(1, CborValue::Bytes(alloc::vec![2; 32]));
        extra.put(2, CborValue::int(3));
        extra.put(3, CborValue::int(4));
        extra.put(4, CborValue::Uint(0));
        assert!(AccountSession::decode(&extra.finish()).is_err());
    }
}
