//! Self-contained Offline License Key bundle and text armor (ADR-0015).

use alloc::string::String;
use alloc::vec::Vec;

use copylocker_suite::cbor::{decode_canonical, CborValue, Limits, MapBuilder};
use copylocker_suite::CodecError;
use copylocker_types::Fingerprint;

use crate::responses::{MAX_EPOCH_CERTIFICATE_BYTES, MAX_KEYSET_CERTIFICATES};
use crate::{field, ProtoError};

/// Bundle schema implemented by this release.
pub const OLK_BUNDLE_SCHEMA_V1: u64 = 1;
/// Maximum decoded binary `.clk` size.
pub const MAX_OLK_BUNDLE_BYTES: usize = 1024 * 1024;
/// Protocol binding input for explicitly enabled unbound OLKs.
pub const UNBOUND_OLK_BINDING_LABEL: &[u8] = b"copylocker/olk-unbound/v1";

const MAX_OLK_ENVELOPE_BYTES: usize = 256 * 1024;
const ARMOR_PREFIX: &str = "CLK1:";
const ARMOR_BEGIN: &str = "-----BEGIN COPYLOCKER OFFLINE LICENSE-----";
const ARMOR_END: &str = "-----END COPYLOCKER OFFLINE LICENSE-----";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const BUNDLE_LIMITS: Limits = Limits {
    max_depth: copylocker_types::MAX_CBOR_DEPTH,
    max_items: 32,
    max_string: MAX_OLK_BUNDLE_BYTES,
};

/// Root-verifiable OLK envelope plus the Epoch certificate chain needed by an air-gapped client.
#[derive(Clone, PartialEq, Eq)]
pub struct OfflineLicenseBundle {
    /// Bundle schema.
    pub schema: u64,
    /// Encoded `Envelope(OfflineLicenseKey)`.
    pub license_envelope: Vec<u8>,
    /// Root-signed Epoch certificate envelopes.
    pub epoch_certificates: Vec<Vec<u8>>,
}

impl OfflineLicenseBundle {
    /// Construct a schema-v1 bundle.
    #[must_use]
    pub fn new(license_envelope: Vec<u8>, epoch_certificates: Vec<Vec<u8>>) -> Self {
        Self {
            schema: OLK_BUNDLE_SCHEMA_V1,
            license_envelope,
            epoch_certificates,
        }
    }

    /// Encode the binary `.clk` payload as canonical CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(self.schema));
        builder.put(1, CborValue::Bytes(self.license_envelope.clone()));
        builder.put(
            2,
            CborValue::Array(
                self.epoch_certificates
                    .iter()
                    .cloned()
                    .map(CborValue::Bytes)
                    .collect(),
            ),
        );
        builder.finish()
    }

    /// Decode a bounded binary `.clk` payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > MAX_OLK_BUNDLE_BYTES {
            return Err(ProtoError::Codec(CodecError::TooLong));
        }
        let value = decode_canonical(bytes, BUNDLE_LIMITS)?;
        if value.as_map().is_none() {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        let schema = field::uint(&value, 0)?;
        let license_envelope = field::bytes(&value, 1)?;
        let certificate_values = field::req(&value, 2)?
            .as_array()
            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(2)))?;
        if schema != OLK_BUNDLE_SCHEMA_V1
            || license_envelope.is_empty()
            || license_envelope.len() > MAX_OLK_ENVELOPE_BYTES
            || certificate_values.is_empty()
            || certificate_values.len() > MAX_KEYSET_CERTIFICATES
        {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        let epoch_certificates = certificate_values
            .iter()
            .map(|value| {
                let bytes = value
                    .as_bytes()
                    .ok_or(ProtoError::Codec(CodecError::TypeMismatch(2)))?;
                if bytes.is_empty() || bytes.len() > MAX_EPOCH_CERTIFICATE_BYTES {
                    return Err(ProtoError::Codec(CodecError::TooLong));
                }
                Ok(bytes.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            schema,
            license_envelope,
            epoch_certificates,
        })
    }

    /// Encode the bundle as the frozen `CLK1` Crockford Base32 armor.
    #[must_use]
    pub fn to_armored(&self) -> String {
        let encoded = crockford_encode(&self.encode());
        let mut output = String::with_capacity(ARMOR_PREFIX.len() + encoded.len());
        output.push_str(ARMOR_PREFIX);
        output.push_str(&encoded);
        output
    }

    /// Parse compact or PEM-bounded `CLK1` armor and decode the contained bundle.
    pub fn from_armored(input: &str) -> Result<Self, ProtoError> {
        let trimmed = input.trim_matches(|character: char| character.is_ascii_whitespace());
        let body = if let Some(after_begin) = trimmed.strip_prefix(ARMOR_BEGIN) {
            after_begin
                .strip_suffix(ARMOR_END)
                .ok_or(ProtoError::Codec(CodecError::Malformed))?
        } else {
            trimmed
        };
        let compact: String = body
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        let payload = compact
            .strip_prefix(ARMOR_PREFIX)
            .ok_or(ProtoError::Codec(CodecError::Malformed))?;
        let decoded = crockford_decode(payload)?;
        Self::decode(&decoded)
    }
}

impl core::fmt::Debug for OfflineLicenseBundle {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OfflineLicenseBundle")
            .field("schema", &self.schema)
            .field("license_envelope_len", &self.license_envelope.len())
            .field("epoch_certificate_count", &self.epoch_certificates.len())
            .finish()
    }
}

/// Select the exact fingerprint input frozen by ADR-0015.
#[must_use]
pub fn olk_binding_fingerprint(bound: Option<&Fingerprint>) -> Fingerprint {
    bound
        .cloned()
        .unwrap_or_else(|| Fingerprint::from_vec(UNBOUND_OLK_BINDING_LABEL.to_vec()))
}

fn crockford_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::from((buffer >> bits) & 0x1f);
            output.push(char::from(CROCKFORD.get(index).copied().unwrap_or(b'0')));
            buffer &= (1u16 << bits).wrapping_sub(1);
        }
    }
    if bits != 0 {
        let index = usize::from((buffer << (5 - bits)) & 0x1f);
        output.push(char::from(CROCKFORD.get(index).copied().unwrap_or(b'0')));
    }
    output
}

fn crockford_decode(input: &str) -> Result<Vec<u8>, ProtoError> {
    if input.is_empty() || input.len() > MAX_OLK_BUNDLE_BYTES.saturating_mul(8).div_ceil(5) {
        return Err(ProtoError::Codec(CodecError::TooLong));
    }
    let mut output = Vec::with_capacity(input.len().saturating_mul(5) / 8);
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in input.bytes() {
        let value = CROCKFORD
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or(ProtoError::Codec(CodecError::Malformed))? as u16;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
            buffer &= (1u16 << bits).wrapping_sub(1);
            if output.len() > MAX_OLK_BUNDLE_BYTES {
                return Err(ProtoError::Codec(CodecError::TooLong));
            }
        }
    }
    if bits != 0 && buffer != 0 {
        return Err(ProtoError::Codec(CodecError::Malformed));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;

    use super::*;

    fn bundle() -> OfflineLicenseBundle {
        OfflineLicenseBundle::new(vec![1, 2, 3], vec![vec![4, 5, 6]])
    }

    #[test]
    fn binary_and_compact_armor_round_trip() {
        let bundle = bundle();
        assert_eq!(
            OfflineLicenseBundle::decode(&bundle.encode()).unwrap(),
            bundle
        );
        assert_eq!(
            OfflineLicenseBundle::from_armored(&bundle.to_armored()).unwrap(),
            bundle
        );
    }

    #[test]
    fn pem_style_whitespace_is_supported_but_arbitrary_punctuation_is_not() {
        let compact = bundle().to_armored();
        let split = compact.len() / 2;
        let pem = format!(
            "{ARMOR_BEGIN}\n{}\n{}\n{ARMOR_END}\n",
            &compact[..split],
            &compact[split..]
        );
        assert_eq!(OfflineLicenseBundle::from_armored(&pem).unwrap(), bundle());
        assert!(OfflineLicenseBundle::from_armored(&format!("{compact}-")).is_err());
    }

    #[test]
    fn non_zero_trailing_bits_and_oversized_inputs_are_rejected() {
        assert!(crockford_decode("1").is_err());
        assert!(OfflineLicenseBundle::decode(&vec![0; MAX_OLK_BUNDLE_BYTES + 1]).is_err());
    }

    #[test]
    fn debug_does_not_render_the_bearer_envelope() {
        let rendered = format!("{:?}", bundle());
        assert!(rendered.contains("license_envelope_len"));
        assert!(!rendered.contains("1, 2, 3"));
    }
}
