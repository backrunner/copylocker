//! Text armor for offline activation requests (`.clar`, ADR-0015 §4 armor family).
//!
//! The `.clar` carrier is the activation-request sibling of the OLK `CLK1` armor: the same
//! Crockford Base32 without padding, ASCII-whitespace-tolerant, with optional PEM-style
//! boundaries. It is a **lossless carrier only**: the armor changes nothing on the wire —
//! `/v1/offline/request` keeps accepting the canonical-CBOR `ActivationRequest` — and
//! integrity comes from the request's own device proof, not from the armor. The uppercase
//! alphabet keeps an armored request inside QR alphanumeric mode, so a single QR code
//! (version 40-M) can carry it for camera-based transfer.

use alloc::string::String;
use alloc::vec::Vec;

use copylocker_suite::CodecError;

use crate::offline_bundle::{crockford_decode, crockford_encode};
use crate::ProtoError;

/// Armor prefix for activation requests (`CL` + request + format version 1).
pub const AR_ARMOR_PREFIX: &str = "CLR1:";
/// Maximum decoded activation-request size (the protocol body cap).
pub const MAX_AR_ARMORED_BYTES: usize = copylocker_types::MAX_BODY_BYTES;

const ARMOR_BEGIN: &str = "-----BEGIN COPYLOCKER ACTIVATION REQUEST-----";
const ARMOR_END: &str = "-----END COPYLOCKER ACTIVATION REQUEST-----";

/// Encode canonical-CBOR activation-request bytes as compact `CLR1` armor.
#[must_use]
pub fn armor_activation_request(bytes: &[u8]) -> String {
    let encoded = crockford_encode(bytes);
    let mut output = String::with_capacity(AR_ARMOR_PREFIX.len() + encoded.len());
    output.push_str(AR_ARMOR_PREFIX);
    output.push_str(&encoded);
    output
}

/// Decode compact or PEM-bounded `CLR1` armor back into the request's CBOR bytes.
///
/// Only ASCII whitespace is ignored; any other punctuation, a missing prefix, a non-Crockford
/// character, non-zero trailing bits, or a payload beyond the protocol body cap is rejected.
pub fn unarmor_activation_request(input: &str) -> Result<Vec<u8>, ProtoError> {
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
        .strip_prefix(AR_ARMOR_PREFIX)
        .ok_or(ProtoError::Codec(CodecError::Malformed))?;
    let decoded = crockford_decode(payload)?;
    if decoded.len() > MAX_AR_ARMORED_BYTES {
        return Err(ProtoError::Codec(CodecError::TooLong));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;

    use super::*;

    #[test]
    fn armor_round_trips_and_tolerates_pem_boundaries() {
        let bytes = vec![0xa7, 0x00, 0x01, 0x42, 1, 2, 3, 4];
        let armor = armor_activation_request(&bytes);
        assert!(armor.starts_with(AR_ARMOR_PREFIX));
        assert_eq!(unarmor_activation_request(&armor).unwrap(), bytes);

        let pem = format!("{ARMOR_BEGIN}\n{armor}\n{ARMOR_END}\n");
        assert_eq!(unarmor_activation_request(&pem).unwrap(), bytes);
    }

    #[test]
    fn malformed_armor_is_rejected() {
        // Wrong prefix, arbitrary punctuation, and non-Crockford characters all fail.
        assert!(unarmor_activation_request("CLK1:00").is_err());
        assert!(unarmor_activation_request("CLR1:0-").is_err());
        assert!(unarmor_activation_request("CLR1:OIO").is_err());
        // Truncated PEM boundary.
        let bytes = vec![1, 2, 3];
        let armor = armor_activation_request(&bytes);
        assert!(unarmor_activation_request(&format!("{ARMOR_BEGIN}\n{armor}")).is_err());
    }

    #[test]
    fn the_alphabet_stays_inside_qr_alphanumeric_mode() {
        // QR alphanumeric mode covers 0-9, A-Z, space, and $%*+-./: — the Crockford alphabet
        // (and the CLR1: prefix) is a subset, so the armor needs no byte-mode encoding.
        let armor = armor_activation_request(&vec![0xab; 1024]);
        assert!(armor
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == ':'));
    }
}
