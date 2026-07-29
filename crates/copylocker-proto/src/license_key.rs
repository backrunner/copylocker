//! The user-visible license key (`protocol-spec.md §2`).
//!
//! ```text
//! CL1-XXXXX-XXXXX-XXXXX-XXXXX
//! └┬┘ └──────────┬────────────┘
//!  │             └── 20 Crockford Base32 characters = 100 bits
//!  └── "CL" + proto_ver
//!
//! bits[0..8]    product_short  — first 8 bits of SHA-256(product_id), for local routing
//! bits[8..88]   key_random     — 80 bits from a CSPRNG
//! bits[88..100] crc12          — over the preceding 88 bits, for typo detection
//! ```
//!
//! The key carries **no signature** (ADR-0005). It is an identifier a human types, not a
//! credential: 80 bits of entropy behind server rate limiting is not brute-forceable, and the
//! actual authority lives in the signed `MachineCredential` the server returns.
//!
//! The server stores `HMAC(pepper, key_bytes)`, never the key itself, so a database leak does
//! not hand over a list of working keys.

use alloc::string::String;
use alloc::vec::Vec;

use copylocker_types::PROTO_VER;

use crate::ProtoError;

/// Crockford Base32 alphabet: no `I`, `L`, `O`, or `U`.
///
/// `I`/`L` are excluded because they look like `1`, `O` because it looks like `0`, and `U` to
/// avoid accidental obscenities in generated keys.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of payload characters (excluding the prefix and separators).
const KEY_CHARS: usize = 20;
/// Total payload bits.
const KEY_BITS: usize = 100;
/// Bits covered by the checksum.
const CHECKED_BITS: usize = 88;
/// Checksum width.
const CRC_BITS: usize = 12;

/// CRC-12/CDMA2000 polynomial, `x^12 + x^11 + x^3 + x^2 + x + 1`.
const CRC12_POLY: u16 = 0xF13;

/// A parsed license key.
#[derive(Clone, PartialEq, Eq)]
pub struct LicenseKey {
    /// First 8 bits of `SHA-256(product_id)`, for cheap local routing and a fast typo reject.
    product_short: u8,
    /// The 80 random bits, most-significant first.
    random: [u8; 10],
}

impl LicenseKey {
    /// Build from a product tag and 80 bits of randomness.
    #[must_use]
    pub fn new(product_short: u8, random: [u8; 10]) -> Self {
        Self {
            product_short,
            random,
        }
    }

    /// Derive the product tag from a product identifier's digest.
    ///
    /// Takes the digest rather than computing it, so this crate stays free of a hash
    /// dependency and the caller's suite decides the algorithm.
    #[must_use]
    pub fn product_short_from_digest(product_id_digest: &[u8]) -> u8 {
        product_id_digest.first().copied().unwrap_or(0)
    }

    /// The product tag.
    #[must_use]
    pub fn product_short(&self) -> u8 {
        self.product_short
    }

    /// The random component.
    #[must_use]
    pub fn random(&self) -> &[u8; 10] {
        &self.random
    }

    /// The 11 bytes the server HMACs for storage: tag followed by randomness.
    ///
    /// Excludes the checksum, which is derived and carries no information.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(11);
        out.push(self.product_short);
        out.extend_from_slice(&self.random);
        out
    }

    /// The 100-bit payload, most-significant bit first.
    fn payload_bits(&self) -> u128 {
        let mut v = u128::from(self.product_short);
        for b in self.random {
            v = (v << 8) | u128::from(b);
        }
        // 8 + 80 = 88 bits so far; append the checksum.
        let crc = crc12(v);
        (v << CRC_BITS) | u128::from(crc)
    }

    /// Render in grouped, human-friendly form.
    #[must_use]
    pub fn to_string_grouped(&self) -> String {
        let bits = self.payload_bits();
        let mut chars = [0u8; KEY_CHARS];
        for (i, slot) in chars.iter_mut().enumerate() {
            // Most-significant group first.
            let shift = KEY_BITS - 5 * (i + 1);
            let idx = ((bits >> shift) & 0x1f) as usize;
            // `idx` is masked to 0..32, so the index is always in range.
            #[allow(clippy::indexing_slicing)]
            {
                *slot = ALPHABET[idx];
            }
        }

        let mut out = String::with_capacity(3 + 1 + KEY_CHARS + 3);
        out.push_str("CL");
        out.push(char::from(b'0' + PROTO_VER));
        for (i, c) in chars.iter().enumerate() {
            if i % 5 == 0 {
                out.push('-');
            }
            out.push(char::from(*c));
        }
        out
    }

    /// Parse a user-typed key.
    ///
    /// Forgiving about presentation, strict about content: case is ignored, any non-alphanumeric
    /// character is treated as a separator, and the Crockford substitutions `I`/`L` → `1` and
    /// `O` → `0` are applied. The checksum is then verified.
    pub fn parse(input: &str) -> Result<Self, ProtoError> {
        let mut chars: Vec<u8> = Vec::with_capacity(KEY_CHARS + 3);
        for ch in input.chars() {
            if !ch.is_ascii_alphanumeric() {
                continue;
            }
            chars.push(ch.to_ascii_uppercase() as u8);
        }

        // Strip the "CL<ver>" prefix when present, and reject a version we do not speak.
        //
        // The version digit gets the same confusable treatment as the payload: a user reading
        // "CL1" off a screen may well type "CLI", and rejecting that as an unknown protocol
        // version would be a baffling error message.
        let body = match chars.split_first_chunk::<3>() {
            Some(([b'C', b'L', v], rest)) => {
                let ver = confusable(*v).wrapping_sub(b'0');
                if ver != PROTO_VER {
                    return Err(ProtoError::UnsupportedProtoVersion(ver));
                }
                rest
            }
            _ => chars.as_slice(),
        };

        if body.len() != KEY_CHARS {
            return Err(ProtoError::MalformedLicenseKey);
        }

        let mut bits: u128 = 0;
        for c in body {
            bits = (bits << 5) | u128::from(decode_char(*c)?);
        }

        let checked = bits >> CRC_BITS;
        let crc = (bits & ((1 << CRC_BITS) - 1)) as u16;
        if crc12(checked) != crc {
            return Err(ProtoError::MalformedLicenseKey);
        }

        let product_short = ((checked >> 80) & 0xff) as u8;
        let mut random = [0u8; 10];
        for (i, slot) in random.iter_mut().enumerate() {
            let shift = 72 - 8 * i;
            *slot = ((checked >> shift) & 0xff) as u8;
        }
        Ok(Self {
            product_short,
            random,
        })
    }
}

impl core::fmt::Display for LicenseKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_string_grouped())
    }
}

impl core::fmt::Debug for LicenseKey {
    /// Shows only the product tag. A license key is a bearer identifier; logging one in full
    /// would put it in every log aggregator the vendor runs (`10-server-worker.md §6`).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "LicenseKey(product_short={:#04x}, …)",
            self.product_short
        )
    }
}

/// Apply the Crockford confusable substitutions: `I`/`L` → `1`, `O` → `0`.
const fn confusable(c: u8) -> u8 {
    match c {
        b'I' | b'L' => b'1',
        b'O' => b'0',
        other => other,
    }
}

/// Decode one Crockford Base32 character, applying the standard confusable substitutions.
fn decode_char(c: u8) -> Result<u8, ProtoError> {
    ALPHABET
        .iter()
        .position(|a| *a == confusable(c))
        .map(|p| p as u8)
        .ok_or(ProtoError::MalformedLicenseKey)
}

/// CRC-12 over the top `CHECKED_BITS` bits, most-significant first.
fn crc12(value: u128) -> u16 {
    let mut crc: u16 = 0;
    for i in (0..CHECKED_BITS).rev() {
        let bit = ((value >> i) & 1) as u16;
        let top = (crc >> (CRC_BITS - 1)) & 1;
        crc = (crc << 1) & 0x0fff;
        if top ^ bit == 1 {
            crc ^= CRC12_POLY & 0x0fff;
        }
    }
    crc & 0x0fff
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn sample() -> LicenseKey {
        LicenseKey::new(0xAB, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    }

    #[test]
    fn renders_in_the_specified_shape() {
        let s = sample().to_string_grouped();
        assert!(s.starts_with("CL1-"), "got {s}");
        assert_eq!(s.len(), 3 + 4 * 6, "prefix + four hyphen-led groups");
        assert_eq!(s.matches('-').count(), 4);
        for c in s.chars().filter(|c| c.is_ascii_alphanumeric()).skip(3) {
            assert!(ALPHABET.contains(&(c as u8)), "unexpected char {c}");
        }
    }

    #[test]
    fn roundtrips_through_display() {
        let k = sample();
        assert_eq!(LicenseKey::parse(&k.to_string_grouped()).unwrap(), k);
    }

    #[test]
    fn parsing_ignores_case_and_separators() {
        let k = sample();
        let canonical = k.to_string_grouped();
        let mangled = canonical.to_lowercase().replace('-', " ");
        assert_eq!(LicenseKey::parse(&mangled).unwrap(), k);
        let no_sep = canonical.replace('-', "");
        assert_eq!(LicenseKey::parse(&no_sep).unwrap(), k);
    }

    #[test]
    fn crockford_confusables_are_corrected() {
        // Build a key whose rendering contains a '1' and a '0', then type them as 'I' and 'O'.
        let k = LicenseKey::new(0x00, [0; 10]);
        let canonical = k.to_string_grouped();
        let typo = canonical.replace('0', "O").replace('1', "I");
        // The 'CL1' prefix also gets mangled to 'CLI'; parsing must still recover.
        assert_eq!(LicenseKey::parse(&typo).unwrap(), k);
    }

    #[test]
    fn any_single_character_typo_is_caught() {
        // The checksum's whole purpose: tell the user "you mistyped" rather than
        // "invalid license".
        let canonical = sample().to_string_grouped();
        let payload: Vec<char> = canonical
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        let mut caught = 0;
        let mut total = 0;
        for i in 3..payload.len() {
            for repl in ALPHABET.iter().map(|b| char::from(*b)) {
                if repl == payload[i] {
                    continue;
                }
                let mut mutated = payload.clone();
                mutated[i] = repl;
                let s: String = mutated.into_iter().collect();
                total += 1;
                if LicenseKey::parse(&s).is_err() {
                    caught += 1;
                }
            }
        }
        // A 12-bit CRC catches every single-character substitution in a payload this short.
        assert_eq!(
            caught, total,
            "{} of {total} single-char typos caught",
            caught
        );
    }

    #[test]
    fn transposition_of_adjacent_characters_is_caught() {
        let canonical = sample().to_string_grouped();
        let payload: Vec<char> = canonical
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        for i in 3..payload.len() - 1 {
            if payload[i] == payload[i + 1] {
                continue;
            }
            let mut mutated = payload.clone();
            mutated.swap(i, i + 1);
            let s: String = mutated.into_iter().collect();
            assert!(
                LicenseKey::parse(&s).is_err(),
                "transposition at {i} slipped through"
            );
        }
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert_eq!(
            LicenseKey::parse("CL1-ABC"),
            Err(ProtoError::MalformedLicenseKey)
        );
        assert_eq!(LicenseKey::parse(""), Err(ProtoError::MalformedLicenseKey));
        let long = format!("{}Z", sample().to_string_grouped());
        assert_eq!(
            LicenseKey::parse(&long),
            Err(ProtoError::MalformedLicenseKey)
        );
    }

    #[test]
    fn an_unknown_protocol_version_is_named_in_the_error() {
        let s = sample().to_string_grouped().replacen("CL1", "CL9", 1);
        assert_eq!(
            LicenseKey::parse(&s),
            Err(ProtoError::UnsupportedProtoVersion(9))
        );
    }

    #[test]
    fn excluded_alphabet_letters_are_rejected() {
        // 'U' is not a confusable substitution; it is simply not in the alphabet.
        let mut s = sample().to_string_grouped();
        let idx = s.len() - 1;
        s.replace_range(idx.., "U");
        assert_eq!(LicenseKey::parse(&s), Err(ProtoError::MalformedLicenseKey));
    }

    #[test]
    fn storage_bytes_exclude_the_derived_checksum() {
        let k = sample();
        assert_eq!(k.to_bytes().len(), 11);
        assert_eq!(k.to_bytes()[0], 0xAB);
        assert_eq!(&k.to_bytes()[1..], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn debug_does_not_reveal_the_key() {
        let rendered = format!("{:?}", sample());
        assert!(rendered.contains("0xab"));
        assert!(!rendered.contains("CL1"));
    }

    #[test]
    fn distinct_random_components_render_distinctly() {
        let a = LicenseKey::new(1, [0; 10]);
        let b = LicenseKey::new(1, [1; 10]);
        assert_ne!(a.to_string_grouped(), b.to_string_grouped());
    }

    #[test]
    fn every_byte_value_survives_a_roundtrip() {
        for tag in [0u8, 1, 127, 128, 255] {
            for fill in [0u8, 0x55, 0xaa, 0xff] {
                let k = LicenseKey::new(tag, [fill; 10]);
                assert_eq!(LicenseKey::parse(&k.to_string_grouped()).unwrap(), k);
            }
        }
    }
}
