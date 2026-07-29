//! Opaque identifiers and digests.
//!
//! All of these are fixed-width byte arrays rather than strings: they cross the wire as CBOR
//! byte strings with a declared `.size`, so a length mismatch is a decode error rather than a
//! silently-truncated comparison.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use zeroize::Zeroize;

/// Declares a fixed-width, byte-array-backed newtype with hex `Debug`/`Display`.
macro_rules! byte_id {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// Width of this identifier in bytes.
            pub const LEN: usize = $len;

            /// Borrow the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Build from a slice, returning `None` on a length mismatch.
            #[must_use]
            pub fn from_slice(b: &[u8]) -> Option<Self> {
                let mut out = [0u8; $len];
                if b.len() != $len {
                    return None;
                }
                out.copy_from_slice(b);
                Some(Self(out))
            }

            /// Lowercase hex rendering.
            #[must_use]
            pub fn to_hex(&self) -> String {
                let mut s = String::with_capacity($len * 2);
                for b in self.0.iter() {
                    push_hex(&mut s, *b);
                }
                s
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

fn push_hex(s: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // Both indices are masked to 0..16, so indexing cannot go out of bounds.
    #[allow(clippy::indexing_slicing)]
    {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
}

byte_id!(
    /// Server-assigned license identifier (`protocol-spec.md §4`, field 3).
    ///
    /// Distinct from the user-visible [`LicenseKey`](crate::ids::LicenseId) *string*: the key is
    /// a routing identifier typed by humans, this is the internal 16-byte handle (ADR-0005).
    LicenseId,
    16
);

byte_id!(
    /// Server-assigned per-activation identifier (`protocol-spec.md §4`, field 4).
    MachineId,
    16
);

byte_id!(
    /// Epoch key identifier; appears in every signed artifact so the client can fetch the
    /// matching `EpochCert` (`crypto-architecture.md §5`).
    EpochId,
    8
);

byte_id!(
    /// A 256-bit hash output. The suite's `HashScheme` decides the algorithm; the width is
    /// fixed at 32 bytes across all currently defined suites.
    Digest,
    32
);

/// Four-byte crypto suite identifier, present in every artifact header and covered by both the
/// signature and the AEAD AAD (`crypto-architecture.md §2`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SuiteId(pub [u8; 4]);

impl SuiteId {
    /// Width in bytes.
    pub const LEN: usize = 4;

    /// Construct from a big-endian `u32`, the form used in documentation
    /// (e.g. `0x0100_0001` for CL-STD-1).
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        Self(v.to_be_bytes())
    }

    /// Big-endian `u32` view.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Build from a slice, returning `None` on a length mismatch.
    #[must_use]
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        let mut out = [0u8; 4];
        if b.len() != 4 {
            return None;
        }
        out.copy_from_slice(b);
        Some(Self(out))
    }
}

impl fmt::Debug for SuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SuiteId(0x{:08x})", self.to_u32())
    }
}

impl fmt::Display for SuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.to_u32())
    }
}

/// Human-readable product slug (`data-model.md §2`, `products.id`).
pub type ProductId = String;

/// Device fingerprint digest produced by the suite's `FingerprintScheme`.
///
/// Variable length because a vendor-supplied `FingerprintProvider` may use a different width
/// (`20-client-core.md §3.4`); CL-STD-1 emits 32 bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Zeroize)]
pub struct Fingerprint(pub Vec<u8>);

impl Fingerprint {
    /// Borrow the raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Wrap owned bytes.
    #[must_use]
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl fmt::Debug for Fingerprint {
    /// Renders only the first 8 hex characters: full fingerprints are treated as personal data
    /// and must not reach logs (`10-server-worker.md §6`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        for b in self.0.iter().take(4) {
            push_hex(&mut s, *b);
        }
        write!(f, "Fingerprint({s}…)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_id_roundtrips_through_u32() {
        let s = SuiteId::from_u32(0x0100_0001);
        assert_eq!(s.to_u32(), 0x0100_0001);
        assert_eq!(s.as_bytes(), &[0x01, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn byte_ids_reject_wrong_length() {
        assert!(LicenseId::from_slice(&[0u8; 15]).is_none());
        assert!(LicenseId::from_slice(&[0u8; 17]).is_none());
        assert!(LicenseId::from_slice(&[0u8; 16]).is_some());
    }

    #[test]
    fn fingerprint_debug_is_truncated() {
        let fp = Fingerprint::from_vec(alloc::vec![0xde, 0xad, 0xbe, 0xef, 0x99, 0x99]);
        let rendered = alloc::format!("{fp:?}");
        assert_eq!(rendered, "Fingerprint(deadbeef…)");
        assert!(!rendered.contains("9999"));
    }
}
