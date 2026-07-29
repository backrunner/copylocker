//! Error types for the crypto slots.

use core::fmt;

/// A cryptographic operation failed.
///
/// The `Invalid` variant is deliberately coarse. `crypto-architecture.md §8` requires that
/// verification failures reveal nothing about *why* they failed: distinguishing "bad signature"
/// from "wrong key" from "expired" hands an attacker an oracle. Detail belongs in local audit
/// logs, not in a returned value that crosses a trust boundary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CryptoError {
    /// Verification, decryption, or decapsulation failed. No further detail, by design.
    Invalid,
    /// An input buffer had the wrong length for the algorithm.
    BadLength,
    /// The requested output length exceeds what the KDF can produce.
    OutputTooLong,
    /// A hybrid signature verified under exactly one component.
    ///
    /// This is a **stripping attack signal**, not an ordinary failure: the caller must record
    /// `HYBRID_STRIP_DETECTED` to the audit log (`crypto-architecture.md §3.1`). It is still an
    /// overall verification failure.
    HybridStripDetected,
    /// The randomness source failed.
    RngFailure,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Invalid => "cryptographic verification failed",
            Self::BadLength => "input length invalid for algorithm",
            Self::OutputTooLong => "requested key material exceeds KDF limit",
            Self::HybridStripDetected => "hybrid signature component stripping detected",
            Self::RngFailure => "randomness source failed",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

/// Encoding or decoding of a wire artifact failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CodecError {
    /// The bytes are not well-formed for the declared type.
    Malformed,
    /// A required field was absent.
    MissingField(u8),
    /// A field held the wrong CBOR major type.
    TypeMismatch(u8),
    /// Nesting exceeded the configured depth limit (`protocol-spec.md §10.1`).
    DepthExceeded,
    /// The encoded value exceeded the configured length limit.
    TooLong,
    /// Input was not canonical CBOR. Non-canonical encodings are rejected because signatures
    /// cover encoded bytes, so two encodings of one value would be two different messages
    /// (`crypto-architecture.md §8`).
    NotCanonical,
    /// Trailing bytes followed a complete value.
    TrailingBytes,
    /// An enumeration discriminant was outside the defined range.
    UnknownDiscriminant,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed encoding"),
            Self::MissingField(k) => write!(f, "missing required field {k}"),
            Self::TypeMismatch(k) => write!(f, "wrong type for field {k}"),
            Self::DepthExceeded => f.write_str("nesting depth limit exceeded"),
            Self::TooLong => f.write_str("length limit exceeded"),
            Self::NotCanonical => f.write_str("encoding is not canonical CBOR"),
            Self::TrailingBytes => f.write_str("trailing bytes after value"),
            Self::UnknownDiscriminant => f.write_str("unknown enum discriminant"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CodecError {}

impl From<CodecError> for CryptoError {
    /// A malformed artifact is not distinguishable from a forged one at the boundary.
    fn from(_: CodecError) -> Self {
        Self::Invalid
    }
}

#[cfg(feature = "std")]
extern crate std;
