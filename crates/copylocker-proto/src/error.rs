//! Protocol errors.

use core::fmt;

use copylocker_suite::{CodecError, CryptoError};

/// A protocol-level failure.
///
/// Every variant here is **fail-closed**: these are cryptographic, structural, or revocation
/// failures, never transient ones. Network and server-side faults are a separate type in
/// `copylocker-core` with no conversion between them, so that a wildcard match cannot
/// accidentally route a signature failure down the fail-open path
/// (`20-client-core.md §1.1`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ProtoError {
    /// The encoding was malformed, non-canonical, or over a limit.
    Codec(CodecError),
    /// A signature or AEAD check failed.
    Crypto(CryptoError),
    /// `proto_ver` is not one this build speaks.
    UnsupportedProtoVersion(u8),
    /// `suite_id` is not one this build implements.
    UnsupportedSuite,
    /// The envelope declared a different artifact kind than the caller expected. Rejecting this
    /// is what stops one artifact body from being reinterpreted as another.
    ArtifactKindMismatch,
    /// The epoch certificate's issuer did not match any pinned root key.
    RootPinMismatch,
    /// A certificate or credential is outside its validity window.
    OutsideValidityWindow,
    /// The signing epoch has been revoked.
    EpochRevoked,
    /// The referenced epoch certificate was not supplied.
    UnknownEpoch,
    /// A revocation epoch or security floor moved backwards, indicating a rollback attempt.
    MonotonicityViolation,
    /// The nonce echoed by the server did not match the one sent.
    NonceMismatch,
    /// The artifact is bound to a different machine.
    MachineMismatch,
    /// A field held a value outside its permitted range.
    FieldOutOfRange(u8),
    /// The user-visible license key failed its checksum or had a bad length.
    MalformedLicenseKey,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(e) => write!(f, "encoding error: {e}"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
            Self::UnsupportedProtoVersion(v) => write!(f, "unsupported protocol version {v}"),
            Self::UnsupportedSuite => f.write_str("unsupported crypto suite"),
            Self::ArtifactKindMismatch => f.write_str("artifact kind mismatch"),
            Self::RootPinMismatch => f.write_str("epoch certificate issuer is not a pinned root"),
            Self::OutsideValidityWindow => f.write_str("outside validity window"),
            Self::EpochRevoked => f.write_str("signing epoch revoked"),
            Self::UnknownEpoch => f.write_str("no certificate for referenced epoch"),
            Self::MonotonicityViolation => f.write_str("monotonic counter moved backwards"),
            Self::NonceMismatch => f.write_str("nonce echo mismatch"),
            Self::MachineMismatch => f.write_str("artifact bound to a different machine"),
            Self::FieldOutOfRange(k) => write!(f, "field {k} out of range"),
            Self::MalformedLicenseKey => f.write_str("malformed license key"),
        }
    }
}

impl From<CodecError> for ProtoError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

impl From<CryptoError> for ProtoError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
impl std::error::Error for ProtoError {}
