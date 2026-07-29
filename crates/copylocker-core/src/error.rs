//! The two error families (`20-client-core.md §1.1`).
//!
//! This split is the most important type decision on the client. Get it wrong and either every
//! network blip locks paying users out, or a forged credential is accepted because the failure
//! was mistaken for a timeout.
//!
//! - [`TransientError`] — the network or the server is unavailable. **Fail open**: enter the
//!   grace window and keep working.
//! - [`FatalError`] — a signature, a chain, or a revocation check failed. **Fail closed**:
//!   stop immediately.
//!
//! There is deliberately **no** `From` in either direction, no shared supertype, and no
//! `Box<dyn Error>` that could unify them. A `?` cannot convert one into the other, so the
//! compiler prevents the mistake rather than a code review having to catch it.

extern crate alloc;

use copylocker_proto::ProtoError;
use copylocker_types::KillReason;

/// A recoverable failure. Fail open.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum TransientError {
    /// No network.
    Offline,
    /// The request timed out.
    Timeout,
    /// The server returned 5xx.
    ///
    /// Server faults are transient by definition (`protocol-spec.md §10.3`): an outage must not
    /// become a mass lockout.
    ServerError(u16),
    /// Rate limited.
    RateLimited {
        /// Seconds to wait.
        retry_after: u32,
    },
    /// TLS or transport failure below the protocol layer.
    TransportFailure,
}

impl core::fmt::Display for TransientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Offline => f.write_str("offline"),
            Self::Timeout => f.write_str("request timed out"),
            Self::ServerError(c) => write!(f, "server error {c}"),
            Self::RateLimited { retry_after } => {
                write!(f, "rate limited, retry in {retry_after}s")
            }
            Self::TransportFailure => f.write_str("transport failure"),
        }
    }
}

/// An unrecoverable failure. Fail closed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum FatalError {
    /// A signature did not verify.
    SignatureInvalid,
    /// The certificate chain did not verify against a pinned root.
    ChainInvalid,
    /// The signing epoch has been revoked.
    EpochRevoked,
    /// The server echoed a nonce we did not send.
    NonceMismatch,
    /// The artifact is bound to a different device.
    MachineMismatch,
    /// A monotonic counter moved backwards.
    RevocationRollback,
    /// The stored credential could not be parsed or decrypted.
    CredentialCorrupt,
    /// A signed kill order was received.
    Revoked(KillReason),
    /// The credential asserts a lower security floor than one already seen.
    ///
    /// The anti-downgrade guard: without it, an attacker could replay an old credential from
    /// before a security fix (`versioning-and-variants.md`).
    SecurityFloorRegression,
    /// A runtime integrity check failed.
    IntegrityFailure,
}

impl core::fmt::Display for FatalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SignatureInvalid => f.write_str("signature invalid"),
            Self::ChainInvalid => f.write_str("certificate chain invalid"),
            Self::EpochRevoked => f.write_str("signing epoch revoked"),
            Self::NonceMismatch => f.write_str("nonce echo mismatch"),
            Self::MachineMismatch => f.write_str("credential belongs to another device"),
            Self::RevocationRollback => f.write_str("revocation state rolled back"),
            Self::CredentialCorrupt => f.write_str("stored credential corrupt"),
            Self::Revoked(_) => f.write_str("credential revoked"),
            Self::SecurityFloorRegression => f.write_str("security floor regression"),
            Self::IntegrityFailure => f.write_str("integrity check failed"),
        }
    }
}

impl From<ProtoError> for FatalError {
    /// Every protocol error is fatal.
    ///
    /// This is the one conversion that exists, and it only goes *into* the fail-closed family.
    /// A malformed or unverifiable artifact is never a reason to keep running.
    fn from(e: ProtoError) -> Self {
        match e {
            ProtoError::RootPinMismatch
            | ProtoError::UnknownEpoch
            | ProtoError::OutsideValidityWindow => Self::ChainInvalid,
            ProtoError::EpochRevoked => Self::EpochRevoked,
            ProtoError::NonceMismatch => Self::NonceMismatch,
            ProtoError::MachineMismatch => Self::MachineMismatch,
            ProtoError::MonotonicityViolation => Self::RevocationRollback,
            ProtoError::Crypto(_) => Self::SignatureInvalid,
            _ => Self::CredentialCorrupt,
        }
    }
}

/// Why a feature key could not be derived.
///
/// Note that there is no `bool` anywhere in this API. Per ADR-0004, the productive check is
/// *obtaining a key*; a caller that fails gets an error and no key, rather than a `false` that
/// one patched branch could invert.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CoreError {
    /// No credential is stored.
    NoCredential,
    /// The licence does not include this feature, or the state does not permit key derivation.
    ///
    /// Deliberately one variant covering both: distinguishing them would tell an attacker
    /// whether a feature exists in the licence, which is the first step in deciding what to
    /// patch.
    NotEntitled,
    /// Key derivation itself failed.
    DerivationFailed,
    /// A sealed asset was malformed or failed AEAD authentication.
    AssetCorrupt,
    /// A fatal condition applies.
    Fatal(FatalError),
}

impl core::fmt::Display for CoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoCredential => f.write_str("no credential"),
            Self::NotEntitled => f.write_str("not entitled"),
            Self::DerivationFailed => f.write_str("key derivation failed"),
            Self::AssetCorrupt => f.write_str("sealed asset is corrupt"),
            Self::Fatal(e) => write!(f, "{e}"),
        }
    }
}

impl From<FatalError> for CoreError {
    fn from(e: FatalError) -> Self {
        Self::Fatal(e)
    }
}

impl core::error::Error for TransientError {}
impl core::error::Error for FatalError {}
impl core::error::Error for CoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_errors_all_land_in_the_fail_closed_family() {
        // A compile-time guarantee expressed as a test: there is no path from ProtoError into
        // TransientError, so a protocol failure can never take the fail-open branch.
        for (e, want) in [
            (ProtoError::RootPinMismatch, FatalError::ChainInvalid),
            (ProtoError::EpochRevoked, FatalError::EpochRevoked),
            (ProtoError::NonceMismatch, FatalError::NonceMismatch),
            (ProtoError::MachineMismatch, FatalError::MachineMismatch),
            (
                ProtoError::MonotonicityViolation,
                FatalError::RevocationRollback,
            ),
            (ProtoError::UnsupportedSuite, FatalError::CredentialCorrupt),
        ] {
            assert_eq!(FatalError::from(e), want, "{e:?}");
        }
    }

    #[test]
    fn a_crypto_failure_maps_to_signature_invalid() {
        assert_eq!(
            FatalError::from(ProtoError::Crypto(
                copylocker_suite::CryptoError::HybridStripDetected
            )),
            FatalError::SignatureInvalid
        );
    }

    #[test]
    fn server_errors_are_classified_transient() {
        // The most consequential single classification in the client: a 5xx must not lock users
        // out (`protocol-spec.md §10.3`).
        let e = TransientError::ServerError(503);
        assert!(matches!(e, TransientError::ServerError(_)));
        assert_eq!(alloc::format!("{e}"), "server error 503");
    }

    #[test]
    fn not_entitled_does_not_reveal_which_condition_failed() {
        // One variant for "feature absent" and "state forbids", so an attacker learns nothing
        // about the licence from probing.
        assert_eq!(alloc::format!("{}", CoreError::NotEntitled), "not entitled");
    }

    #[test]
    fn a_kill_order_carries_its_reason() {
        let e = FatalError::Revoked(KillReason::Refund);
        assert!(matches!(e, FatalError::Revoked(KillReason::Refund)));
    }
}
