use core::fmt;

use copylocker_core::{FatalError, TransientError};
use copylocker_fingerprint::FingerprintError;
use copylocker_store::StoreError;

use crate::ConfigError;

/// Stable rejection returned by `/v1/activate`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ActivationRejection {
    /// Key or request was not accepted.
    InvalidCredential,
    /// Every licensed seat is occupied.
    SeatExhausted,
    /// Account authentication is required or expired.
    AccountAuthenticationRequired,
    /// Client protocol version is unsupported.
    UnsupportedProtocol,
    /// Release has not been registered.
    ReleaseNotRegistered,
    /// Release is outside the licensed version scope.
    VersionOutOfScope,
    /// Release was marked compromised.
    ReleaseCompromised,
    /// Future server rejection unknown to this SDK.
    Other(u64),
}

impl ActivationRejection {
    pub(crate) const fn from_code(code: u64) -> Self {
        match code {
            1_000 => Self::InvalidCredential,
            1_001 => Self::SeatExhausted,
            1_003 => Self::AccountAuthenticationRequired,
            1_004 => Self::UnsupportedProtocol,
            1_007 => Self::ReleaseNotRegistered,
            1_008 => Self::VersionOutOfScope,
            1_009 => Self::ReleaseCompromised,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for ActivationRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCredential => "activation credential was rejected",
            Self::SeatExhausted => "all licensed seats are occupied",
            Self::AccountAuthenticationRequired => "account authentication is required",
            Self::UnsupportedProtocol => "client protocol is unsupported",
            Self::ReleaseNotRegistered => "application release is not registered",
            Self::VersionOutOfScope => "application release is outside the licensed version scope",
            Self::ReleaseCompromised => "application release has been withdrawn",
            Self::Other(_) => "activation was rejected",
        })
    }
}

/// Failure from an activation attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum ActivateError {
    /// The server made a valid business rejection.
    Rejected(ActivationRejection),
    /// Network or server outage. Existing grace behavior, if any, remains available.
    Transient(TransientError),
    /// Signed protocol or cryptographic verification failed closed.
    Fatal(FatalError),
    /// Local persistence or entropy failed.
    Local(LocalError),
    /// A credential already exists; deactivate it before replacing the license.
    AlreadyActivated,
}

impl fmt::Display for ActivateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(error) => write!(formatter, "{error}"),
            Self::Transient(error) => write!(formatter, "activation network failure: {error}"),
            Self::Fatal(error) => write!(formatter, "activation verification failed: {error}"),
            Self::Local(error) => write!(formatter, "activation failed locally: {error}"),
            Self::AlreadyActivated => formatter.write_str("a credential is already active"),
        }
    }
}

impl std::error::Error for ActivateError {}

/// Failure from an online validation attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum ValidationError {
    /// No stored credential exists.
    NotActivated,
    /// Another trigger already owns the one allowed in-flight validation.
    AlreadyInFlight,
    /// The signed server verdict requires a fresh activation.
    ReactivationRequired,
    /// The signed server verdict restricts this application release.
    VersionOutOfScope,
    /// Network or server outage; the state machine applies grace semantics.
    Transient(TransientError),
    /// Signed protocol or cryptographic verification failed closed.
    Fatal(FatalError),
    /// Local persistence or entropy failed.
    Local(LocalError),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotActivated => formatter.write_str("no credential is available to validate"),
            Self::AlreadyInFlight => formatter.write_str("validation is already in flight"),
            Self::ReactivationRequired => {
                formatter.write_str("the credential must be activated again")
            }
            Self::VersionOutOfScope => {
                formatter.write_str("the application release is outside the licensed scope")
            }
            Self::Transient(error) => write!(formatter, "validation network failure: {error}"),
            Self::Fatal(error) => write!(formatter, "validation failed closed: {error}"),
            Self::Local(error) => write!(formatter, "validation failed locally: {error}"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Failure from server-backed deactivation.
#[derive(Debug)]
#[non_exhaustive]
pub enum DeactivateError {
    /// No credential exists.
    NotActivated,
    /// Network or server outage; local state is retained so the seat is not orphaned silently.
    Transient(TransientError),
    /// Protocol response was malformed or unauthentic.
    Fatal(FatalError),
    /// Local persistence or entropy failed.
    Local(LocalError),
}

impl fmt::Display for DeactivateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotActivated => formatter.write_str("no credential is available to deactivate"),
            Self::Transient(error) => write!(formatter, "deactivation network failure: {error}"),
            Self::Fatal(error) => write!(formatter, "deactivation response rejected: {error}"),
            Self::Local(error) => write!(formatter, "deactivation failed locally: {error}"),
        }
    }
}

impl std::error::Error for DeactivateError {}

/// Failure while creating or importing an offline activation artifact.
#[derive(Debug)]
#[non_exhaustive]
pub enum OfflineError {
    /// A machine credential is already installed.
    AlreadyActivated,
    /// No locally generated request nonce is waiting for this response.
    NoPendingRequest,
    /// An unbound OLK was supplied without the explicit low-strength opt-in.
    UnboundOlkDisabled,
    /// The offline artifact is valid but unsupported by this client configuration.
    UnsupportedCredential,
    /// Signed protocol or cryptographic verification failed closed.
    Fatal(FatalError),
    /// Local persistence or entropy failed.
    Local(LocalError),
}

impl fmt::Display for OfflineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyActivated => formatter.write_str("a credential is already active"),
            Self::NoPendingRequest => {
                formatter.write_str("no offline activation request is pending")
            }
            Self::UnboundOlkDisabled => {
                formatter.write_str("unbound offline license keys are disabled")
            }
            Self::UnsupportedCredential => {
                formatter.write_str("offline credential is unsupported by this client")
            }
            Self::Fatal(error) => write!(formatter, "offline credential rejected: {error}"),
            Self::Local(error) => write!(formatter, "offline activation failed locally: {error}"),
        }
    }
}

impl std::error::Error for OfflineError {}

/// A local facade failure that is neither a network outage nor a protocol verdict.
#[derive(Debug)]
#[non_exhaustive]
pub enum LocalError {
    /// Secure storage failed.
    Store(StoreError),
    /// The operating-system random source failed.
    EntropyUnavailable,
    /// Persisted client state was malformed.
    SnapshotCorrupt,
    /// A short-lived internal lock was poisoned.
    StateUnavailable,
    /// The default HTTP client could not be constructed.
    TransportInitialization,
    /// No Tokio runtime is available to host validation scheduling.
    RuntimeUnavailable,
}

impl fmt::Display for LocalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "secure storage failed: {error}"),
            Self::EntropyUnavailable => formatter.write_str("secure randomness is unavailable"),
            Self::SnapshotCorrupt => formatter.write_str("persisted client state is corrupt"),
            Self::StateUnavailable => formatter.write_str("client state is unavailable"),
            Self::TransportInitialization => {
                formatter.write_str("HTTP transport initialization failed")
            }
            Self::RuntimeUnavailable => formatter.write_str("Tokio runtime is unavailable"),
        }
    }
}

impl std::error::Error for LocalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StoreError> for LocalError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Failure while constructing and restoring a client.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientInitError {
    /// Invalid build-time configuration.
    Config(ConfigError),
    /// Device fingerprint collection is unsupported.
    Fingerprint(FingerprintError),
    /// Local storage, entropy, or snapshot failure.
    Local(LocalError),
    /// Stored signed material failed closed.
    Fatal(FatalError),
    /// An optional startup refresh failed transiently.
    Transient(TransientError),
    /// A persisted unbound OLK requires the explicit low-strength opt-in.
    UnboundOlkDisabled,
}

impl fmt::Display for ClientInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "{error}"),
            Self::Fingerprint(error) => write!(formatter, "fingerprint collection failed: {error}"),
            Self::Local(error) => write!(formatter, "{error}"),
            Self::Fatal(error) => write!(formatter, "stored credential rejected: {error}"),
            Self::Transient(error) => write!(formatter, "startup network check failed: {error}"),
            Self::UnboundOlkDisabled => {
                formatter.write_str("unbound offline license keys are disabled")
            }
        }
    }
}

impl std::error::Error for ClientInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Fingerprint(error) => Some(error),
            Self::Local(error) => Some(error),
            Self::Fatal(error) => Some(error),
            Self::Transient(error) => Some(error),
            Self::UnboundOlkDisabled => None,
        }
    }
}

impl From<ConfigError> for ClientInitError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<FingerprintError> for ClientInitError {
    fn from(error: FingerprintError) -> Self {
        Self::Fingerprint(error)
    }
}

impl From<LocalError> for ClientInitError {
    fn from(error: LocalError) -> Self {
        Self::Local(error)
    }
}
