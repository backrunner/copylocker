//! Stable, detail-free error codes for FFI and JavaScript host boundaries.

use copylocker_core::CoreError;

use crate::{
    ActivateError, ActivationRejection, ClientInitError, DeactivateError, OfflineError,
    ValidationError,
};

/// A stable numeric failure code suitable for crossing an untrusted host boundary.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HostErrorCode(u32);

impl HostErrorCode {
    /// Unknown future error, handled fail-closed.
    pub const UNKNOWN_FATAL: Self = Self(3_999);
    /// Invalid host-boundary input or configuration.
    pub const INVALID_ARGUMENT: Self = Self(4_010);

    /// Return the stable wire value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<ActivateError> for HostErrorCode {
    fn from(value: ActivateError) -> Self {
        match value {
            ActivateError::Rejected(rejection) => Self(match rejection {
                ActivationRejection::InvalidCredential => 1_000,
                ActivationRejection::SeatExhausted => 1_001,
                ActivationRejection::AccountAuthenticationRequired => 1_003,
                ActivationRejection::UnsupportedProtocol => 1_004,
                ActivationRejection::ReleaseNotRegistered => 1_007,
                ActivationRejection::VersionOutOfScope => 1_008,
                ActivationRejection::ReleaseCompromised => 1_009,
                ActivationRejection::Other(code) => u32::try_from(code).unwrap_or(1_099),
            }),
            ActivateError::Transient(_) => Self(2_000),
            ActivateError::Fatal(_) => Self(3_000),
            ActivateError::Local(_) => Self(4_000),
            ActivateError::AlreadyActivated => Self(4_001),
        }
    }
}

impl From<DeactivateError> for HostErrorCode {
    fn from(value: DeactivateError) -> Self {
        match value {
            DeactivateError::NotActivated => Self(4_002),
            DeactivateError::Transient(_) => Self(2_000),
            DeactivateError::Fatal(_) => Self(3_000),
            DeactivateError::Local(_) => Self(4_000),
        }
    }
}

impl From<OfflineError> for HostErrorCode {
    fn from(value: OfflineError) -> Self {
        match value {
            OfflineError::AlreadyActivated => Self(4_001),
            OfflineError::NoPendingRequest => Self(4_003),
            OfflineError::UnboundOlkDisabled => Self(4_004),
            OfflineError::UnsupportedCredential => Self(4_005),
            OfflineError::Fatal(_) => Self(3_000),
            OfflineError::Local(_) => Self(4_000),
        }
    }
}

impl From<CoreError> for HostErrorCode {
    fn from(value: CoreError) -> Self {
        match value {
            CoreError::NoCredential => Self(4_002),
            CoreError::NotEntitled => Self(4_100),
            CoreError::DerivationFailed => Self(3_100),
            CoreError::AssetCorrupt => Self(4_101),
            CoreError::Fatal(_) => Self(3_000),
            _ => Self::UNKNOWN_FATAL,
        }
    }
}

impl From<ClientInitError> for HostErrorCode {
    fn from(value: ClientInitError) -> Self {
        match value {
            ClientInitError::Config(_) => Self::INVALID_ARGUMENT,
            ClientInitError::Fingerprint(_) | ClientInitError::Local(_) => Self(4_000),
            ClientInitError::Transient(_) => Self(2_000),
            ClientInitError::Fatal(_) => Self(3_000),
            ClientInitError::UnboundOlkDisabled => Self(4_004),
        }
    }
}

impl From<ValidationError> for HostErrorCode {
    fn from(value: ValidationError) -> Self {
        match value {
            ValidationError::NotActivated => Self(4_002),
            ValidationError::AlreadyInFlight => Self(4_020),
            ValidationError::ReactivationRequired => Self(1_010),
            ValidationError::VersionOutOfScope => Self(1_008),
            ValidationError::Transient(_) => Self(2_000),
            ValidationError::Fatal(_) => Self(3_000),
            ValidationError::Local(_) => Self(4_000),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn productive_failures_do_not_disclose_feature_presence() {
        assert_eq!(HostErrorCode::from(CoreError::NotEntitled).get(), 4_100);
    }

    #[test]
    fn business_rejections_keep_the_server_codes() {
        assert_eq!(
            HostErrorCode::from(ActivateError::Rejected(
                ActivationRejection::VersionOutOfScope
            ))
            .get(),
            1_008
        );
        assert_eq!(
            HostErrorCode::from(ActivateError::Rejected(ActivationRejection::Other(
                u64::MAX
            )))
            .get(),
            1_099
        );
    }
}
