use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;

use copylocker_client::{
    ActivateError, CopyLockerClient, DeactivateError, HostErrorCode, OfflineError, StateChange,
    StateSubscription,
};
use copylocker_core::CoreError;
use copylocker_suite::{CryptoSuite, SignatureScheme};
use copylocker_types::{KillReason, LicenseState, StateReason};
use serde::Serialize;
use ts_rs::TS;

type CommandFuture<'a> = Pin<Box<dyn Future<Output = Result<(), CommandError>> + Send + 'a>>;

/// Stable advisory state name for UI presentation only.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../guest-js/bindings/")]
pub enum StateName {
    /// No credential is installed.
    Unlicensed,
    /// Activation is in progress.
    Activating,
    /// The credential is current.
    Active,
    /// An online refresh is due.
    NeedsRevalidation,
    /// A transient outage is inside grace.
    Grace,
    /// Productive key derivation is unavailable pending recovery.
    Locked,
    /// The credential was revoked and wiped.
    Revoked,
    /// Integrity verification failed closed.
    Tampered,
}

impl From<LicenseState> for StateName {
    fn from(value: LicenseState) -> Self {
        match value {
            LicenseState::Unlicensed => Self::Unlicensed,
            LicenseState::Activating => Self::Activating,
            LicenseState::Active => Self::Active,
            LicenseState::NeedsRevalidation => Self::NeedsRevalidation,
            LicenseState::Grace => Self::Grace,
            LicenseState::Locked => Self::Locked,
            LicenseState::Revoked => Self::Revoked,
            LicenseState::Tampered => Self::Tampered,
        }
    }
}

/// Stable advisory transition reason.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../guest-js/bindings/")]
pub enum StateReasonName {
    Activated,
    Validated,
    ReactivationRequired,
    VersionOutOfScope,
    RefreshDue,
    NetworkUnavailable,
    GraceExhausted,
    CredentialExpired,
    ClockRollback,
    RevokedLicense,
    RevokedActivation,
    SeatReclaimed,
    Fraud,
    Refund,
    EpochRevoked,
    IntegrityFailure,
    UserRequested,
    Other,
}

impl From<StateReason> for StateReasonName {
    fn from(value: StateReason) -> Self {
        match value {
            StateReason::Activated => Self::Activated,
            StateReason::Validated => Self::Validated,
            StateReason::ReactivationRequired => Self::ReactivationRequired,
            StateReason::VersionOutOfScope => Self::VersionOutOfScope,
            StateReason::RefreshDue => Self::RefreshDue,
            StateReason::NetworkUnavailable => Self::NetworkUnavailable,
            StateReason::GraceExhausted => Self::GraceExhausted,
            StateReason::CredentialExpired => Self::CredentialExpired,
            StateReason::ClockRollback => Self::ClockRollback,
            StateReason::KillOrder(reason) => match reason {
                KillReason::RevokedLicense => Self::RevokedLicense,
                KillReason::RevokedActivation => Self::RevokedActivation,
                KillReason::SeatReclaimed => Self::SeatReclaimed,
                KillReason::Fraud => Self::Fraud,
                KillReason::Refund => Self::Refund,
                KillReason::EpochRevoked => Self::EpochRevoked,
            },
            StateReason::IntegrityFailure => Self::IntegrityFailure,
            StateReason::UserRequested => Self::UserRequested,
            _ => Self::Other,
        }
    }
}

/// Advisory state payload. Never gate product functionality on this value.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "../guest-js/bindings/")]
pub struct StateDto {
    /// Current display state.
    pub state: StateName,
    /// Cause of the latest transition, if this is not the initial snapshot.
    pub reason: Option<StateReasonName>,
}

impl From<StateChange> for StateDto {
    fn from(value: StateChange) -> Self {
        Self {
            state: value.state.into(),
            reason: value.reason.map(Into::into),
        }
    }
}

/// Stable numeric command failure; details stay inside the native process.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, TS)]
#[ts(export, export_to = "../guest-js/bindings/")]
pub struct CommandError {
    /// Stable category code.
    pub code: u32,
}

impl CommandError {
    const fn new(code: u32) -> Self {
        Self { code }
    }
}

impl From<ActivateError> for CommandError {
    fn from(value: ActivateError) -> Self {
        Self::new(HostErrorCode::from(value).get())
    }
}

impl From<DeactivateError> for CommandError {
    fn from(value: DeactivateError) -> Self {
        Self::new(HostErrorCode::from(value).get())
    }
}

impl From<OfflineError> for CommandError {
    fn from(value: OfflineError) -> Self {
        Self::new(HostErrorCode::from(value).get())
    }
}

impl From<CoreError> for CommandError {
    fn from(value: CoreError) -> Self {
        Self::new(HostErrorCode::from(value).get())
    }
}

pub(crate) trait ClientApi: Send + Sync {
    fn activate(&self, key: String) -> CommandFuture<'_>;
    fn deactivate(&self) -> CommandFuture<'_>;
    fn state(&self) -> StateDto;
    fn unseal(&self, feature: &str, data: &[u8]) -> Result<Vec<u8>, CommandError>;
    fn challenge(&self, input: &[u8]) -> Result<Vec<u8>, CommandError>;
    fn offline_request(&self, key: &str) -> Result<Vec<u8>, CommandError>;
    fn offline_import(&self, data: &[u8]) -> Result<(), CommandError>;
    fn import_olk(&self, data: &str) -> Result<(), CommandError>;
    fn subscribe(&self) -> StateSubscription;
}

impl<S: CryptoSuite> ClientApi for CopyLockerClient<S>
where
    <S::Sig as SignatureScheme>::VerifyingKey: Send + Sync,
{
    fn activate(&self, key: String) -> CommandFuture<'_> {
        Box::pin(async move { self.activate(&key).await.map_err(Into::into) })
    }

    fn deactivate(&self) -> CommandFuture<'_> {
        Box::pin(async move { self.deactivate().await.map_err(Into::into) })
    }

    fn state(&self) -> StateDto {
        StateDto {
            state: self.state().into(),
            reason: None,
        }
    }

    fn unseal(&self, feature: &str, data: &[u8]) -> Result<Vec<u8>, CommandError> {
        self.unseal(feature, data).map_err(Into::into)
    }

    fn challenge(&self, input: &[u8]) -> Result<Vec<u8>, CommandError> {
        self.challenge(input).map_err(Into::into)
    }

    fn offline_request(&self, key: &str) -> Result<Vec<u8>, CommandError> {
        self.build_offline_request(key).map_err(Into::into)
    }

    fn offline_import(&self, data: &[u8]) -> Result<(), CommandError> {
        self.import_offline_response(data).map_err(Into::into)
    }

    fn import_olk(&self, data: &str) -> Result<(), CommandError> {
        self.import_olk(data).map_err(Into::into)
    }

    fn subscribe(&self) -> StateSubscription {
        self.subscribe()
    }
}

pub(crate) struct ManagedClient {
    inner: Arc<dyn ClientApi>,
}

impl ManagedClient {
    pub(crate) fn new(inner: Arc<dyn ClientApi>) -> Self {
        Self { inner }
    }

    pub(crate) fn get(&self) -> &dyn ClientApi {
        self.inner.as_ref()
    }
}

impl core::fmt::Debug for ManagedClient {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ManagedClient(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_states_are_complete_and_never_boolean() {
        let names = [
            LicenseState::Unlicensed,
            LicenseState::Activating,
            LicenseState::Active,
            LicenseState::NeedsRevalidation,
            LicenseState::Grace,
            LicenseState::Locked,
            LicenseState::Revoked,
            LicenseState::Tampered,
        ]
        .map(StateName::from);
        assert_eq!(names.len(), 8);
        assert!(!StateName::decl(&ts_rs::Config::default()).contains("boolean"));
    }

    #[test]
    fn productive_errors_do_not_disclose_feature_presence() {
        assert_eq!(
            CommandError::from(CoreError::NotEntitled),
            CommandError::new(4_100)
        );
    }
}
