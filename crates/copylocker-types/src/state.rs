//! Client-visible state, artifact taxonomy, and enforcement mode.

use core::fmt;

/// Client license state (`system-architecture.md §6`).
///
/// # ⚠️ Advisory only
///
/// This value exists for user interface copy. It must **not** gate access to functionality:
/// per ADR-0004 the productive check is deriving a Feature Key, which fails closed by
/// returning `Err` rather than by returning `false`. A `bool` gate is one patched instruction.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum LicenseState {
    /// No credential present.
    #[default]
    Unlicensed,
    /// An activation request is in flight.
    Activating,
    /// Valid credential, inside `refresh_after`.
    Active,
    /// Past `refresh_after`; an online validation is due but has not failed yet.
    NeedsRevalidation,
    /// Revalidation failed for transient (network) reasons; running on borrowed time.
    Grace,
    /// Grace exhausted or hard `not_after` reached. Recoverable by going online.
    Locked,
    /// A `KillOrder` was received or a revocation matched. Credentials have been wiped.
    Revoked,
    /// Integrity or cryptographic verification failed. Fail-closed, not recoverable offline.
    Tampered,
}

impl LicenseState {
    /// Whether the state is one in which a Feature Key may be derived at all.
    ///
    /// `Grace` is included deliberately: fail-open on transient network failure is the whole
    /// point of the grace window (`system-architecture.md §6`).
    #[must_use]
    pub const fn permits_key_derivation(self) -> bool {
        matches!(self, Self::Active | Self::NeedsRevalidation | Self::Grace)
    }

    /// Whether reaching this state requires wiping stored credential material.
    #[must_use]
    pub const fn requires_wipe(self) -> bool {
        matches!(self, Self::Revoked | Self::Tampered)
    }

    /// Stable lowercase name for logs and telemetry dimensions.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unlicensed => "unlicensed",
            Self::Activating => "activating",
            Self::Active => "active",
            Self::NeedsRevalidation => "needs_revalidation",
            Self::Grace => "grace",
            Self::Locked => "locked",
            Self::Revoked => "revoked",
            Self::Tampered => "tampered",
        }
    }
}

impl fmt::Display for LicenseState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the state last changed. Surfaced to the host application for UI copy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum StateReason {
    /// Activation completed and a credential was stored.
    Activated,
    /// An online validation succeeded.
    Validated,
    /// A valid server ticket requires the credential to be issued again.
    ReactivationRequired,
    /// A valid server ticket says this release is outside the licensed version range.
    VersionOutOfScope,
    /// `refresh_after` elapsed.
    RefreshDue,
    /// A transient failure pushed the client into the grace window.
    NetworkUnavailable,
    /// The grace window ended.
    GraceExhausted,
    /// The credential's hard `not_after` was reached.
    CredentialExpired,
    /// The wall clock moved backwards past the tolerated skew.
    ClockRollback,
    /// A signed `KillOrder` was received and verified.
    KillOrder(KillReason),
    /// A signature, chain, or integrity check failed.
    IntegrityFailure,
    /// The user asked to deactivate.
    UserRequested,
}

/// Reason codes carried by a `KillOrder` (`protocol-spec.md §6`, field 5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KillReason {
    /// The whole license was revoked.
    RevokedLicense = 1,
    /// This activation specifically was revoked.
    RevokedActivation = 2,
    /// The seat was reclaimed (zombie recovery or admin action).
    SeatReclaimed = 3,
    /// Fraud signal.
    Fraud = 4,
    /// The purchase was refunded.
    Refund = 5,
    /// The signing epoch itself was revoked.
    EpochRevoked = 6,
}

impl KillReason {
    /// Decode from the wire representation.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::RevokedLicense),
            2 => Some(Self::RevokedActivation),
            3 => Some(Self::SeatReclaimed),
            4 => Some(Self::Fraud),
            5 => Some(Self::Refund),
            6 => Some(Self::EpochRevoked),
            _ => None,
        }
    }
}

/// Signed artifact taxonomy (`protocol-spec.md §1`).
///
/// Every artifact kind gets its own domain-separation context. **Adding a new signed artifact
/// requires adding a variant here**; the testkit asserts that a signature made for one kind
/// never verifies under another (`crypto-architecture.md §2`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ArtifactKind {
    /// Root-signed epoch certificate.
    EpochCert = 1,
    /// The durable per-device credential.
    MachineCred = 2,
    /// Per-validation ticket.
    ValidationTicket = 3,
    /// Immediate revocation instruction for one device.
    KillOrder = 4,
    /// Batched revocation state.
    RevocationBatch = 5,
    /// Compact offline license key.
    OfflineLicenseKey = 6,
    /// Build-time integrity manifest.
    IntegrityManifest = 7,
    /// Client-self-signed activation request (not a trust anchor).
    ActivationRequest = 8,
    /// Offline activation response.
    ActivationResponse = 9,
    /// Client-self-signed validation request (not a trust anchor).
    ValidateRequest = 10,
    /// Client-self-signed heartbeat request (not a trust anchor).
    HeartbeatRequest = 11,
    /// Client-self-signed deactivation request (not a trust anchor).
    DeactivateRequest = 12,
}

impl ArtifactKind {
    /// The name embedded in the domain-separation context.
    ///
    /// These strings are **protocol-visible and frozen**: changing one invalidates every
    /// signature ever made over that artifact kind.
    #[must_use]
    pub const fn ctx_name(self) -> &'static str {
        match self {
            Self::EpochCert => "epoch-cert",
            Self::MachineCred => "machine-cred",
            Self::ValidationTicket => "validation-ticket",
            Self::KillOrder => "kill-order",
            Self::RevocationBatch => "revocation-batch",
            Self::OfflineLicenseKey => "olk",
            Self::IntegrityManifest => "manifest",
            Self::ActivationRequest => "ar",
            Self::ActivationResponse => "aresp",
            Self::ValidateRequest => "validate-request",
            Self::HeartbeatRequest => "heartbeat-request",
            Self::DeactivateRequest => "deactivate-request",
        }
    }

    /// Decode from the wire representation.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::EpochCert),
            2 => Some(Self::MachineCred),
            3 => Some(Self::ValidationTicket),
            4 => Some(Self::KillOrder),
            5 => Some(Self::RevocationBatch),
            6 => Some(Self::OfflineLicenseKey),
            7 => Some(Self::IntegrityManifest),
            8 => Some(Self::ActivationRequest),
            9 => Some(Self::ActivationResponse),
            10 => Some(Self::ValidateRequest),
            11 => Some(Self::HeartbeatRequest),
            12 => Some(Self::DeactivateRequest),
            _ => None,
        }
    }

    /// Every defined kind, for exhaustive tests.
    pub const ALL: [Self; 12] = [
        Self::EpochCert,
        Self::MachineCred,
        Self::ValidationTicket,
        Self::KillOrder,
        Self::RevocationBatch,
        Self::OfflineLicenseKey,
        Self::IntegrityManifest,
        Self::ActivationRequest,
        Self::ActivationResponse,
        Self::ValidateRequest,
        Self::HeartbeatRequest,
        Self::DeactivateRequest,
    ];
}

/// Enforcement mode (`protocol-spec.md §4`, field 14; axis five of the policy model).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Mode {
    /// Mode O: works offline within `refresh_after` + grace.
    #[default]
    OfflineHybrid = 0,
    /// Mode E: requires a live session; locks when refresh + grace elapse.
    EnforcedOnline = 1,
}

impl Mode {
    /// Decode from the wire representation.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::OfflineHybrid),
            1 => Some(Self::EnforcedOnline),
            _ => None,
        }
    }
}

/// Server verdict carried by a `ValidationTicket` (`protocol-spec.md §5`, field 9).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Everything is in order.
    Ok = 0,
    /// The credential must be re-issued via `/v1/activate`.
    NeedsReactivation = 1,
    /// The running release falls outside the licensed version scope. This is a **restricted
    /// mode**, not a piracy signal (`licensing-model.md §4.3`).
    VersionOutOfScope = 2,
}

impl Verdict {
    /// Decode from the wire representation.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ok),
            1 => Some(Self::NeedsReactivation),
            2 => Some(Self::VersionOutOfScope),
            _ => None,
        }
    }
}

/// Claimed classical-equivalent security level of a signature scheme.
///
/// Used by `security_floor` monotonicity checks (`versioning-and-variants.md`): a client that
/// has seen level N refuses a credential asserting less.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SecurityLevel {
    /// NIST category 1 (~AES-128).
    Category1 = 1,
    /// NIST category 3 (~AES-192).
    Category3 = 3,
    /// NIST category 5 (~AES-256).
    Category5 = 5,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_kind_ctx_names_are_unique() {
        for (i, a) in ArtifactKind::ALL.iter().enumerate() {
            for b in ArtifactKind::ALL.iter().skip(i + 1) {
                assert_ne!(
                    a.ctx_name(),
                    b.ctx_name(),
                    "domain separation collapses if two kinds share a context name"
                );
            }
        }
    }

    #[test]
    fn artifact_kind_roundtrips_through_wire_value() {
        for k in ArtifactKind::ALL {
            assert_eq!(ArtifactKind::from_u8(k as u8), Some(k));
        }
        assert_eq!(ArtifactKind::from_u8(0), None);
        assert_eq!(ArtifactKind::from_u8(13), None);
    }

    #[test]
    fn terminal_states_do_not_permit_key_derivation() {
        for s in [
            LicenseState::Unlicensed,
            LicenseState::Activating,
            LicenseState::Locked,
            LicenseState::Revoked,
            LicenseState::Tampered,
        ] {
            assert!(!s.permits_key_derivation(), "{s} must not yield keys");
        }
        for s in [
            LicenseState::Active,
            LicenseState::NeedsRevalidation,
            LicenseState::Grace,
        ] {
            assert!(s.permits_key_derivation(), "{s} must yield keys");
        }
    }
}
