//! Server fault taxonomy (`10-server-worker.md §4`).
//!
//! The split between [`ClientFault`] and [`ServerFault`] is the single most consequential type
//! decision in the server: it decides whether an outage locks users out.
//!
//! - A **client fault** is the client's problem — bad credential, exhausted seats, unregistered
//!   release. It becomes a 4xx and the client fails **closed**.
//! - A **server fault** is ours — storage unavailable, signing failed. It becomes a 5xx and the
//!   client fails **open**, entering its grace window (`protocol-spec.md §10.3`).
//!
//! There is deliberately no `From` between them and no shared supertype, so a `?` cannot quietly
//! reclassify a database outage as an invalid license.

use alloc::string::String;

/// The client's request cannot be satisfied.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ClientFault {
    /// The credential is not usable.
    ///
    /// Deliberately covers "no such key", "revoked", and "expired" as one code. Distinguishing
    /// them would turn the activation endpoint into a key-validity oracle, letting an attacker
    /// enumerate which guessed keys exist (FR-SRV-026).
    InvalidCredential,
    /// Every seat is taken.
    SeatExhausted,
    /// The credential must be re-issued through activation.
    NeedsReactivation,
    /// Mode E requires a login.
    NeedsLogin,
    /// The protocol version is not supported.
    UnsupportedProto,
    /// Rate limited.
    RateLimited {
        /// Seconds until the client should retry.
        retry_after: u32,
    },
    /// The fingerprint differs beyond the configured tolerance.
    FingerprintMismatch,
    /// The reported release was never registered.
    ReleaseNotRegistered {
        /// The identifier that was reported.
        release_id: String,
    },
    /// The running release is outside the licensed version scope.
    ///
    /// A **restricted mode**, not a piracy signal: this is a paying customer running a newer
    /// build than they bought (`licensing-model.md §4.3`).
    VersionOutOfScope {
        /// Highest release the license does cover, for the "you can use this" message.
        highest_allowed: Option<String>,
    },
    /// The release has been marked compromised.
    ReleaseCompromised {
        /// What the policy says to do: `warn`, `force_upgrade`, or `revoke`.
        action: String,
    },
    /// The device did not prove possession of its key.
    ProofInvalid,
    /// A nonce was reused.
    ReplayedNonce,
    /// The request would downgrade a monotonic counter.
    RollbackAttempt,
    /// The policy forbids running in a virtual machine.
    VirtualMachineNotAllowed,
}

impl ClientFault {
    /// The numeric code sent on the wire (`protocol-spec.md §10.3`).
    ///
    /// Several distinct internal conditions map to `1000`. That collapsing is intentional: the
    /// wire must not reveal more than "this did not work". Detail goes to the audit log.
    #[must_use]
    pub const fn code(&self) -> u16 {
        match self {
            Self::InvalidCredential
            | Self::ProofInvalid
            | Self::ReplayedNonce
            | Self::RollbackAttempt
            | Self::VirtualMachineNotAllowed => 1000,
            Self::SeatExhausted => 1001,
            Self::NeedsReactivation => 1002,
            Self::NeedsLogin => 1003,
            Self::UnsupportedProto => 1004,
            Self::RateLimited { .. } => 1005,
            Self::FingerprintMismatch => 1006,
            Self::ReleaseNotRegistered { .. } => 1007,
            Self::VersionOutOfScope { .. } => 1008,
            Self::ReleaseCompromised { .. } => 1009,
        }
    }

    /// Retry hint, when one applies.
    #[must_use]
    pub const fn retry_after(&self) -> Option<u32> {
        match self {
            Self::RateLimited { retry_after } => Some(*retry_after),
            _ => None,
        }
    }

    /// HTTP status.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::UnsupportedProto => 426,
            Self::RateLimited { .. } => 429,
            Self::SeatExhausted | Self::VersionOutOfScope { .. } => 409,
            _ => 403,
        }
    }
}

impl core::fmt::Display for ClientFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "client fault {}", self.code())
    }
}

/// Something on our side failed.
///
/// Always maps to `5000` on the wire, which the client treats as equivalent to a network
/// failure and handles by entering its grace window rather than locking
/// (`protocol-spec.md §10.3`).
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ServerFault {
    /// A storage backend failed.
    Storage(String),
    /// Signing failed or the issuer was unreachable.
    Issuer(String),
    /// A policy or catalog stored by the operator is unsound.
    ///
    /// Classified as *our* fault, not the client's: a misconfigured catalog must not lock out
    /// paying users while it is being fixed.
    Configuration(String),
    /// Anything else.
    Internal(String),
}

impl ServerFault {
    /// The single numeric code sent on the wire.
    #[must_use]
    pub const fn code(&self) -> u16 {
        5000
    }

    /// HTTP status.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        500
    }

    /// Internal detail, for logs only. Never returned to a client.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Storage(s) | Self::Issuer(s) | Self::Configuration(s) | Self::Internal(s) => s,
        }
    }
}

impl core::fmt::Display for ServerFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Renders only the class, never the detail: this Display may reach a response body.
        let class = match self {
            Self::Storage(_) => "storage",
            Self::Issuer(_) => "issuer",
            Self::Configuration(_) => "configuration",
            Self::Internal(_) => "internal",
        };
        write!(f, "server fault ({class})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn credential_failures_are_indistinguishable_on_the_wire() {
        // The anti-enumeration property: an attacker probing keys learns only "no".
        let codes = [
            ClientFault::InvalidCredential.code(),
            ClientFault::ProofInvalid.code(),
            ClientFault::ReplayedNonce.code(),
            ClientFault::RollbackAttempt.code(),
            ClientFault::VirtualMachineNotAllowed.code(),
        ];
        assert!(codes.iter().all(|c| *c == 1000));
    }

    #[test]
    fn wire_codes_match_the_specification_table() {
        assert_eq!(ClientFault::SeatExhausted.code(), 1001);
        assert_eq!(ClientFault::NeedsReactivation.code(), 1002);
        assert_eq!(ClientFault::NeedsLogin.code(), 1003);
        assert_eq!(ClientFault::UnsupportedProto.code(), 1004);
        assert_eq!(ClientFault::RateLimited { retry_after: 5 }.code(), 1005);
        assert_eq!(ClientFault::FingerprintMismatch.code(), 1006);
        assert_eq!(
            ClientFault::ReleaseNotRegistered {
                release_id: "r".to_string()
            }
            .code(),
            1007
        );
        assert_eq!(
            ClientFault::VersionOutOfScope {
                highest_allowed: None
            }
            .code(),
            1008
        );
        assert_eq!(
            ClientFault::ReleaseCompromised {
                action: "warn".to_string()
            }
            .code(),
            1009
        );
    }

    #[test]
    fn every_server_fault_maps_to_the_fail_open_code() {
        for f in [
            ServerFault::Storage("db down".to_string()),
            ServerFault::Issuer("hsm timeout".to_string()),
            ServerFault::Configuration("bad catalog".to_string()),
            ServerFault::Internal("boom".to_string()),
        ] {
            assert_eq!(f.code(), 5000);
            assert_eq!(f.http_status(), 500);
        }
    }

    #[test]
    fn server_fault_display_hides_internal_detail() {
        let f = ServerFault::Storage("connection to shard-7 refused".to_string());
        let rendered = alloc::format!("{f}");
        assert!(!rendered.contains("shard-7"));
        assert_eq!(f.detail(), "connection to shard-7 refused");
    }

    #[test]
    fn rate_limiting_carries_a_retry_hint_and_others_do_not() {
        assert_eq!(
            ClientFault::RateLimited { retry_after: 30 }.retry_after(),
            Some(30)
        );
        assert_eq!(ClientFault::SeatExhausted.retry_after(), None);
    }

    #[test]
    fn http_statuses_are_sensible() {
        assert_eq!(ClientFault::UnsupportedProto.http_status(), 426);
        assert_eq!(
            ClientFault::RateLimited { retry_after: 1 }.http_status(),
            429
        );
        assert_eq!(ClientFault::SeatExhausted.http_status(), 409);
        assert_eq!(ClientFault::InvalidCredential.http_status(), 403);
    }
}
