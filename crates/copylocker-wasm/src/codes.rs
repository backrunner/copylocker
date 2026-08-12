//! Numeric op and error codes for the opaque `step` interface (NFR-SEC-011).
//!
//! Nothing here is a string: the wire contract is numbers inside canonical CBOR, and the
//! wasm-bindgen shell surfaces failures as a bare numeric `JsValue`. The values are part of
//! the `@copylocker/web` protocol and must stay stable.

use copylocker_core::FatalError;
use copylocker_types::{KillReason, LicenseState, StateReason};

// --- ops (request map key 0) ---

/// Generate (or confirm) the device KEM + signing key pair.
pub const OP_DEVICE_KEYGEN: u64 = 1;
/// Export the opaque, persistable session snapshot.
pub const OP_SNAPSHOT_EXPORT: u64 = 2;
/// Import a previously exported snapshot; rebuilds all verified state.
pub const OP_SNAPSHOT_IMPORT: u64 = 3;
/// Build a `/v1/activate` request body for a license key or account token.
pub const OP_BUILD_ACTIVATE_REQUEST: u64 = 4;
/// Ingest a `/v1/keys` keyset; verifies epoch certificates against the pinned roots.
pub const OP_INGEST_KEYSET: u64 = 5;
/// Ingest a `/v1/activate` response: full chain + KEM + binding verification.
pub const OP_INGEST_ACTIVATE_RESPONSE: u64 = 6;
/// Build a `/v1/validate` request body.
pub const OP_BUILD_VALIDATE_REQUEST: u64 = 7;
/// Ingest a `/v1/validate` response (validation ticket or kill order).
pub const OP_INGEST_VALIDATE_RESPONSE: u64 = 8;
/// Derive the 32-byte half-baked material `M` for a feature (never a Feature Key).
pub const OP_DERIVE_M: u64 = 9;
/// Drive the state machine with a host event (tick, network, resume, deactivate).
pub const OP_EVENT: u64 = 10;
/// Advisory state query. Never usable for gating (ADR-0004).
pub const OP_STATE_QUERY: u64 = 11;
/// Build a `/v1/deactivate` request body.
pub const OP_BUILD_DEACTIVATE_REQUEST: u64 = 12;
/// Unwrap an entitled feature's asset KEK from the credential/ticket wrapped KEKs.
pub const OP_UNSEAL_ASSET: u64 = 13;

// --- event kinds (op 10, key 1) ---

/// Periodic tick; runs the clock guard and deadline checks.
pub const EVENT_TICK: u64 = 1;
/// The network became available.
pub const EVENT_NETWORK_AVAILABLE: u64 = 2;
/// The page/app resumed; key 3 carries the monotonic gap in milliseconds.
pub const EVENT_APP_RESUMED: u64 = 3;
/// A request failed for transient (network) reasons; may open the grace window.
pub const EVENT_NETWORK_FAILED: u64 = 4;
/// The user deactivated; wipes all local credential material.
pub const EVENT_USER_DEACTIVATE: u64 = 5;

// --- effect codes (response key 90) ---

/// The host should re-export the snapshot and persist it.
pub const EFFECT_PERSIST: u64 = 1;
/// The host should perform an online validation.
pub const EFFECT_SEND_VALIDATION: u64 = 2;
/// The host must wipe its stored snapshot.
pub const EFFECT_WIPE_ALL: u64 = 3;
/// The advisory state changed; keys 1/2 carry the new state and reason.
pub const EFFECT_STATE_CHANGED: u64 = 4;
/// The host should wake the session at the instant in key 91.
pub const EFFECT_SCHEDULE_WAKE: u64 = 5;

// --- error codes (returned as `Err(u16)`; the JS side sees only the number) ---

/// Input is not canonical CBOR within limits, or exceeds the size cap.
pub const ERR_MALFORMED: u16 = 1;
/// Unknown op code.
pub const ERR_UNKNOWN_OP: u16 = 2;
/// A required field is missing or has the wrong type/shape.
pub const ERR_BAD_FIELD: u16 = 3;
/// The constructor configuration is invalid.
pub const ERR_BAD_CONFIG: u16 = 4;
/// The system CSPRNG failed.
pub const ERR_ENTROPY: u16 = 5;
/// The op cannot run before device keys exist (call `device-keygen` first).
pub const ERR_NO_DEVICE_KEYS: u16 = 10;
/// A credential is already installed.
pub const ERR_ALREADY_ACTIVATED: u16 = 11;
/// The op needs an installed credential.
pub const ERR_NO_CREDENTIAL: u16 = 12;
/// The feature is not entitled, or the state forbids derivation.
///
/// Deliberately one code for both, so probing reveals nothing about the licence
/// (mirrors `CoreError::NotEntitled`).
pub const ERR_NOT_ENTITLED: u16 = 13;
/// No verified keyset/chain is installed (ingest a keyset first).
pub const ERR_NO_CHAIN: u16 = 14;
/// The op needs a matching pending request (e.g. a validate nonce).
pub const ERR_NO_PENDING: u16 = 15;
/// A snapshot is malformed, of an unknown schema, or otherwise unusable.
pub const ERR_BAD_SNAPSHOT: u16 = 16;
/// Key derivation failed.
pub const ERR_DERIVATION: u16 = 17;
/// The op is not valid for the session's current lifecycle phase.
pub const ERR_BAD_STATE: u16 = 18;

/// Map a fatal (fail-closed) error onto the numeric contract. The codes are stable; the
/// `u16` space above 100 is reserved for them.
#[must_use]
pub const fn fatal_code(error: FatalError) -> u16 {
    match error {
        FatalError::SignatureInvalid => 100,
        FatalError::ChainInvalid => 101,
        FatalError::EpochRevoked => 102,
        FatalError::NonceMismatch => 103,
        FatalError::MachineMismatch => 104,
        FatalError::RevocationRollback => 105,
        FatalError::CredentialCorrupt => 106,
        FatalError::Revoked(_) => 107,
        FatalError::SecurityFloorRegression => 108,
        FatalError::IntegrityFailure => 109,
        _ => 106,
    }
}

/// Numeric advisory state code (response key 1).
#[must_use]
pub const fn state_code(state: LicenseState) -> u64 {
    match state {
        LicenseState::Unlicensed => 0,
        LicenseState::Activating => 1,
        LicenseState::Active => 2,
        LicenseState::NeedsRevalidation => 3,
        LicenseState::Grace => 4,
        LicenseState::Locked => 5,
        LicenseState::Revoked => 6,
        LicenseState::Tampered => 7,
    }
}

/// Numeric reason code (response key 2); 0 means "no transition".
#[must_use]
pub const fn reason_code(reason: StateReason) -> u64 {
    match reason {
        StateReason::Activated => 1,
        StateReason::Validated => 2,
        StateReason::ReactivationRequired => 3,
        StateReason::VersionOutOfScope => 4,
        StateReason::RefreshDue => 5,
        StateReason::NetworkUnavailable => 6,
        StateReason::GraceExhausted => 7,
        StateReason::CredentialExpired => 8,
        StateReason::ClockRollback => 9,
        StateReason::KillOrder(_) => 10,
        StateReason::IntegrityFailure => 11,
        StateReason::UserRequested => 12,
        _ => 0,
    }
}

/// Numeric kill-reason code, for hosts that log advisory detail.
#[must_use]
pub const fn kill_reason_code(reason: KillReason) -> u64 {
    reason as u64
}
