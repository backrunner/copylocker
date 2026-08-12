//! The CopyLocker wire protocol (`protocol-spec.md`).
//!
//! Everything a client and server exchange is defined here: the artifact bodies, the signature
//! envelope that wraps them, the certificate chain that anchors them to a pinned root, and the
//! user-visible license key format.
//!
//! # Parsing discipline
//!
//! Every entry point is bounded. Bodies have a maximum length, CBOR has a maximum nesting
//! depth, arrays and strings have element limits, and non-canonical encodings are rejected
//! outright. A malformed artifact must produce an error, never a panic and never an
//! unbounded allocation (`protocol-spec.md §10.1`).

#![no_std]
#![forbid(unsafe_code)]
// In tests, unwrap/expect are assertion shorthand. Production code keeps the workspace denies.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

extern crate alloc;

pub mod artifacts;
pub mod chain;
pub mod challenge;
pub mod entitlements;
pub mod envelope;
pub mod error;
pub(crate) mod field;
pub mod keywrap;
pub mod license_key;
pub mod offline_armor;
pub mod offline_bundle;
pub mod requests;
pub mod responses;
pub mod sealed_asset;

pub use artifacts::{
    ActivationResponse, EpochCert, IntegrityManifest, KillOrder, MachineCredential,
    OfflineLicenseKey, RevocationBatch, ValidationTicket,
};
pub use chain::{PinnedRoots, VerifiedChain};
pub use challenge::{
    FeatureChallenge, FeatureResponse, FEATURE_CHALLENGE_SCHEMA_V1, FEATURE_RESPONSE_LEN,
    MAX_CHALLENGE_BYTES, MAX_FEATURE_CHALLENGE_BYTES, MAX_FEATURE_ID_BYTES,
};
pub use envelope::Envelope;
pub use error::ProtoError;
pub use license_key::LicenseKey;
pub use offline_armor::{
    armor_activation_request, unarmor_activation_request, AR_ARMOR_PREFIX, MAX_AR_ARMORED_BYTES,
};
pub use offline_bundle::{
    olk_binding_fingerprint, OfflineLicenseBundle, MAX_OLK_BUNDLE_BYTES, OLK_BUNDLE_SCHEMA_V1,
    UNBOUND_OLK_BINDING_LABEL,
};
pub use requests::{
    AccountLoginRequest, AccountLogoutRequest, AccountRefreshRequest, ActivationRequest,
    ClientInfo, Credential, DeactivateRequest, HeartbeatRequest, TelemetryBlock, ValidateRequest,
    ACCOUNT_SCHEMA_V1, ACCOUNT_TOKEN_LEN, MAX_ACCOUNT_EMAIL_BYTES, MAX_ACCOUNT_PASSWORD_BYTES,
    MAX_TELEMETRY_BLOCK_BYTES,
};
pub use responses::{AccountSession, AckResponse, Keyset, ProtocolErrorResponse};
pub use sealed_asset::{SealedAsset, MAX_SEALED_ASSET_BYTES, SEALED_ASSET_SCHEMA_V1};

use copylocker_suite::cbor::Limits;

/// Parsing limits for client-facing endpoints (`protocol-spec.md §10.1`).
pub const CLIENT_LIMITS: Limits = Limits {
    max_depth: copylocker_types::MAX_CBOR_DEPTH,
    max_items: 1024,
    max_string: 16 * 1024,
};

/// Parsing limits for artifacts that legitimately carry bulk data, such as a revocation batch
/// or an integrity manifest listing every chunk of a web build.
pub const BULK_LIMITS: Limits = Limits {
    max_depth: copylocker_types::MAX_CBOR_DEPTH,
    max_items: 65_536,
    max_string: 1024 * 1024,
};
