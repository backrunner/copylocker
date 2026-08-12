//! Client → server request bodies (`protocol-spec.md §3` and `§10.2`).

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use copylocker_suite::cbor::{decode_canonical, CborValue, MapBuilder};
use copylocker_suite::device::{AttrValue, DeviceAttrs};
use copylocker_suite::{Artifact, CodecError};
use copylocker_types::{ArtifactKind, Fingerprint, LicenseId, MachineId, SuiteId};

use crate::field;
use crate::{ProtoError, CLIENT_LIMITS};

/// Implement encoding for request types.
///
/// Requests carry an `ArtifactKind` so that the device's self-signature is domain-separated from
/// server-issued artifacts, but they are not server-signed, so they get their own macro rather
/// than reusing the artifact one.
macro_rules! artifact_like {
    ($ty:ty, $kind:expr) => {
        impl $ty {
            /// Encode to canonical bytes.
            #[must_use]
            pub fn encode(&self) -> Vec<u8> {
                self.to_value().to_canonical()
            }

            /// Decode from canonical bytes, applying client-facing limits.
            pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
                if bytes.len() > copylocker_types::MAX_BODY_BYTES {
                    return Err(ProtoError::Codec(CodecError::TooLong));
                }
                let v = decode_canonical(bytes, CLIENT_LIMITS)?;
                if v.as_map().is_none() {
                    return Err(ProtoError::Codec(CodecError::Malformed));
                }
                Self::from_value(&v)
            }
        }

        impl Artifact for $ty {
            const KIND: ArtifactKind = $kind;

            fn to_canonical(&self) -> Result<Vec<u8>, CodecError> {
                Ok(self.encode())
            }

            fn from_canonical(bytes: &[u8]) -> Result<Self, CodecError> {
                Self::decode(bytes).map_err(|e| match e {
                    ProtoError::Codec(c) => c,
                    _ => CodecError::Malformed,
                })
            }
        }
    };
}

/// How the client is identifying itself (`protocol-spec.md §3`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Credential {
    /// Mode O: a user-typed license key.
    LicenseKey(String),
    /// Mode E: a bearer token from `/v1/auth/login`.
    AccountToken(Vec<u8>),
}

impl Credential {
    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        match self {
            Self::LicenseKey(k) => b.put(0, CborValue::Text(k.clone())),
            Self::AccountToken(t) => b.put(1, CborValue::Bytes(t.clone())),
        };
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        let entries = v.as_map().ok_or(ProtoError::Codec(CodecError::Malformed))?;
        if entries.len() != 1 {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        if field::opt(v, 0).is_some() {
            return Ok(Self::LicenseKey(field::text(v, 0)?));
        }
        if field::opt(v, 1).is_some() {
            return Ok(Self::AccountToken(field::bytes(v, 1)?));
        }
        Err(ProtoError::Codec(CodecError::UnknownDiscriminant))
    }
}

/// Build and version metadata the client reports (`protocol-spec.md §3.1`).
///
/// Every field here is **self-reported and therefore untrusted**. `release_id` in particular can
/// be forged — the mitigation is not to trust it but to make lying useless: a client claiming an
/// old release receives that release's wrapped KEKs, which its actual build cannot use
/// (`licensing-model.md §4.2`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ClientInfo {
    /// Application version, semver.
    pub app_version: String,
    /// SDK version, semver.
    pub sdk_version: String,
    /// Operating system.
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// Build fingerprint injected at build time.
    pub build_fingerprint: String,
    /// Registered release identifier.
    pub release_id: String,
    /// Variant this build derives keys for.
    pub variant_id: u64,
    /// Suites the client can verify.
    pub supported_suites: Vec<SuiteId>,
    /// Variants whose sealed assets this build can still open.
    pub supported_variants: Vec<u64>,
}

impl ClientInfo {
    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Text(self.app_version.clone()));
        b.put(1, CborValue::Text(self.sdk_version.clone()));
        b.put(2, CborValue::Text(self.os.clone()));
        b.put(3, CborValue::Text(self.arch.clone()));
        b.put(4, CborValue::Text(self.build_fingerprint.clone()));
        b.put(5, CborValue::Text(self.release_id.clone()));
        b.put(6, CborValue::Uint(self.variant_id));
        b.put(
            7,
            CborValue::Array(
                self.supported_suites
                    .iter()
                    .map(|s| CborValue::Bytes(s.as_bytes().to_vec()))
                    .collect(),
            ),
        );
        b.put(
            8,
            CborValue::Array(
                self.supported_variants
                    .iter()
                    .copied()
                    .map(CborValue::Uint)
                    .collect(),
            ),
        );
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        let variants = field::req(v, 8)?
            .as_array()
            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(8)))?
            .iter()
            .map(|x| {
                x.as_uint()
                    .ok_or(ProtoError::Codec(CodecError::TypeMismatch(8)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            app_version: field::text(v, 0)?,
            sdk_version: field::text(v, 1)?,
            os: field::text(v, 2)?,
            arch: field::text(v, 3)?,
            build_fingerprint: field::text(v, 4)?,
            release_id: field::text(v, 5)?,
            variant_id: field::uint(v, 6)?,
            supported_suites: field::fixed_array::<4>(v, 7)?
                .into_iter()
                .map(SuiteId)
                .collect(),
            supported_variants: variants,
        })
    }
}

/// `POST /v1/activate` (`protocol-spec.md §3`).
///
/// Self-signed by the device key. That signature is **not a trust anchor** — anyone can generate
/// a key pair. Its only job is to bind `nonce_c` to `device_kem_ek` so that an intermediary
/// cannot substitute their own encapsulation key and receive the credential secret.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ActivationRequest {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite the client proposes.
    pub suite_id: SuiteId,
    /// Product slug.
    pub product_id: String,
    /// License key or account token.
    pub credential: Credential,
    /// Device fingerprint digest.
    pub fingerprint: Fingerprint,
    /// Raw normalised attributes, sent only when the policy enables tolerance matching.
    /// Omitted otherwise, since they are more identifying than the digest
    /// (`20-client-core.md §3.4`).
    pub device_attrs: Option<DeviceAttrs>,
    /// Device long-term KEM encapsulation key.
    pub device_kem_ek: Vec<u8>,
    /// Device signature verifying key, used to authenticate later validate requests.
    pub device_sig_vk: Vec<u8>,
    /// Client nonce, echoed by the server to prove freshness.
    pub nonce_c: [u8; 32],
    /// Client wall clock. Reported for diagnostics; the server does not trust it.
    pub client_time: i64,
    /// Build and version metadata.
    pub client_info: ClientInfo,
    /// Platform attestation, when available.
    pub attestation: Option<Vec<u8>>,
    /// Ed25519 signature by `device_sig_vk` over [`Self::proof_input`].
    ///
    /// This is not an entitlement trust anchor. It prevents an intermediary from replacing the
    /// KEM key, signature key, nonce, or credential while forwarding the request.
    pub proof: Vec<u8>,
}

impl ActivationRequest {
    /// Canonical bytes covered by the device proof: the complete request with key 12 omitted.
    #[must_use]
    pub fn proof_input(&self) -> Vec<u8> {
        self.to_value_without_proof().to_canonical()
    }

    fn to_value_without_proof(&self) -> CborValue {
        self.to_value_inner(false)
    }

    fn to_value(&self) -> CborValue {
        self.to_value_inner(true)
    }

    fn to_value_inner(&self, include_proof: bool) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Text(self.product_id.clone()));
        b.put(3, self.credential.to_value());
        b.put(4, CborValue::Bytes(self.fingerprint.as_bytes().to_vec()));
        b.put_opt(5, self.device_attrs.as_ref().map(encode_attrs));
        b.put(6, CborValue::Bytes(self.device_kem_ek.clone()));
        b.put(7, CborValue::Bytes(self.nonce_c.to_vec()));
        b.put(8, CborValue::int(self.client_time));
        b.put(9, self.client_info.to_value());
        b.put_opt(10, self.attestation.clone().map(CborValue::Bytes));
        b.put(11, CborValue::Bytes(self.device_sig_vk.clone()));
        if include_proof {
            b.put(12, CborValue::Bytes(self.proof.clone()));
        }
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            product_id: field::text(v, 2)?,
            credential: Credential::from_value(field::req(v, 3)?)?,
            fingerprint: field::fingerprint(v, 4)?,
            device_attrs: match field::opt(v, 5) {
                None => None,
                Some(a) => Some(decode_attrs(a)?),
            },
            device_kem_ek: field::bytes(v, 6)?,
            nonce_c: field::fixed::<32>(v, 7)?,
            client_time: field::int(v, 8)?,
            client_info: ClientInfo::from_value(field::req(v, 9)?)?,
            attestation: field::opt_bytes(v, 10)?,
            device_sig_vk: field::bytes(v, 11)?,
            proof: field::bytes(v, 12)?,
        })
    }
}

artifact_like!(ActivationRequest, ArtifactKind::ActivationRequest);

/// `POST /v1/validate` (`protocol-spec.md §10.2`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidateRequest {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite.
    pub suite_id: SuiteId,
    /// Authoritative Durable Object routing key.
    pub license_id: LicenseId,
    /// Which activation is asking.
    pub machine_id: MachineId,
    /// Current fingerprint, which may have drifted since activation.
    pub fingerprint: Fingerprint,
    /// Fresh client nonce.
    pub nonce_c: [u8; 32],
    /// Client wall clock, untrusted.
    pub client_time: i64,
    /// Revocation sequence the client already holds, so the server can send only the delta.
    pub known_revocation_epoch: u64,
    /// Build and version metadata.
    pub client_info: ClientInfo,
    /// Signature by the device key over the preceding fields.
    ///
    /// Without this, knowing a `machine_id` would be enough to impersonate a device and keep its
    /// seat alive — or to burn its rate limit.
    pub proof: Vec<u8>,
    /// Optional client-side integrity self-check summary.
    pub integrity_summary: Option<Vec<u8>>,
    /// Highest security floor the client has seen, so the server can detect a downgrade.
    pub known_security_floor: u64,
    /// Optional consented, untrusted telemetry carried on the validation request.
    pub telemetry: Option<TelemetryBlock>,
}

impl ValidateRequest {
    /// The bytes the device signature covers: every field except key 8 (`proof`) itself.
    ///
    /// Computed by re-encoding rather than by remembering the received bytes, so a client that
    /// re-orders fields cannot produce a body that verifies under one reading and is acted on
    /// under another.
    #[must_use]
    pub fn proof_input(&self) -> Vec<u8> {
        self.to_value_inner(false).to_canonical()
    }

    fn to_value(&self) -> CborValue {
        self.to_value_inner(true)
    }

    fn to_value_inner(&self, include_proof: bool) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Bytes(self.machine_id.as_bytes().to_vec()));
        b.put(3, CborValue::Bytes(self.fingerprint.as_bytes().to_vec()));
        b.put(4, CborValue::Bytes(self.nonce_c.to_vec()));
        b.put(5, CborValue::int(self.client_time));
        b.put(6, CborValue::Uint(self.known_revocation_epoch));
        b.put(7, self.client_info.to_value());
        if include_proof {
            b.put(8, CborValue::Bytes(self.proof.clone()));
        }
        b.put_opt(9, self.integrity_summary.clone().map(CborValue::Bytes));
        b.put(10, CborValue::Uint(self.known_security_floor));
        b.put_opt(11, self.telemetry.as_ref().map(TelemetryBlock::to_value));
        b.put(12, CborValue::Bytes(self.license_id.as_bytes().to_vec()));
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            license_id: field::license_id(v, 12)?,
            machine_id: field::machine_id(v, 2)?,
            fingerprint: field::fingerprint(v, 3)?,
            nonce_c: field::fixed::<32>(v, 4)?,
            client_time: field::int(v, 5)?,
            known_revocation_epoch: field::uint(v, 6)?,
            client_info: ClientInfo::from_value(field::req(v, 7)?)?,
            proof: field::bytes(v, 8)?,
            integrity_summary: field::opt_bytes(v, 9)?,
            known_security_floor: field::uint(v, 10)?,
            telemetry: field::opt(v, 11)
                .map(TelemetryBlock::from_value)
                .transpose()?,
        })
    }
}

artifact_like!(ValidateRequest, ArtifactKind::ValidateRequest);

/// Maximum canonical-CBOR byte length of a telemetry block (`90-analytics-telemetry.md §2.6`:
/// blocks over 512 bytes are dropped, not truncated).
pub const MAX_TELEMETRY_BLOCK_BYTES: usize = 512;

/// User-consented telemetry piggybacked on validation (`90-analytics-telemetry.md §6`).
///
/// The server treats every value as untrusted and clips it before projection. Keeping the block
/// typed here ensures the device proof covers the exact canonical fields the server consumes.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TelemetryBlock {
    /// Privacy notice version the user consented to; zero means no valid consent.
    pub consent_version: u64,
    /// Start of the aggregation window, anchored to a previous server time.
    pub window_start: u64,
    /// Sessions observed during the window.
    pub session_count: u64,
    /// Four duration-bucket counters.
    pub session_duration_histogram: [u64; 4],
    /// Per-feature counts, limited to the SDK-configured allow-list by the server.
    pub feature_hits: BTreeMap<String, u64>,
    /// Active days in the window; semantic validation constrains this to 0..=28.
    pub days_active: u64,
}

impl TelemetryBlock {
    /// Encode to canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.to_value().to_canonical()
    }

    /// Decode from canonical bytes, applying client-facing limits and the block size cap.
    ///
    /// The block travels to clients that embed it into a signed `ValidateRequest` (proto
    /// key 11), so this is the bounded entry point for host-produced bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > MAX_TELEMETRY_BLOCK_BYTES {
            return Err(ProtoError::Codec(CodecError::TooLong));
        }
        let v = decode_canonical(bytes, CLIENT_LIMITS)?;
        if v.as_map().is_none() {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        Self::from_value(&v)
    }

    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(self.consent_version));
        b.put(1, CborValue::Uint(self.window_start));
        b.put(2, CborValue::Uint(self.session_count));
        b.put(
            3,
            CborValue::Array(
                self.session_duration_histogram
                    .iter()
                    .copied()
                    .map(CborValue::Uint)
                    .collect(),
            ),
        );
        b.put(
            4,
            CborValue::Map(
                self.feature_hits
                    .iter()
                    .map(|(name, count)| (CborValue::Text(name.clone()), CborValue::Uint(*count)))
                    .collect(),
            ),
        );
        b.put(5, CborValue::Uint(self.days_active));
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        let histogram = field::req(v, 3)?
            .as_array()
            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(3)))?;
        let histogram: [u64; 4] = histogram
            .iter()
            .map(|value| {
                value
                    .as_uint()
                    .ok_or(ProtoError::Codec(CodecError::TypeMismatch(3)))
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| ProtoError::Codec(CodecError::Malformed))?;

        let hits = field::req(v, 4)?
            .as_map()
            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(4)))?;
        let mut feature_hits = BTreeMap::new();
        for (name, count) in hits {
            let name = name
                .as_text()
                .ok_or(ProtoError::Codec(CodecError::TypeMismatch(4)))?;
            let count = count
                .as_uint()
                .ok_or(ProtoError::Codec(CodecError::TypeMismatch(4)))?;
            if feature_hits.insert(name.to_string(), count).is_some() {
                return Err(ProtoError::Codec(CodecError::Malformed));
            }
        }

        Ok(Self {
            consent_version: field::uint(v, 0)?,
            window_start: field::uint(v, 1)?,
            session_count: field::uint(v, 2)?,
            session_duration_histogram: histogram,
            feature_hits,
            days_active: field::uint(v, 5)?,
        })
    }
}

/// Account message schema implemented by this release.
pub const ACCOUNT_SCHEMA_V1: u64 = 1;
/// Byte length of an account access or refresh token.
pub const ACCOUNT_TOKEN_LEN: usize = 32;
/// Maximum account email length.
pub const MAX_ACCOUNT_EMAIL_BYTES: usize = 254;
/// Maximum accepted password length. Longer inputs are rejected rather than truncated so a
/// client never silently authenticates with a different password than the user typed.
pub const MAX_ACCOUNT_PASSWORD_BYTES: usize = 1024;

/// `POST /v1/account/login` (Mode E, `protocol-spec.md §10.2`).
///
/// Carries the account password, so it is only ever sent over TLS to the account endpoint and
/// is never logged, journaled, or echoed back.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountLoginRequest {
    /// Account message schema.
    pub schema: u64,
    /// Product the account belongs to.
    pub product_id: String,
    /// Account email, compared case-insensitively.
    pub email: String,
    /// Account password. Verified against the stored Argon2id hash and then dropped.
    pub password: String,
}

impl AccountLoginRequest {
    /// Construct a schema-v1 request after validation.
    pub fn new(
        product_id: impl Into<String>,
        email: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ProtoError> {
        let value = Self {
            schema: ACCOUNT_SCHEMA_V1,
            product_id: product_id.into(),
            email: email.into(),
            password: password.into(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Encode as canonical CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(self.schema));
        builder.put(1, CborValue::Text(self.product_id.clone()));
        builder.put(2, CborValue::Text(self.email.clone()));
        builder.put(3, CborValue::Text(self.password.clone()));
        builder.finish()
    }

    /// Decode a bounded, canonical request.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > copylocker_types::MAX_BODY_BYTES {
            return Err(ProtoError::Codec(CodecError::TooLong));
        }
        let value = decode_canonical(bytes, CLIENT_LIMITS)?;
        if value.as_map().is_none_or(|entries| entries.len() != 4) {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        let request = Self {
            schema: field::uint(&value, 0)?,
            product_id: field::text(&value, 1)?,
            email: field::text(&value, 2)?,
            password: field::text(&value, 3)?,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), ProtoError> {
        if self.schema != ACCOUNT_SCHEMA_V1
            || !is_product_slug(&self.product_id)
            || !is_account_email(&self.email)
            || self.password.is_empty()
            || self.password.len() > MAX_ACCOUNT_PASSWORD_BYTES
            || self.password.as_bytes().contains(&0)
        {
            return Err(ProtoError::Codec(CodecError::Malformed));
        }
        Ok(())
    }
}

impl core::fmt::Debug for AccountLoginRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AccountLoginRequest")
            .field("schema", &self.schema)
            .field("product_id", &self.product_id)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// `POST /v1/account/refresh`: exchange a refresh token for a fresh session.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountRefreshRequest {
    /// Account message schema.
    pub schema: u64,
    /// Refresh token issued by login or a previous refresh.
    pub refresh_token: [u8; ACCOUNT_TOKEN_LEN],
}

impl AccountRefreshRequest {
    /// Construct a schema-v1 request.
    #[must_use]
    pub fn new(refresh_token: [u8; ACCOUNT_TOKEN_LEN]) -> Self {
        Self {
            schema: ACCOUNT_SCHEMA_V1,
            refresh_token,
        }
    }

    /// Encode as canonical CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(self.schema));
        builder.put(1, CborValue::Bytes(self.refresh_token.to_vec()));
        builder.finish()
    }

    /// Decode a bounded, canonical request.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        account_token_request(bytes).map(|refresh_token| Self {
            schema: ACCOUNT_SCHEMA_V1,
            refresh_token,
        })
    }
}

impl core::fmt::Debug for AccountRefreshRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AccountRefreshRequest")
            .field("schema", &self.schema)
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

/// `POST /v1/account/logout`: revoke one session. Idempotent by design.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountLogoutRequest {
    /// Account message schema.
    pub schema: u64,
    /// Refresh token identifying the session to revoke.
    pub refresh_token: [u8; ACCOUNT_TOKEN_LEN],
}

impl AccountLogoutRequest {
    /// Construct a schema-v1 request.
    #[must_use]
    pub fn new(refresh_token: [u8; ACCOUNT_TOKEN_LEN]) -> Self {
        Self {
            schema: ACCOUNT_SCHEMA_V1,
            refresh_token,
        }
    }

    /// Encode as canonical CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(self.schema));
        builder.put(1, CborValue::Bytes(self.refresh_token.to_vec()));
        builder.finish()
    }

    /// Decode a bounded, canonical request.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        account_token_request(bytes).map(|refresh_token| Self {
            schema: ACCOUNT_SCHEMA_V1,
            refresh_token,
        })
    }
}

impl core::fmt::Debug for AccountLogoutRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AccountLogoutRequest")
            .field("schema", &self.schema)
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

fn account_token_request(bytes: &[u8]) -> Result<[u8; ACCOUNT_TOKEN_LEN], ProtoError> {
    if bytes.len() > copylocker_types::MAX_BODY_BYTES {
        return Err(ProtoError::Codec(CodecError::TooLong));
    }
    let value = decode_canonical(bytes, CLIENT_LIMITS)?;
    if value.as_map().is_none_or(|entries| entries.len() != 2) {
        return Err(ProtoError::Codec(CodecError::Malformed));
    }
    if field::uint(&value, 0)? != ACCOUNT_SCHEMA_V1 {
        return Err(ProtoError::Codec(CodecError::Malformed));
    }
    field::fixed::<ACCOUNT_TOKEN_LEN>(&value, 1)
}

fn is_product_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_account_email(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= MAX_ACCOUNT_EMAIL_BYTES
        && value.bytes().any(|byte| byte == b'@')
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == 0)
}

/// `POST /v1/heartbeat`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HeartbeatRequest {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite used by this activation.
    pub suite_id: SuiteId,
    /// Authoritative Durable Object routing key.
    pub license_id: LicenseId,
    /// Activation proving liveness.
    pub machine_id: MachineId,
    /// Fresh nonce, consumed atomically with the heartbeat update.
    pub nonce_c: [u8; 32],
    /// Client wall clock, untrusted.
    pub client_time: i64,
    /// Ed25519 signature by the activation's stored device key.
    pub proof: Vec<u8>,
}

impl HeartbeatRequest {
    /// Canonical request bytes with key 6 (`proof`) omitted.
    #[must_use]
    pub fn proof_input(&self) -> Vec<u8> {
        self.to_value_inner(false).to_canonical()
    }

    fn to_value(&self) -> CborValue {
        self.to_value_inner(true)
    }

    fn to_value_inner(&self, include_proof: bool) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Bytes(self.license_id.as_bytes().to_vec()));
        b.put(3, CborValue::Bytes(self.machine_id.as_bytes().to_vec()));
        b.put(4, CborValue::Bytes(self.nonce_c.to_vec()));
        b.put(5, CborValue::int(self.client_time));
        if include_proof {
            b.put(6, CborValue::Bytes(self.proof.clone()));
        }
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            license_id: field::license_id(v, 2)?,
            machine_id: field::machine_id(v, 3)?,
            nonce_c: field::fixed::<32>(v, 4)?,
            client_time: field::int(v, 5)?,
            proof: field::bytes(v, 6)?,
        })
    }
}

artifact_like!(HeartbeatRequest, ArtifactKind::HeartbeatRequest);

/// `POST /v1/deactivate`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeactivateRequest {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite used by this activation.
    pub suite_id: SuiteId,
    /// Authoritative Durable Object routing key.
    pub license_id: LicenseId,
    /// Activation whose seat should be released.
    pub machine_id: MachineId,
    /// Fresh nonce, consumed atomically with the release.
    pub nonce_c: [u8; 32],
    /// Client wall clock, untrusted.
    pub client_time: i64,
    /// Ed25519 signature by the activation's stored device key.
    pub proof: Vec<u8>,
}

impl DeactivateRequest {
    /// Canonical request bytes with key 6 (`proof`) omitted.
    #[must_use]
    pub fn proof_input(&self) -> Vec<u8> {
        self.to_value_inner(false).to_canonical()
    }

    fn to_value(&self) -> CborValue {
        self.to_value_inner(true)
    }

    fn to_value_inner(&self, include_proof: bool) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Bytes(self.license_id.as_bytes().to_vec()));
        b.put(3, CborValue::Bytes(self.machine_id.as_bytes().to_vec()));
        b.put(4, CborValue::Bytes(self.nonce_c.to_vec()));
        b.put(5, CborValue::int(self.client_time));
        if include_proof {
            b.put(6, CborValue::Bytes(self.proof.clone()));
        }
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            license_id: field::license_id(v, 2)?,
            machine_id: field::machine_id(v, 3)?,
            nonce_c: field::fixed::<32>(v, 4)?,
            client_time: field::int(v, 5)?,
            proof: field::bytes(v, 6)?,
        })
    }
}

artifact_like!(DeactivateRequest, ArtifactKind::DeactivateRequest);

/// Encode normalised device attributes for transport.
fn encode_attrs(attrs: &DeviceAttrs) -> CborValue {
    CborValue::Map(
        attrs
            .iter()
            .map(|(k, v)| {
                let val = match v {
                    AttrValue::Absent => CborValue::Array(alloc::vec![CborValue::Uint(0)]),
                    AttrValue::Text(t) => CborValue::Array(alloc::vec![
                        CborValue::Uint(1),
                        CborValue::Text(t.clone())
                    ]),
                    AttrValue::Set(items) => CborValue::Array(alloc::vec![
                        CborValue::Uint(2),
                        CborValue::Array(items.iter().cloned().map(CborValue::Text).collect())
                    ]),
                    AttrValue::Int(n) => {
                        CborValue::Array(alloc::vec![CborValue::Uint(3), CborValue::int(*n)])
                    }
                };
                (CborValue::Text(k.clone()), val)
            })
            .collect(),
    )
}

/// Decode normalised device attributes.
fn decode_attrs(v: &CborValue) -> Result<DeviceAttrs, ProtoError> {
    let entries = v.as_map().ok_or(ProtoError::Codec(CodecError::Malformed))?;
    let mut out = DeviceAttrs::new();
    for (k, val) in entries {
        let key = k
            .as_text()
            .ok_or(ProtoError::Codec(CodecError::Malformed))?;
        let arr = val
            .as_array()
            .ok_or(ProtoError::Codec(CodecError::Malformed))?;
        let tag = arr
            .first()
            .and_then(CborValue::as_uint)
            .ok_or(ProtoError::Codec(CodecError::Malformed))?;
        let payload = arr.get(1);
        let value = match (tag, payload) {
            (0, None) => AttrValue::Absent,
            (1, Some(p)) => AttrValue::Text(
                p.as_text()
                    .ok_or(ProtoError::Codec(CodecError::Malformed))?
                    .into(),
            ),
            (2, Some(p)) => {
                let items = p
                    .as_array()
                    .ok_or(ProtoError::Codec(CodecError::Malformed))?;
                let mut v = Vec::with_capacity(items.len());
                for i in items {
                    v.push(String::from(
                        i.as_text()
                            .ok_or(ProtoError::Codec(CodecError::Malformed))?,
                    ));
                }
                AttrValue::Set(v)
            }
            (3, Some(p)) => {
                AttrValue::Int(p.as_int().ok_or(ProtoError::Codec(CodecError::Malformed))?)
            }
            _ => return Err(ProtoError::Codec(CodecError::UnknownDiscriminant)),
        };
        out.insert(key, value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn client_info() -> ClientInfo {
        ClientInfo {
            app_version: "4.2.0".to_string(),
            sdk_version: "0.1.0".to_string(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            build_fingerprint: "build-abc".to_string(),
            release_id: "rel_01H".to_string(),
            variant_id: 7,
            supported_suites: vec![SuiteId::from_u32(0x0100_0001)],
            supported_variants: vec![7, 6, 5, 4],
        }
    }

    fn attrs() -> DeviceAttrs {
        let mut a = DeviceAttrs::new();
        a.insert("machine_guid", AttrValue::text("A1B2"));
        a.insert("mac_addrs", AttrValue::set(vec!["aa:bb", "cc:dd"]));
        a.insert("hardware_concurrency", AttrValue::Int(8));
        a.insert("board_serial", AttrValue::Absent);
        a
    }

    fn activation_request() -> ActivationRequest {
        ActivationRequest {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            product_id: "acme".to_string(),
            credential: Credential::LicenseKey("CL1-ABCDE-FGHJK-MNPQR-STVWX".to_string()),
            fingerprint: Fingerprint::from_vec(vec![1; 32]),
            device_attrs: Some(attrs()),
            device_kem_ek: vec![2; 1216],
            device_sig_vk: vec![3; 32],
            nonce_c: [4; 32],
            client_time: 1_800_000_000,
            client_info: client_info(),
            attestation: Some(vec![5; 64]),
            proof: vec![6; 64],
        }
    }

    fn telemetry() -> TelemetryBlock {
        let mut feature_hits = BTreeMap::new();
        feature_hits.insert("export.pdf".to_string(), 3);
        TelemetryBlock {
            consent_version: 2,
            window_start: 1_799_900_000,
            session_count: 5,
            session_duration_histogram: [1, 2, 1, 1],
            feature_hits,
            days_active: 4,
        }
    }

    fn validate_request() -> ValidateRequest {
        ValidateRequest {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            license_id: LicenseId([5; 16]),
            machine_id: MachineId([6; 16]),
            fingerprint: Fingerprint::from_vec(vec![1; 32]),
            nonce_c: [7; 32],
            client_time: 1_800_000_000,
            known_revocation_epoch: 42,
            client_info: client_info(),
            proof: vec![8; 64],
            integrity_summary: Some(vec![9; 32]),
            known_security_floor: 3,
            telemetry: Some(telemetry()),
        }
    }

    fn heartbeat_request() -> HeartbeatRequest {
        HeartbeatRequest {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            license_id: LicenseId([5; 16]),
            machine_id: MachineId([6; 16]),
            nonce_c: [7; 32],
            client_time: 1_800_000_000,
            proof: vec![8; 64],
        }
    }

    fn deactivate_request() -> DeactivateRequest {
        DeactivateRequest {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            license_id: LicenseId([5; 16]),
            machine_id: MachineId([6; 16]),
            nonce_c: [9; 32],
            client_time: 1_800_000_001,
            proof: vec![10; 64],
        }
    }

    fn without_key(bytes: &[u8], key: u64) -> Vec<u8> {
        let mut value = decode_canonical(bytes, CLIENT_LIMITS).unwrap();
        assert!(
            matches!(value, CborValue::Map(_)),
            "request must encode as a map"
        );
        if let CborValue::Map(entries) = &mut value {
            entries.retain(|(candidate, _)| candidate.as_uint() != Some(key));
        }
        value.to_canonical()
    }

    fn assert_key_absent(bytes: &[u8], key: u64) {
        let value = decode_canonical(bytes, CLIENT_LIMITS).unwrap();
        assert!(field::opt(&value, key).is_none());
    }

    #[test]
    fn activation_request_roundtrips() {
        let r = activation_request();
        let bytes = r.encode();
        assert_eq!(ActivationRequest::decode(&bytes).unwrap(), r);
        assert_eq!(ActivationRequest::decode(&bytes).unwrap().encode(), bytes);
    }

    #[test]
    fn validate_request_roundtrips() {
        let r = validate_request();
        let bytes = r.encode();
        assert_eq!(ValidateRequest::decode(&bytes).unwrap(), r);
        assert_eq!(ValidateRequest::KIND, ArtifactKind::ValidateRequest);
        assert_ne!(ValidateRequest::KIND, ActivationRequest::KIND);
    }

    #[test]
    fn heartbeat_and_deactivate_requests_roundtrip_in_distinct_domains() {
        let heartbeat = heartbeat_request();
        let deactivate = deactivate_request();
        assert_eq!(
            HeartbeatRequest::decode(&heartbeat.encode()).unwrap(),
            heartbeat
        );
        assert_eq!(
            DeactivateRequest::decode(&deactivate.encode()).unwrap(),
            deactivate
        );
        assert_eq!(HeartbeatRequest::KIND, ArtifactKind::HeartbeatRequest);
        assert_eq!(DeactivateRequest::KIND, ArtifactKind::DeactivateRequest);
        assert_ne!(HeartbeatRequest::KIND, DeactivateRequest::KIND);
        assert_ne!(HeartbeatRequest::KIND, ValidateRequest::KIND);
    }

    #[test]
    fn both_credential_variants_roundtrip() {
        for c in [
            Credential::LicenseKey("CL1-AAAAA-AAAAA-AAAAA-AAAAA".to_string()),
            Credential::AccountToken(vec![1, 2, 3]),
        ] {
            let mut r = activation_request();
            r.credential = c.clone();
            assert_eq!(
                ActivationRequest::decode(&r.encode()).unwrap().credential,
                c
            );
        }
    }

    #[test]
    fn an_ambiguous_credential_is_rejected() {
        let v = CborValue::Map(vec![
            (CborValue::Uint(0), CborValue::Text("k".into())),
            (CborValue::Uint(1), CborValue::Bytes(vec![1])),
        ]);
        assert!(Credential::from_value(&v).is_err());
        assert!(Credential::from_value(&CborValue::Map(vec![])).is_err());
    }

    #[test]
    fn device_attributes_survive_a_roundtrip_including_absent() {
        let r = activation_request();
        let back = ActivationRequest::decode(&r.encode()).unwrap();
        let a = back.device_attrs.expect("attrs present");
        assert_eq!(a.get("board_serial"), Some(&AttrValue::Absent));
        assert_eq!(a.get("hardware_concurrency"), Some(&AttrValue::Int(8)));
        assert_eq!(a, attrs());
        // Same attributes in, same canonical bytes out — so the fingerprint the server
        // recomputes matches the one the client sent.
        assert_eq!(a.canonical_bytes(), attrs().canonical_bytes());
    }

    #[test]
    fn omitting_attributes_is_supported_for_privacy_conscious_policies() {
        let mut r = activation_request();
        r.device_attrs = None;
        let back = ActivationRequest::decode(&r.encode()).unwrap();
        assert!(back.device_attrs.is_none());
        assert_eq!(back, r);
    }

    #[test]
    fn proof_inputs_omit_the_proof_key_and_ignore_its_value() {
        let activation = activation_request();
        let mut changed_activation = activation.clone();
        changed_activation.proof = vec![0xff; 64];
        assert_eq!(activation.proof_input(), changed_activation.proof_input());
        assert_key_absent(&activation.proof_input(), 12);

        let validate = validate_request();
        let mut changed_validate = validate.clone();
        changed_validate.proof = vec![0xfe; 64];
        assert_eq!(validate.proof_input(), changed_validate.proof_input());
        assert_key_absent(&validate.proof_input(), 8);

        let heartbeat = heartbeat_request();
        let mut changed_heartbeat = heartbeat.clone();
        changed_heartbeat.proof = vec![0xfd; 64];
        assert_eq!(heartbeat.proof_input(), changed_heartbeat.proof_input());
        assert_key_absent(&heartbeat.proof_input(), 6);

        let deactivate = deactivate_request();
        let mut changed_deactivate = deactivate.clone();
        changed_deactivate.proof = vec![0xfc; 64];
        assert_eq!(deactivate.proof_input(), changed_deactivate.proof_input());
        assert_key_absent(&deactivate.proof_input(), 6);
    }

    #[test]
    fn validate_proof_covers_routing_telemetry_and_security_fields() {
        let base = validate_request();
        let original = base.proof_input();

        let mut changed = base.clone();
        changed.nonce_c = [0xaa; 32];
        assert_ne!(original, changed.proof_input());

        let mut changed2 = base.clone();
        changed2.client_info.release_id = "rel_other".to_string();
        assert_ne!(original, changed2.proof_input());

        let mut changed3 = base.clone();
        changed3.known_security_floor = 99;
        assert_ne!(original, changed3.proof_input());

        let mut changed4 = base.clone();
        changed4.license_id = LicenseId([0xbb; 16]);
        assert_ne!(original, changed4.proof_input());

        let mut changed5 = base;
        changed5.telemetry.as_mut().unwrap().session_count += 1;
        assert_ne!(original, changed5.proof_input());
    }

    #[test]
    fn telemetry_block_encode_decode_round_trip() {
        let block = telemetry();
        let encoded = block.encode();
        assert!(
            encoded.len() <= MAX_TELEMETRY_BLOCK_BYTES,
            "the fixture must fit the design cap"
        );
        assert_eq!(TelemetryBlock::decode(&encoded).unwrap(), block);
        // The default (all-zero) block round-trips too.
        assert_eq!(
            TelemetryBlock::decode(&TelemetryBlock::default().encode()).unwrap(),
            TelemetryBlock::default()
        );
    }

    #[test]
    fn telemetry_block_decode_rejects_malformed_input() {
        // Not CBOR, not canonical, and not a map.
        assert!(TelemetryBlock::decode(&[0xff]).is_err());
        assert!(TelemetryBlock::decode(&[0xbf, 0x00, 0x00, 0xff]).is_err());
        assert!(TelemetryBlock::decode(&[0x01]).is_err());
        // Oversized input is rejected before parsing.
        assert!(TelemetryBlock::decode(&vec![0u8; MAX_TELEMETRY_BLOCK_BYTES + 1]).is_err());
        // A valid map with the wrong field shapes.
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(1));
        b.put(1, CborValue::Uint(2));
        b.put(2, CborValue::Uint(3));
        b.put(3, CborValue::Array(vec![CborValue::Uint(1)]));
        b.put(4, CborValue::Map(vec![]));
        b.put(5, CborValue::Uint(1));
        assert!(
            TelemetryBlock::decode(&b.finish()).is_err(),
            "short histogram"
        );
        // Duplicate feature keys are malformed.
        let mut hits = MapBuilder::new();
        hits.put(0, CborValue::Uint(1));
        hits.put(1, CborValue::Uint(2));
        hits.put(2, CborValue::Uint(3));
        hits.put(
            3,
            CborValue::Array(vec![
                CborValue::Uint(1),
                CborValue::Uint(0),
                CborValue::Uint(0),
                CborValue::Uint(0),
            ]),
        );
        hits.put(
            4,
            CborValue::Map(vec![
                (CborValue::Text("f".to_string()), CborValue::Uint(1)),
                (CborValue::Text("f".to_string()), CborValue::Uint(2)),
            ]),
        );
        hits.put(5, CborValue::Uint(1));
        assert!(
            TelemetryBlock::decode(&hits.finish()).is_err(),
            "duplicate feature"
        );
    }

    #[test]
    fn activation_proof_binds_both_device_keys_and_the_credential() {
        let base = activation_request();
        let original = base.proof_input();

        let mut changed = base.clone();
        changed.device_kem_ek[0] ^= 1;
        assert_ne!(original, changed.proof_input());

        let mut changed = base.clone();
        changed.device_sig_vk[0] ^= 1;
        assert_ne!(original, changed.proof_input());

        let mut changed = base.clone();
        changed.credential = Credential::AccountToken(vec![0x44; 32]);
        assert_ne!(original, changed.proof_input());

        let mut changed = base;
        changed.nonce_c[0] ^= 1;
        assert_ne!(original, changed.proof_input());
    }

    #[test]
    fn heartbeat_and_deactivate_proofs_bind_route_machine_nonce_and_time() {
        let heartbeat = heartbeat_request();
        let heartbeat_input = heartbeat.proof_input();
        let mut changed = heartbeat.clone();
        changed.license_id = LicenseId([0x11; 16]);
        assert_ne!(heartbeat_input, changed.proof_input());
        let mut changed = heartbeat.clone();
        changed.machine_id = MachineId([0x12; 16]);
        assert_ne!(heartbeat_input, changed.proof_input());
        let mut changed = heartbeat.clone();
        changed.nonce_c[0] ^= 1;
        assert_ne!(heartbeat_input, changed.proof_input());
        let mut changed = heartbeat;
        changed.client_time += 1;
        assert_ne!(heartbeat_input, changed.proof_input());

        let deactivate = deactivate_request();
        let deactivate_input = deactivate.proof_input();
        let mut changed = deactivate.clone();
        changed.license_id = LicenseId([0x21; 16]);
        assert_ne!(deactivate_input, changed.proof_input());
        let mut changed = deactivate.clone();
        changed.machine_id = MachineId([0x22; 16]);
        assert_ne!(deactivate_input, changed.proof_input());
        let mut changed = deactivate.clone();
        changed.nonce_c[0] ^= 1;
        assert_ne!(deactivate_input, changed.proof_input());
        let mut changed = deactivate;
        changed.client_time += 1;
        assert_ne!(deactivate_input, changed.proof_input());
    }

    #[test]
    fn routing_and_proof_fields_are_required() {
        let validate = validate_request();
        assert_eq!(
            ValidateRequest::decode(&without_key(&validate.encode(), 12)),
            Err(ProtoError::Codec(CodecError::MissingField(12)))
        );

        let activation = activation_request();
        assert_eq!(
            ActivationRequest::decode(&without_key(&activation.encode(), 12)),
            Err(ProtoError::Codec(CodecError::MissingField(12)))
        );

        let heartbeat = heartbeat_request();
        assert_eq!(
            HeartbeatRequest::decode(&without_key(&heartbeat.encode(), 2)),
            Err(ProtoError::Codec(CodecError::MissingField(2)))
        );

        let deactivate = deactivate_request();
        assert_eq!(
            DeactivateRequest::decode(&without_key(&deactivate.encode(), 2)),
            Err(ProtoError::Codec(CodecError::MissingField(2)))
        );
    }

    #[test]
    fn telemetry_requires_exactly_four_histogram_buckets() {
        let mut value = telemetry().to_value();
        assert!(
            matches!(value, CborValue::Map(_)),
            "telemetry must encode as a map"
        );
        if let CborValue::Map(entries) = &mut value {
            for (key, payload) in entries {
                if key.as_uint() == Some(3) {
                    *payload = CborValue::Array(vec![CborValue::Uint(1); 3]);
                }
            }
        }
        assert_eq!(
            TelemetryBlock::from_value(&value),
            Err(ProtoError::Codec(CodecError::Malformed))
        );
    }

    #[test]
    fn oversized_bodies_are_rejected_before_parsing() {
        let huge = vec![0u8; copylocker_types::MAX_BODY_BYTES + 1];
        assert_eq!(
            ValidateRequest::decode(&huge),
            Err(ProtoError::Codec(CodecError::TooLong))
        );
    }

    #[test]
    fn truncated_requests_error_without_panicking() {
        let bytes = validate_request().encode();
        for cut in 0..bytes.len() {
            assert!(ValidateRequest::decode(&bytes[..cut]).is_err());
        }
    }

    #[test]
    fn corrupting_any_byte_never_panics() {
        let bytes = activation_request().encode();
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 0xff;
            let _ = ActivationRequest::decode(&bad);
        }
    }

    #[test]
    fn unknown_attribute_tag_is_rejected() {
        let v = CborValue::Map(vec![(
            CborValue::Text("k".into()),
            CborValue::Array(vec![CborValue::Uint(9), CborValue::Uint(1)]),
        )]);
        assert_eq!(
            decode_attrs(&v),
            Err(ProtoError::Codec(CodecError::UnknownDiscriminant))
        );
    }

    #[test]
    fn account_requests_round_trip_and_stay_bounded() {
        let login = AccountLoginRequest::new("acme", "user@example.test", "correct horse")
            .expect("valid login request");
        assert_eq!(AccountLoginRequest::decode(&login.encode()).unwrap(), login);

        let refresh = AccountRefreshRequest::new([7; ACCOUNT_TOKEN_LEN]);
        assert_eq!(
            AccountRefreshRequest::decode(&refresh.encode()).unwrap(),
            refresh
        );

        let logout = AccountLogoutRequest::new([9; ACCOUNT_TOKEN_LEN]);
        assert_eq!(
            AccountLogoutRequest::decode(&logout.encode()).unwrap(),
            logout
        );
    }

    #[test]
    fn account_requests_reject_invalid_shapes() {
        assert!(AccountLoginRequest::new("acme", "not-an-email", "password").is_err());
        assert!(AccountLoginRequest::new("acme", "user@example.test", "").is_err());
        assert!(AccountLoginRequest::new("", "user@example.test", "password").is_err());
        assert!(AccountLoginRequest::new("acme", "user@example.test", "x".repeat(1025)).is_err());

        let extended = {
            let mut builder = MapBuilder::new();
            builder.put(0, CborValue::Uint(ACCOUNT_SCHEMA_V1));
            builder.put(1, CborValue::Bytes(vec![1; ACCOUNT_TOKEN_LEN]));
            builder.put(2, CborValue::Uint(0));
            builder.finish()
        };
        assert!(AccountRefreshRequest::decode(&extended).is_err());
        assert!(AccountLogoutRequest::decode(&extended).is_err());

        let mut short_token = MapBuilder::new();
        short_token.put(0, CborValue::Uint(ACCOUNT_SCHEMA_V1));
        short_token.put(1, CborValue::Bytes(vec![1; 8]));
        assert!(AccountRefreshRequest::decode(&short_token.finish()).is_err());
    }

    #[test]
    fn account_debug_never_renders_secrets() {
        let login = AccountLoginRequest::new("acme", "user@example.test", "hunter2hunter2")
            .expect("valid login request");
        let rendered = alloc::format!("{login:?}");
        assert!(!rendered.contains("hunter2hunter2"));
        assert!(rendered.contains("<redacted>"));

        let session_secret_rendered = alloc::format!(
            "{:?}",
            AccountRefreshRequest::new([0x41; ACCOUNT_TOKEN_LEN])
        );
        assert!(!session_secret_rendered.contains("65"));
    }
}
