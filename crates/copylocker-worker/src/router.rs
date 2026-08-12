use std::collections::BTreeMap;

use copylocker_core::keys::{KeyMaterial, SessionKind};
use copylocker_proto::keywrap::{seal_credential_secret, CredentialSealContext};
use copylocker_proto::{
    ActivationRequest, Credential, DeactivateRequest, HeartbeatRequest, KillOrder, LicenseKey,
    MachineCredential, ValidateRequest, ValidationTicket,
};
use copylocker_server_core::policy::{OfflineUpgradePolicy, VtSignature};
use copylocker_suite::cbor::{CborValue, MapBuilder};
use copylocker_suite::{
    Artifact, DomainCtx, EnvEvidence, HashScheme, KeyEncapsulation, Secret, SharedSecret,
    Signature, SignatureScheme,
};
use copylocker_suite_std::{FastSig, Sha256Scheme, XWingKem};
use copylocker_types::{ArtifactKind, Fingerprint, KillReason, LicenseId, LicenseState, MachineId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use worker::{
    wasm_bindgen::JsValue, Context, Date, Env, Error, Headers, Method, Request, RequestInit,
    Response, Result,
};

use crate::bindings::authorization::{
    self, AuthorizationContext, AuthorizationError, LoadPurpose, ReleaseMaterial, SigningEpoch,
};
use crate::bindings::kv_cache;
use crate::bindings::rng::WorkerRng;
use crate::bindings::signing::FastEpochSigner;
use crate::events::{
    issuer_object_name, issuer_shard, SuspicionAlertEvent, SuspicionContribution,
    SUSPICION_ALERT_EVENT, SUSPICION_ALERT_SCHEMA_VERSION,
};
use crate::middleware::body::{self, BodyError};
use crate::response;
use crate::suites::{suite_dispatch, RequestSuite};

const CLIENT_PROTO_HEADER: &str = "X-CL-Proto";
const INVALID_CREDENTIAL: u64 = 1000;
const NEEDS_LOGIN: u64 = 1003;
const UNSUPPORTED_PROTO: u64 = 1004;
const SERVER_ERROR: u64 = 5000;

#[derive(Debug, Serialize)]
struct Health<'a> {
    ok: bool,
    service: &'a str,
    version: &'a str,
}

pub(crate) async fn route(mut request: Request, env: Env, _context: Context) -> Result<Response> {
    let method = request.method();
    let path = request.path();

    if let Some(provider) = crate::webhook::BillingProvider::parse_path(&path) {
        return crate::webhook::route(&mut request, &env, provider).await;
    }

    match path.as_str() {
        path if path == "/v1/admin" || path.starts_with("/v1/admin/") => {
            crate::admin::route(&mut request, &env).await
        }
        // Test-only introspection (404 outside `ENVIRONMENT == "test"`); see
        // `analytics::test_detail_event_queue_body`.
        "/__test/analytics-detail-queue-body" if method == Method::Get => {
            crate::analytics::test_detail_event_queue_body(&env)
        }
        "/health" if method == Method::Get => response::json(
            200,
            &Health {
                ok: true,
                service: "copylocker",
                version: env!("CARGO_PKG_VERSION"),
            },
        ),
        "/v1/keys" if method == Method::Get => {
            if let Some(response) = require_protocol(&request)? {
                return Ok(response);
            }
            keys(&env).await
        }
        "/v1/revocations" if method == Method::Get => {
            if let Some(response) = require_protocol(&request)? {
                return Ok(response);
            }
            revocations(&request, &env).await
        }
        "/v1/activate" if method == Method::Post => {
            if let Some(response) = require_protocol(&request)? {
                return Ok(response);
            }
            activate(&mut request, &env).await
        }
        "/v1/validate" if method == Method::Post => {
            if let Some(response) = require_protocol(&request)? {
                return Ok(response);
            }
            validate(&mut request, &env).await
        }
        "/v1/heartbeat" if method == Method::Post => {
            if let Some(response) = require_protocol(&request)? {
                return Ok(response);
            }
            heartbeat(&mut request, &env).await
        }
        "/v1/deactivate" if method == Method::Post => {
            if let Some(response) = require_protocol(&request)? {
                return Ok(response);
            }
            deactivate(&mut request, &env).await
        }
        "/v1/offline/request" if method == Method::Post => {
            if let Some(response) = require_protocol(&request)? {
                return Ok(response);
            }
            crate::offline::request(request, &env).await
        }
        "/v1/account/login" if method == Method::Post => {
            if let Some(response) = require_protocol(&request)? {
                return Ok(response);
            }
            crate::account::login(request, &env).await
        }
        "/v1/account/refresh" if method == Method::Post => {
            if let Some(response) = require_protocol(&request)? {
                return Ok(response);
            }
            crate::account::refresh(request, &env).await
        }
        "/v1/account/logout" if method == Method::Post => {
            if let Some(response) = require_protocol(&request)? {
                return Ok(response);
            }
            crate::account::logout(request, &env).await
        }
        "/v1/keys"
        | "/v1/revocations"
        | "/v1/activate"
        | "/v1/validate"
        | "/v1/heartbeat"
        | "/v1/deactivate"
        | "/v1/offline/request"
        | "/v1/account/login"
        | "/v1/account/refresh"
        | "/v1/account/logout"
            if method == Method::Options =>
        {
            response::cors_preflight()
        }
        "/v1/keys"
        | "/v1/revocations"
        | "/v1/activate"
        | "/v1/validate"
        | "/v1/heartbeat"
        | "/v1/deactivate"
        | "/v1/offline/request"
        | "/v1/account/login"
        | "/v1/account/refresh"
        | "/v1/account/logout" => response::protocol_error(405, INVALID_CREDENTIAL, None, None),
        path if path.starts_with("/v1/") => {
            response::protocol_error(404, INVALID_CREDENTIAL, None, None)
        }
        _ if method == Method::Get => response::api_error(404, "not_found", "route not found"),
        _ => response::api_error(405, "method_not_allowed", "HTTP method not allowed"),
    }
}

fn require_protocol(request: &Request) -> Result<Option<Response>> {
    let protocol = request.headers().get(CLIENT_PROTO_HEADER)?;
    if protocol.as_deref() == Some("1") {
        Ok(None)
    } else {
        Ok(Some(response::protocol_error(
            426,
            UNSUPPORTED_PROTO,
            None,
            None,
        )?))
    }
}

async fn keys(env: &Env) -> Result<Response> {
    match kv_cache::stream(env, "keys:current").await? {
        Some(stream) => response::cbor_stream(200, stream, "public, max-age=300"),
        None => response::protocol_error(503, SERVER_ERROR, None, Some(1)),
    }
}

async fn revocations(request: &Request, env: &Env) -> Result<Response> {
    let Some(since) = parse_since(request)? else {
        return response::protocol_error(400, INVALID_CREDENTIAL, None, None);
    };
    let key = format!("rev:batch:{since}");
    match kv_cache::stream(env, &key).await? {
        Some(stream) => response::cbor_stream(200, stream, "public, max-age=31536000, immutable"),
        None => response::protocol_error(503, SERVER_ERROR, None, Some(1)),
    }
}

fn parse_since(request: &Request) -> Result<Option<u64>> {
    let url = request.url()?;
    let mut since = None;
    for (name, value) in url.query_pairs() {
        if name != "since" || since.is_some() {
            return Ok(None);
        }
        since = value.parse::<u64>().ok();
        if since.is_none() {
            return Ok(None);
        }
    }
    Ok(since)
}

async fn activate(request: &mut Request, env: &Env) -> Result<Response> {
    // Country-level geo for the analytics detail stream; never an IP.
    let country = request.cf().and_then(|cf| cf.country());
    let parsed = match parse_activation_request(request, env).await? {
        Ok(parsed) => parsed,
        Err(response) => return Ok(response),
    };
    let credential = match resolve_activation_credential(env, &parsed.activation).await? {
        Ok(credential) => credential,
        Err(response) => return Ok(response),
    };
    let now = now_seconds();
    let authorization =
        match authorize_activation(env, &parsed.activation, &credential, now).await? {
            Ok(authorization) => authorization,
            Err(response) => return Ok(response),
        };
    let activation_path = match &credential {
        ActivationCredential::LicenseKey(_) => "online",
        ActivationCredential::Account(_) => "account",
    };
    let issued = match issue_activation(env, &parsed, &authorization, activation_path, country, now)
        .await?
    {
        Ok(issued) => issued,
        Err(response) => return Ok(response),
    };
    response::cbor(200, issued.envelope, "no-store")
}

pub(crate) struct ParsedActivation {
    pub(crate) activation: ActivationRequest,
    pub(crate) idempotency_key: String,
    pub(crate) request_hash: Vec<u8>,
    pub(crate) suite: RequestSuite,
    pub(crate) device_encapsulation_key: <XWingKem as KeyEncapsulation>::EncapKey,
}

/// Parse and authenticate the shared shape of `/v1/activate` and `/v1/offline/request`.
pub(crate) async fn parse_activation_request(
    request: &mut Request,
    env: &Env,
) -> Result<std::result::Result<ParsedActivation, Response>> {
    let bytes = match body::read_cbor(request).await {
        Ok(bytes) => bytes,
        Err(error) => return Ok(Err(body_error(error)?)),
    };
    let Some(idempotency_key) = idempotency_key(request)? else {
        return Ok(Err(response::protocol_error(
            400,
            INVALID_CREDENTIAL,
            None,
            None,
        )?));
    };
    let request_hash = Sha256Scheme::hash(&bytes);
    let activation = match ActivationRequest::decode(&bytes) {
        Ok(activation) => activation,
        Err(_) => {
            return Ok(Err(response::protocol_error(
                400,
                INVALID_CREDENTIAL,
                None,
                None,
            )?));
        }
    };
    if activation.proto_ver != copylocker_types::PROTO_VER {
        return Ok(Err(response::protocol_error(
            426,
            UNSUPPORTED_PROTO,
            None,
            None,
        )?));
    }
    let Some(suite) = RequestSuite::resolve(env, activation.suite_id) else {
        return Ok(Err(response::protocol_error(
            403,
            INVALID_CREDENTIAL,
            None,
            None,
        )?));
    };
    if activation.fingerprint.as_bytes().len() != 32 || !activation_proof_is_valid(&activation) {
        return Ok(Err(response::protocol_error(
            403,
            INVALID_CREDENTIAL,
            None,
            None,
        )?));
    }
    let device_encapsulation_key = match suite_dispatch!(
        suite,
        S,
        <S as copylocker_suite::CryptoSuite>::Kem::decode_ek(&activation.device_kem_ek)
    ) {
        Ok(key) => key,
        Err(_) => {
            return Ok(Err(response::protocol_error(
                403,
                INVALID_CREDENTIAL,
                None,
                None,
            )?));
        }
    };
    Ok(Ok(ParsedActivation {
        activation,
        idempotency_key,
        request_hash: request_hash.as_bytes().to_vec(),
        suite,
        device_encapsulation_key,
    }))
}

/// How an activation authenticates: a user-typed license key (Mode O) or a bearer account
/// token whose session the `AccountDO` has confirmed (Mode E).
pub(crate) enum ActivationCredential {
    LicenseKey(LicenseKey),
    Account(String),
}

pub(crate) async fn resolve_activation_credential(
    env: &Env,
    activation: &ActivationRequest,
) -> Result<std::result::Result<ActivationCredential, Response>> {
    match &activation.credential {
        Credential::LicenseKey(value) => match LicenseKey::parse(value) {
            Ok(key) => Ok(Ok(ActivationCredential::LicenseKey(key))),
            Err(_) => Ok(Err(response::protocol_error(
                403,
                INVALID_CREDENTIAL,
                None,
                None,
            )?)),
        },
        Credential::AccountToken(token) => {
            match crate::account::resolve_session(env, token).await? {
                Some(account_id) => Ok(Ok(ActivationCredential::Account(account_id))),
                None => Ok(Err(response::protocol_error(401, NEEDS_LOGIN, None, None)?)),
            }
        }
    }
}

/// Load the authorization context for an activation and apply every check that is identical
/// across the online and offline-relay paths.
pub(crate) async fn authorize_activation(
    env: &Env,
    activation: &ActivationRequest,
    credential: &ActivationCredential,
    now: i64,
) -> Result<std::result::Result<AuthorizationContext, Response>> {
    let loaded = match credential {
        ActivationCredential::LicenseKey(license_key) => {
            authorization::load_by_license_key(
                env,
                license_key,
                &activation.client_info.release_id,
                LoadPurpose::Activate,
                now,
            )
            .await
        }
        ActivationCredential::Account(account_id) => {
            authorization::load_by_account(
                env,
                account_id,
                &activation.client_info.release_id,
                LoadPurpose::Activate,
                now,
            )
            .await
        }
    };
    let authorization = match loaded {
        Ok(context) => context,
        Err(error) => {
            return Ok(Err(authorization_rejection(
                error,
                &registration_hint(Some(&activation.product_id), &activation.client_info),
            )?));
        }
    };
    if authorization.product_id != activation.product_id
        || authorization.license_status != "active"
        || authorization.expires_at.is_some_and(|expiry| now >= expiry)
    {
        return Ok(Err(response::protocol_error(
            403,
            INVALID_CREDENTIAL,
            None,
            None,
        )?));
    }
    // Mode E first activation requires the account credential: a license key alone never
    // activates an enforced-online policy (`prd.md` §5.2).
    if authorization.policy.mode == copylocker_types::Mode::EnforcedOnline
        && matches!(credential, ActivationCredential::LicenseKey(_))
    {
        return Ok(Err(response::protocol_error(401, NEEDS_LOGIN, None, None)?));
    }
    let Some(release) = authorization.release.as_ref() else {
        return Err(Error::RustError(
            "activation authorization omitted release material".to_owned(),
        ));
    };
    if release.release_id != activation.client_info.release_id
        || release.variant_id != activation.client_info.variant_id
        || release.build_fingerprint != activation.client_info.build_fingerprint
    {
        return Ok(Err(response::protocol_error(
            403,
            INVALID_CREDENTIAL,
            None,
            None,
        )?));
    }
    if activation.device_attrs.as_ref().is_some_and(|attrs| {
        attrs.env_class() == copylocker_suite::device::EnvClass::VirtualMachine
            && !authorization.policy.runtime.allow_vm
    }) {
        return Ok(Err(response::protocol_error(
            403,
            INVALID_CREDENTIAL,
            None,
            None,
        )?));
    }
    Ok(Ok(authorization))
}

pub(crate) struct IssuedActivation {
    pub(crate) envelope: Vec<u8>,
    pub(crate) license_id: LicenseId,
    pub(crate) product_id: String,
}

/// Reserve the seat, seal the credential to the device key, sign the machine credential, and
/// complete the reservation. Shared by `/v1/activate` and `/v1/offline/request`, which differ
/// only in how the signed envelope is returned. `country` is the request's country-level geo
/// for the analytics detail stream (`None` on the offline relay, where the relay's location
/// would masquerade as the offline device's).
pub(crate) async fn issue_activation(
    env: &Env,
    parsed: &ParsedActivation,
    authorization: &AuthorizationContext,
    activation_path: &str,
    country: Option<String>,
    now: i64,
) -> Result<std::result::Result<IssuedActivation, Response>> {
    let activation = &parsed.activation;
    let release = authorization
        .release
        .as_ref()
        .ok_or_else(|| Error::RustError("activation release material is unavailable".to_owned()))?;
    let epoch = authorization::load_signing_epoch(env, &authorization.product_id, now)
        .await
        .map_err(authorization_server_error)?;
    let authoritative_security_floor = authorization::current_security_floor(env)
        .await
        .map_err(authorization_server_error)?;
    let heartbeat_sec = authorization
        .heartbeat_secs
        .map(u64::try_from)
        .transpose()
        .map_err(|_| Error::RustError("authorization heartbeat interval is invalid".to_owned()))?;
    let init = InitLicenseCall {
        license_id: authorization.license_id.as_bytes().to_vec(),
        product_id: authorization.product_id.clone(),
        suite_id: activation.suite_id.as_bytes().to_vec(),
        seats: authorization.seats,
        heartbeat_sec,
        expires_at: authorization.expires_at,
    };
    if let LicenseCall::Rejected { status, error } =
        call_license::<_, OkDoResponse>(env, &authorization.license_id, "/init", &init).await?
    {
        return Ok(Err(activation_do_rejection(status, &error)?));
    }

    let mut rng = WorkerRng::new()?;
    let candidate_machine_id = MachineId(rng.random_array::<16>()?);
    let candidate_secret = Secret::new(rng.random_array::<32>()?);
    let candidate_state = release.seal_credential_state(
        authorization.license_id,
        &activation.fingerprint,
        &candidate_secret,
        &mut rng,
    )?;
    rng.ensure_healthy()?;
    let attrs = if authorization.policy.runtime.report_attrs {
        activation
            .device_attrs
            .as_ref()
            .map(copylocker_suite::device::DeviceAttrs::canonical_bytes)
    } else {
        None
    };
    let reserve = ReserveLicenseCall {
        idempotency_key: parsed.idempotency_key.clone(),
        request_hash: parsed.request_hash.clone(),
        machine_id: candidate_machine_id.as_bytes().to_vec(),
        fingerprint: activation.fingerprint.as_bytes().to_vec(),
        attrs,
        device_kem_ek: activation.device_kem_ek.clone(),
        device_sig_vk: activation.device_sig_vk.clone(),
        activation_path: activation_path.to_owned(),
        release_id: release.release_id.clone(),
        variant_id: release.variant_id,
        refresh_after: authorization.next_refresh_after(now),
        not_after: authorization.not_after(now),
        build_fp: Some(release.build_fingerprint.clone()),
        app_version: Some(activation.client_info.app_version.clone()),
        os: Some(activation.client_info.os.clone()),
        arch: Some(activation.client_info.arch.clone()),
        sdk_version: Some(activation.client_info.sdk_version.clone()),
        geo: None,
        credential_state: Some(candidate_state),
        authoritative_security_floor,
    };
    let reservation = match call_license::<_, ReserveDoResponse>(
        env,
        &authorization.license_id,
        "/reserve",
        &reserve,
    )
    .await?
    {
        LicenseCall::Success(reservation) => reservation,
        LicenseCall::Rejected { status, error } => {
            return Ok(Err(activation_do_rejection(status, &error)?));
        }
    };
    drop(candidate_secret);
    if !reservation.ok {
        return Err(Error::RustError(
            "LicenseDO returned an unsuccessful reservation".to_owned(),
        ));
    }
    if let Some(envelope) = reservation.activation_envelope {
        return Ok(Ok(IssuedActivation {
            envelope,
            license_id: authorization.license_id,
            product_id: authorization.product_id.clone(),
        }));
    }
    if reservation.fingerprint != activation.fingerprint.as_bytes()
        || reservation.variant_id < 0
        || reservation.refresh_after <= 0
        || reservation.not_after < 0
        || reservation.build_fp.as_deref() != Some(release.build_fingerprint.as_str())
    {
        return Err(Error::RustError(
            "LicenseDO returned inconsistent reservation state".to_owned(),
        ));
    }
    let machine_id = MachineId::from_slice(&reservation.machine_id).ok_or_else(|| {
        Error::RustError("LicenseDO returned an invalid machine identifier".to_owned())
    })?;
    let issuance_fingerprint = Fingerprint::from_vec(reservation.fingerprint.clone());
    let encrypted_state = reservation.credential_state.as_deref().ok_or_else(|| {
        Error::RustError("LicenseDO omitted activation credential state".to_owned())
    })?;
    let credential_secret = release.open_credential_state(
        authorization.license_id,
        &issuance_fingerprint,
        encrypted_state,
    )?;
    let (kem_ct, kem_shared_secret) = suite_dispatch!(
        parsed.suite,
        S,
        <S as copylocker_suite::CryptoSuite>::Kem::encap(
            &parsed.device_encapsulation_key,
            &mut rng
        )
    )
    .map_err(|_| Error::RustError("device credential encapsulation failed".to_owned()))?;
    let offline_nonce = rng.random_array::<32>()?;
    let variant_id = u64::try_from(reservation.variant_id)
        .map_err(|_| Error::RustError("LicenseDO returned an invalid variant".to_owned()))?;
    let seal_context = CredentialSealContext {
        proto_ver: copylocker_types::PROTO_VER,
        suite_id: activation.suite_id,
        product_id: &authorization.product_id,
        license_id: authorization.license_id,
        machine_id,
        fingerprint: &issuance_fingerprint,
        kem_ct: kem_ct.as_bytes(),
        offline_nonce: &offline_nonce,
        epoch_id: epoch.epoch_id,
        variant_id,
    };
    let sealed_cs = suite_dispatch!(
        parsed.suite,
        S,
        seal_credential_secret::<S>(
            &kem_shared_secret,
            &seal_context,
            &credential_secret,
            &mut rng
        )
    )
    .map_err(|_| Error::RustError("credential secret sealing failed".to_owned()))?;
    let wrapped_keks = wrap_offline_keks(
        authorization,
        &epoch,
        machine_id,
        &issuance_fingerprint,
        &credential_secret,
        offline_nonce,
        parsed.suite,
        &mut rng,
    )?;
    let preloaded_keks = preload_offline_keks(
        env,
        authorization,
        &epoch,
        machine_id,
        &issuance_fingerprint,
        &credential_secret,
        offline_nonce,
        parsed.suite,
        &mut rng,
    )
    .await?;
    rng.ensure_healthy()?;

    let revocation_epoch = u64::try_from(reservation.revocation_epoch)
        .map_err(|_| Error::RustError("LicenseDO revocation epoch is invalid".to_owned()))?;
    let security_floor = u64::try_from(reservation.security_floor)
        .map_err(|_| Error::RustError("LicenseDO security floor is invalid".to_owned()))?;
    let credential = MachineCredential {
        proto_ver: copylocker_types::PROTO_VER,
        suite_id: activation.suite_id,
        product_id: authorization.product_id.clone(),
        license_id: authorization.license_id,
        machine_id,
        fingerprint: issuance_fingerprint,
        kem_ct: kem_ct.as_bytes().to_vec(),
        sealed_cs,
        offline_nonce,
        entitlements: authorization.entitlements.clone(),
        issued_at: now,
        not_after: reservation.not_after,
        refresh_after: reservation.refresh_after,
        grace_seconds: authorization.policy.runtime.grace_secs,
        mode: authorization.policy.mode,
        revocation_epoch,
        epoch_id: epoch.epoch_id,
        build_fingerprint: reservation.build_fp,
        policy_flags: None,
        security_floor,
        variant_id,
        wrapped_keks,
        preloaded_keks,
    };
    let tbs = credential
        .to_canonical()
        .map_err(|_| Error::RustError("machine credential encoding failed".to_owned()))?;
    let envelope = issue_artifact(
        env,
        authorization.license_id,
        &authorization.product_id,
        authorization.license_id.as_bytes().to_vec(),
        ArtifactKind::MachineCred,
        tbs,
    )
    .await?;
    let complete = CompleteLicenseCall {
        idempotency_key: parsed.idempotency_key.clone(),
        request_hash: parsed.request_hash.clone(),
        machine_id: machine_id.as_bytes().to_vec(),
        activation_envelope: envelope,
    };
    match call_license::<_, CompleteDoResponse>(
        env,
        &authorization.license_id,
        "/complete",
        &complete,
    )
    .await?
    {
        LicenseCall::Success(result) if result.ok => {
            // A genuinely completed activation joins the detail stream; idempotent replays
            // return the stored envelope above and never reach this point.
            crate::analytics::emit_activation_detail(
                env,
                authorization,
                &parsed.activation,
                machine_id,
                activation_path,
                reservation.reused_existing,
                country,
                now,
            )
            .await;
            Ok(Ok(IssuedActivation {
                envelope: result.envelope,
                license_id: authorization.license_id,
                product_id: authorization.product_id.clone(),
            }))
        }
        LicenseCall::Success(_) => Err(Error::RustError(
            "LicenseDO returned an unsuccessful activation completion".to_owned(),
        )),
        LicenseCall::Rejected { status, error } => {
            Ok(Err(activation_do_rejection(status, &error)?))
        }
    }
}

fn activation_proof_is_valid(activation: &ActivationRequest) -> bool {
    let Ok(verifying_key) = FastSig::decode_vk(&activation.device_sig_vk) else {
        return false;
    };
    let signature = Signature(activation.proof.clone());
    let context = DomainCtx::new(
        ArtifactKind::ActivationRequest,
        activation.suite_id,
        &activation.product_id,
    );
    FastSig::verify(
        &verifying_key,
        context,
        &activation.proof_input(),
        &signature,
    )
    .is_ok()
}

#[allow(clippy::too_many_arguments)]
fn wrap_offline_keks(
    authorization: &AuthorizationContext,
    epoch: &SigningEpoch,
    machine_id: MachineId,
    fingerprint: &Fingerprint,
    credential_secret: &Secret<[u8; 32]>,
    offline_nonce: [u8; 32],
    suite: RequestSuite,
    rng: &mut WorkerRng,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let release = authorization
        .release
        .as_ref()
        .ok_or_else(|| Error::RustError("activation release material is unavailable".to_owned()))?;
    wrap_release_keks(
        release,
        authorization,
        epoch,
        machine_id,
        fingerprint,
        credential_secret,
        offline_nonce,
        suite,
        rng,
    )
}

/// `preload_n` offline upgrades (`versioning-and-variants.md` §3.2): wrap the entitled asset
/// KEKs of the newest registered sibling releases into `preloaded_keks`, keyed by their
/// variant, so a device that upgrades while offline can still open the new build's assets.
/// `require_online` (the default) preloads nothing; `variant_stable` needs nothing because
/// every release shares the issuing variant.
#[allow(clippy::too_many_arguments)]
async fn preload_offline_keks(
    env: &Env,
    authorization: &AuthorizationContext,
    epoch: &SigningEpoch,
    machine_id: MachineId,
    fingerprint: &Fingerprint,
    credential_secret: &Secret<[u8; 32]>,
    offline_nonce: [u8; 32],
    suite: RequestSuite,
    rng: &mut WorkerRng,
) -> Result<Option<BTreeMap<u64, BTreeMap<String, Vec<u8>>>>> {
    if authorization.policy.runtime.offline_upgrade_policy != OfflineUpgradePolicy::PreloadN {
        return Ok(None);
    }
    let current = authorization
        .release
        .as_ref()
        .ok_or_else(|| Error::RustError("activation release material is unavailable".to_owned()))?;
    let database = env.d1("DB")?;
    let sibling_ids = authorization::preload_release_ids(
        &database,
        &authorization.product_id,
        &current.release_id,
        authorization.policy.runtime.preload_variants_n,
    )
    .await
    .map_err(authorization_server_error)?;
    let mut preloaded = BTreeMap::new();
    for sibling_id in sibling_ids {
        let Some(release) = authorization::load_release_material_by_id(
            env,
            &database,
            &sibling_id,
            &authorization.product_id,
        )
        .await
        .map_err(authorization_server_error)?
        else {
            continue;
        };
        if release.variant_id == current.variant_id {
            continue;
        }
        let wrapped = wrap_release_keks(
            &release,
            authorization,
            epoch,
            machine_id,
            fingerprint,
            credential_secret,
            offline_nonce,
            suite,
            rng,
        )?;
        if !wrapped.is_empty() {
            preloaded.insert(release.variant_id, wrapped);
        }
    }
    rng.ensure_healthy()?;
    if preloaded.is_empty() {
        Ok(None)
    } else {
        Ok(Some(preloaded))
    }
}

#[allow(clippy::too_many_arguments)]
fn wrap_release_keks(
    release: &ReleaseMaterial,
    authorization: &AuthorizationContext,
    epoch: &SigningEpoch,
    machine_id: MachineId,
    fingerprint: &Fingerprint,
    credential_secret: &Secret<[u8; 32]>,
    offline_nonce: [u8; 32],
    suite: RequestSuite,
    rng: &mut WorkerRng,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let shared_secret = SharedSecret::new(*credential_secret.expose());
    let evidence = EnvEvidence {
        module_digest: release.module_digest,
        build_fingerprint: release.build_fingerprint.as_bytes().to_vec(),
        extra: release.binder_extra.clone(),
    };
    let material = suite_dispatch!(
        suite,
        S,
        KeyMaterial::bind::<S>(
            &shared_secret,
            fingerprint,
            &evidence,
            &authorization.product_id,
            authorization.license_id,
            machine_id,
            epoch.epoch_id,
            release.variant_id,
            release.variant_const,
            offline_nonce,
        )
    )
    .map_err(|_| Error::RustError("offline key material derivation failed".to_owned()))?;

    let mut wrapped = BTreeMap::new();
    for asset in &release.asset_keks {
        if !authorization.entitlements.has_feature(&asset.feature_id) {
            continue;
        }
        let value = suite_dispatch!(
            suite,
            S,
            material.wrap_kek::<S>(
                LicenseState::Active,
                &authorization.entitlements,
                &asset.feature_id,
                SessionKind::Offline,
                &asset.key,
                rng,
            )
        )
        .map_err(|_| Error::RustError("offline asset KEK wrapping failed".to_owned()))?;
        wrapped.insert(asset.feature_id.clone(), value);
    }
    Ok(wrapped)
}

async fn validate(request: &mut Request, env: &Env) -> Result<Response> {
    // Country-level geo for the analytics detail stream (`90-analytics-telemetry.md
    // §2.4`); never an IP. Captured before the body is consumed.
    let country = request.cf().and_then(|cf| cf.country());
    let validation = match decode_request::<ValidateRequest>(request).await? {
        Ok(request) => request,
        Err(response) => return Ok(response),
    };
    if validation.proto_ver != copylocker_types::PROTO_VER {
        return response::protocol_error(426, UNSUPPORTED_PROTO, None, None);
    }
    let Some(suite) = RequestSuite::resolve(env, validation.suite_id) else {
        return response::protocol_error(403, INVALID_CREDENTIAL, None, None);
    };

    let now = now_seconds();
    let authorization = match authorization::load_by_license_id(
        env,
        validation.license_id,
        &validation.client_info.release_id,
        LoadPurpose::Validate,
        now,
    )
    .await
    {
        Ok(context) => context,
        Err(error) => {
            return authorization_rejection(
                error,
                &registration_hint(None, &validation.client_info),
            );
        }
    };
    let variant_id = authorization
        .release
        .as_ref()
        .map(|release| {
            i64::try_from(release.variant_id)
                .map_err(|_| Error::RustError("release variant id is too large".to_owned()))
        })
        .transpose()?;
    let authoritative_revocation_epoch = crate::admin::current_revocation_epoch(env).await?;
    let authoritative_security_floor = authorization::current_security_floor(env)
        .await
        .map_err(authorization_server_error)?;
    let call = ValidateMachineCall {
        auth: AuthenticatedMachineCall {
            license_id: validation.license_id.as_bytes().to_vec(),
            machine_id: validation.machine_id.as_bytes().to_vec(),
            suite_id: validation.suite_id.as_bytes().to_vec(),
            nonce: validation.nonce_c.to_vec(),
            proof_input: validation.proof_input(),
            proof: validation.proof.clone(),
            idempotency_key: None,
        },
        known_revocation_epoch: validation.known_revocation_epoch,
        authoritative_revocation_epoch,
        known_security_floor: validation.known_security_floor,
        next_refresh_after: authorization.next_refresh_after(now),
        not_after: authorization.not_after(now),
        variant_id,
        authoritative_security_floor,
    };
    let state = match call_license::<_, ValidateDoResponse>(
        env,
        &validation.license_id,
        "/validate",
        &call,
    )
    .await?
    {
        LicenseCall::Success(state) => state,
        LicenseCall::Rejected { status, error } => return do_rejection(status, &error),
    };
    if !state.ok {
        return Err(Error::RustError(
            "LicenseDO returned an unsuccessful validation result".to_owned(),
        ));
    }
    let revocation_epoch = u64::try_from(state.revocation_epoch)
        .map_err(|_| Error::RustError("LicenseDO revocation epoch is invalid".to_owned()))?;
    let security_floor = u64::try_from(state.security_floor)
        .map_err(|_| Error::RustError("LicenseDO security floor is invalid".to_owned()))?;
    let epoch = authorization::load_signing_epoch(env, &authorization.product_id, now)
        .await
        .map_err(authorization_server_error)?;

    let do_kill_reason = state
        .kill_reason
        .map(|reason| {
            KillReason::from_u8(reason)
                .ok_or_else(|| Error::RustError("LicenseDO kill reason is invalid".to_owned()))
        })
        .transpose()?;
    let kill_reason = do_kill_reason.or(authorization.kill_reason);
    match (state.outcome.as_str(), kill_reason) {
        ("kill", Some(reason)) | ("ticket", Some(reason)) => {
            let order = KillOrder {
                proto_ver: copylocker_types::PROTO_VER,
                suite_id: validation.suite_id,
                machine_id: validation.machine_id,
                nonce_c_echo: validation.nonce_c,
                server_time: now,
                reason,
                user_message: kill_message(reason).map(str::to_owned),
                revocation_epoch,
            };
            let envelope = sign_online_artifact(
                env,
                &authorization,
                &epoch,
                validation.machine_id,
                &order,
                validation.suite_id,
            )
            .await?;
            response::cbor(200, envelope, "no-store")
        }
        ("ticket", None) => {
            // T1 telemetry consumption + the check-in detail stream run here, after the
            // LicenseDO has verified the device proof (which covers proto key 11), and
            // strictly best-effort: analytics can never fail a validate.
            crate::analytics::emit_check_in_detail(
                env,
                &authorization,
                &validation,
                state.activation_path.as_deref(),
                country,
                now,
            )
            .await;
            let suspicion_score = u8::try_from(state.suspicion)
                .ok()
                .filter(|score| *score <= 100)
                .ok_or_else(|| {
                    Error::RustError("LicenseDO suspicion score is invalid".to_owned())
                })?;
            maybe_enqueue_suspicion_alert(
                env,
                &authorization,
                validation.license_id,
                validation.machine_id,
                suspicion_score,
                state.previous_suspicion,
                state.suspicion_contributions.as_deref(),
                now,
            )
            .await;
            let mut rng = WorkerRng::new()?;
            let server_nonce = rng.random_array::<32>()?;
            let issuance_fingerprint =
                state
                    .fingerprint
                    .map(Fingerprint::from_vec)
                    .ok_or_else(|| {
                        Error::RustError(
                            "LicenseDO omitted the activation fingerprint for a ticket".to_owned(),
                        )
                    })?;
            let wrapped_keks = wrap_online_keks(
                &authorization,
                &epoch,
                &validation,
                &issuance_fingerprint,
                state.credential_state.as_deref(),
                server_nonce,
                suite,
                &mut rng,
            )?;
            rng.ensure_healthy()?;
            let ticket = ValidationTicket {
                proto_ver: copylocker_types::PROTO_VER,
                suite_id: validation.suite_id,
                machine_id: validation.machine_id,
                nonce_c_echo: validation.nonce_c,
                server_nonce,
                server_time: now,
                next_refresh_after: authorization.next_refresh_after(now),
                not_after: authorization.not_after(now),
                revocation_epoch,
                verdict: authorization.verdict,
                entitlements: Some(authorization.entitlements.clone()),
                epoch_id: epoch.epoch_id,
                suspicion_score: Some(suspicion_score),
                security_floor,
                release_status: authorization.release_status,
                wrapped_keks,
                refresh_now: Some(validation.known_revocation_epoch < revocation_epoch),
            };
            let envelope = sign_online_artifact(
                env,
                &authorization,
                &epoch,
                validation.machine_id,
                &ticket,
                validation.suite_id,
            )
            .await?;
            response::cbor(200, envelope, "no-store")
        }
        _ => Err(Error::RustError(
            "LicenseDO validation outcome is inconsistent".to_owned(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn wrap_online_keks(
    authorization: &AuthorizationContext,
    epoch: &SigningEpoch,
    validation: &ValidateRequest,
    issuance_fingerprint: &Fingerprint,
    credential_state: Option<&[u8]>,
    server_nonce: [u8; 32],
    suite: RequestSuite,
    rng: &mut WorkerRng,
) -> Result<Option<BTreeMap<String, Vec<u8>>>> {
    let Some(release) = authorization.release.as_ref() else {
        return Ok(None);
    };
    if release.asset_keks.is_empty() {
        return Ok(None);
    }
    let encrypted = credential_state.ok_or_else(|| {
        Error::RustError(
            "activation credential state is unavailable for registered KEKs".to_owned(),
        )
    })?;
    let credential =
        release.open_credential_state(authorization.license_id, issuance_fingerprint, encrypted)?;
    let shared_secret = SharedSecret::new(*credential.expose());
    let evidence = EnvEvidence {
        module_digest: release.module_digest,
        build_fingerprint: validation.client_info.build_fingerprint.as_bytes().to_vec(),
        extra: release.binder_extra.clone(),
    };
    let mut material = suite_dispatch!(
        suite,
        S,
        KeyMaterial::bind::<S>(
            &shared_secret,
            issuance_fingerprint,
            &evidence,
            &authorization.product_id,
            authorization.license_id,
            validation.machine_id,
            epoch.epoch_id,
            release.variant_id,
            release.variant_const,
            [0; 32],
        )
    )
    .map_err(|_| Error::RustError("online key material derivation failed".to_owned()))?;
    material.set_server_nonce(server_nonce);

    let mut wrapped = BTreeMap::new();
    for asset in &release.asset_keks {
        if !authorization.entitlements.has_feature(&asset.feature_id) {
            continue;
        }
        let value = suite_dispatch!(
            suite,
            S,
            material.wrap_kek::<S>(
                LicenseState::Active,
                &authorization.entitlements,
                &asset.feature_id,
                SessionKind::Online,
                &asset.key,
                rng,
            )
        )
        .map_err(|_| Error::RustError("online asset KEK wrapping failed".to_owned()))?;
        wrapped.insert(asset.feature_id.clone(), value);
    }
    rng.ensure_healthy()?;
    Ok(Some(wrapped))
}

async fn sign_online_artifact<A: Artifact>(
    env: &Env,
    authorization: &AuthorizationContext,
    epoch: &SigningEpoch,
    machine_id: MachineId,
    artifact: &A,
    suite_id: copylocker_types::SuiteId,
) -> Result<Vec<u8>> {
    match authorization.policy.runtime.vt_signature {
        VtSignature::Fast => FastEpochSigner::load(env, epoch).await?.seal(
            artifact,
            &authorization.product_id,
            suite_id,
        ),
        VtSignature::Pq => {
            let tbs = artifact
                .to_canonical()
                .map_err(|_| Error::RustError("artifact encoding failed".to_owned()))?;
            issue_artifact(
                env,
                authorization.license_id,
                &authorization.product_id,
                machine_id.as_bytes().to_vec(),
                A::KIND,
                tbs,
            )
            .await
        }
    }
}

pub(crate) async fn issue_artifact(
    env: &Env,
    license_id: LicenseId,
    product_id: &str,
    subject: Vec<u8>,
    kind: ArtifactKind,
    tbs: Vec<u8>,
) -> Result<Vec<u8>> {
    let routing_key = license_id.as_bytes();
    let shard = issuer_shard(routing_key);
    let tbs_digest = Sha256Scheme::hash(&tbs);
    let call = IssueCall {
        idempotency_key: format!("issue-{}-{}", kind as u8, tbs_digest.to_hex()),
        shard,
        routing_key: routing_key.to_vec(),
        kind: kind as u8,
        product_id: product_id.to_owned(),
        subject,
        tbs,
    };
    let namespace = env.durable_object("ISSUER")?;
    let stub = namespace.get_by_name(&issuer_object_name(shard))?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&serde_json::to_string(&call)?)));
    let request = Request::new_with_init("https://issuer.internal/sign", &init)?;
    let mut result = stub.fetch_with_request(request).await?;
    if !(200..300).contains(&result.status_code()) {
        let error = result.json::<InternalDoError>().await?.error;
        return Err(Error::RustError(format!(
            "IssuerDO rejected artifact signing: {error}"
        )));
    }
    Ok(result.json::<IssueDoResponse>().await?.envelope)
}

fn authorization_rejection(error: AuthorizationError, registration_hint: &str) -> Result<Response> {
    match error {
        AuthorizationError::InvalidCredential => {
            response::protocol_error(403, INVALID_CREDENTIAL, None, None)
        }
        AuthorizationError::ReleaseNotRegistered => {
            response::protocol_error(403, 1007, Some(registration_hint), None)
        }
        AuthorizationError::VersionOutOfScope => response::protocol_error(409, 1008, None, None),
        AuthorizationError::ReleaseCompromised => response::protocol_error(403, 1009, None, None),
        AuthorizationError::Server(error) => Err(error),
    }
}

/// The 1007 detail names the exact registration command (`protocol-spec.md` §10.3,
/// AC-20): an unregistered release is a release-engineering mistake, not piracy.
fn registration_hint(
    product_id: Option<&str>,
    client_info: &copylocker_proto::ClientInfo,
) -> String {
    let product = product_id
        .map(|id| format!(" --product {id}"))
        .unwrap_or_default();
    format!(
        "release {} is not registered; run `copylocker release register{} --app-version {} \
         --build-fingerprint {}` to publish it",
        client_info.release_id, product, client_info.app_version, client_info.build_fingerprint
    )
}

fn authorization_server_error(error: AuthorizationError) -> Error {
    match error {
        AuthorizationError::Server(error) => error,
        _ => Error::RustError("signing epoch authorization failed".to_owned()),
    }
}

/// Alerting must never break validation: delivery problems are logged, not propagated.
#[allow(clippy::too_many_arguments)]
async fn maybe_enqueue_suspicion_alert(
    env: &Env,
    authorization: &AuthorizationContext,
    license_id: LicenseId,
    machine_id: MachineId,
    score: u8,
    previous: i64,
    contributions: Option<&[SuspicionContribution]>,
    now: i64,
) {
    if let Err(error) = enqueue_suspicion_alert(
        env,
        authorization,
        license_id,
        machine_id,
        score,
        previous,
        contributions,
        now,
    )
    .await
    {
        worker::console_error!(
            "{}",
            serde_json::json!({
                "level": "error",
                "message": "suspicion alert could not be enqueued",
                "license_id": license_id.to_hex(),
                "error": error.to_string()
            })
        );
    }
}

/// Rising-edge alert: enqueue only when the score crosses the configured threshold from below,
/// so a noisy license does not produce one webhook per validation.
#[allow(clippy::too_many_arguments)]
async fn enqueue_suspicion_alert(
    env: &Env,
    authorization: &AuthorizationContext,
    license_id: LicenseId,
    machine_id: MachineId,
    score: u8,
    previous: i64,
    contributions: Option<&[SuspicionContribution]>,
    now: i64,
) -> Result<()> {
    let database = env.d1("DB")?;
    let config =
        crate::admin_resources::load_alert_config(&database, &authorization.product_id).await?;
    let threshold = u8::try_from(config.threshold.unwrap_or(70))
        .map_err(|_| Error::RustError("alert suspicion threshold is invalid".to_owned()))?;
    let previous_score = u8::try_from(previous.clamp(0, 100)).unwrap_or(0);
    if score < threshold || previous_score >= threshold {
        return Ok(());
    }
    let Some(_) = config.url else {
        // "Record only": without a configured webhook the crossing is logged and nothing is
        // delivered (`10-server-worker.md` §2.5).
        worker::console_log!(
            "{}",
            serde_json::json!({
                "level": "warn",
                "message": "suspicion threshold crossed without a configured alert webhook",
                "product_id": authorization.product_id,
                "license_id": license_id.to_hex(),
                "machine_id": machine_id.to_hex(),
                "score": score,
                "threshold": threshold,
            })
        );
        return Ok(());
    };
    let event = SuspicionAlertEvent {
        event: SUSPICION_ALERT_EVENT.to_owned(),
        schema_version: SUSPICION_ALERT_SCHEMA_VERSION,
        occurred_at: now,
        product_id: authorization.product_id.clone(),
        license_id: license_id.to_hex(),
        machine_id: machine_id.to_hex(),
        score,
        previous_score,
        threshold,
        contributions: contributions.unwrap_or(&[]).to_vec(),
    };
    env.queue("EVENTS")?.send(event).await?;
    Ok(())
}

fn kill_message(reason: KillReason) -> Option<&'static str> {
    match reason {
        KillReason::RevokedLicense => {
            Some("This license has been revoked. Please contact support.")
        }
        KillReason::RevokedActivation => Some("This device's activation was revoked."),
        KillReason::SeatReclaimed => {
            Some("This device's seat was released. Activate again to continue.")
        }
        KillReason::Fraud => Some("This application version has been withdrawn. Please update."),
        KillReason::Refund => Some("This purchase was refunded."),
        KillReason::EpochRevoked => Some("This credential must be activated again."),
    }
}

fn now_seconds() -> i64 {
    i64::try_from(Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
}

async fn heartbeat(request: &mut Request, env: &Env) -> Result<Response> {
    let heartbeat = match decode_request::<HeartbeatRequest>(request).await? {
        Ok(request) => request,
        Err(response) => return Ok(response),
    };
    if heartbeat.proto_ver != copylocker_types::PROTO_VER {
        return response::protocol_error(426, UNSUPPORTED_PROTO, None, None);
    }

    let license_id = heartbeat.license_id;
    let call = AuthenticatedMachineCall {
        license_id: license_id.as_bytes().to_vec(),
        machine_id: heartbeat.machine_id.as_bytes().to_vec(),
        suite_id: heartbeat.suite_id.as_bytes().to_vec(),
        nonce: heartbeat.nonce_c.to_vec(),
        proof_input: heartbeat.proof_input(),
        proof: heartbeat.proof,
        idempotency_key: None,
    };
    match call_license::<_, HeartbeatDoResponse>(env, &license_id, "/heartbeat", &call).await? {
        LicenseCall::Success(result) => {
            let mut body = MapBuilder::new();
            body.put(0, CborValue::Bool(result.ok));
            body.put(1, CborValue::int(result.next_after));
            response::cbor(200, body.finish(), "no-store")
        }
        LicenseCall::Rejected { status, error } => do_rejection(status, &error),
    }
}

async fn deactivate(request: &mut Request, env: &Env) -> Result<Response> {
    let Some(idempotency_key) = idempotency_key(request)? else {
        return response::protocol_error(400, INVALID_CREDENTIAL, None, None);
    };
    let deactivation = match decode_request::<DeactivateRequest>(request).await? {
        Ok(request) => request,
        Err(response) => return Ok(response),
    };
    if deactivation.proto_ver != copylocker_types::PROTO_VER {
        return response::protocol_error(426, UNSUPPORTED_PROTO, None, None);
    }

    let license_id = deactivation.license_id;
    let call = AuthenticatedMachineCall {
        license_id: license_id.as_bytes().to_vec(),
        machine_id: deactivation.machine_id.as_bytes().to_vec(),
        suite_id: deactivation.suite_id.as_bytes().to_vec(),
        nonce: deactivation.nonce_c.to_vec(),
        proof_input: deactivation.proof_input(),
        proof: deactivation.proof,
        idempotency_key: Some(idempotency_key),
    };
    match call_license::<_, OkDoResponse>(env, &license_id, "/deactivate", &call).await? {
        LicenseCall::Success(result) => {
            let mut body = MapBuilder::new();
            body.put(0, CborValue::Bool(result.ok));
            response::cbor(200, body.finish(), "no-store")
        }
        LicenseCall::Rejected { status, error } => do_rejection(status, &error),
    }
}

async fn decode_request<T>(request: &mut Request) -> Result<std::result::Result<T, Response>>
where
    T: ClientRequest,
{
    let bytes = match body::read_cbor(request).await {
        Ok(bytes) => bytes,
        Err(error) => return Ok(Err(body_error(error)?)),
    };
    match T::decode_request(&bytes) {
        Some(request) => Ok(Ok(request)),
        None => Ok(Err(response::protocol_error(
            400,
            INVALID_CREDENTIAL,
            None,
            None,
        )?)),
    }
}

trait ClientRequest: Sized {
    fn decode_request(bytes: &[u8]) -> Option<Self>;
}

impl ClientRequest for HeartbeatRequest {
    fn decode_request(bytes: &[u8]) -> Option<Self> {
        Self::decode(bytes).ok()
    }
}

impl ClientRequest for DeactivateRequest {
    fn decode_request(bytes: &[u8]) -> Option<Self> {
        Self::decode(bytes).ok()
    }
}

impl ClientRequest for ValidateRequest {
    fn decode_request(bytes: &[u8]) -> Option<Self> {
        Self::decode(bytes).ok()
    }
}

fn idempotency_key(request: &Request) -> Result<Option<String>> {
    let value = request.headers().get("Idempotency-Key")?;
    Ok(value.filter(|value| !value.is_empty() && value.len() <= 128))
}

async fn call_license<T, U>(
    env: &Env,
    license_id: &LicenseId,
    path: &str,
    payload: &T,
) -> Result<LicenseCall<U>>
where
    T: Serialize,
    U: DeserializeOwned,
{
    let namespace = env.durable_object("LICENSE")?;
    let stub = namespace.get_by_name(&license_id.to_hex())?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&serde_json::to_string(payload)?)));
    let request = Request::new_with_init(&format!("https://license.internal{path}"), &init)?;
    let mut result = stub.fetch_with_request(request).await?;
    let status = result.status_code();
    if (200..300).contains(&status) {
        return Ok(LicenseCall::Success(result.json::<U>().await?));
    }
    let error = result.json::<InternalDoError>().await?.error;
    Ok(LicenseCall::Rejected { status, error })
}

fn do_rejection(status: u16, error: &str) -> Result<Response> {
    match (status, error) {
        (400, _) => response::protocol_error(400, INVALID_CREDENTIAL, None, None),
        (401, _) | (409, "replayed_nonce") => {
            response::protocol_error(403, INVALID_CREDENTIAL, None, None)
        }
        (409, "idempotency_conflict") => {
            response::protocol_error(409, INVALID_CREDENTIAL, None, None)
        }
        _ => response::protocol_error(503, SERVER_ERROR, None, Some(1)),
    }
}

fn activation_do_rejection(status: u16, error: &str) -> Result<Response> {
    match (status, error) {
        (409, "seat_exhausted") => response::protocol_error(409, 1001, None, None),
        (400, _) => response::protocol_error(400, INVALID_CREDENTIAL, None, None),
        (401, _) => response::protocol_error(403, INVALID_CREDENTIAL, None, None),
        (409, "idempotency_conflict") => {
            response::protocol_error(409, INVALID_CREDENTIAL, None, None)
        }
        (409, "activation_pending") => response::protocol_error(503, SERVER_ERROR, None, Some(1)),
        _ => response::protocol_error(503, SERVER_ERROR, None, Some(1)),
    }
}

#[derive(Debug, Serialize)]
struct InitLicenseCall {
    license_id: Vec<u8>,
    product_id: String,
    suite_id: Vec<u8>,
    seats: u32,
    heartbeat_sec: Option<u64>,
    expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
struct ReserveLicenseCall {
    idempotency_key: String,
    request_hash: Vec<u8>,
    machine_id: Vec<u8>,
    fingerprint: Vec<u8>,
    attrs: Option<Vec<u8>>,
    device_kem_ek: Vec<u8>,
    device_sig_vk: Vec<u8>,
    activation_path: String,
    release_id: String,
    variant_id: u64,
    refresh_after: i64,
    not_after: i64,
    build_fp: Option<String>,
    app_version: Option<String>,
    os: Option<String>,
    arch: Option<String>,
    sdk_version: Option<String>,
    geo: Option<String>,
    credential_state: Option<Vec<u8>>,
    authoritative_security_floor: u64,
}

#[derive(Debug, Deserialize)]
struct ReserveDoResponse {
    ok: bool,
    machine_id: Vec<u8>,
    revocation_epoch: i64,
    security_floor: i64,
    variant_id: i64,
    refresh_after: i64,
    not_after: i64,
    build_fp: Option<String>,
    fingerprint: Vec<u8>,
    credential_state: Option<Vec<u8>>,
    activation_envelope: Option<Vec<u8>>,
    /// The reservation reused an existing machine row (fingerprint-tolerance hit or
    /// re-activation), so it is not an `act.new` (`90-analytics-telemetry.md §2.1`).
    #[serde(default)]
    reused_existing: bool,
}

#[derive(Debug, Serialize)]
struct CompleteLicenseCall {
    idempotency_key: String,
    request_hash: Vec<u8>,
    machine_id: Vec<u8>,
    activation_envelope: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct CompleteDoResponse {
    ok: bool,
    envelope: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct AuthenticatedMachineCall {
    license_id: Vec<u8>,
    machine_id: Vec<u8>,
    suite_id: Vec<u8>,
    nonce: Vec<u8>,
    proof_input: Vec<u8>,
    proof: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct ValidateMachineCall {
    auth: AuthenticatedMachineCall,
    known_revocation_epoch: u64,
    authoritative_revocation_epoch: u64,
    known_security_floor: u64,
    next_refresh_after: i64,
    not_after: i64,
    variant_id: Option<i64>,
    authoritative_security_floor: u64,
}

#[derive(Debug, Deserialize)]
struct HeartbeatDoResponse {
    ok: bool,
    next_after: i64,
}

#[derive(Debug, Deserialize)]
struct OkDoResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct ValidateDoResponse {
    ok: bool,
    outcome: String,
    kill_reason: Option<u8>,
    revocation_epoch: i64,
    security_floor: i64,
    suspicion: i64,
    #[serde(default)]
    previous_suspicion: i64,
    #[serde(default)]
    suspicion_contributions: Option<Vec<SuspicionContribution>>,
    fingerprint: Option<Vec<u8>>,
    credential_state: Option<Vec<u8>>,
    #[serde(default)]
    activation_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct IssueCall {
    idempotency_key: String,
    shard: u8,
    routing_key: Vec<u8>,
    kind: u8,
    product_id: String,
    subject: Vec<u8>,
    tbs: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct IssueDoResponse {
    envelope: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct InternalDoError {
    error: String,
}

#[derive(Debug)]
enum LicenseCall<T> {
    Success(T),
    Rejected { status: u16, error: String },
}

fn body_error(error: BodyError) -> Result<Response> {
    match error {
        BodyError::Read(error) => Err(error),
        BodyError::TooLarge => response::protocol_error(413, INVALID_CREDENTIAL, None, None),
        BodyError::UnsupportedEncoding | BodyError::UnsupportedMediaType => {
            response::protocol_error(415, INVALID_CREDENTIAL, None, None)
        }
        BodyError::InvalidContentLength
        | BodyError::MissingBody
        | BodyError::InvalidCompressedBody => {
            response::protocol_error(400, INVALID_CREDENTIAL, None, None)
        }
    }
}
