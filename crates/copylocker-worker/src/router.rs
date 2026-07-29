use std::collections::BTreeMap;

use copylocker_core::keys::{KeyMaterial, SessionKind};
use copylocker_proto::keywrap::{seal_credential_secret, CredentialSealContext};
use copylocker_proto::{
    ActivationRequest, Credential, DeactivateRequest, HeartbeatRequest, KillOrder, LicenseKey,
    MachineCredential, ValidateRequest, ValidationTicket,
};
use copylocker_server_core::policy::VtSignature;
use copylocker_suite::cbor::{CborValue, MapBuilder};
use copylocker_suite::{
    Artifact, DomainCtx, EnvEvidence, HashScheme, KeyEncapsulation, Secret, SharedSecret,
    Signature, SignatureScheme,
};
use copylocker_suite_std::{ClStd1, FastSig, Sha256Scheme, XWingKem};
use copylocker_types::{ArtifactKind, Fingerprint, KillReason, LicenseId, LicenseState, MachineId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use worker::{
    wasm_bindgen::JsValue, Context, Date, Env, Error, Headers, Method, Request, RequestInit,
    Response, Result,
};

use crate::bindings::authorization::{
    self, AuthorizationContext, AuthorizationError, LoadPurpose, SigningEpoch,
};
use crate::bindings::kv_cache;
use crate::bindings::rng::WorkerRng;
use crate::bindings::signing::FastEpochSigner;
use crate::events::{issuer_object_name, issuer_shard};
use crate::middleware::body::{self, BodyError};
use crate::response;

const CLIENT_PROTO_HEADER: &str = "X-CL-Proto";
const INVALID_CREDENTIAL: u64 = 1000;
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
        "/v1/keys" | "/v1/revocations" | "/v1/activate" | "/v1/validate" | "/v1/heartbeat"
        | "/v1/deactivate" => response::protocol_error(405, INVALID_CREDENTIAL, None, None),
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
    let bytes = match body::read_cbor(request).await {
        Ok(bytes) => bytes,
        Err(error) => return body_error(error),
    };
    let Some(idempotency_key) = idempotency_key(request)? else {
        return response::protocol_error(400, INVALID_CREDENTIAL, None, None);
    };
    let request_hash = Sha256Scheme::hash(&bytes);
    let activation = match ActivationRequest::decode(&bytes) {
        Ok(activation) => activation,
        Err(_) => {
            return response::protocol_error(400, INVALID_CREDENTIAL, None, None);
        }
    };
    if activation.proto_ver != copylocker_types::PROTO_VER {
        return response::protocol_error(426, UNSUPPORTED_PROTO, None, None);
    }
    if activation.suite_id != copylocker_suite_std::CL_STD_1_SUITE_ID
        || activation.fingerprint.as_bytes().len() != 32
        || !activation_proof_is_valid(&activation)
    {
        return response::protocol_error(403, INVALID_CREDENTIAL, None, None);
    }
    let device_encapsulation_key = match XWingKem::decode_ek(&activation.device_kem_ek) {
        Ok(key) => key,
        Err(_) => return response::protocol_error(403, INVALID_CREDENTIAL, None, None),
    };
    let license_key = match &activation.credential {
        Credential::LicenseKey(value) => match LicenseKey::parse(value) {
            Ok(key) => key,
            Err(_) => return response::protocol_error(403, INVALID_CREDENTIAL, None, None),
        },
        Credential::AccountToken(_) => {
            return response::protocol_error(401, 1003, None, None);
        }
    };

    let now = now_seconds();
    let authorization = match authorization::load_by_license_key(
        env,
        &license_key,
        &activation.client_info.release_id,
        LoadPurpose::Activate,
        now,
    )
    .await
    {
        Ok(context) => context,
        Err(error) => return authorization_rejection(error),
    };
    if authorization.product_id != activation.product_id
        || authorization.license_status != "active"
        || authorization.expires_at.is_some_and(|expiry| now >= expiry)
    {
        return response::protocol_error(403, INVALID_CREDENTIAL, None, None);
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
        return response::protocol_error(403, INVALID_CREDENTIAL, None, None);
    }
    if activation.device_attrs.as_ref().is_some_and(|attrs| {
        attrs.env_class() == copylocker_suite::device::EnvClass::VirtualMachine
            && !authorization.policy.runtime.allow_vm
    }) {
        return response::protocol_error(403, INVALID_CREDENTIAL, None, None);
    }

    let epoch = authorization::load_signing_epoch(env, &authorization.product_id, now)
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
        return activation_do_rejection(status, &error);
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
        idempotency_key: idempotency_key.clone(),
        request_hash: request_hash.as_bytes().to_vec(),
        machine_id: candidate_machine_id.as_bytes().to_vec(),
        fingerprint: activation.fingerprint.as_bytes().to_vec(),
        attrs,
        device_kem_ek: activation.device_kem_ek.clone(),
        device_sig_vk: activation.device_sig_vk.clone(),
        activation_path: "online".to_owned(),
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
            return activation_do_rejection(status, &error);
        }
    };
    drop(candidate_secret);
    if !reservation.ok {
        return Err(Error::RustError(
            "LicenseDO returned an unsuccessful reservation".to_owned(),
        ));
    }
    if let Some(envelope) = reservation.activation_envelope {
        return response::cbor(200, envelope, "no-store");
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
    let (kem_ct, kem_shared_secret) = XWingKem::encap(&device_encapsulation_key, &mut rng)
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
    let sealed_cs = seal_credential_secret::<ClStd1>(
        &kem_shared_secret,
        &seal_context,
        &credential_secret,
        &mut rng,
    )
    .map_err(|_| Error::RustError("credential secret sealing failed".to_owned()))?;
    let wrapped_keks = wrap_offline_keks(
        &authorization,
        &epoch,
        machine_id,
        &issuance_fingerprint,
        &credential_secret,
        offline_nonce,
        &mut rng,
    )?;
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
        preloaded_keks: None,
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
        idempotency_key,
        request_hash: request_hash.as_bytes().to_vec(),
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
            response::cbor(200, result.envelope, "no-store")
        }
        LicenseCall::Success(_) => Err(Error::RustError(
            "LicenseDO returned an unsuccessful activation completion".to_owned(),
        )),
        LicenseCall::Rejected { status, error } => activation_do_rejection(status, &error),
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

fn wrap_offline_keks(
    authorization: &AuthorizationContext,
    epoch: &SigningEpoch,
    machine_id: MachineId,
    fingerprint: &Fingerprint,
    credential_secret: &Secret<[u8; 32]>,
    offline_nonce: [u8; 32],
    rng: &mut WorkerRng,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let release = authorization
        .release
        .as_ref()
        .ok_or_else(|| Error::RustError("activation release material is unavailable".to_owned()))?;
    let shared_secret = SharedSecret::new(*credential_secret.expose());
    let evidence = EnvEvidence {
        module_digest: release.module_digest,
        build_fingerprint: release.build_fingerprint.as_bytes().to_vec(),
        extra: release.binder_extra.clone(),
    };
    let material = KeyMaterial::bind::<ClStd1>(
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
    .map_err(|_| Error::RustError("offline key material derivation failed".to_owned()))?;

    let mut wrapped = BTreeMap::new();
    for asset in &release.asset_keks {
        if !authorization.entitlements.has_feature(&asset.feature_id) {
            continue;
        }
        let value = material
            .wrap_kek::<ClStd1>(
                LicenseState::Active,
                &authorization.entitlements,
                &asset.feature_id,
                SessionKind::Offline,
                &asset.key,
                rng,
            )
            .map_err(|_| Error::RustError("offline asset KEK wrapping failed".to_owned()))?;
        wrapped.insert(asset.feature_id.clone(), value);
    }
    Ok(wrapped)
}

async fn validate(request: &mut Request, env: &Env) -> Result<Response> {
    let validation = match decode_request::<ValidateRequest>(request).await? {
        Ok(request) => request,
        Err(response) => return Ok(response),
    };
    if validation.proto_ver != copylocker_types::PROTO_VER {
        return response::protocol_error(426, UNSUPPORTED_PROTO, None, None);
    }
    if validation.suite_id != copylocker_suite_std::CL_STD_1_SUITE_ID {
        return response::protocol_error(403, INVALID_CREDENTIAL, None, None);
    }

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
        Err(error) => return authorization_rejection(error),
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
            let envelope =
                sign_online_artifact(env, &authorization, &epoch, validation.machine_id, &order)
                    .await?;
            response::cbor(200, envelope, "no-store")
        }
        ("ticket", None) => {
            let suspicion_score = u8::try_from(state.suspicion)
                .ok()
                .filter(|score| *score <= 100)
                .ok_or_else(|| {
                    Error::RustError("LicenseDO suspicion score is invalid".to_owned())
                })?;
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
            let envelope =
                sign_online_artifact(env, &authorization, &epoch, validation.machine_id, &ticket)
                    .await?;
            response::cbor(200, envelope, "no-store")
        }
        _ => Err(Error::RustError(
            "LicenseDO validation outcome is inconsistent".to_owned(),
        )),
    }
}

fn wrap_online_keks(
    authorization: &AuthorizationContext,
    epoch: &SigningEpoch,
    validation: &ValidateRequest,
    issuance_fingerprint: &Fingerprint,
    credential_state: Option<&[u8]>,
    server_nonce: [u8; 32],
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
    let mut material = KeyMaterial::bind::<ClStd1>(
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
    .map_err(|_| Error::RustError("online key material derivation failed".to_owned()))?;
    material.set_server_nonce(server_nonce);

    let mut wrapped = BTreeMap::new();
    for asset in &release.asset_keks {
        if !authorization.entitlements.has_feature(&asset.feature_id) {
            continue;
        }
        let value = material
            .wrap_kek::<ClStd1>(
                LicenseState::Active,
                &authorization.entitlements,
                &asset.feature_id,
                SessionKind::Online,
                &asset.key,
                rng,
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
) -> Result<Vec<u8>> {
    match authorization.policy.runtime.vt_signature {
        VtSignature::Fast => FastEpochSigner::load(env, epoch)
            .await?
            .seal(artifact, &authorization.product_id),
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

fn authorization_rejection(error: AuthorizationError) -> Result<Response> {
    match error {
        AuthorizationError::InvalidCredential => {
            response::protocol_error(403, INVALID_CREDENTIAL, None, None)
        }
        AuthorizationError::ReleaseNotRegistered => response::protocol_error(403, 1007, None, None),
        AuthorizationError::VersionOutOfScope => response::protocol_error(409, 1008, None, None),
        AuthorizationError::ReleaseCompromised => response::protocol_error(403, 1009, None, None),
        AuthorizationError::Server(error) => Err(error),
    }
}

fn authorization_server_error(error: AuthorizationError) -> Error {
    match error {
        AuthorizationError::Server(error) => error,
        _ => Error::RustError("signing epoch authorization failed".to_owned()),
    }
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
    fingerprint: Option<Vec<u8>>,
    credential_state: Option<Vec<u8>>,
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
