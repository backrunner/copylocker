//! Offline License Key issuance (`POST /v1/admin/licenses/:id/offline-key`, ADR-0015).
//!
//! The issued OLK is a self-contained bearer credential: it carries the ADR-0015 productive
//! fields (`key_seed`, `machine_id`, `offline_nonce`, wrapped KEKs) and is wrapped with the
//! epoch certificate chain into a `.clk` bundle whose `CLK1` armor is returned exactly once per
//! idempotency key. Issuance goes through the Admin operation journal, so a retry replays the
//! identical bundle instead of minting a second seed.

use copylocker_core::keys::{KeyMaterial, SessionKind};
use copylocker_proto::{olk_binding_fingerprint, OfflineLicenseBundle, OfflineLicenseKey};
use copylocker_suite::{Artifact, EnvEvidence};
use copylocker_types::{Fingerprint, LicenseId, LicenseState, MachineId};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::*;
use crate::admin::decode_hex_id;
use crate::bindings::authorization::{AuthorizationError, LoadPurpose};
use crate::bindings::rng::WorkerRng;
use crate::router;
use crate::suites::suite_dispatch;

pub(super) async fn issue_offline_key(
    request: &mut Request,
    env: &Env,
    encoded_id: &str,
) -> Result<Response> {
    let principal = match authorize(request, env, "licenses:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let Some(id) = decode_hex_id(encoded_id, LicenseId::LEN) else {
        return invalid_request("license id must be 16-byte hexadecimal");
    };
    let body = match read_json::<OfflineKeyBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    if !valid_identifier(&body.release_id)
        || body
            .max_seats
            .is_some_and(|value| !(1..=100_000).contains(&value))
    {
        return invalid_request("offline key request contains invalid data");
    }
    let bound_fingerprint = match body.bound_fingerprint_hex.as_deref() {
        Some(value) => {
            let Some(bytes) = decode_hex_id(value, 32) else {
                return invalid_request("bound fingerprint must be 32-byte hexadecimal");
            };
            Some(Fingerprint::from_vec(bytes))
        }
        None => None,
    };
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };

    let database = env.d1("DB")?;
    let Some(license) = load_owned_license(&database, &id, &principal.vendor_id).await? else {
        return not_found("license not found");
    };
    if license.status != "active" {
        return conflict(
            "license_not_active",
            "offline keys can only be issued for an active license",
        );
    }

    let action = "license:offline-key";
    let target = format!("{}/licenses/{}/offline-key", license.product_id, encoded_id);
    let request_value = serde_json::to_value(&body)?;
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    if let Some(response) = replay_operation(
        env,
        &database,
        &principal,
        &request_id,
        &request_hash,
        "licenses:rw",
    )
    .await?
    {
        return Ok(response);
    }

    let now = now_seconds();
    let license_id = LicenseId::from_slice(&id)
        .ok_or_else(|| worker::Error::RustError("license id is corrupt".to_owned()))?;
    let authorization = match authorization::load_by_license_id(
        env,
        license_id,
        &body.release_id,
        LoadPurpose::Activate,
        now,
    )
    .await
    {
        Ok(context) => context,
        Err(AuthorizationError::ReleaseNotRegistered) => {
            return not_found("release is not registered for this product");
        }
        Err(AuthorizationError::VersionOutOfScope) => {
            return response::api_error_no_store(
                422,
                "version_out_of_scope",
                "the release is outside the license version scope",
            );
        }
        Err(AuthorizationError::ReleaseCompromised) => {
            return conflict(
                "release_compromised",
                "offline keys are never issued for a compromised release",
            );
        }
        Err(AuthorizationError::InvalidCredential) => {
            return not_found("license not found");
        }
        Err(AuthorizationError::Server(error)) => return Err(error),
    };
    let Some(release) = authorization.release.as_ref() else {
        return not_found("release is not registered for this product");
    };
    if release.release_id != body.release_id {
        return invalid_request("release id does not match the registered release");
    }
    if !authorization.policy.runtime.allow_olk {
        return response::api_error_no_store(
            422,
            "olk_not_allowed",
            "the license policy does not allow offline license keys",
        );
    }
    if bound_fingerprint.is_none() && !authorization.policy.runtime.allow_unbound_olk {
        return response::api_error_no_store(
            422,
            "unbound_olk_not_allowed",
            "the license policy requires a bound fingerprint for offline license keys",
        );
    }

    let epoch = authorization::load_signing_epoch(env, &authorization.product_id, now)
        .await
        .map_err(authorization_error)?;
    let security_floor = authorization::current_security_floor(env)
        .await
        .map_err(authorization_error)?;
    let revocation_epoch = crate::admin::current_revocation_epoch(env).await?;

    let mut rng = WorkerRng::new()?;
    let machine_id = MachineId(rng.random_array::<16>()?);
    let offline_nonce = rng.random_array::<32>()?;
    let key_seed = rng.random_array::<32>()?;
    let binding = olk_binding_fingerprint(bound_fingerprint.as_ref());
    let evidence = EnvEvidence {
        module_digest: release.module_digest,
        build_fingerprint: release.build_fingerprint.as_bytes().to_vec(),
        extra: release.binder_extra.clone(),
    };
    // The OLK's suite flows from the registered release, not a constant: the same dispatch that
    // serves machine credentials derives and wraps the productive OLK material.
    let suite = release.suite;
    let material = suite_dispatch!(
        suite,
        S,
        KeyMaterial::bind_olk::<S>(
            &key_seed,
            &binding,
            &evidence,
            &authorization.product_id,
            license_id,
            machine_id,
            epoch.epoch_id,
            release.variant_id,
            release.variant_const,
            offline_nonce,
        )
    )
    .map_err(|_| worker::Error::RustError("OLK key material derivation failed".to_owned()))?;
    let mut wrapped_keks = std::collections::BTreeMap::new();
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
                &mut rng,
            )
        )
        .map_err(|_| worker::Error::RustError("OLK asset KEK wrapping failed".to_owned()))?;
        wrapped_keks.insert(asset.feature_id.clone(), value);
    }
    rng.ensure_healthy()?;

    let olk = OfflineLicenseKey {
        proto_ver: copylocker_types::PROTO_VER,
        suite_id: suite.suite_id(),
        product_id: authorization.product_id.clone(),
        license_id,
        entitlements: authorization.entitlements.clone(),
        issued_at: now,
        // `not_after = 0` is the documented permanent OLK (ADR-0015 §5); every other deadline
        // is a hard expiry with no refresh or grace extension.
        not_after: authorization.not_after(now),
        bound_fingerprint: bound_fingerprint.clone(),
        max_seats: u64::from(body.max_seats.unwrap_or(authorization.seats)),
        epoch_id: epoch.epoch_id,
        machine_id,
        offline_nonce,
        key_seed,
        build_fingerprint: release.build_fingerprint.clone(),
        variant_id: release.variant_id,
        security_floor,
        revocation_epoch,
        wrapped_keks,
    };
    let tbs = olk
        .to_canonical()
        .map_err(|_| worker::Error::RustError("OLK encoding failed".to_owned()))?;
    let envelope = router::issue_artifact(
        env,
        license_id,
        &authorization.product_id,
        license_id.as_bytes().to_vec(),
        copylocker_types::ArtifactKind::OfflineLicenseKey,
        tbs,
    )
    .await?;
    let chain = crate::offline::epoch_cert_chain(env, &authorization.product_id, now).await?;
    let bundle = OfflineLicenseBundle::new(envelope, chain);
    let armor = bundle.to_armored();

    let result = json!({
        "ok": true,
        "license_id": encoded_id,
        "product_id": authorization.product_id,
        "release_id": body.release_id,
        "variant_id": release.variant_id,
        "bound": bound_fingerprint.is_some(),
        "bound_fingerprint_hex": body.bound_fingerprint_hex,
        "not_after": olk.not_after,
        "max_seats": olk.max_seats,
        "revocation_epoch": revocation_epoch,
        "security_floor": security_floor,
        "armor": armor,
        "armor_chars": armor.len(),
        "max_seats_advisory": true,
    });
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "licenses:rw".to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "license_olk".to_owned(),
        source_id: encoded_id.to_owned(),
        request_hash: request_hash.clone(),
        before: Value::Null,
        after: json!({
            "kind": "offline_license_key",
            "license_id": encoded_id,
            "release_id": body.release_id,
            "bound": bound_fingerprint.is_some(),
        }),
        result,
        response_status: 201,
        side_effect: None,
        created_at: now,
    };
    let statements = vec![admin_operations::insert_statement(&database, &operation)?];
    if let Err(error) = database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &database,
            &principal,
            &request_id,
            &request_hash,
            "licenses:rw",
        )
        .await?
        {
            return Ok(response);
        }
        return Err(error);
    }
    finish_new_operation(env, &database, &principal, &request_id).await
}

struct OwnedLicense {
    product_id: String,
    status: String,
}

async fn load_owned_license(
    database: &D1Database,
    id: &[u8],
    vendor_id: &str,
) -> Result<Option<OwnedLicense>> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT l.product_id, l.status FROM licenses l              JOIN products product ON product.id = l.product_id              WHERE l.id = ? AND product.vendor_id = ?",
        )
        .bind(&[blob(id), text(vendor_id)])?
        .first::<OwnedLicenseRow>(None)
        .await?;
    Ok(row.map(|row| OwnedLicense {
        product_id: row.product_id,
        status: row.status,
    }))
}

#[derive(Debug, Deserialize)]
struct OwnedLicenseRow {
    product_id: String,
    status: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OfflineKeyBody {
    release_id: String,
    #[serde(default)]
    bound_fingerprint_hex: Option<String>,
    #[serde(default)]
    max_seats: Option<u32>,
}
