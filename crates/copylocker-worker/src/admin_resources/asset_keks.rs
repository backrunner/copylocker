//! Asset KEK registration plane (M4-B, `50-unplugin-integrity.md` §4.1).
//!
//! The sealing build step uploads one 32-byte KEK per `(release, feature)`. The Worker encrypts
//! it with the `ASSET_KEK_KEY` secret before it reaches D1 (the at-rest AAD mirrors
//! `bindings/authorization.rs`), and the activation/validation paths wrap it per device into
//! `wrapped_keks`. Plaintext KEKs never appear in D1, in responses (fingerprints only), or in
//! the Admin audit journal.

use copylocker_suite::{HashScheme, Secret};
use copylocker_suite_std::Sha256Scheme;
use serde::Deserialize;
use serde_json::{json, Value};
use worker::{D1Database, D1SessionConstraint, Env, Method, Request, Response, Result};

use super::*;
use crate::admin::hex_encode;
use crate::bindings::authorization;
use crate::bindings::rng::WorkerRng;

const KEK_LEN: usize = 32;
const MAX_LIST_ITEMS: usize = 1_000;

pub(super) async fn route(request: &mut Request, env: &Env, segments: &[&str]) -> Result<Response> {
    match segments {
        ["asset-keks"] => collection(request, env).await,
        ["asset-keks", release_id, feature_id]
            if !release_id.is_empty() && !feature_id.is_empty() =>
        {
            resource(request, env, release_id, feature_id).await
        }
        _ => not_found("asset KEK route not found"),
    }
}

async fn collection(request: &mut Request, env: &Env) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Post) {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "releases:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    if request.method() == Method::Get {
        return list(request, env, &principal).await;
    }
    let body = match read_json::<RegisterBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    register(request, env, &principal, body).await
}

async fn list(request: &Request, env: &Env, principal: &AdminPrincipal) -> Result<Response> {
    let mut product_id = None;
    let mut release_id = None;
    for (name, value) in request.url()?.query_pairs() {
        match name.as_ref() {
            "product_id" if product_id.is_none() && valid_identifier(&value) => {
                product_id = Some(value.into_owned());
            }
            "release_id" if release_id.is_none() && valid_identifier(&value) => {
                release_id = Some(value.into_owned());
            }
            _ => {
                return invalid_request(
                    "exactly one valid product_id and an optional release_id are required",
                );
            }
        }
    }
    let Some(product_id) = product_id else {
        return invalid_request(
            "exactly one valid product_id and an optional release_id are required",
        );
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let rows = match release_id {
        Some(release_id) => {
            database
                .prepare(
                    "SELECT release_id, product_id, feature_id, key_version, encrypted_kek, \
                            created_at, updated_at \
                     FROM release_feature_keks \
                     WHERE product_id = ? AND release_id = ? ORDER BY feature_id LIMIT 1001",
                )
                .bind(&[text(&product_id), text(&release_id)])?
                .all()
                .await?
        }
        None => {
            database
                .prepare(
                    "SELECT release_id, product_id, feature_id, key_version, encrypted_kek, \
                            created_at, updated_at \
                     FROM release_feature_keks \
                     WHERE product_id = ? ORDER BY release_id, feature_id LIMIT 1001",
                )
                .bind(&[text(&product_id)])?
                .all()
                .await?
        }
    }
    .results::<AssetKekRow>()?;
    if rows.len() > MAX_LIST_ITEMS {
        return response::api_error_no_store(
            413,
            "result_too_large",
            "asset KEK list exceeds 1000 items",
        );
    }
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(item) = decrypt_row(env, row).await? else {
            return Err(worker::Error::RustError(
                "stored asset KEK could not be decrypted".to_owned(),
            ));
        };
        items.push(item);
    }
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "product_id": product_id,
            "items": items
        }),
    )
}

async fn register(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    body: RegisterBody,
) -> Result<Response> {
    if !valid_identifier(&body.product_id)
        || !valid_identifier(&body.release_id)
        || !valid_identifier(&body.feature_id)
    {
        return invalid_request("asset KEK identity fields are invalid");
    }
    let Some(kek_bytes) = crate::admin::decode_hex_id(&body.kek_hex, KEK_LEN) else {
        return invalid_request("kek_hex must contain exactly 64 hexadecimal characters");
    };
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let action = "asset-kek:register";
    let target = format!(
        "{}/releases/{}/keks/{}",
        body.product_id, body.release_id, body.feature_id
    );
    let request_value = json!({
        "product_id": body.product_id,
        "release_id": body.release_id,
        "feature_id": body.feature_id,
        "kek_sha256": hex_encode(Sha256Scheme::hash(&kek_bytes).as_bytes()),
    });
    let kek_fingerprint = request_value
        .get("kek_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| worker::Error::RustError("asset KEK fingerprint is missing".to_owned()))?
        .to_owned();
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    let database = env.d1("DB")?;
    if let Some(response) = replay_operation(
        env,
        &database,
        principal,
        &request_id,
        &request_hash,
        "releases:rw",
    )
    .await?
    {
        return Ok(response);
    }
    if !product_owned(&database, &body.product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    if !release_exists(&database, &body.release_id, &body.product_id).await? {
        return not_found("release not found");
    }
    if !feature_exists(&database, &body.product_id, &body.feature_id).await? {
        return not_found("feature not found");
    }
    if load_row(
        &database,
        &body.release_id,
        &body.product_id,
        &body.feature_id,
    )
    .await?
    .is_some()
    {
        return conflict(
            "already_exists",
            "an asset KEK is already registered for this release and feature; delete it first",
        );
    }

    let kek = Secret::new(
        <[u8; KEK_LEN]>::try_from(kek_bytes.as_slice())
            .map_err(|_| worker::Error::RustError("asset KEK has an invalid length".to_owned()))?,
    );
    let key_version = 1_u64;
    let mut rng = WorkerRng::new()?;
    // Asset-KEK registration is CL-STD-1-only on the admin axis, matching release registration.
    let encrypted = authorization::seal_asset_kek_at_rest(
        env,
        &body.release_id,
        &body.product_id,
        &body.feature_id,
        key_version,
        copylocker_suite_std::CL_STD_1_SUITE_ID,
        &kek,
        &mut rng,
    )
    .await
    .map_err(|error| match error {
        authorization::AuthorizationError::Server(error) => error,
        _ => worker::Error::RustError("asset KEK at-rest encryption failed".to_owned()),
    })?;
    drop(kek);
    rng.ensure_healthy()?;

    let fingerprint = hex_encode(Sha256Scheme::hash(&encrypted).as_bytes());
    let after = json!({
        "product_id": body.product_id,
        "release_id": body.release_id,
        "feature_id": body.feature_id,
        "key_version": key_version,
        "kek_fingerprint": kek_fingerprint,
        "ciphertext_sha256": fingerprint,
    });
    let result = json!({
        "ok": true,
        "product_id": body.product_id,
        "release_id": body.release_id,
        "feature_id": body.feature_id,
        "key_version": key_version,
        "kek_fingerprint": kek_fingerprint,
    });
    let now = now_seconds();
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "releases:rw".to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "asset_kek".to_owned(),
        source_id: format!("{}/{}", body.release_id, body.feature_id),
        request_hash: request_hash.clone(),
        before: Value::Null,
        after,
        result,
        response_status: 201,
        side_effect: None,
        created_at: now,
    };
    let statements = vec![
        admin_operations::insert_statement(&database, &operation)?,
        database
            .prepare(
                "INSERT INTO release_feature_keks(\
                   release_id, product_id, feature_id, key_version, encrypted_kek, \
                   created_at, updated_at\
                 ) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&[
                text(&body.release_id),
                text(&body.product_id),
                text(&body.feature_id),
                integer(i64::try_from(key_version).map_err(|_| {
                    worker::Error::RustError("asset KEK version is invalid".to_owned())
                })?)?,
                blob(&encrypted),
                integer(now)?,
                integer(now)?,
            ])?,
    ];
    if let Err(error) = database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &database,
            principal,
            &request_id,
            &request_hash,
            "releases:rw",
        )
        .await?
        {
            return Ok(response);
        }
        return Err(error);
    }
    finish_new_operation(env, &database, principal, &request_id).await
}

async fn resource(
    request: &mut Request,
    env: &Env,
    release_id: &str,
    feature_id: &str,
) -> Result<Response> {
    if request.method() != Method::Delete {
        return method_not_allowed();
    }
    if !valid_identifier(release_id) || !valid_identifier(feature_id) {
        return invalid_request("release or feature identifier is invalid");
    }
    let principal = match authorize(request, env, "releases:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let (product_id, dry_run) = match product_dry_run_query(request)? {
        Ok(query) => query,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let row = load_row(&database, release_id, &product_id, feature_id).await?;

    if dry_run {
        let Some(row) = row else {
            return not_found("asset KEK not found");
        };
        return response::json_no_store(
            200,
            &json!({
                "ok": true,
                "dry_run": true,
                "product_id": product_id,
                "release_id": release_id,
                "feature_id": feature_id,
                "key_version": row.key_version,
            }),
        );
    }

    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let action = "asset-kek:delete";
    let target = format!("{product_id}/releases/{release_id}/keks/{feature_id}");
    // The idempotency hash covers the request identity only, so a replay after a completed
    // deletion still matches its journal entry even though the row is gone.
    let request_value = json!({
        "product_id": product_id,
        "release_id": release_id,
        "feature_id": feature_id,
    });
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    if let Some(response) = replay_operation(
        env,
        &database,
        &principal,
        &request_id,
        &request_hash,
        "releases:rw",
    )
    .await?
    {
        return Ok(response);
    }
    let Some(row) = row else {
        return not_found("asset KEK not found");
    };
    let before = json!({
        "product_id": product_id,
        "release_id": release_id,
        "feature_id": feature_id,
        "key_version": row.key_version,
    });
    let result = json!({
        "ok": true,
        "dry_run": false,
        "product_id": product_id,
        "release_id": release_id,
        "feature_id": feature_id,
        "deleted": true,
    });
    let now = now_seconds();
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "releases:rw".to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "asset_kek".to_owned(),
        source_id: format!("{release_id}/{feature_id}"),
        request_hash: request_hash.clone(),
        before,
        after: json!({"deleted": true}),
        result,
        response_status: 200,
        side_effect: None,
        created_at: now,
    };
    let statements = vec![
        admin_operations::insert_statement(&database, &operation)?,
        database
            .prepare(
                "DELETE FROM release_feature_keks \
                 WHERE release_id = ? AND product_id = ? AND feature_id = ?",
            )
            .bind(&[text(release_id), text(&product_id), text(feature_id)])?,
    ];
    if let Err(error) = database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &database,
            &principal,
            &request_id,
            &request_hash,
            "releases:rw",
        )
        .await?
        {
            return Ok(response);
        }
        return Err(error);
    }
    finish_new_operation(env, &database, &principal, &request_id).await
}

async fn release_exists(database: &D1Database, release_id: &str, product_id: &str) -> Result<bool> {
    Ok(database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT id AS release_id FROM releases WHERE id = ? AND product_id = ?")
        .bind(&[text(release_id), text(product_id)])?
        .first::<ReleaseIdRow>(None)
        .await?
        .is_some())
}

async fn feature_exists(database: &D1Database, product_id: &str, feature_id: &str) -> Result<bool> {
    Ok(database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT id AS feature_id FROM features WHERE product_id = ? AND id = ?")
        .bind(&[text(product_id), text(feature_id)])?
        .first::<FeatureIdRow>(None)
        .await?
        .is_some())
}

async fn load_row(
    database: &D1Database,
    release_id: &str,
    product_id: &str,
    feature_id: &str,
) -> Result<Option<AssetKekRow>> {
    database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT release_id, product_id, feature_id, key_version, encrypted_kek, \
                    created_at, updated_at \
             FROM release_feature_keks \
             WHERE release_id = ? AND product_id = ? AND feature_id = ?",
        )
        .bind(&[text(release_id), text(product_id), text(feature_id)])?
        .first::<AssetKekRow>(None)
        .await
}

/// Decrypt one stored row for a fingerprint-only projection. The plaintext KEK
/// is dropped inside this function; it never escapes into a response or log.
async fn decrypt_row(env: &Env, row: AssetKekRow) -> Result<Option<Value>> {
    if row.key_version <= 0 || row.created_at < 0 || row.updated_at < 0 {
        return Ok(None);
    }
    let key_version = u64::try_from(row.key_version)
        .map_err(|_| worker::Error::RustError("asset KEK version is invalid".to_owned()))?;
    // Rows are sealed at registration time, which is CL-STD-1-only on the admin axis.
    let plaintext = authorization::open_asset_kek_at_rest(
        env,
        &row.release_id,
        &row.product_id,
        &row.feature_id,
        key_version,
        copylocker_suite_std::CL_STD_1_SUITE_ID,
        &row.encrypted_kek,
    )
    .await
    .map_err(|error| match error {
        authorization::AuthorizationError::Server(error) => error,
        _ => worker::Error::RustError("stored asset KEK could not be decrypted".to_owned()),
    })?;
    let fingerprint = hex_encode(Sha256Scheme::hash(plaintext.expose()).as_bytes());
    drop(plaintext);
    Ok(Some(json!({
        "product_id": row.product_id,
        "release_id": row.release_id,
        "feature_id": row.feature_id,
        "key_version": key_version,
        "kek_fingerprint": fingerprint,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    product_id: String,
    release_id: String,
    feature_id: String,
    kek_hex: String,
}

#[derive(Debug, Deserialize)]
struct AssetKekRow {
    release_id: String,
    product_id: String,
    feature_id: String,
    key_version: i64,
    #[serde(with = "serde_bytes")]
    encrypted_kek: Vec<u8>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct ReleaseIdRow {
    #[serde(rename = "release_id")]
    _release_id: String,
}

#[derive(Debug, Deserialize)]
struct FeatureIdRow {
    #[serde(rename = "feature_id")]
    _feature_id: String,
}
