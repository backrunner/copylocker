//! Remote integrity-manifest signing (M4-B, `50-unplugin-integrity.md` §2.5).
//!
//! `POST /v1/admin/integrity/sign` is the server half of `@copylocker/unplugin`'s `remote`
//! signer: the request body is the raw manifest tbs, the response body is the raw 64-byte
//! Ed25519 signature over `"copylocker/im-sig/v1" ‖ tbs`. Callers authenticate either with an
//! Admin bearer token (`sign:manifest` scope) or with a GitHub Actions OIDC JWT (see
//! `crate::oidc`). The signing key never touches D1; it must be registered by fingerprint
//! through `POST /v1/admin/integrity/keys` before the endpoint will use it.
//!
//! Every signed tbs is journaled through the recoverable Admin operation/audit machinery with a
//! deterministic request id derived from the tbs digest, so retries are idempotent and the
//! audit chain records exactly which manifest bytes were signed by which actor.

use copylocker_suite::cbor::{decode_canonical, CborValue, Limits};
use copylocker_suite::HashScheme;
use copylocker_suite_std::Sha256Scheme;
use serde::Deserialize;
use serde_json::{json, Value};
use worker::{D1Database, D1SessionConstraint, Env, Headers, Method, Request, Response, Result};

use super::*;
use crate::admin::{authenticate_scope, decode_hex_id, hex_encode, unauthorized, AuthResult};
use crate::bindings::build_signing::BuildSigningKey;
use crate::middleware::body::{self, BodyError};
use crate::oidc;

const SIGN_SCOPE: &str = "sign:manifest";
const MAX_TBS_BYTES: usize = MAX_ADMIN_BODY;
const FINGERPRINT_LEN: usize = 32;
const MAX_LIST_ITEMS: usize = 1_000;
const TBS_LIMITS: Limits = Limits {
    max_depth: 8,
    max_items: 16_384,
    max_string: 8 * 1024,
};

pub(super) async fn route(request: &mut Request, env: &Env, segments: &[&str]) -> Result<Response> {
    match segments {
        ["integrity", "sign"] => sign(request, env).await,
        ["integrity", "keys"] => keys_collection(request, env).await,
        ["integrity", "keys", fingerprint, "revoke"] if !fingerprint.is_empty() => {
            key_revoke(request, env, fingerprint).await
        }
        _ => not_found("integrity route not found"),
    }
}

enum SignerIdentity {
    Admin(AdminPrincipal),
    Oidc {
        actor: String,
        repository: String,
        reference: String,
    },
}

impl SignerIdentity {
    fn actor(&self) -> String {
        match self {
            Self::Admin(principal) => principal.actor.clone(),
            Self::Oidc { actor, .. } => actor.clone(),
        }
    }
}

async fn sign(request: &mut Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    let identity = match authenticate_signer(request, env).await? {
        Ok(identity) => identity,
        Err(rejection) => return Ok(rejection),
    };
    let tbs = match read_tbs(request).await? {
        Ok(tbs) => tbs,
        Err(rejection) => return Ok(rejection),
    };
    let Some(product_id) = manifest_product_id(&tbs) else {
        return invalid_request(
            "the body is not a CL-STD-1 integrity manifest tbs (canonical CBOR, fields 0-2)",
        );
    };
    let database = env.d1("DB")?;
    let Some(vendor_id) = product_vendor(&database, &product_id).await? else {
        return not_found("product not found");
    };
    if let SignerIdentity::Admin(principal) = &identity {
        if principal.vendor_id != vendor_id {
            return not_found("product not found");
        }
    }

    let signing_key = BuildSigningKey::load(env).await?;
    let verifying_key = signing_key.verifying_key();
    let fingerprint = hex_encode(Sha256Scheme::hash(&verifying_key).as_bytes());
    if !signer_key_active(&database, &product_id, &vendor_id, &fingerprint).await? {
        return response::api_error_no_store(
            403,
            "signer_key_not_registered",
            "the configured build signing key is not registered and active for this product",
        );
    }

    let signature = signing_key.sign_manifest(&tbs);
    let tbs_digest = Sha256Scheme::hash(&tbs);
    journal_signature(
        env,
        &database,
        &vendor_id,
        &identity,
        &product_id,
        &fingerprint,
        tbs_digest.as_bytes(),
        &signature,
    )
    .await?;

    let headers = Headers::new();
    headers.set("Content-Type", "application/octet-stream")?;
    headers.set("Cache-Control", "no-store")?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    headers.set("X-CL-Signer-Key", &fingerprint)?;
    Ok(Response::from_bytes(signature.to_vec())?
        .with_status(200)
        .with_headers(headers))
}

async fn authenticate_signer(
    request: &Request,
    env: &Env,
) -> Result<std::result::Result<SignerIdentity, Response>> {
    let Some(header) = request.headers().get("Authorization")? else {
        return Ok(Err(unauthorized()?));
    };
    let mut parts = header.split_ascii_whitespace();
    let (Some(scheme), Some(token), None) = (parts.next(), parts.next(), parts.next()) else {
        return Ok(Err(unauthorized()?));
    };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Ok(Err(unauthorized()?));
    }
    if token.starts_with("clat_") {
        return Ok(match authenticate_scope(request, env, SIGN_SCOPE).await? {
            AuthResult::Authenticated(principal) => Ok(SignerIdentity::Admin(principal)),
            AuthResult::Unauthorized => Err(unauthorized()?),
            AuthResult::Forbidden => Err(response::api_error_no_store(
                403,
                "insufficient_scope",
                "the token does not grant the sign:manifest scope",
            )?),
        });
    }
    match oidc::authenticate(env, token, now_seconds()).await? {
        Some(identity) => Ok(Ok(SignerIdentity::Oidc {
            actor: identity.actor(),
            repository: identity.repository().to_owned(),
            reference: identity.reference().to_owned(),
        })),
        None => Ok(Err(unauthorized()?)),
    }
}

async fn read_tbs(request: &mut Request) -> Result<std::result::Result<Vec<u8>, Response>> {
    let Some(content_type) = request.headers().get("Content-Type")? else {
        return Ok(Err(response::api_error_no_store(
            415,
            "unsupported_media_type",
            "Content-Type must be application/octet-stream",
        )?));
    };
    let media_type = content_type
        .split_once(';')
        .map_or(content_type.as_str(), |(value, _)| value)
        .trim();
    if !media_type.eq_ignore_ascii_case("application/octet-stream") {
        return Ok(Err(response::api_error_no_store(
            415,
            "unsupported_media_type",
            "Content-Type must be application/octet-stream",
        )?));
    }
    if request
        .headers()
        .get("Content-Encoding")?
        .is_some_and(|value| !value.trim().is_empty() && !value.eq_ignore_ascii_case("identity"))
    {
        return Ok(Err(response::api_error_no_store(
            415,
            "unsupported_content_encoding",
            "Content-Encoding must be identity",
        )?));
    }
    Ok(match body::read_raw(request, MAX_TBS_BYTES).await {
        Ok(bytes) if !bytes.is_empty() => Ok(bytes),
        Ok(_) => Err(response::api_error_no_store(
            400,
            "invalid_request",
            "request body must contain the manifest tbs bytes",
        )?),
        Err(BodyError::TooLarge) => Err(response::api_error_no_store(
            413,
            "payload_too_large",
            "manifest tbs exceeds the 256 KiB limit",
        )?),
        Err(BodyError::Read(error)) => return Err(error),
        Err(_) => Err(response::api_error_no_store(
            400,
            "invalid_request",
            "request body must contain the manifest tbs bytes",
        )?),
    })
}

/// Extract the product id from a manifest tbs, enforcing the structural contract before any
/// signature is produced: canonical CBOR map, `proto_ver == 1`, the CL-STD-1 suite id, and a
/// well-formed `product_id` (`protocol-spec.md` §9).
fn manifest_product_id(tbs: &[u8]) -> Option<String> {
    let value = decode_canonical(tbs, TBS_LIMITS).ok()?;
    let entries = value.as_map()?;
    if value.get(0).and_then(CborValue::as_uint) != Some(u64::from(copylocker_types::PROTO_VER)) {
        return None;
    }
    let suite = value.get(1).and_then(CborValue::as_bytes)?;
    if suite != copylocker_suite_std::CL_STD_1_SUITE_ID.as_bytes() {
        return None;
    }
    let product_id = value.get(2).and_then(CborValue::as_text)?;
    if !valid_identifier(product_id) || entries.is_empty() {
        return None;
    }
    Some(product_id.to_owned())
}

async fn product_vendor(database: &D1Database, product_id: &str) -> Result<Option<String>> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT vendor_id FROM products WHERE id = ? AND archived_at IS NULL")
        .bind(&[text(product_id)])?
        .first::<ProductVendorRow>(None)
        .await?;
    Ok(row.map(|row| row.vendor_id))
}

async fn signer_key_active(
    database: &D1Database,
    product_id: &str,
    vendor_id: &str,
    fingerprint: &str,
) -> Result<bool> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT status FROM integrity_signer_keys \
             WHERE product_id = ? AND fingerprint = ? AND vendor_id = ?",
        )
        .bind(&[text(product_id), text(fingerprint), text(vendor_id)])?
        .first::<SignerKeyStatusRow>(None)
        .await?;
    Ok(row.is_some_and(|row| row.status == "active"))
}

/// Record the signature in the recoverable Admin journal. The request id is derived from the
/// tbs digest, so a retry of the same manifest is a no-op replay; a different manifest with a
/// colliding id is impossible in practice (SHA-256) and rejected defensively.
#[allow(clippy::too_many_arguments)] // Keep every journaled field explicit at this boundary.
async fn journal_signature(
    env: &Env,
    database: &D1Database,
    vendor_id: &str,
    identity: &SignerIdentity,
    product_id: &str,
    fingerprint: &str,
    tbs_digest: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    let request_id = format!("integrity-sign:{}", hex_encode(tbs_digest));
    let action = "integrity:sign";
    let target = format!("{product_id}/integrity/{fingerprint}");
    let (actor_kind, detail) = match identity {
        SignerIdentity::Admin(_) => ("admin", Value::Null),
        SignerIdentity::Oidc {
            repository,
            reference,
            ..
        } => (
            "oidc",
            json!({ "repository": repository, "ref": reference }),
        ),
    };
    let request_value = json!({
        "product_id": product_id,
        "key_fingerprint": fingerprint,
        "tbs_sha256": hex_encode(tbs_digest),
    });
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    if let Some(existing) = admin_operations::load(database, vendor_id, &request_id).await? {
        if !existing.matches_request(&request_hash) || existing.required_scope != SIGN_SCOPE {
            return Err(worker::Error::RustError(
                "integrity signature journal conflict".to_owned(),
            ));
        }
        admin_operations::finalize(env, database, &existing).await?;
        return Ok(());
    }

    let record = json!({
        "product_id": product_id,
        "key_fingerprint": fingerprint,
        "tbs_sha256": hex_encode(tbs_digest),
        "signature": hex_encode(signature),
        "actor_kind": actor_kind,
        "actor_detail": detail,
    });
    let now = now_seconds();
    let operation = NewOperation {
        vendor_id: vendor_id.to_owned(),
        request_id: request_id.clone(),
        actor: identity.actor(),
        required_scope: SIGN_SCOPE.to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "integrity_sign".to_owned(),
        source_id: fingerprint.to_owned(),
        request_hash,
        before: Value::Null,
        after: record.clone(),
        result: json!({ "ok": true, "record": record }),
        response_status: 200,
        side_effect: None,
        created_at: now,
    };
    if let Err(error) = database
        .batch(vec![admin_operations::insert_statement(
            database, &operation,
        )?])
        .await
    {
        let existing = admin_operations::load(database, vendor_id, &request_id)
            .await?
            .filter(|existing| {
                existing.matches_request(&operation.request_hash)
                    && existing.required_scope == SIGN_SCOPE
            })
            .ok_or(error)?;
        admin_operations::finalize(env, database, &existing).await?;
        return Ok(());
    }
    let stored = admin_operations::load(database, vendor_id, &request_id)
        .await?
        .ok_or_else(|| {
            worker::Error::RustError("integrity signature operation was not persisted".to_owned())
        })?;
    admin_operations::finalize(env, database, &stored).await?;
    Ok(())
}

async fn keys_collection(request: &mut Request, env: &Env) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Post) {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, SIGN_SCOPE).await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    if request.method() == Method::Get {
        return list_keys(request, env, &principal).await;
    }
    let body = match read_json::<RegisterKeyBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    register_key(request, env, &principal, body).await
}

async fn list_keys(request: &Request, env: &Env, principal: &AdminPrincipal) -> Result<Response> {
    let product_id = match product_query(request)? {
        Ok(product_id) => product_id,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let rows = database
        .prepare(
            "SELECT product_id, fingerprint, public_key, status, created_by, created_at, \
                    revoked_at \
             FROM integrity_signer_keys \
             WHERE product_id = ? AND vendor_id = ? ORDER BY created_at, fingerprint LIMIT 1001",
        )
        .bind(&[text(&product_id), text(&principal.vendor_id)])?
        .all()
        .await?
        .results::<SignerKeyRow>()?;
    if rows.len() > MAX_LIST_ITEMS {
        return response::api_error_no_store(
            413,
            "result_too_large",
            "signer key list exceeds 1000 items",
        );
    }
    let items = rows
        .into_iter()
        .map(|row| {
            json!({
                "product_id": row.product_id,
                "fingerprint": row.fingerprint,
                "public_key_hex": hex_encode(&row.public_key),
                "status": row.status,
                "created_by": row.created_by,
                "created_at": row.created_at,
                "revoked_at": row.revoked_at,
            })
        })
        .collect::<Vec<_>>();
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "product_id": product_id,
            "items": items
        }),
    )
}

async fn register_key(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    body: RegisterKeyBody,
) -> Result<Response> {
    if !valid_identifier(&body.product_id) {
        return invalid_request("product id is invalid");
    }
    let Some(public_key) = decode_hex_id(&body.public_key_hex, FINGERPRINT_LEN) else {
        return invalid_request("public_key_hex must contain exactly 64 hexadecimal characters");
    };
    if ed25519_dalek::VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(public_key.as_slice())
            .map_err(|_| worker::Error::RustError("signer public key is invalid".to_owned()))?,
    )
    .is_err()
    {
        return invalid_request("public_key_hex is not a valid Ed25519 public key");
    }
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let fingerprint = hex_encode(Sha256Scheme::hash(&public_key).as_bytes());
    let action = "integrity-key:register";
    let target = format!("{}/integrity/{}", body.product_id, fingerprint);
    let request_value = json!({
        "product_id": body.product_id,
        "public_key_hex": body.public_key_hex.to_lowercase(),
    });
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    let database = env.d1("DB")?;
    if let Some(response) = replay_operation(
        env,
        &database,
        principal,
        &request_id,
        &request_hash,
        SIGN_SCOPE,
    )
    .await?
    {
        return Ok(response);
    }
    if !product_owned(&database, &body.product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    if load_key(&database, &body.product_id, &fingerprint)
        .await?
        .is_some()
    {
        return conflict(
            "already_exists",
            "this signer key is already registered for the product",
        );
    }

    let after = json!({
        "product_id": body.product_id,
        "fingerprint": fingerprint,
        "public_key_hex": hex_encode(&public_key),
        "status": "active",
    });
    let result = json!({
        "ok": true,
        "product_id": body.product_id,
        "fingerprint": fingerprint,
        "public_key_hex": hex_encode(&public_key),
        "status": "active",
    });
    let now = now_seconds();
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: SIGN_SCOPE.to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "integrity_signer_key".to_owned(),
        source_id: fingerprint.clone(),
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
                "INSERT INTO integrity_signer_keys(\
                   product_id, vendor_id, fingerprint, public_key, status, created_by, created_at\
                 ) VALUES (?, ?, ?, ?, 'active', ?, ?)",
            )
            .bind(&[
                text(&body.product_id),
                text(&principal.vendor_id),
                text(&fingerprint),
                blob(&public_key),
                text(&principal.actor),
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
            SIGN_SCOPE,
        )
        .await?
        {
            return Ok(response);
        }
        return Err(error);
    }
    finish_new_operation(env, &database, principal, &request_id).await
}

async fn key_revoke(request: &mut Request, env: &Env, fingerprint: &str) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    if decode_hex_id(fingerprint, FINGERPRINT_LEN).is_none() {
        return invalid_request("fingerprint must contain exactly 64 hexadecimal characters");
    }
    let principal = match authorize(request, env, SIGN_SCOPE).await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let (product_id, dry_run) = match product_dry_run_query(request)? {
        Ok(query) => query,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    let Some(key) = load_key(&database, &product_id, fingerprint).await? else {
        return not_found("signer key not found");
    };
    if key.vendor_id != principal.vendor_id {
        return not_found("signer key not found");
    }
    let already_revoked = key.status == "revoked";

    if dry_run {
        return response::json_no_store(
            200,
            &json!({
                "ok": true,
                "dry_run": true,
                "product_id": product_id,
                "fingerprint": fingerprint,
                "status": key.status,
                "already_revoked": already_revoked,
            }),
        );
    }
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let action = "integrity-key:revoke";
    let target = format!("{product_id}/integrity/{fingerprint}");
    let before = json!({
        "product_id": product_id,
        "fingerprint": fingerprint,
        "status": "active",
    });
    let request_hash = admin_operations::request_hash(action, &target, &before)?;
    // Replay before the already-revoked check: a repeated confirmed request must return its
    // stored result, while a fresh request for a revoked key conflicts.
    if let Some(response) = replay_operation(
        env,
        &database,
        &principal,
        &request_id,
        &request_hash,
        SIGN_SCOPE,
    )
    .await?
    {
        return Ok(response);
    }
    if already_revoked {
        return conflict("already_revoked", "signer key is already revoked");
    }
    let result = json!({
        "ok": true,
        "dry_run": false,
        "product_id": product_id,
        "fingerprint": fingerprint,
        "status": "revoked",
    });
    let now = now_seconds();
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: SIGN_SCOPE.to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "integrity_signer_key".to_owned(),
        source_id: fingerprint.to_owned(),
        request_hash: request_hash.clone(),
        before,
        after: json!({
            "product_id": product_id,
            "fingerprint": fingerprint,
            "status": "revoked",
        }),
        result,
        response_status: 200,
        side_effect: None,
        created_at: now,
    };
    let statements = vec![
        admin_operations::insert_statement(&database, &operation)?,
        database
            .prepare(
                "UPDATE integrity_signer_keys SET status = 'revoked', revoked_at = ? \
                 WHERE product_id = ? AND fingerprint = ? AND status = 'active'",
            )
            .bind(&[integer(now)?, text(&product_id), text(fingerprint)])?,
    ];
    if let Err(error) = database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &database,
            &principal,
            &request_id,
            &request_hash,
            SIGN_SCOPE,
        )
        .await?
        {
            return Ok(response);
        }
        return Err(error);
    }
    finish_new_operation(env, &database, &principal, &request_id).await
}

async fn load_key(
    database: &D1Database,
    product_id: &str,
    fingerprint: &str,
) -> Result<Option<SignerKeyRow>> {
    database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT product_id, fingerprint, public_key, status, created_by, created_at, \
                    revoked_at, vendor_id \
             FROM integrity_signer_keys WHERE product_id = ? AND fingerprint = ?",
        )
        .bind(&[text(product_id), text(fingerprint)])?
        .first::<SignerKeyRow>(None)
        .await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterKeyBody {
    product_id: String,
    public_key_hex: String,
}

#[derive(Debug, Deserialize)]
struct ProductVendorRow {
    vendor_id: String,
}

#[derive(Debug, Deserialize)]
struct SignerKeyStatusRow {
    status: String,
}

#[derive(Debug, Deserialize)]
struct SignerKeyRow {
    product_id: String,
    fingerprint: String,
    #[serde(with = "serde_bytes")]
    public_key: Vec<u8>,
    status: String,
    created_by: String,
    created_at: i64,
    revoked_at: Option<i64>,
    #[serde(default)]
    vendor_id: String,
}
