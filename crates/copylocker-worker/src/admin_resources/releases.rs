//! Release registration and version-level revocation (M5-A,
//! `versioning-and-variants.md` §2 and §4).
//!
//! `POST /v1/admin/releases` is the write side of the release registry: the CLI registers every
//! published build so the activation path can resolve its variant. Variant parameters are
//! derived from a client-supplied CSPRNG seed (`variant_seed_hex`, the public-suite derivation
//! of §2.2) and stored AEAD-encrypted under `VARIANT_PARAMS_KEY`; only their SHA-256 fingerprint
//! reaches the operation journal. Deprecate and mark-compromised follow the Admin dry-run
//! discipline: the default response only reports the impact, and a confirmed `revoke`
//! additionally requires an explicit in-body acknowledgement.

use copylocker_server_core::version::CompromisedAction;
use copylocker_suite::{HashScheme, Secret};
use copylocker_suite_std::Sha256Scheme;
use serde::Deserialize;
use serde_json::{json, Value};
use worker::wasm_bindgen::JsValue;
use worker::{D1Database, D1SessionConstraint, Env, Method, Request, Response, Result};

use super::*;
use crate::admin::hex_encode;
use crate::bindings::authorization::{self, VariantParams};
use crate::bindings::rng::WorkerRng;

const SEVEN_DAYS_SECS: i64 = 7 * 24 * 60 * 60;
const RELEASE_SELECT: &str =
    "SELECT id, product_id, app_version, variant_id, variant_params, build_fingerprint, \
            manifest_root, channel, status, compromised_action, published_at, deprecated_at, \
            created_at \
     FROM releases";

pub(super) async fn route(request: &mut Request, env: &Env, segments: &[&str]) -> Result<Response> {
    match segments {
        ["releases"] => collection(request, env).await,
        ["releases", release_id] if !release_id.is_empty() => show(request, env, release_id).await,
        ["releases", release_id, "deprecate"] if !release_id.is_empty() => {
            deprecate(request, env, release_id).await
        }
        ["releases", release_id, "mark-compromised"] if !release_id.is_empty() => {
            mark_compromised(request, env, release_id).await
        }
        _ => not_found("release route not found"),
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
    let product_id = match product_query(request)? {
        Ok(product_id) => product_id,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let rows = database
        .prepare(format!(
            "{RELEASE_SELECT} WHERE product_id = ? ORDER BY published_at, id LIMIT 1001"
        ))
        .bind(&[text(&product_id)])?
        .all()
        .await?
        .results::<ReleaseRow>()?;
    if rows.len() > MAX_LIST_ITEMS {
        return response::api_error_no_store(
            413,
            "result_too_large",
            "release list exceeds 1000 items",
        );
    }
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(release_value(&row)?);
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

async fn show(request: &mut Request, env: &Env, release_id: &str) -> Result<Response> {
    if request.method() != Method::Get {
        return method_not_allowed();
    }
    if !valid_identifier(release_id) {
        return invalid_request("release id is invalid");
    }
    let principal = match authorize(request, env, "releases:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let product_id = match product_query(request)? {
        Ok(product_id) => product_id,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let Some(row) = load_release(&database, release_id, &product_id).await? else {
        return not_found("release not found");
    };
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "release": release_value(&row)?
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
        || !valid_app_version(&body.app_version)
        || !valid_build_fingerprint(&body.build_fingerprint)
        || !valid_identifier(&body.channel)
    {
        return invalid_request("release identity fields are invalid");
    }
    let manifest_root = match optional_hex32(&body.manifest_root_hex, "manifest_root_hex") {
        Ok(value) => value,
        Err(message) => return invalid_request(&message),
    };
    let module_digest = match optional_hex32(&body.module_digest_hex, "module_digest_hex") {
        Ok(value) => value,
        Err(message) => return invalid_request(&message),
    };
    let variant_seed = match optional_hex32(&body.variant_seed_hex, "variant_seed_hex") {
        Ok(value) => value.map(Secret::new),
        Err(message) => return invalid_request(&message),
    };
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let action = "release:register";
    let target = format!("{}/releases/{}", body.product_id, body.build_fingerprint);
    // The journal records the seed's fingerprint, never the seed itself.
    let seed_fingerprint = variant_seed
        .as_ref()
        .map(|seed| hex_encode(Sha256Scheme::hash(seed.expose()).as_bytes()));
    let request_value = json!({
        "product_id": body.product_id,
        "app_version": body.app_version,
        "build_fingerprint": body.build_fingerprint,
        "channel": body.channel,
        "manifest_root_hex": body.manifest_root_hex,
        "module_digest_hex": body.module_digest_hex,
        "variant_seed_sha256": seed_fingerprint,
    });
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

    // Re-registering the same build is idempotent even under a fresh Idempotency-Key:
    // the release identity is the (product, build fingerprint) pair.
    if let Some(existing) =
        load_release_by_fingerprint(&database, &body.product_id, &body.build_fingerprint).await?
    {
        if existing.app_version == body.app_version && existing.channel == body.channel {
            return response::json_no_store(
                200,
                &json!({
                    "ok": true,
                    "already_registered": true,
                    "release": release_value(&existing)?,
                }),
            );
        }
        return conflict(
            "already_exists",
            "a different release is already registered for this build fingerprint",
        );
    }

    let variant_stable = product_variant_stable(&database, &body.product_id).await?;
    let mut warnings = Vec::new();
    if variant_stable {
        warnings.push(json!({
            "id": "variant_stable",
            "message": "this product has a variant_stable policy; every release shares one \
                        variant, which disables per-release key isolation"
        }));
    }
    let stable_source = if variant_stable {
        load_first_active_release(&database, &body.product_id).await?
    } else {
        None
    };
    if variant_seed.is_none() && stable_source.is_none() {
        return invalid_request(
            "variant_seed_hex is required unless a variant_stable product reuses an existing variant",
        );
    }

    let mut rng = WorkerRng::new()?;
    let release_id = format!("rel_{}", hex_encode(&rng.random_array::<12>()?));
    let (variant_id, encrypted_params, variant_reused) = match &stable_source {
        Some(source) => {
            let variant_id = source.variant_id_u64()?;
            // Release registration is CL-STD-1-only on the admin axis; the request path
            // dispatches on the persisted suite when serving this release.
            let params = authorization::open_variant_params_at_rest(
                env,
                &source.id,
                &source.product_id,
                variant_id,
                &source.build_fingerprint,
                copylocker_suite_std::CL_STD_1_SUITE_ID,
                &source.variant_params,
            )
            .await
            .map_err(authorization_error)?;
            if params.variant_id != variant_id {
                return Err(worker::Error::RustError(
                    "release variant parameter id mismatch".to_owned(),
                ));
            }
            let encrypted = authorization::seal_variant_params_at_rest(
                env,
                &release_id,
                &body.product_id,
                &body.build_fingerprint,
                copylocker_suite_std::CL_STD_1_SUITE_ID,
                &VariantParams {
                    variant_id,
                    ..params
                },
                &mut rng,
            )
            .await
            .map_err(authorization_error)?;
            (variant_id, encrypted, true)
        }
        None => {
            let seed = variant_seed.ok_or_else(|| {
                worker::Error::RustError("variant seed requirement was not enforced".to_owned())
            })?;
            let variant_id = next_variant_id(&database, &body.product_id).await?;
            let encrypted = authorization::seal_variant_params_at_rest(
                env,
                &release_id,
                &body.product_id,
                &body.build_fingerprint,
                copylocker_suite_std::CL_STD_1_SUITE_ID,
                &VariantParams {
                    variant_id,
                    variant_const: *seed.expose(),
                    module_digest: module_digest.unwrap_or([0; 32]),
                    binder_extra: Vec::new(),
                },
                &mut rng,
            )
            .await
            .map_err(authorization_error)?;
            drop(seed);
            (variant_id, encrypted, false)
        }
    };
    rng.ensure_healthy()?;

    let now = now_seconds();
    let after = json!({
        "id": release_id,
        "product_id": body.product_id,
        "app_version": body.app_version,
        "variant_id": variant_id,
        "build_fingerprint": body.build_fingerprint,
        "channel": body.channel,
        "status": "active",
        "published_at": now,
        "variant_seed_sha256": seed_fingerprint,
    });
    let result = json!({
        "ok": true,
        "already_registered": false,
        "variant_reused": variant_reused,
        "release": {
            "id": release_id,
            "product_id": body.product_id,
            "app_version": body.app_version,
            "variant_id": variant_id,
            "build_fingerprint": body.build_fingerprint,
            "manifest_root_hex": body.manifest_root_hex,
            "channel": body.channel,
            "status": "active",
            "compromised_action": Value::Null,
            "published_at": now,
            "deprecated_at": Value::Null,
            "created_at": now,
        },
        "warnings": warnings,
    });
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "releases:rw".to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "release".to_owned(),
        source_id: release_id.clone(),
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
                "INSERT INTO releases(\
                   id, product_id, app_version, variant_id, variant_params, build_fingerprint, \
                   manifest_root, channel, status, compromised_action, min_sdk_version, \
                   proto_ver, suite_id, published_at, deprecated_at, created_at\
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', NULL, '0.0.0', ?, ?, ?, NULL, ?)",
            )
            .bind(&[
                text(&release_id),
                text(&body.product_id),
                text(&body.app_version),
                integer(i64::try_from(variant_id).map_err(|_| {
                    worker::Error::RustError("release variant id is invalid".to_owned())
                })?)?,
                blob(&encrypted_params),
                text(&body.build_fingerprint),
                match &manifest_root {
                    Some(root) => blob(root),
                    None => JsValue::NULL,
                },
                text(&body.channel),
                integer(i64::from(copylocker_types::PROTO_VER))?,
                blob(copylocker_suite_std::CL_STD_1_SUITE_ID.as_bytes()),
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

async fn deprecate(request: &mut Request, env: &Env, release_id: &str) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    let context = match transition_context(request, env, release_id).await? {
        Ok(context) => context,
        Err(rejection) => return Ok(rejection),
    };
    if context.dry_run {
        if let Some(rejection) = deprecatable(&context.release)? {
            return Ok(rejection);
        }
        let impact = load_impact(
            &context.database,
            &context.release.id,
            &context.release.product_id,
        )
        .await?;
        return response::json_no_store(
            200,
            &json!({
                "ok": true,
                "dry_run": true,
                "action": "deprecate",
                "release": release_value(&context.release)?,
                "impact": impact,
                "effects": [
                    "the release keeps working; validation tickets carry the deprecated marker",
                    "new activations remain possible until the version scope excludes the release"
                ],
            }),
        );
    }

    // A retried confirm must return the stored result, not a state conflict.
    let (request_id, request_hash) =
        match begin_transition(request, env, &context, "release:deprecate", &json!({})).await? {
            Ok(begin) => begin,
            Err(rejection) => return Ok(rejection),
        };
    if let Some(rejection) = deprecatable(&context.release)? {
        return Ok(rejection);
    }
    let impact = load_impact(
        &context.database,
        &context.release.id,
        &context.release.product_id,
    )
    .await?;
    let now = now_seconds();
    let before = json!({
        "id": context.release.id,
        "status": "active",
        "deprecated_at": Value::Null,
    });
    let after = json!({
        "id": context.release.id,
        "status": "deprecated",
        "deprecated_at": now,
    });
    let result = json!({
        "ok": true,
        "dry_run": false,
        "action": "deprecate",
        "release": after,
        "impact": impact,
    });
    finish_transition(
        env,
        &context,
        request_id,
        request_hash,
        "release:deprecate",
        before,
        after,
        result,
        vec![context
            .database
            .prepare(
                "UPDATE releases SET status = 'deprecated', deprecated_at = ? \
                 WHERE id = ? AND status = 'active'",
            )
            .bind(&[integer(now)?, text(&context.release.id)])?],
        now,
    )
    .await
}

fn deprecatable(release: &ReleaseRow) -> Result<Option<Response>> {
    if release.status == "deprecated" {
        return conflict("already_deprecated", "release is already deprecated").map(Some);
    }
    if release.status != "active" {
        return conflict("invalid_state", "only an active release can be deprecated").map(Some);
    }
    Ok(None)
}

async fn mark_compromised(request: &mut Request, env: &Env, release_id: &str) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    let body = match read_json::<CompromiseBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    let action = match body.action.as_str() {
        "warn" => CompromisedAction::Warn,
        "force_upgrade" => CompromisedAction::ForceUpgrade,
        "revoke" => CompromisedAction::Revoke,
        _ => return invalid_request("action must be warn, force_upgrade, or revoke"),
    };
    let context = match transition_context(request, env, release_id).await? {
        Ok(context) => context,
        Err(rejection) => return Ok(rejection),
    };

    let current_floor = authorization::current_security_floor(env)
        .await
        .map_err(authorization_error)?;
    let next_floor =
        if body.bump_security_floor {
            Some(current_floor.checked_add(1).ok_or_else(|| {
                worker::Error::RustError("security floor is exhausted".to_owned())
            })?)
        } else {
            None
        };
    if context.dry_run {
        if context.release.status == "compromised" {
            return conflict("already_compromised", "release is already compromised");
        }
        let impact = load_impact(
            &context.database,
            &context.release.id,
            &context.release.product_id,
        )
        .await?;
        return response::json_no_store(
            200,
            &json!({
                "ok": true,
                "dry_run": true,
                "action": action.as_str(),
                "release": release_value(&context.release)?,
                "impact": impact,
                "effects": action_effects(action),
                "requires_acknowledgement": action == CompromisedAction::Revoke,
                "security_floor": {
                    "current": current_floor,
                    "next": next_floor,
                },
            }),
        );
    }

    // A retried confirm must return the stored result, not a state conflict.
    let request_value = json!({
        "action": action.as_str(),
        "bump_security_floor": body.bump_security_floor,
        "acknowledge_revoke": body.acknowledge_revoke,
    });
    let (request_id, request_hash) = match begin_transition(
        request,
        env,
        &context,
        "release:mark-compromised",
        &request_value,
    )
    .await?
    {
        Ok(begin) => begin,
        Err(rejection) => return Ok(rejection),
    };
    if action == CompromisedAction::Revoke && !body.acknowledge_revoke {
        return response::api_error_no_store(
            400,
            "acknowledgement_required",
            "a confirmed revoke requires acknowledge_revoke: true in the request body",
        );
    }
    if context.release.status == "compromised" {
        return conflict("already_compromised", "release is already compromised");
    }
    let impact = load_impact(
        &context.database,
        &context.release.id,
        &context.release.product_id,
    )
    .await?;

    let now = now_seconds();
    let before = json!({
        "id": context.release.id,
        "status": context.release.status,
        "compromised_action": context.release.compromised_action,
    });
    let after = json!({
        "id": context.release.id,
        "status": "compromised",
        "compromised_action": action.as_str(),
        "security_floor": next_floor,
    });
    let result = json!({
        "ok": true,
        "dry_run": false,
        "action": action.as_str(),
        "release": {
            "id": context.release.id,
            "status": "compromised",
            "compromised_action": action.as_str(),
        },
        "impact": impact,
        "security_floor": next_floor,
    });
    let mut mutations = vec![context
        .database
        .prepare(
            "UPDATE releases SET status = 'compromised', compromised_action = ? \
             WHERE id = ? AND status IN ('active', 'deprecated')",
        )
        .bind(&[text(action.as_str()), text(&context.release.id)])?];
    if let Some(floor) = next_floor {
        mutations.push(
            context
                .database
                .prepare(
                    "INSERT INTO security_floor_log(floor, reason, release_id, actor, created_at) \
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(&[
                    integer(i64::try_from(floor).map_err(|_| {
                        worker::Error::RustError("security floor is invalid".to_owned())
                    })?)?,
                    text(&format!(
                        "release {} marked compromised ({})",
                        context.release.id,
                        action.as_str()
                    )),
                    text(&context.release.id),
                    text(&context.principal.actor),
                    integer(now)?,
                ])?,
        );
    }
    finish_transition(
        env,
        &context,
        request_id,
        request_hash,
        "release:mark-compromised",
        before,
        after,
        result,
        mutations,
        now,
    )
    .await
}

struct TransitionContext {
    principal: AdminPrincipal,
    database: D1Database,
    release: ReleaseRow,
    dry_run: bool,
}

/// Shared prelude for release lifecycle transitions: scope, identity, ownership, and the
/// dry-run default.
async fn transition_context(
    request: &Request,
    env: &Env,
    release_id: &str,
) -> Result<std::result::Result<TransitionContext, Response>> {
    if !valid_identifier(release_id) {
        return invalid_request("release id is invalid").map(Err);
    }
    let principal = match authorize(request, env, "releases:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(Err(rejection)),
    };
    let (product_id, dry_run) = match product_dry_run_query(request)? {
        Ok(query) => query,
        Err(rejection) => return Ok(Err(rejection)),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &product_id, &principal.vendor_id).await? {
        return not_found("product not found").map(Err);
    }
    let Some(release) = load_release(&database, release_id, &product_id).await? else {
        return not_found("release not found").map(Err);
    };
    Ok(Ok(TransitionContext {
        principal,
        database,
        release,
        dry_run,
    }))
}

/// Confirmed-transition prelude: idempotency key plus journal replay. Runs before the state
/// checks so a retried confirm returns the stored result instead of a conflict.
async fn begin_transition(
    request: &Request,
    env: &Env,
    context: &TransitionContext,
    action: &str,
    request_value: &Value,
) -> Result<std::result::Result<(String, Vec<u8>), Response>> {
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(Err(rejection)),
    };
    let target = format!(
        "{}/releases/{}",
        context.release.product_id, context.release.id
    );
    let request_hash = admin_operations::request_hash(action, &target, request_value)?;
    if let Some(response) = replay_operation(
        env,
        &context.database,
        &context.principal,
        &request_id,
        &request_hash,
        "releases:rw",
    )
    .await?
    {
        return Ok(Err(response));
    }
    Ok(Ok((request_id, request_hash)))
}

/// Journals and applies a confirmed release transition, returning the stored result.
#[allow(clippy::too_many_arguments)]
async fn finish_transition(
    env: &Env,
    context: &TransitionContext,
    request_id: String,
    request_hash: Vec<u8>,
    action: &str,
    before: Value,
    after: Value,
    result: Value,
    mutations: Vec<worker::D1PreparedStatement>,
    now: i64,
) -> Result<Response> {
    let target = format!(
        "{}/releases/{}",
        context.release.product_id, context.release.id
    );
    let operation = NewOperation {
        vendor_id: context.principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: context.principal.actor.clone(),
        required_scope: "releases:rw".to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "release".to_owned(),
        source_id: context.release.id.clone(),
        request_hash: request_hash.clone(),
        before,
        after,
        result,
        response_status: 200,
        side_effect: None,
        created_at: now,
    };
    let mut statements = vec![admin_operations::insert_statement(
        &context.database,
        &operation,
    )?];
    statements.extend(mutations);
    if let Err(error) = context.database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &context.database,
            &context.principal,
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
    finish_new_operation(env, &context.database, &context.principal, &request_id).await
}

fn action_effects(action: CompromisedAction) -> Vec<&'static str> {
    match action {
        CompromisedAction::Warn => vec![
            "validation tickets carry the compromised marker; activations and refreshes continue",
        ],
        CompromisedAction::ForceUpgrade => vec![
            "new activations for this release are rejected (1009)",
            "existing devices must upgrade before their next refresh to renew",
            "no device is disabled immediately",
        ],
        CompromisedAction::Revoke => vec![
            "new activations for this release are rejected (1009)",
            "every device on this release receives a KillOrder at its next validation",
        ],
    }
}

async fn load_impact(database: &D1Database, release_id: &str, product_id: &str) -> Result<Value> {
    let cutoff = now_seconds()
        .checked_sub(SEVEN_DAYS_SECS)
        .ok_or_else(|| worker::Error::RustError("impact window underflow".to_owned()))?;
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT COUNT(*) AS devices, \
                    COALESCE(SUM(CASE WHEN m.last_seen_at >= ? THEN 1 ELSE 0 END), 0) AS recent \
             FROM machines m \
             JOIN licenses l ON l.id = m.license_id \
             WHERE m.release_id = ? AND l.product_id = ? AND m.status IN ('active', 'pending')",
        )
        .bind(&[integer(cutoff)?, text(release_id), text(product_id)])?
        .first::<ImpactRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("impact query returned no row".to_owned()))?;
    if row.devices < 0 || row.recent < 0 || row.recent > row.devices {
        return Err(worker::Error::RustError(
            "release impact counts are invalid".to_owned(),
        ));
    }
    Ok(json!({
        "devices": row.devices,
        "checkins_last_7d": row.recent,
    }))
}

async fn load_release(
    database: &D1Database,
    release_id: &str,
    product_id: &str,
) -> Result<Option<ReleaseRow>> {
    database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(format!("{RELEASE_SELECT} WHERE id = ? AND product_id = ?"))
        .bind(&[text(release_id), text(product_id)])?
        .first::<ReleaseRow>(None)
        .await
}

async fn load_release_by_fingerprint(
    database: &D1Database,
    product_id: &str,
    build_fingerprint: &str,
) -> Result<Option<ReleaseRow>> {
    database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(format!(
            "{RELEASE_SELECT} WHERE product_id = ? AND build_fingerprint = ?"
        ))
        .bind(&[text(product_id), text(build_fingerprint)])?
        .first::<ReleaseRow>(None)
        .await
}

async fn load_first_active_release(
    database: &D1Database,
    product_id: &str,
) -> Result<Option<ReleaseRow>> {
    database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(format!(
            "{RELEASE_SELECT} WHERE product_id = ? AND status = 'active' \
             ORDER BY published_at, id LIMIT 1"
        ))
        .bind(&[text(product_id)])?
        .first::<ReleaseRow>(None)
        .await
}

async fn product_variant_stable(database: &D1Database, product_id: &str) -> Result<bool> {
    Ok(database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT 1 AS value FROM policies \
             WHERE product_id = ? AND offline_upgrade_policy = 'variant_stable' LIMIT 1",
        )
        .bind(&[text(product_id)])?
        .first::<ExistsRow>(None)
        .await?
        .is_some())
}

async fn next_variant_id(database: &D1Database, product_id: &str) -> Result<u64> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT COALESCE(MAX(variant_id), 0) + 1 AS value FROM releases WHERE product_id = ?",
        )
        .bind(&[text(product_id)])?
        .first::<VariantIdRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("variant id query returned no row".to_owned()))?;
    u64::try_from(row.value)
        .map_err(|_| worker::Error::RustError("variant id is out of range".to_owned()))
}

fn release_value(row: &ReleaseRow) -> Result<Value> {
    let variant_id = row.variant_id_u64()?;
    if row.published_at < 0 || row.created_at < 0 || row.deprecated_at.is_some_and(|v| v < 0) {
        return Err(worker::Error::RustError(
            "release row contains invalid timestamps".to_owned(),
        ));
    }
    Ok(json!({
        "id": row.id,
        "product_id": row.product_id,
        "app_version": row.app_version,
        "variant_id": variant_id,
        "build_fingerprint": row.build_fingerprint,
        "manifest_root_hex": row.manifest_root.as_ref().map(|root| hex_encode(root)),
        "channel": row.channel,
        "status": row.status,
        "compromised_action": row.compromised_action,
        "published_at": row.published_at,
        "deprecated_at": row.deprecated_at,
        "created_at": row.created_at,
    }))
}

fn valid_app_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

fn valid_build_fingerprint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'+')
        })
}

fn optional_hex32(
    value: &Option<String>,
    field: &str,
) -> std::result::Result<Option<[u8; 32]>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(bytes) = crate::admin::decode_hex_id(value, 32) else {
        return Err(format!(
            "{field} must contain exactly 64 hexadecimal characters"
        ));
    };
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Some(out))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    product_id: String,
    app_version: String,
    build_fingerprint: String,
    channel: String,
    #[serde(default)]
    manifest_root_hex: Option<String>,
    #[serde(default)]
    module_digest_hex: Option<String>,
    #[serde(default)]
    variant_seed_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompromiseBody {
    action: String,
    #[serde(default)]
    bump_security_floor: bool,
    #[serde(default)]
    acknowledge_revoke: bool,
}

#[derive(Debug, Deserialize)]
struct ReleaseRow {
    id: String,
    product_id: String,
    app_version: String,
    variant_id: i64,
    #[serde(with = "serde_bytes")]
    variant_params: Vec<u8>,
    build_fingerprint: String,
    #[serde(default, with = "serde_bytes")]
    manifest_root: Option<Vec<u8>>,
    channel: String,
    status: String,
    compromised_action: Option<String>,
    published_at: i64,
    deprecated_at: Option<i64>,
    created_at: i64,
}

impl ReleaseRow {
    fn variant_id_u64(&self) -> Result<u64> {
        u64::try_from(self.variant_id)
            .map_err(|_| worker::Error::RustError("release variant id is out of range".to_owned()))
    }
}

#[derive(Debug, Deserialize)]
struct ImpactRow {
    devices: i64,
    recent: i64,
}

#[derive(Debug, Deserialize)]
struct ExistsRow {
    #[serde(rename = "value")]
    _value: i64,
}

#[derive(Debug, Deserialize)]
struct VariantIdRow {
    value: i64,
}
