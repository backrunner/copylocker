use std::collections::BTreeMap;

use copylocker_server_core::catalog::{Catalog, Feature, FeatureGroup, GroupMembers, Tier};
use copylocker_server_core::entitlement::{resolve, EntitlementSpec};
use copylocker_server_core::policy::{OfflineUpgradePolicy, Policy, VtSignature};
use copylocker_types::Mode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use worker::wasm_bindgen::JsValue;
use worker::{D1Database, D1SessionConstraint, D1Type, Env, Method, Request, Response, Result};

use crate::admin::{
    authenticate_scope, idempotency_key, now_seconds, unauthorized, valid_identifier,
    AdminPrincipal, AuthResult,
};
use crate::admin_operations::{self, NewOperation};
use crate::bindings::authorization::{self, AuthorizationError};
use crate::middleware::body::{self, BodyError};
use crate::response;

const MAX_ADMIN_BODY: usize = 256 * 1024;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_LIST_ITEMS: usize = 1_000;

mod epochs;
mod licenses;

pub(crate) async fn route(request: &mut Request, env: &Env) -> Result<Response> {
    let path = request.path();
    let Some(rest) = path.strip_prefix("/v1/admin/") else {
        return response::api_error_no_store(404, "not_found", "admin route not found");
    };
    let segments = rest.split('/').collect::<Vec<_>>();
    match segments.as_slice() {
        ["licenses", ..] => licenses::route(request, env, &segments).await,
        ["epochs", ..] => epochs::route(request, env, &segments).await,
        ["catalog", collection @ ("features" | "groups" | "tiers")] => {
            catalog_collection(request, env, collection).await
        }
        ["catalog", "resolve"] => catalog_resolve(request, env).await,
        ["policies"] => policies_collection(request, env).await,
        ["policies", policy_id] if !policy_id.is_empty() => {
            policy_resource(request, env, policy_id).await
        }
        _ => response::api_error_no_store(404, "not_found", "admin route not found"),
    }
}

async fn catalog_collection(
    request: &mut Request,
    env: &Env,
    collection: &str,
) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Post | Method::Patch) {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "catalog:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    if request.method() == Method::Get {
        let product_id = match product_query(request)? {
            Ok(product_id) => product_id,
            Err(rejection) => return Ok(rejection),
        };
        if !product_owned(&env.d1("DB")?, &product_id, &principal.vendor_id).await? {
            return not_found("product not found");
        }
        let catalog = load_current_catalog(&env.d1("DB")?, &product_id).await?;
        let items = match collection {
            "features" => serde_json::to_value(catalog.features)?,
            "groups" => serde_json::to_value(catalog.groups)?,
            "tiers" => serde_json::to_value(catalog.tiers)?,
            _ => Value::Null,
        };
        return response::json_no_store(
            200,
            &json!({
                "ok": true,
                "product_id": product_id,
                "catalog_version": catalog.version,
                "items": items
            }),
        );
    }

    let component = match collection {
        "features" => match read_json::<FeatureBody>(request).await? {
            Ok(body) => CatalogComponent::Feature(body),
            Err(rejection) => return Ok(rejection),
        },
        "groups" => match read_json::<GroupBody>(request).await? {
            Ok(body) => CatalogComponent::Group(body),
            Err(rejection) => return Ok(rejection),
        },
        "tiers" => match read_json::<TierBody>(request).await? {
            Ok(body) => CatalogComponent::Tier(body),
            Err(rejection) => return Ok(rejection),
        },
        _ => return not_found("catalog collection not found"),
    };
    mutate_catalog(request, env, &principal, component).await
}

async fn mutate_catalog(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    component: CatalogComponent,
) -> Result<Response> {
    if component.validate().is_err() {
        return invalid_request("catalog item contains invalid data");
    }
    let create = request.method() == Method::Post;
    let verb = if create { "create" } else { "update" };
    let action = format!("catalog:{}:{verb}", component.singular());
    let target = format!(
        "{}/catalog/{}/{}",
        component.product_id(),
        component.plural(),
        component.id()
    );
    let request_value = component.request_value()?;
    let request_hash = admin_operations::request_hash(&action, &target, &request_value)?;
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if let Some(response) = replay_operation(
        env,
        &database,
        principal,
        &request_id,
        &request_hash,
        "catalog:rw",
    )
    .await?
    {
        return Ok(response);
    }
    if !product_owned(&database, component.product_id(), &principal.vendor_id).await? {
        return not_found("product not found");
    }

    let mut catalog = load_current_catalog(&database, component.product_id()).await?;
    let previous_version = catalog.version;
    let before = match component.apply(&mut catalog, create) {
        Ok(before) => before,
        Err(ComponentError::AlreadyExists) => {
            return conflict("already_exists", "catalog item already exists");
        }
        Err(ComponentError::NotFound) => return not_found("catalog item not found"),
        Err(ComponentError::NoChange) => {
            return conflict("no_change", "catalog update does not change the item");
        }
    };
    catalog.version = catalog
        .version
        .checked_add(1)
        .ok_or_else(|| worker::Error::RustError("catalog version is exhausted".to_owned()))?;
    catalog.sort_items();
    let previous_catalog =
        load_catalog_at(&database, component.product_id(), previous_version).await?;
    if let Err(error) = previous_catalog.validate_evolution(&catalog) {
        return response::api_error_no_store(422, "invalid_catalog", &error.to_string());
    }
    let snapshot = crate::json_cbor::encode(&catalog)?;
    let after = component.snapshot_value()?;
    let before = before.unwrap_or(Value::Null);
    let result = json!({
        "ok": true,
        "product_id": component.product_id(),
        "catalog_version": catalog.version,
        "item": after
    });
    let now = now_seconds();
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "catalog:rw".to_owned(),
        action,
        target,
        source_kind: "catalog".to_owned(),
        source_id: format!(
            "{}/{}/{}",
            component.product_id(),
            component.plural(),
            component.id()
        ),
        request_hash: request_hash.clone(),
        before,
        after,
        result,
        response_status: if create { 201 } else { 200 },
        side_effect: None,
        created_at: now,
    };
    let mut statements = vec![admin_operations::insert_statement(&database, &operation)?];
    statements.push(component.statement(&database, create, now)?);
    statements.push(
        database
            .prepare(
                "INSERT INTO catalog_versions(\
                   product_id, version, snapshot, created_by, created_at\
                 ) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&[
                text(component.product_id()),
                integer(i64::from(catalog.version))?,
                blob(&snapshot),
                text(&principal.actor),
                integer(now)?,
            ])?,
    );

    if let Err(error) = database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &database,
            principal,
            &request_id,
            &request_hash,
            "catalog:rw",
        )
        .await?
        {
            return Ok(response);
        }
        let current = current_catalog_version(&database, component.product_id()).await?;
        if current != i64::from(previous_version) {
            return conflict(
                "concurrent_modification",
                "the catalog changed; reload it and retry with a new Idempotency-Key",
            );
        }
        return Err(error);
    }
    finish_new_operation(env, &database, principal, &request_id).await
}

async fn catalog_resolve(request: &mut Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "catalog:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let input = match read_json::<ResolveBody>(request).await? {
        Ok(input) => input,
        Err(rejection) => return Ok(rejection),
    };
    if !valid_identifier(&input.product_id)
        || input
            .at
            .is_some_and(|value| !(0..=MAX_SAFE_INTEGER).contains(&value))
    {
        return invalid_request("resolve request contains invalid product or time data");
    }
    let database = env.d1("DB")?;
    if !product_owned(&database, &input.product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let version = match input.catalog_version {
        Some(version) => version,
        None => u32::try_from(current_catalog_version(&database, &input.product_id).await?)
            .map_err(|_| worker::Error::RustError("catalog version is invalid".to_owned()))?,
    };
    let catalog = load_catalog_at(&database, &input.product_id, version).await?;
    let at = input.at.unwrap_or_else(now_seconds);
    let resolved = match resolve(&catalog, &input.entitlement, at) {
        Ok(resolved) => resolved,
        Err(error) => {
            return response::api_error_no_store(422, "invalid_entitlement", &error.to_string());
        }
    };
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "product_id": input.product_id,
            "catalog_version": version,
            "at": at,
            "entitlements": resolved
        }),
    )
}

async fn policies_collection(request: &mut Request, env: &Env) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Post) {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "policies:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    if request.method() == Method::Get {
        let product_id = match product_query(request)? {
            Ok(product_id) => product_id,
            Err(rejection) => return Ok(rejection),
        };
        return list_policies(env, &principal, &product_id).await;
    }
    let policy = match read_json::<Policy>(request).await? {
        Ok(policy) => policy,
        Err(rejection) => return Ok(rejection),
    };
    mutate_policy(request, env, &principal, policy, None).await
}

async fn policy_resource(request: &mut Request, env: &Env, policy_id: &str) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Patch) {
        return method_not_allowed();
    }
    if !valid_identifier(policy_id) {
        return invalid_request("policy id is invalid");
    }
    let principal = match authorize(request, env, "policies:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    if request.method() == Method::Get {
        let database = env.d1("DB")?;
        let Some(policy) = load_owned_policy(&database, policy_id, &principal.vendor_id).await?
        else {
            return not_found("policy not found");
        };
        let version =
            admin_operations::current_entity_version(&database, "policy", policy_id).await?;
        return policy_response(200, &policy, Some(version));
    }
    let policy = match read_json::<Policy>(request).await? {
        Ok(policy) => policy,
        Err(rejection) => return Ok(rejection),
    };
    if policy.id != policy_id {
        return invalid_request("request policy id does not match the URL");
    }
    mutate_policy(request, env, &principal, policy, Some(policy_id)).await
}

async fn mutate_policy(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    policy: Policy,
    existing_id: Option<&str>,
) -> Result<Response> {
    if !valid_policy_identity(&policy) {
        return invalid_request("policy identity or display name is invalid");
    }
    if let Err(error) = policy.validate() {
        return response::api_error_no_store(422, "invalid_policy", &error.to_string());
    }
    let create = existing_id.is_none();
    let action = if create {
        "policy:create".to_owned()
    } else {
        "policy:update".to_owned()
    };
    let target = format!("{}/policies/{}", policy.product_id, policy.id);
    let request_value = serde_json::to_value(&policy)?;
    let request_hash = admin_operations::request_hash(&action, &target, &request_value)?;
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if let Some(response) = replay_operation(
        env,
        &database,
        principal,
        &request_id,
        &request_hash,
        "policies:rw",
    )
    .await?
    {
        return Ok(response);
    }
    if !product_owned(&database, &policy.product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let current_catalog = load_current_catalog(&database, &policy.product_id).await?;
    if let Err(error) = resolve(&current_catalog, &policy.entitlement, now_seconds()) {
        return response::api_error_no_store(422, "invalid_entitlement", &error.to_string());
    }

    let before_policy = load_owned_policy(&database, &policy.id, &principal.vendor_id).await?;
    match (create, before_policy.as_ref()) {
        (true, Some(_)) => return conflict("already_exists", "policy already exists"),
        (false, None) => return not_found("policy not found"),
        _ => {}
    }
    if before_policy.as_ref() == Some(&policy) {
        return conflict("no_change", "policy update does not change the policy");
    }
    if before_policy
        .as_ref()
        .is_some_and(|before| before.product_id != policy.product_id)
    {
        return invalid_request("a policy cannot move to another product");
    }
    let version = admin_operations::current_entity_version(&database, "policy", &policy.id).await?;
    let next_version = version
        .checked_add(1)
        .ok_or_else(|| worker::Error::RustError("policy version is exhausted".to_owned()))?;
    let warnings = policy_warning_values(&policy);
    let result = json!({
        "ok": true,
        "policy": policy,
        "version": next_version,
        "warnings": warnings
    });
    let now = now_seconds();
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "policies:rw".to_owned(),
        action,
        target,
        source_kind: "policy".to_owned(),
        source_id: policy.id.clone(),
        request_hash: request_hash.clone(),
        before: before_policy
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or(Value::Null),
        after: serde_json::to_value(&policy)?,
        result,
        response_status: if create { 201 } else { 200 },
        side_effect: None,
        created_at: now,
    };
    let statements = vec![
        admin_operations::insert_statement(&database, &operation)?,
        admin_operations::version_statement(
            &database,
            &operation.operation_id(),
            "policy",
            &policy.id,
            next_version,
            now,
        )?,
        policy_statement(&database, &policy, create, now)?,
    ];
    if let Err(error) = database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &database,
            principal,
            &request_id,
            &request_hash,
            "policies:rw",
        )
        .await?
        {
            return Ok(response);
        }
        let current =
            admin_operations::current_entity_version(&database, "policy", &policy.id).await?;
        if current != version {
            return conflict(
                "concurrent_modification",
                "the policy changed; reload it and retry with a new Idempotency-Key",
            );
        }
        return Err(error);
    }
    finish_new_operation(env, &database, principal, &request_id).await
}

async fn list_policies(
    env: &Env,
    principal: &AdminPrincipal,
    product_id: &str,
) -> Result<Response> {
    let database = env.d1("DB")?;
    if !product_owned(&database, product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let rows = database
        .prepare(
            "SELECT p.id FROM policies p \
             JOIN products product ON product.id = p.product_id \
             WHERE p.product_id = ? AND product.vendor_id = ? ORDER BY p.id LIMIT 1001",
        )
        .bind(&[text(product_id), text(&principal.vendor_id)])?
        .all()
        .await?
        .results::<PolicyIdRow>()?;
    if rows.len() > MAX_LIST_ITEMS {
        return response::api_error_no_store(
            413,
            "result_too_large",
            "policy list exceeds 1000 items",
        );
    }
    let mut policies = Vec::with_capacity(rows.len());
    for row in rows {
        let policy = authorization::load_policy(&database, &row.id, product_id)
            .await
            .map_err(authorization_error)?;
        policies.push(policy);
    }
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "product_id": product_id,
            "items": policies
        }),
    )
}

async fn load_owned_policy(
    database: &D1Database,
    policy_id: &str,
    vendor_id: &str,
) -> Result<Option<Policy>> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT p.product_id FROM policies p \
             JOIN products product ON product.id = p.product_id \
             WHERE p.id = ? AND product.vendor_id = ?",
        )
        .bind(&[text(policy_id), text(vendor_id)])?
        .first::<ProductIdRow>(None)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    authorization::load_policy(database, policy_id, &row.product_id)
        .await
        .map(Some)
        .map_err(authorization_error)
}

fn policy_statement(
    database: &D1Database,
    policy: &Policy,
    create: bool,
    now: i64,
) -> Result<worker::D1PreparedStatement> {
    let entitlement = serde_json::to_string(&policy.entitlement)?;
    let validity = serde_json::to_string(&policy.validity)?;
    let version_scope = serde_json::to_string(&policy.version_scope)?;
    let mode = match policy.mode {
        Mode::OfflineHybrid => 0,
        Mode::EnforcedOnline => 1,
    };
    let signature = match policy.runtime.vt_signature {
        VtSignature::Fast => "fast",
        VtSignature::Pq => "pq",
    };
    let upgrade = match policy.runtime.offline_upgrade_policy {
        OfflineUpgradePolicy::RequireOnline => "require_online",
        OfflineUpgradePolicy::PreloadN => "preload_n",
        OfflineUpgradePolicy::VariantStable => "variant_stable",
    };
    let values = [
        text(&policy.name),
        optional_text(policy.preset.as_deref()),
        text(&entitlement),
        text(&validity),
        text(&version_scope),
        integer(i64::from(policy.seats.seats))?,
        optional_u32(policy.seats.max_transfers)?,
        optional_integer(policy.seats.transfer_window_secs)?,
        optional_integer(policy.seats.heartbeat_secs)?,
        integer(mode)?,
        integer(policy.runtime.refresh_after_secs)?,
        integer(i64::from(policy.runtime.grace_secs))?,
        integer(i64::from(policy.runtime.fpr_tolerance))?,
        integer(i64::from(policy.runtime.allow_vm))?,
        integer(i64::from(policy.runtime.allow_olk))?,
        integer(i64::from(policy.runtime.allow_unbound_olk))?,
        text(signature),
        text(upgrade),
        integer(i64::from(policy.runtime.preload_variants_n))?,
        integer(i64::from(policy.runtime.report_attrs))?,
        integer(now)?,
    ];
    if create {
        let mut bindings = vec![text(&policy.id), text(&policy.product_id)];
        bindings.extend(values);
        bindings.push(integer(now)?);
        database
            .prepare(
                "INSERT INTO policies(\
                   id, product_id, name, preset, entitlement_json, validity_json, \
                   version_scope_json, seats, max_transfers, transfer_window_s, heartbeat_sec, \
                   mode, refresh_after_sec, grace_seconds, fpr_tolerance, allow_vm, allow_olk, \
                   allow_unbound_olk, vt_signature, offline_upgrade_policy, preload_variants_n, \
                   report_attrs, created_at, updated_at\
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&bindings)
    } else {
        let mut bindings = values.to_vec();
        bindings.push(text(&policy.id));
        bindings.push(text(&policy.product_id));
        database
            .prepare(
                "UPDATE policies SET \
                   name = ?, preset = ?, entitlement_json = ?, validity_json = ?, \
                   version_scope_json = ?, seats = ?, max_transfers = ?, transfer_window_s = ?, \
                   heartbeat_sec = ?, mode = ?, refresh_after_sec = ?, grace_seconds = ?, \
                   fpr_tolerance = ?, allow_vm = ?, allow_olk = ?, allow_unbound_olk = ?, \
                   vt_signature = ?, offline_upgrade_policy = ?, preload_variants_n = ?, \
                   report_attrs = ?, updated_at = ? \
                 WHERE id = ? AND product_id = ?",
            )
            .bind(&bindings)
    }
}

fn policy_warning_values(policy: &Policy) -> Vec<Value> {
    policy
        .warnings()
        .into_iter()
        .map(|warning| json!({"id": warning.id, "message": warning.message}))
        .collect()
}

fn policy_response(status: u16, policy: &Policy, version: Option<i64>) -> Result<Response> {
    response::json_no_store(
        status,
        &json!({
            "ok": true,
            "policy": policy,
            "version": version,
            "warnings": policy_warning_values(policy)
        }),
    )
}

async fn replay_operation(
    env: &Env,
    database: &D1Database,
    principal: &AdminPrincipal,
    request_id: &str,
    request_hash: &[u8],
    required_scope: &str,
) -> Result<Option<Response>> {
    let Some(operation) =
        admin_operations::load(database, &principal.vendor_id, request_id).await?
    else {
        return Ok(None);
    };
    if !operation.matches_request(request_hash) || operation.required_scope != required_scope {
        return conflict(
            "idempotency_conflict",
            "Idempotency-Key was already used for another request",
        )
        .map(Some);
    }
    let completed = complete_operation(env, database, &operation).await?;
    response::json_no_store(completed.response_status, &completed.result).map(Some)
}

async fn finish_new_operation(
    env: &Env,
    database: &D1Database,
    principal: &AdminPrincipal,
    request_id: &str,
) -> Result<Response> {
    let operation = admin_operations::load(database, &principal.vendor_id, request_id)
        .await?
        .ok_or_else(|| worker::Error::RustError("Admin operation was not persisted".to_owned()))?;
    let completed = complete_operation(env, database, &operation).await?;
    response::json_no_store(completed.response_status, &completed.result)
}

async fn complete_operation(
    env: &Env,
    database: &D1Database,
    operation: &admin_operations::StoredOperation,
) -> Result<admin_operations::StoredOperation> {
    let operation = if operation.side_effect_pending() {
        match operation.source_kind.as_str() {
            "license" => licenses::apply_side_effect(env, operation).await?,
            "epoch" => epochs::apply_side_effect(env, operation).await?,
            _ => {
                return Err(worker::Error::RustError(
                    "Admin operation has an unsupported side effect".to_owned(),
                ));
            }
        }
        admin_operations::mark_side_effect_complete(database, operation).await?
    } else {
        operation.clone()
    };
    admin_operations::finalize(env, database, &operation).await
}

pub(crate) async fn reconcile_pending_side_effect(env: &Env) -> Result<bool> {
    let database = env.d1("DB")?;
    let Some(operation) = admin_operations::load_pending_side_effect(&database).await? else {
        return Ok(false);
    };
    complete_operation(env, &database, &operation).await?;
    Ok(true)
}

async fn authorize(
    request: &Request,
    env: &Env,
    required_scope: &str,
) -> Result<std::result::Result<AdminPrincipal, Response>> {
    Ok(
        match authenticate_scope(request, env, required_scope).await? {
            AuthResult::Authenticated(principal) => Ok(principal),
            AuthResult::Unauthorized => Err(unauthorized()?),
            AuthResult::Forbidden => Err(response::api_error_no_store(
                403,
                "insufficient_scope",
                &format!("the token does not grant the {required_scope} scope"),
            )?),
        },
    )
}

async fn read_json<T: DeserializeOwned>(
    request: &mut Request,
) -> Result<std::result::Result<T, Response>> {
    let Some(content_type) = request.headers().get("Content-Type")? else {
        return Ok(Err(response::api_error_no_store(
            415,
            "unsupported_media_type",
            "Content-Type must be application/json",
        )?));
    };
    let media_type = content_type
        .split_once(';')
        .map_or(content_type.as_str(), |(value, _)| value)
        .trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Ok(Err(response::api_error_no_store(
            415,
            "unsupported_media_type",
            "Content-Type must be application/json",
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
    let bytes = match body::read_raw(request, MAX_ADMIN_BODY).await {
        Ok(bytes) => bytes,
        Err(BodyError::Read(error)) => return Err(error),
        Err(BodyError::TooLarge) => {
            return Ok(Err(response::api_error_no_store(
                413,
                "payload_too_large",
                "request body exceeds the 256 KiB limit",
            )?));
        }
        Err(_) => {
            return Ok(Err(response::api_error_no_store(
                400,
                "invalid_request",
                "request body must be a JSON object",
            )?));
        }
    };
    Ok(match serde_json::from_slice(&bytes) {
        Ok(value) => Ok(value),
        Err(_) => Err(response::api_error_no_store(
            400,
            "invalid_request",
            "request body does not match the endpoint schema",
        )?),
    })
}

fn require_idempotency_key(request: &Request) -> Result<std::result::Result<String, Response>> {
    Ok(match idempotency_key(request)? {
        Some(value) => Ok(value),
        None => Err(response::api_error_no_store(
            400,
            "missing_idempotency_key",
            "Admin mutations require a valid Idempotency-Key",
        )?),
    })
}

fn product_query(request: &Request) -> Result<std::result::Result<String, Response>> {
    let mut product_id = None;
    for (name, value) in request.url()?.query_pairs() {
        if name != "product_id" || product_id.is_some() || !valid_identifier(&value) {
            return Ok(Err(response::api_error_no_store(
                400,
                "invalid_query",
                "exactly one valid product_id query parameter is required",
            )?));
        }
        product_id = Some(value.into_owned());
    }
    Ok(match product_id {
        Some(value) => Ok(value),
        None => Err(response::api_error_no_store(
            400,
            "invalid_query",
            "exactly one valid product_id query parameter is required",
        )?),
    })
}

async fn product_owned(database: &D1Database, product_id: &str, vendor_id: &str) -> Result<bool> {
    Ok(database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT id AS product_id FROM products \
             WHERE id = ? AND vendor_id = ? AND archived_at IS NULL",
        )
        .bind(&[text(product_id), text(vendor_id)])?
        .first::<ProductIdRow>(None)
        .await?
        .is_some())
}

async fn current_catalog_version(database: &D1Database, product_id: &str) -> Result<i64> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT COALESCE(MAX(version), 0) AS value FROM catalog_versions WHERE product_id = ?",
        )
        .bind(&[text(product_id)])?
        .first::<IntegerRow>(None)
        .await?
        .ok_or_else(|| {
            worker::Error::RustError("catalog version query returned no row".to_owned())
        })?;
    if (0..=i64::from(u32::MAX)).contains(&row.value) {
        Ok(row.value)
    } else {
        Err(worker::Error::RustError(
            "catalog version is invalid".to_owned(),
        ))
    }
}

async fn load_current_catalog(database: &D1Database, product_id: &str) -> Result<Catalog> {
    let version = u32::try_from(current_catalog_version(database, product_id).await?)
        .map_err(|_| worker::Error::RustError("catalog version is invalid".to_owned()))?;
    load_catalog_at(database, product_id, version).await
}

async fn load_catalog_at(database: &D1Database, product_id: &str, version: u32) -> Result<Catalog> {
    authorization::load_catalog(database, product_id, version)
        .await
        .map_err(authorization_error)
}

fn authorization_error(error: AuthorizationError) -> worker::Error {
    match error {
        AuthorizationError::Server(error) => error,
        _ => worker::Error::RustError("unexpected authorization lookup failure".to_owned()),
    }
}

fn valid_policy_identity(policy: &Policy) -> bool {
    valid_identifier(&policy.id)
        && valid_identifier(&policy.product_id)
        && !policy.name.trim().is_empty()
        && policy.name.len() <= 256
        && policy
            .preset
            .as_ref()
            .is_none_or(|value| value.len() <= 128)
}

fn method_not_allowed() -> Result<Response> {
    response::api_error_no_store(405, "method_not_allowed", "HTTP method not allowed")
}

fn invalid_request(message: &str) -> Result<Response> {
    response::api_error_no_store(400, "invalid_request", message)
}

fn not_found(message: &str) -> Result<Response> {
    response::api_error_no_store(404, "not_found", message)
}

fn conflict(code: &str, message: &str) -> Result<Response> {
    response::api_error_no_store(409, code, message)
}

fn blob(value: &[u8]) -> JsValue {
    JsValue::from(&D1Type::Blob(value))
}

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn optional_text(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, JsValue::from_str)
}

fn integer(value: i64) -> Result<JsValue> {
    if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
        return Err(worker::Error::RustError(
            "Admin integer exceeds JavaScript safe range".to_owned(),
        ));
    }
    Ok(JsValue::from_f64(value as f64))
}

fn optional_integer(value: Option<i64>) -> Result<JsValue> {
    value.map_or(Ok(JsValue::NULL), integer)
}

fn optional_u32(value: Option<u32>) -> Result<JsValue> {
    optional_integer(value.map(i64::from))
}

trait CatalogSort {
    fn sort_items(&mut self);
}

impl CatalogSort for Catalog {
    fn sort_items(&mut self) {
        self.features.sort_by(|left, right| left.id.cmp(&right.id));
        self.groups.sort_by(|left, right| left.id.cmp(&right.id));
        self.tiers.sort_by(|left, right| left.id.cmp(&right.id));
    }
}

enum CatalogComponent {
    Feature(FeatureBody),
    Group(GroupBody),
    Tier(TierBody),
}

impl CatalogComponent {
    fn product_id(&self) -> &str {
        match self {
            Self::Feature(value) => &value.product_id,
            Self::Group(value) => &value.product_id,
            Self::Tier(value) => &value.product_id,
        }
    }

    fn id(&self) -> &str {
        match self {
            Self::Feature(value) => &value.id,
            Self::Group(value) => &value.id,
            Self::Tier(value) => &value.id,
        }
    }

    const fn singular(&self) -> &'static str {
        match self {
            Self::Feature(_) => "feature",
            Self::Group(_) => "group",
            Self::Tier(_) => "tier",
        }
    }

    const fn plural(&self) -> &'static str {
        match self {
            Self::Feature(_) => "features",
            Self::Group(_) => "groups",
            Self::Tier(_) => "tiers",
        }
    }

    fn validate(&self) -> Result<()> {
        let (product_id, id, label) = match self {
            Self::Feature(value) => (&value.product_id, &value.id, &value.label),
            Self::Group(value) => (&value.product_id, &value.id, &value.label),
            Self::Tier(value) => (&value.product_id, &value.id, &value.label),
        };
        let valid = valid_identifier(product_id)
            && valid_identifier(id)
            && !label.trim().is_empty()
            && label.len() <= 256;
        let valid = valid
            && match self {
                Self::Feature(value) => {
                    value
                        .description
                        .as_ref()
                        .is_none_or(|value| value.len() <= 4096)
                        && value.deprecated_at.is_none_or(|value| value >= 0)
                }
                Self::Group(value) => {
                    value.members.includes.len() <= 256 && value.members.features.len() <= 256
                }
                Self::Tier(value) => {
                    value.groups.len() <= 256
                        && value.features.len() <= 256
                        && value.limits.len() <= 256
                        && value.archived_at.is_none_or(|value| value >= 0)
                }
            };
        if valid {
            Ok(())
        } else {
            Err(worker::Error::RustError(
                "catalog item contains invalid data".to_owned(),
            ))
        }
    }

    fn request_value(&self) -> Result<Value> {
        match self {
            Self::Feature(value) => Ok(serde_json::to_value(value)?),
            Self::Group(value) => Ok(serde_json::to_value(value)?),
            Self::Tier(value) => Ok(serde_json::to_value(value)?),
        }
    }

    fn snapshot_value(&self) -> Result<Value> {
        match self {
            Self::Feature(value) => Ok(serde_json::to_value(value.feature())?),
            Self::Group(value) => Ok(serde_json::to_value(value.group())?),
            Self::Tier(value) => Ok(serde_json::to_value(value.tier())?),
        }
    }

    fn apply(
        &self,
        catalog: &mut Catalog,
        create: bool,
    ) -> std::result::Result<Option<Value>, ComponentError> {
        match self {
            Self::Feature(value) => replace_item(
                &mut catalog.features,
                value.feature(),
                &value.id,
                create,
                |item| &item.id,
            ),
            Self::Group(value) => replace_item(
                &mut catalog.groups,
                value.group(),
                &value.id,
                create,
                |item| &item.id,
            ),
            Self::Tier(value) => replace_item(
                &mut catalog.tiers,
                value.tier(),
                &value.id,
                create,
                |item| &item.id,
            ),
        }
    }

    fn statement(
        &self,
        database: &D1Database,
        create: bool,
        now: i64,
    ) -> Result<worker::D1PreparedStatement> {
        match self {
            Self::Feature(value) if create => database
                .prepare(
                    "INSERT INTO features(\
                       product_id, id, label, description, deprecated_at, created_at\
                     ) VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&[
                    text(&value.product_id),
                    text(&value.id),
                    text(&value.label),
                    optional_text(value.description.as_deref()),
                    optional_integer(value.deprecated_at)?,
                    integer(now)?,
                ]),
            Self::Feature(value) => database
                .prepare(
                    "UPDATE features SET label = ?, description = ?, deprecated_at = ? \
                     WHERE product_id = ? AND id = ?",
                )
                .bind(&[
                    text(&value.label),
                    optional_text(value.description.as_deref()),
                    optional_integer(value.deprecated_at)?,
                    text(&value.product_id),
                    text(&value.id),
                ]),
            Self::Group(value) if create => database
                .prepare(
                    "INSERT INTO feature_groups(product_id, id, label, members_json, updated_at) \
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(&[
                    text(&value.product_id),
                    text(&value.id),
                    text(&value.label),
                    text(&serde_json::to_string(&value.members)?),
                    integer(now)?,
                ]),
            Self::Group(value) => database
                .prepare(
                    "UPDATE feature_groups SET label = ?, members_json = ?, updated_at = ? \
                     WHERE product_id = ? AND id = ?",
                )
                .bind(&[
                    text(&value.label),
                    text(&serde_json::to_string(&value.members)?),
                    integer(now)?,
                    text(&value.product_id),
                    text(&value.id),
                ]),
            Self::Tier(value) if create => database
                .prepare(
                    "INSERT INTO tiers(\
                       product_id, id, label, rank, groups_json, features_json, limits_json, \
                       archived_at\
                     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&[
                    text(&value.product_id),
                    text(&value.id),
                    text(&value.label),
                    integer(i64::from(value.rank))?,
                    text(&serde_json::to_string(&value.groups)?),
                    text(&serde_json::to_string(&value.features)?),
                    text(&serde_json::to_string(&value.limits)?),
                    optional_integer(value.archived_at)?,
                ]),
            Self::Tier(value) => database
                .prepare(
                    "UPDATE tiers SET label = ?, rank = ?, groups_json = ?, features_json = ?, \
                       limits_json = ?, archived_at = ? WHERE product_id = ? AND id = ?",
                )
                .bind(&[
                    text(&value.label),
                    integer(i64::from(value.rank))?,
                    text(&serde_json::to_string(&value.groups)?),
                    text(&serde_json::to_string(&value.features)?),
                    text(&serde_json::to_string(&value.limits)?),
                    optional_integer(value.archived_at)?,
                    text(&value.product_id),
                    text(&value.id),
                ]),
        }
    }
}

fn replace_item<T, F>(
    items: &mut Vec<T>,
    proposed: T,
    id: &str,
    create: bool,
    id_of: F,
) -> std::result::Result<Option<Value>, ComponentError>
where
    T: Clone + PartialEq + Serialize,
    F: Fn(&T) -> &String,
{
    let position = items.iter().position(|item| id_of(item) == id);
    match (create, position) {
        (true, Some(_)) => Err(ComponentError::AlreadyExists),
        (false, None) => Err(ComponentError::NotFound),
        (true, None) => {
            items.push(proposed);
            Ok(None)
        }
        (false, Some(position)) => {
            let current = items.get(position).ok_or(ComponentError::NotFound)?;
            if current == &proposed {
                return Err(ComponentError::NoChange);
            }
            let before = serde_json::to_value(current).map_err(|_| ComponentError::NotFound)?;
            let slot = items.get_mut(position).ok_or(ComponentError::NotFound)?;
            *slot = proposed;
            Ok(Some(before))
        }
    }
}

enum ComponentError {
    AlreadyExists,
    NotFound,
    NoChange,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FeatureBody {
    product_id: String,
    id: String,
    label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deprecated_at: Option<i64>,
}

impl FeatureBody {
    fn feature(&self) -> Feature {
        Feature {
            id: self.id.clone(),
            label: self.label.clone(),
            description: self.description.clone(),
            deprecated_at: self.deprecated_at,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GroupBody {
    product_id: String,
    id: String,
    label: String,
    members: GroupMembers,
}

impl GroupBody {
    fn group(&self) -> FeatureGroup {
        FeatureGroup {
            id: self.id.clone(),
            label: self.label.clone(),
            members: self.members.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TierBody {
    product_id: String,
    id: String,
    label: String,
    rank: i32,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    limits: BTreeMap<String, copylocker_types::LimitValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    archived_at: Option<i64>,
}

impl TierBody {
    fn tier(&self) -> Tier {
        Tier {
            id: self.id.clone(),
            label: self.label.clone(),
            rank: self.rank,
            groups: self.groups.clone(),
            features: self.features.clone(),
            limits: self.limits.clone(),
            archived_at: self.archived_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveBody {
    product_id: String,
    #[serde(default)]
    catalog_version: Option<u32>,
    entitlement: EntitlementSpec,
    #[serde(default)]
    at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ProductIdRow {
    product_id: String,
}

#[derive(Debug, Deserialize)]
struct PolicyIdRow {
    id: String,
}

#[derive(Debug, Deserialize)]
struct IntegerRow {
    value: i64,
}
