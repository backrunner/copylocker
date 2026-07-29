use copylocker_server_core::policy::Validity;
use copylocker_server_core::subscription::{preview_ending, Subscription, SubscriptionState};
use copylocker_suite::HashScheme;
use copylocker_suite_std::Sha256Scheme;
use copylocker_types::{LicenseId, VersionScope};
use serde::{Deserialize, Serialize};
use worker::{Headers, RequestInit};

use super::*;

const MAX_LICENSE_BATCH: u32 = 100;

pub(super) async fn route(request: &mut Request, env: &Env, segments: &[&str]) -> Result<Response> {
    match segments {
        ["licenses"] => collection(request, env).await,
        ["licenses", license_id] if !license_id.is_empty() => {
            resource(request, env, license_id).await
        }
        ["licenses", license_id, "change-tier"] if !license_id.is_empty() => {
            change_tier(request, env, license_id).await
        }
        ["licenses", license_id, "preview-fallback"] if !license_id.is_empty() => {
            preview_fallback(request, env, license_id).await
        }
        ["licenses", license_id, "machines"] if !license_id.is_empty() => {
            machines(request, env, license_id).await
        }
        _ => not_found("license route not found"),
    }
}

pub(super) async fn apply_side_effect(
    env: &Env,
    operation: &admin_operations::StoredOperation,
) -> Result<()> {
    let side_effect = operation.side_effect.clone().ok_or_else(|| {
        worker::Error::RustError("Admin operation side effect is missing".to_owned())
    })?;
    let effect = serde_json::from_value::<SideEffect>(side_effect).map_err(|_| {
        worker::Error::RustError("Admin operation side effect is corrupt".to_owned())
    })?;
    match effect {
        SideEffect::LicenseSync {
            license_id,
            version,
            status,
            seats,
            heartbeat_sec,
            expires_at,
        } => {
            let id = LicenseId::from_slice(&license_id).ok_or_else(|| {
                worker::Error::RustError("Admin side effect license id is invalid".to_owned())
            })?;
            let namespace = env.durable_object("LICENSE")?;
            let stub = namespace.get_by_name(&id.to_hex())?;
            let headers = Headers::new();
            headers.set("Content-Type", "application/json")?;
            let payload = LicenseDoUpdate {
                license_id,
                operation_id: operation.operation_id.clone(),
                version,
                status,
                seats,
                heartbeat_sec,
                expires_at,
            };
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                .with_body(Some(JsValue::from_str(&serde_json::to_string(&payload)?)));
            let request = Request::new_with_init("https://license.internal/admin-update", &init)?;
            let mut response = stub.fetch_with_request(request).await?;
            if response.status_code() == 200
                && response
                    .json::<LicenseDoUpdateResponse>()
                    .await
                    .is_ok_and(|value| value.ok)
            {
                Ok(())
            } else {
                Err(worker::Error::RustError(
                    "LicenseDO rejected an Admin update".to_owned(),
                ))
            }
        }
    }
}

async fn collection(request: &mut Request, env: &Env) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Post) {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "licenses:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    if request.method() == Method::Get {
        return list(request, env, &principal).await;
    }
    let body = match read_json::<IssueBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    issue(request, env, &principal, body).await
}

async fn resource(request: &mut Request, env: &Env, encoded_id: &str) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Patch) {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "licenses:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let Some(id) = crate::admin::decode_hex_id(encoded_id, LicenseId::LEN) else {
        return invalid_request("license id must be 16-byte hexadecimal");
    };
    let database = env.d1("DB")?;
    let Some(current) = load_license(&database, &id, &principal.vendor_id).await? else {
        return not_found("license not found");
    };
    if request.method() == Method::Get {
        return response::json_no_store(200, &json!({"ok": true, "license": current}));
    }
    let patch = match read_json::<LicensePatch>(request).await? {
        Ok(patch) => patch,
        Err(rejection) => return Ok(rejection),
    };
    patch_license(request, env, &principal, current, patch).await
}

async fn issue(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    body: IssueBody,
) -> Result<Response> {
    if !valid_identifier(&body.product_id)
        || !valid_identifier(&body.policy_id)
        || !(1..=MAX_LICENSE_BATCH).contains(&body.count)
        || body
            .account_id
            .as_ref()
            .is_some_and(|value| !valid_identifier(value))
        || body
            .seats_override
            .is_some_and(|value| !(1..=100_000).contains(&value))
        || body.expires_at.is_some_and(|value| value <= now_seconds())
    {
        return invalid_request("license issue request contains invalid data");
    }
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let action = "license:issue";
    let target = format!("{}/licenses", body.product_id);
    let request_value = serde_json::to_value(&body)?;
    if crate::events::admin_snapshot_canonical(&request_value).is_none() {
        return invalid_request("license issue request contains unsupported JSON data");
    }
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    let operation_id = admin_operations::operation_id(&principal.vendor_id, &request_id);
    let database = env.d1("DB")?;
    if let Some(operation) =
        admin_operations::load(&database, &principal.vendor_id, &request_id).await?
    {
        if !operation.matches_request(&request_hash) || operation.required_scope != "licenses:rw" {
            return conflict(
                "idempotency_conflict",
                "Idempotency-Key was already used for another request",
            );
        }
        let completed = complete_operation(env, &database, &operation).await?;
        return issued_response(env, &body, &completed).await;
    }
    if !product_owned(&database, &body.product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let Some(policy) = load_owned_policy(&database, &body.policy_id, &principal.vendor_id).await?
    else {
        return not_found("policy not found");
    };
    if policy.product_id != body.product_id {
        return invalid_request("policy does not belong to the requested product");
    }
    let catalog = load_current_catalog(&database, &body.product_id).await?;
    let entitlement = body
        .entitlement_override
        .as_ref()
        .unwrap_or(&policy.entitlement);
    if let Err(error) = resolve(&catalog, entitlement, now_seconds()) {
        return response::api_error_no_store(422, "invalid_entitlement", &error.to_string());
    }

    let product_digest = Sha256Scheme::hash(body.product_id.as_bytes());
    let product_short =
        copylocker_proto::LicenseKey::product_short_from_digest(product_digest.as_bytes());
    let issued =
        authorization::derive_license_issue_batch(env, &operation_id, product_short, body.count)
            .await
            .map_err(authorization_error)?;
    let now = now_seconds();
    let expiry = body.expires_at.or_else(|| policy.expires_at(now));
    let metadata_json = body
        .metadata
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let entitlement_json = body
        .entitlement_override
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let version_scope_json = body
        .version_scope_override
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let license_ids = issued
        .iter()
        .map(|(id, _, _)| id.to_hex())
        .collect::<Vec<_>>();
    let after = json!({
        "kind": "license_batch",
        "product_id": body.product_id,
        "policy_id": body.policy_id,
        "catalog_version": catalog.version,
        "status": "active",
        "license_ids": license_ids
    });
    let result = json!({
        "ok": true,
        "product_id": body.product_id,
        "policy_id": body.policy_id,
        "catalog_version": catalog.version,
        "count": body.count,
        "license_ids": license_ids
    });
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "licenses:rw".to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "license_batch".to_owned(),
        source_id: operation_id.clone(),
        request_hash: request_hash.clone(),
        before: Value::Null,
        after,
        result,
        response_status: 201,
        side_effect: None,
        created_at: now,
    };
    let mut statements = Vec::with_capacity(issued.len() + 1);
    statements.push(admin_operations::insert_statement(&database, &operation)?);
    for (license_id, _license_key, key_hmac) in &issued {
        statements.push(
            database
                .prepare(
                    "INSERT INTO licenses(\
                       id, product_id, policy_id, key_hmac, account_id, status, seats_override, \
                       entitlement_override_json, version_scope_override_json, expires_at, \
                       catalog_version, metadata_json, created_at, updated_at\
                     ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&[
                    blob(license_id.as_bytes()),
                    text(&body.product_id),
                    text(&body.policy_id),
                    blob(key_hmac),
                    optional_text(body.account_id.as_deref()),
                    optional_u32(body.seats_override)?,
                    optional_text(entitlement_json.as_deref()),
                    optional_text(version_scope_json.as_deref()),
                    optional_integer(expiry)?,
                    integer(i64::from(catalog.version))?,
                    optional_text(metadata_json.as_deref()),
                    integer(now)?,
                    integer(now)?,
                ])?,
        );
    }
    if let Err(error) = database.batch(statements).await {
        if let Some(operation) =
            admin_operations::load(&database, &principal.vendor_id, &request_id).await?
        {
            if operation.matches_request(&request_hash) {
                let completed = complete_operation(env, &database, &operation).await?;
                return issued_response(env, &body, &completed).await;
            }
        }
        return Err(error);
    }
    let operation = admin_operations::load(&database, &principal.vendor_id, &request_id)
        .await?
        .ok_or_else(|| {
            worker::Error::RustError("license issue operation disappeared".to_owned())
        })?;
    let completed = complete_operation(env, &database, &operation).await?;
    issued_response(env, &body, &completed).await
}

async fn issued_response(
    env: &Env,
    body: &IssueBody,
    operation: &admin_operations::StoredOperation,
) -> Result<Response> {
    let product_digest = Sha256Scheme::hash(body.product_id.as_bytes());
    let product_short =
        copylocker_proto::LicenseKey::product_short_from_digest(product_digest.as_bytes());
    let issued = authorization::derive_license_issue_batch(
        env,
        &operation.operation_id,
        product_short,
        body.count,
    )
    .await
    .map_err(authorization_error)?;
    let expected_ids = operation
        .result
        .get("license_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| worker::Error::RustError("license issue result is corrupt".to_owned()))?;
    if expected_ids.len() != issued.len()
        || expected_ids
            .iter()
            .zip(&issued)
            .any(|(expected, (id, _, _))| expected.as_str() != Some(id.to_hex().as_str()))
    {
        return Err(worker::Error::RustError(
            "license issue derivation conflicts with its journal".to_owned(),
        ));
    }
    let licenses = issued
        .into_iter()
        .map(|(id, key, _)| {
            json!({
                "license_id": id.to_hex(),
                "license_key": key.to_string_grouped()
            })
        })
        .collect::<Vec<_>>();
    let mut result = operation.result.clone();
    let object = result.as_object_mut().ok_or_else(|| {
        worker::Error::RustError("license issue result is not an object".to_owned())
    })?;
    object.insert("licenses".to_owned(), Value::Array(licenses));
    response::json_no_store(operation.response_status, &result)
}

async fn list(request: &Request, env: &Env, principal: &AdminPrincipal) -> Result<Response> {
    let query = match LicenseListQuery::parse(request)? {
        Ok(query) => query,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &query.product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let rows = database
        .prepare(
            "SELECT l.id, l.product_id, l.policy_id, l.account_id, l.status, \
                    l.seats_override, l.entitlement_override_json, \
                    l.version_scope_override_json, l.expires_at, l.catalog_version, \
                    l.metadata_json, l.created_at, l.updated_at, l.seats_used, l.last_seen_at \
             FROM licenses l JOIN products product ON product.id = l.product_id \
             WHERE l.product_id = ? AND product.vendor_id = ? \
               AND (? IS NULL OR l.status = ?) \
             ORDER BY l.created_at DESC, l.id LIMIT ?",
        )
        .bind(&[
            text(&query.product_id),
            text(&principal.vendor_id),
            optional_text(query.status.as_deref()),
            optional_text(query.status.as_deref()),
            integer(i64::from(query.limit))?,
        ])?
        .all()
        .await?
        .results::<LicenseDbRow>()?;
    let items = rows
        .into_iter()
        .map(LicenseRecord::try_from)
        .collect::<Result<Vec<_>>>()?;
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "product_id": query.product_id,
            "items": items
        }),
    )
}

async fn patch_license(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    current: LicenseRecord,
    patch: LicensePatch,
) -> Result<Response> {
    if current.status == "revoked" {
        return conflict("already_revoked", "a revoked license cannot be changed");
    }
    if !patch.is_valid() {
        return invalid_request("license patch is empty or internally inconsistent");
    }
    let request_value = serde_json::to_value(&patch)?;
    let mut proposed = current.clone();
    if let Some(status) = patch.status.as_deref() {
        if !matches!(status, "active" | "suspended" | "expired") {
            return invalid_request("license status must be active, suspended, or expired");
        }
        proposed.status = status.to_owned();
    }
    if let Some(extension) = patch.extend_by_seconds {
        if extension <= 0 {
            return invalid_request("extend_by_seconds must be positive");
        }
        let Some(expiry) = proposed.expires_at else {
            return invalid_request("a perpetual license has no expiry to extend");
        };
        proposed.expires_at = Some(
            expiry
                .checked_add(extension)
                .ok_or_else(|| worker::Error::RustError("license expiry overflow".to_owned()))?,
        );
    } else if patch.clear_expires_at {
        proposed.expires_at = None;
    } else if let Some(expiry) = patch.expires_at {
        if expiry < 0 {
            return invalid_request("license expiry cannot be negative");
        }
        proposed.expires_at = Some(expiry);
    }
    if patch.clear_seats_override {
        proposed.seats_override = None;
    } else if let Some(seats) = patch.seats_override {
        if !(1..=100_000).contains(&seats) {
            return invalid_request("seat override must be between 1 and 100000");
        }
        proposed.seats_override = Some(seats);
    }
    if patch.clear_entitlement_override {
        proposed.entitlement_override = None;
    } else if let Some(entitlement) = patch.entitlement_override {
        proposed.entitlement_override = Some(entitlement);
    }
    if patch.clear_version_scope_override {
        proposed.version_scope_override = None;
    } else if let Some(scope) = patch.version_scope_override {
        proposed.version_scope_override = Some(scope);
    }
    if patch.clear_metadata {
        proposed.metadata = None;
    } else if let Some(metadata) = patch.metadata {
        proposed.metadata = Some(metadata);
    }
    persist_update(
        request,
        env,
        principal,
        current,
        proposed,
        "license:update",
        request_value,
    )
    .await
}

async fn change_tier(request: &mut Request, env: &Env, encoded_id: &str) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "licenses:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let Some(id) = crate::admin::decode_hex_id(encoded_id, LicenseId::LEN) else {
        return invalid_request("license id must be 16-byte hexadecimal");
    };
    let body = match read_json::<ChangeTierBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    if !valid_identifier(&body.tier) {
        return invalid_request("tier id is invalid");
    }
    let database = env.d1("DB")?;
    let Some(current) = load_license(&database, &id, &principal.vendor_id).await? else {
        return not_found("license not found");
    };
    if current.status == "revoked" {
        return conflict("already_revoked", "a revoked license cannot change tier");
    }
    let policy = authorization::load_policy(&database, &current.policy_id, &current.product_id)
        .await
        .map_err(authorization_error)?;
    let mut entitlement = current
        .entitlement_override
        .clone()
        .unwrap_or(policy.entitlement);
    entitlement.tier = body.tier.clone();
    let catalog = load_catalog_at(&database, &current.product_id, current.catalog_version).await?;
    if let Err(error) = resolve(&catalog, &entitlement, now_seconds()) {
        return response::api_error_no_store(422, "invalid_entitlement", &error.to_string());
    }
    let mut proposed = current.clone();
    proposed.entitlement_override = Some(entitlement);
    persist_update(
        request,
        env,
        &principal,
        current,
        proposed,
        "license:change-tier",
        serde_json::to_value(body)?,
    )
    .await
}

async fn persist_update(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    current: LicenseRecord,
    mut proposed: LicenseRecord,
    action: &str,
    request_value: Value,
) -> Result<Response> {
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let target = format!("{}/licenses/{}", current.product_id, current.license_id);
    if request_value.is_null() || crate::events::admin_snapshot_canonical(&request_value).is_none()
    {
        return invalid_request("license update contains unsupported JSON data");
    }
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    let database = env.d1("DB")?;
    if let Some(response) = replay_operation(
        env,
        &database,
        principal,
        &request_id,
        &request_hash,
        "licenses:rw",
    )
    .await?
    {
        return Ok(response);
    }
    if current == proposed {
        return conflict("no_change", "license update does not change the license");
    }
    let now = now_seconds();
    proposed.updated_at = now;
    if crate::events::admin_snapshot_canonical(&serde_json::to_value(&proposed)?).is_none() {
        return invalid_request("license update contains unsupported JSON data");
    }
    validate_license_overrides(&database, &proposed).await?;
    let policy = authorization::load_policy(&database, &proposed.policy_id, &proposed.product_id)
        .await
        .map_err(authorization_error)?;
    let version =
        admin_operations::current_entity_version(&database, "license", &proposed.license_id)
            .await?;
    let next_version = version
        .checked_add(1)
        .ok_or_else(|| worker::Error::RustError("license version is exhausted".to_owned()))?;
    let effective_seats = proposed.seats_override.unwrap_or(policy.seats.seats);
    let side_effect = SideEffect::LicenseSync {
        license_id: crate::admin::decode_hex_id(&proposed.license_id, LicenseId::LEN)
            .ok_or_else(|| worker::Error::RustError("license id is corrupt".to_owned()))?,
        version: next_version,
        status: proposed.status.clone(),
        seats: effective_seats,
        heartbeat_sec: policy
            .seats
            .heartbeat_secs
            .map(u64::try_from)
            .transpose()
            .map_err(|_| worker::Error::RustError("policy heartbeat is invalid".to_owned()))?,
        expires_at: proposed.expires_at,
    };
    let result = json!({"ok": true, "license": proposed, "version": next_version});
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "licenses:rw".to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "license".to_owned(),
        source_id: proposed.license_id.clone(),
        request_hash: request_hash.clone(),
        before: serde_json::to_value(&current)?,
        after: serde_json::to_value(&proposed)?,
        result,
        response_status: 200,
        side_effect: Some(serde_json::to_value(side_effect)?),
        created_at: now,
    };
    let statements = vec![
        admin_operations::insert_statement(&database, &operation)?,
        admin_operations::version_statement(
            &database,
            &operation.operation_id(),
            "license",
            &proposed.license_id,
            next_version,
            now,
        )?,
        license_update_statement(&database, &proposed, now)?,
    ];
    if let Err(error) = database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &database,
            principal,
            &request_id,
            &request_hash,
            "licenses:rw",
        )
        .await?
        {
            return Ok(response);
        }
        let current_version =
            admin_operations::current_entity_version(&database, "license", &proposed.license_id)
                .await?;
        if current_version != version {
            return conflict(
                "concurrent_modification",
                "the license changed; reload it and retry with a new Idempotency-Key",
            );
        }
        return Err(error);
    }
    finish_new_operation(env, &database, principal, &request_id).await
}

async fn validate_license_overrides(database: &D1Database, license: &LicenseRecord) -> Result<()> {
    if !matches!(
        license.status.as_str(),
        "active" | "suspended" | "expired" | "revoked"
    ) || license
        .seats_override
        .is_some_and(|value| !(1..=100_000).contains(&value))
        || license.expires_at.is_some_and(|value| value < 0)
    {
        return Err(worker::Error::RustError(
            "license update generated invalid state".to_owned(),
        ));
    }
    let policy = authorization::load_policy(database, &license.policy_id, &license.product_id)
        .await
        .map_err(authorization_error)?;
    let catalog = load_catalog_at(database, &license.product_id, license.catalog_version).await?;
    let entitlement = license
        .entitlement_override
        .as_ref()
        .unwrap_or(&policy.entitlement);
    resolve(&catalog, entitlement, now_seconds()).map_err(|error| {
        worker::Error::RustError(format!("license entitlement override is invalid: {error}"))
    })?;
    Ok(())
}

fn license_update_statement(
    database: &D1Database,
    license: &LicenseRecord,
    now: i64,
) -> Result<worker::D1PreparedStatement> {
    let entitlement = license
        .entitlement_override
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let scope = license
        .version_scope_override
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let metadata = license
        .metadata
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let id = crate::admin::decode_hex_id(&license.license_id, LicenseId::LEN)
        .ok_or_else(|| worker::Error::RustError("license id is corrupt".to_owned()))?;
    database
        .prepare(
            "UPDATE licenses SET status = ?, seats_override = ?, \
               entitlement_override_json = ?, version_scope_override_json = ?, expires_at = ?, \
               metadata_json = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&[
            text(&license.status),
            optional_u32(license.seats_override)?,
            optional_text(entitlement.as_deref()),
            optional_text(scope.as_deref()),
            optional_integer(license.expires_at)?,
            optional_text(metadata.as_deref()),
            integer(now)?,
            blob(&id),
        ])
}

async fn preview_fallback(request: &Request, env: &Env, encoded_id: &str) -> Result<Response> {
    if request.method() != Method::Get {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "licenses:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let Some(id) = crate::admin::decode_hex_id(encoded_id, LicenseId::LEN) else {
        return invalid_request("license id must be 16-byte hexadecimal");
    };
    let database = env.d1("DB")?;
    if load_license(&database, &id, &principal.vendor_id)
        .await?
        .is_none()
    {
        return not_found("license not found");
    }
    let row = database
        .prepare(
            "SELECT s.provider, s.external_id, s.state, s.current_period_start, \
                    s.current_period_end, s.dunning_until, s.continuous_paid_months, \
                    s.fallback_earned_at, s.canceled_at, s.updated_at, p.validity_json \
             FROM subscriptions s JOIN licenses l ON l.id = s.license_id \
             JOIN policies p ON p.id = l.policy_id WHERE s.license_id = ?",
        )
        .bind(&[blob(&id)])?
        .first::<SubscriptionPreviewRow>(None)
        .await?;
    let Some(row) = row else {
        return not_found("license has no subscription");
    };
    let subscription = row.subscription()?;
    let fallback = match serde_json::from_str::<Validity>(&row.validity_json)? {
        Validity::Subscription { fallback, .. } => fallback,
        _ => None,
    };
    let (end_state, cutoff) = preview_ending(&subscription, fallback);
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "license_id": encoded_id,
            "current_state": subscription.state,
            "end_state": end_state,
            "version_cutoff": cutoff,
            "fallback_earned_at": subscription.fallback_earned_at,
            "continuous_paid_months": subscription.continuous_paid_months
        }),
    )
}

async fn machines(request: &Request, env: &Env, encoded_id: &str) -> Result<Response> {
    if request.method() != Method::Get {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "licenses:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let Some(id) = crate::admin::decode_hex_id(encoded_id, LicenseId::LEN) else {
        return invalid_request("license id must be 16-byte hexadecimal");
    };
    let database = env.d1("DB")?;
    if load_license(&database, &id, &principal.vendor_id)
        .await?
        .is_none()
    {
        return not_found("license not found");
    }
    let rows = database
        .prepare(
            "SELECT id, status, activation_path, first_seen_at, last_seen_at, os, arch, \
                    app_version, sdk_version, release_id, variant_id, build_fp, geo_country, \
                    suspicion FROM machines WHERE license_id = ? ORDER BY first_seen_at LIMIT 1000",
        )
        .bind(&[blob(&id)])?
        .all()
        .await?
        .results::<MachineDbRow>()?;
    let items = rows
        .into_iter()
        .map(MachineView::try_from)
        .collect::<Result<Vec<_>>>()?;
    response::json_no_store(
        200,
        &json!({"ok": true, "license_id": encoded_id, "items": items}),
    )
}

async fn load_license(
    database: &D1Database,
    id: &[u8],
    vendor_id: &str,
) -> Result<Option<LicenseRecord>> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT l.id, l.product_id, l.policy_id, l.account_id, l.status, \
                    l.seats_override, l.entitlement_override_json, \
                    l.version_scope_override_json, l.expires_at, l.catalog_version, \
                    l.metadata_json, l.created_at, l.updated_at, l.seats_used, l.last_seen_at \
             FROM licenses l JOIN products product ON product.id = l.product_id \
             WHERE l.id = ? AND product.vendor_id = ?",
        )
        .bind(&[blob(id), text(vendor_id)])?
        .first::<LicenseDbRow>(None)
        .await?;
    row.map(LicenseRecord::try_from).transpose()
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct LicenseRecord {
    license_id: String,
    product_id: String,
    policy_id: String,
    account_id: Option<String>,
    status: String,
    seats_override: Option<u32>,
    entitlement_override: Option<EntitlementSpec>,
    version_scope_override: Option<VersionScope>,
    expires_at: Option<i64>,
    catalog_version: u32,
    metadata: Option<Value>,
    created_at: i64,
    updated_at: i64,
    seats_used: u32,
    last_seen_at: Option<i64>,
}

impl TryFrom<LicenseDbRow> for LicenseRecord {
    type Error = worker::Error;

    fn try_from(row: LicenseDbRow) -> std::result::Result<Self, Self::Error> {
        let id = LicenseId::from_slice(&row.id).ok_or_else(|| {
            worker::Error::RustError("license row contains an invalid id".to_owned())
        })?;
        if !valid_identifier(&row.product_id)
            || !valid_identifier(&row.policy_id)
            || row
                .account_id
                .as_ref()
                .is_some_and(|value| !valid_identifier(value))
            || !matches!(
                row.status.as_str(),
                "active" | "suspended" | "expired" | "revoked"
            )
            || row.expires_at.is_some_and(|value| value < 0)
            || row.created_at < 0
            || row.updated_at < 0
            || row.last_seen_at.is_some_and(|value| value < 0)
        {
            return Err(worker::Error::RustError(
                "license row contains invalid data".to_owned(),
            ));
        }
        Ok(Self {
            license_id: id.to_hex(),
            product_id: row.product_id,
            policy_id: row.policy_id,
            account_id: row.account_id,
            status: row.status,
            seats_override: row
                .seats_override
                .map(u32::try_from)
                .transpose()
                .map_err(|_| worker::Error::RustError("license seats are invalid".to_owned()))?,
            entitlement_override: parse_optional_json(
                row.entitlement_override_json.as_deref(),
                "license entitlement override",
            )?,
            version_scope_override: parse_optional_json(
                row.version_scope_override_json.as_deref(),
                "license version scope override",
            )?,
            expires_at: row.expires_at,
            catalog_version: u32::try_from(row.catalog_version).map_err(|_| {
                worker::Error::RustError("license catalog version is invalid".to_owned())
            })?,
            metadata: parse_optional_json(row.metadata_json.as_deref(), "license metadata")?,
            created_at: row.created_at,
            updated_at: row.updated_at,
            seats_used: u32::try_from(row.seats_used).map_err(|_| {
                worker::Error::RustError("license seat projection is invalid".to_owned())
            })?,
            last_seen_at: row.last_seen_at,
        })
    }
}

fn parse_optional_json<T: DeserializeOwned>(value: Option<&str>, field: &str) -> Result<Option<T>> {
    value
        .map(|value| {
            serde_json::from_str(value)
                .map_err(|_| worker::Error::RustError(format!("{field} contains invalid JSON")))
        })
        .transpose()
}

#[derive(Debug, Deserialize)]
struct LicenseDbRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    product_id: String,
    policy_id: String,
    account_id: Option<String>,
    status: String,
    seats_override: Option<i64>,
    entitlement_override_json: Option<String>,
    version_scope_override_json: Option<String>,
    expires_at: Option<i64>,
    catalog_version: i64,
    metadata_json: Option<String>,
    created_at: i64,
    updated_at: i64,
    seats_used: i64,
    last_seen_at: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IssueBody {
    product_id: String,
    policy_id: String,
    #[serde(default = "default_count")]
    count: u32,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    seats_override: Option<u32>,
    #[serde(default)]
    entitlement_override: Option<EntitlementSpec>,
    #[serde(default)]
    version_scope_override: Option<VersionScope>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    metadata: Option<Value>,
}

const fn default_count() -> u32 {
    1
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LicensePatch {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    extend_by_seconds: Option<i64>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    clear_expires_at: bool,
    #[serde(default)]
    seats_override: Option<u32>,
    #[serde(default)]
    clear_seats_override: bool,
    #[serde(default)]
    entitlement_override: Option<EntitlementSpec>,
    #[serde(default)]
    clear_entitlement_override: bool,
    #[serde(default)]
    version_scope_override: Option<VersionScope>,
    #[serde(default)]
    clear_version_scope_override: bool,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(default)]
    clear_metadata: bool,
}

impl LicensePatch {
    fn is_valid(&self) -> bool {
        let any = self.status.is_some()
            || self.extend_by_seconds.is_some()
            || self.expires_at.is_some()
            || self.clear_expires_at
            || self.seats_override.is_some()
            || self.clear_seats_override
            || self.entitlement_override.is_some()
            || self.clear_entitlement_override
            || self.version_scope_override.is_some()
            || self.clear_version_scope_override
            || self.metadata.is_some()
            || self.clear_metadata;
        any && usize::from(self.extend_by_seconds.is_some())
            + usize::from(self.expires_at.is_some())
            + usize::from(self.clear_expires_at)
            <= 1
            && !(self.seats_override.is_some() && self.clear_seats_override)
            && !(self.entitlement_override.is_some() && self.clear_entitlement_override)
            && !(self.version_scope_override.is_some() && self.clear_version_scope_override)
            && !(self.metadata.is_some() && self.clear_metadata)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChangeTierBody {
    tier: String,
}

struct LicenseListQuery {
    product_id: String,
    status: Option<String>,
    limit: u32,
}

impl LicenseListQuery {
    fn parse(request: &Request) -> Result<std::result::Result<Self, Response>> {
        let mut product_id = None;
        let mut status = None;
        let mut limit = 50_u32;
        let mut seen_limit = false;
        for (name, value) in request.url()?.query_pairs() {
            match name.as_ref() {
                "product_id" if product_id.is_none() && valid_identifier(&value) => {
                    product_id = Some(value.into_owned());
                }
                "status"
                    if status.is_none()
                        && matches!(
                            value.as_ref(),
                            "active" | "suspended" | "expired" | "revoked"
                        ) =>
                {
                    status = Some(value.into_owned());
                }
                "limit" if !seen_limit => {
                    seen_limit = true;
                    let Ok(parsed) = value.parse::<u32>() else {
                        return Ok(Err(response::api_error_no_store(
                            400,
                            "invalid_query",
                            "license list query is invalid",
                        )?));
                    };
                    if !(1..=100).contains(&parsed) {
                        return Ok(Err(response::api_error_no_store(
                            400,
                            "invalid_query",
                            "license list limit must be between 1 and 100",
                        )?));
                    }
                    limit = parsed;
                }
                _ => {
                    return Ok(Err(response::api_error_no_store(
                        400,
                        "invalid_query",
                        "license list query is invalid",
                    )?));
                }
            }
        }
        Ok(match product_id {
            Some(product_id) => Ok(Self {
                product_id,
                status,
                limit,
            }),
            None => Err(response::api_error_no_store(
                400,
                "invalid_query",
                "product_id is required",
            )?),
        })
    }
}

#[derive(Debug, Deserialize)]
struct SubscriptionPreviewRow {
    provider: String,
    external_id: String,
    state: String,
    current_period_start: i64,
    current_period_end: i64,
    dunning_until: Option<i64>,
    continuous_paid_months: i64,
    fallback_earned_at: Option<i64>,
    canceled_at: Option<i64>,
    updated_at: i64,
    validity_json: String,
}

impl SubscriptionPreviewRow {
    fn subscription(&self) -> Result<Subscription> {
        let state = match self.state.as_str() {
            "active" => SubscriptionState::Active,
            "past_due" => SubscriptionState::PastDue,
            "canceling" => SubscriptionState::Canceling,
            "suspended" => SubscriptionState::Suspended,
            "ended" => SubscriptionState::Ended,
            "expired" => SubscriptionState::Expired,
            "perpetual_fallback" => SubscriptionState::PerpetualFallback,
            _ => {
                return Err(worker::Error::RustError(
                    "subscription state is invalid".to_owned(),
                ));
            }
        };
        Ok(Subscription {
            provider: self.provider.clone(),
            external_id: self.external_id.clone(),
            state,
            current_period_start: self.current_period_start,
            current_period_end: self.current_period_end,
            dunning_until: self.dunning_until,
            continuous_paid_months: u32::try_from(self.continuous_paid_months).map_err(|_| {
                worker::Error::RustError("subscription paid months are invalid".to_owned())
            })?,
            fallback_earned_at: self.fallback_earned_at,
            canceled_at: self.canceled_at,
            updated_at: self.updated_at,
            processed_events: Vec::new(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct MachineDbRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    status: String,
    activation_path: String,
    first_seen_at: i64,
    last_seen_at: Option<i64>,
    os: Option<String>,
    arch: Option<String>,
    app_version: Option<String>,
    sdk_version: Option<String>,
    release_id: Option<String>,
    variant_id: Option<i64>,
    build_fp: Option<String>,
    geo_country: Option<String>,
    suspicion: i64,
}

#[derive(Debug, Serialize)]
struct MachineView {
    machine_id: String,
    status: String,
    activation_path: String,
    first_seen_at: i64,
    last_seen_at: Option<i64>,
    os: Option<String>,
    arch: Option<String>,
    app_version: Option<String>,
    sdk_version: Option<String>,
    release_id: Option<String>,
    variant_id: Option<i64>,
    build_fingerprint: Option<String>,
    geo_country: Option<String>,
    suspicion: i64,
}

impl TryFrom<MachineDbRow> for MachineView {
    type Error = worker::Error;

    fn try_from(row: MachineDbRow) -> std::result::Result<Self, Self::Error> {
        let id = copylocker_types::MachineId::from_slice(&row.id).ok_or_else(|| {
            worker::Error::RustError("machine row contains an invalid id".to_owned())
        })?;
        Ok(Self {
            machine_id: id.to_hex(),
            status: row.status,
            activation_path: row.activation_path,
            first_seen_at: row.first_seen_at,
            last_seen_at: row.last_seen_at,
            os: row.os,
            arch: row.arch,
            app_version: row.app_version,
            sdk_version: row.sdk_version,
            release_id: row.release_id,
            variant_id: row.variant_id,
            build_fingerprint: row.build_fp,
            geo_country: row.geo_country,
            suspicion: row.suspicion,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SideEffect {
    LicenseSync {
        license_id: Vec<u8>,
        version: i64,
        status: String,
        seats: u32,
        heartbeat_sec: Option<u64>,
        expires_at: Option<i64>,
    },
}

#[derive(Debug, Serialize)]
struct LicenseDoUpdate {
    license_id: Vec<u8>,
    operation_id: String,
    version: i64,
    status: String,
    seats: u32,
    heartbeat_sec: Option<u64>,
    expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct LicenseDoUpdateResponse {
    ok: bool,
    #[serde(rename = "initialized")]
    _initialized: bool,
}
