use copylocker_proto::{Envelope, EpochCert, RevocationBatch};
use copylocker_suite::cbor::{CborValue, MapBuilder};
use copylocker_suite::{Artifact, HashScheme, SignatureScheme};
use copylocker_suite_std::{FastSig, HybridSig, Sha256Scheme, CL_STD_1_SUITE_ID};
use copylocker_types::{ArtifactKind, EpochId, KillReason, LicenseId, PROTO_VER};

use super::*;

const APPROVAL_WINDOW_SECONDS: i64 = 15 * 60;
const MAX_EPOCH_CERT_BYTES: usize = 64 * 1024;

pub(super) async fn route(request: &mut Request, env: &Env, segments: &[&str]) -> Result<Response> {
    match segments {
        ["epochs"] => collection(request, env).await,
        ["epochs", epoch_id] if !epoch_id.is_empty() => resource(request, env, epoch_id).await,
        ["epochs", epoch_id, "revoke"] if !epoch_id.is_empty() => {
            revoke(request, env, epoch_id).await
        }
        _ => not_found("epoch route not found"),
    }
}

pub(super) async fn apply_side_effect(
    env: &Env,
    operation: &admin_operations::StoredOperation,
) -> Result<()> {
    let side_effect = operation.side_effect.clone().ok_or_else(|| {
        worker::Error::RustError("Epoch Admin operation side effect is missing".to_owned())
    })?;
    let effect = serde_json::from_value::<SideEffect>(side_effect).map_err(|_| {
        worker::Error::RustError("Epoch Admin operation side effect is corrupt".to_owned())
    })?;
    let database = env.d1("DB")?;
    match effect {
        SideEffect::PublishKeyset => rebuild_keyset(env, &database).await,
        SideEffect::PublishRevocation {
            revocation_seq,
            epoch_id,
            product_id,
        } => {
            publish_epoch_revocation(
                env,
                &database,
                operation,
                revocation_seq,
                &epoch_id,
                &product_id,
            )
            .await
        }
    }
}

async fn collection(request: &mut Request, env: &Env) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Post) {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "epochs:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    if request.method() == Method::Get {
        return list(request, env, &principal).await;
    }
    let body = match read_json::<UploadBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    upload(request, env, &principal, body).await
}

async fn resource(request: &Request, env: &Env, encoded_id: &str) -> Result<Response> {
    if request.method() != Method::Get {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "epochs:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let Some(id) = crate::admin::decode_hex_id(encoded_id, EpochId::LEN) else {
        return invalid_request("epoch id must be 8-byte hexadecimal");
    };
    let database = env.d1("DB")?;
    let Some(epoch) = load_epoch(&database, &id, &principal.vendor_id).await? else {
        return not_found("epoch not found");
    };
    let replacements = replacement_epoch_ids(&database, &epoch, now_seconds()).await?;
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "epoch": epoch,
            "replacement_ready": !replacements.is_empty(),
            "replacement_epoch_ids": replacements
        }),
    )
}

async fn list(request: &Request, env: &Env, principal: &AdminPrincipal) -> Result<Response> {
    let product_id = match product_query(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let rows = database
        .prepare(
            "SELECT e.id, e.product_scope, e.suite_id, e.not_before, e.not_after, \
                    e.revoked_at, e.created_at, \
                    (SELECT COUNT(*) FROM machines m JOIN licenses l ON l.id = m.license_id \
                     WHERE l.product_id = e.product_scope \
                       AND m.status IN ('active', 'pending')) AS affected_machines \
             FROM epochs e WHERE e.product_scope = ? ORDER BY e.not_before DESC, e.id LIMIT 100",
        )
        .bind(&[text(&product_id)])?
        .all()
        .await?
        .results::<EpochDbRow>()?;
    let now = now_seconds();
    let items = rows
        .into_iter()
        .map(|row| EpochView::try_from_row(row, now))
        .collect::<Result<Vec<_>>>()?;
    response::json_no_store(
        200,
        &json!({"ok": true, "product_id": product_id, "items": items}),
    )
}

async fn upload(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    body: UploadBody,
) -> Result<Response> {
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let parsed = match ParsedEpoch::parse(&body) {
        Ok(value) => value,
        Err(message) => return response::api_error_no_store(422, "invalid_epoch", &message),
    };
    let epoch_id = parsed.cert.epoch_id.to_hex();
    let product_id = parsed
        .cert
        .product_scope
        .as_deref()
        .ok_or_else(|| worker::Error::RustError("validated epoch lost its scope".to_owned()))?;
    let target = format!("{product_id}/epochs/{epoch_id}");
    let request_value = serde_json::to_value(&body)?;
    let request_hash = admin_operations::request_hash("epoch:upload", &target, &request_value)?;
    let database = env.d1("DB")?;
    if let Some(response) = replay_operation(
        env,
        &database,
        principal,
        &request_id,
        &request_hash,
        "epochs:rw",
    )
    .await?
    {
        return Ok(response);
    }
    if !product_owned(&database, product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    if epoch_id_exists(&database, parsed.cert.epoch_id.as_bytes()).await? {
        return conflict("epoch_exists", "epoch id already exists");
    }
    let version = admin_operations::current_entity_version(&database, "epoch", &epoch_id).await?;
    if version != 0 {
        return Err(worker::Error::RustError(
            "new epoch already has entity history".to_owned(),
        ));
    }
    let now = now_seconds();
    let view = EpochView::from_cert(&parsed.cert, None, now, 0);
    let result = json!({"ok": true, "epoch": view, "version": 1});
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "epochs:rw".to_owned(),
        action: "epoch:upload".to_owned(),
        target,
        source_kind: "epoch".to_owned(),
        source_id: epoch_id.clone(),
        request_hash: request_hash.clone(),
        before: Value::Null,
        after: serde_json::to_value(&view)?,
        result,
        response_status: 201,
        side_effect: Some(serde_json::to_value(SideEffect::PublishKeyset)?),
        created_at: now,
    };
    let statements = vec![
        admin_operations::insert_statement(&database, &operation)?,
        admin_operations::version_statement(
            &database,
            &operation.operation_id(),
            "epoch",
            &epoch_id,
            1,
            now,
        )?,
        database
            .prepare(
                "INSERT INTO epochs(\
                   id, product_scope, suite_id, vk_pq, vk_trad, vk_fast, cert, \
                   not_before, not_after, created_at\
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&[
                blob(parsed.cert.epoch_id.as_bytes()),
                text(product_id),
                blob(parsed.cert.suite_id.as_bytes()),
                blob(&parsed.vk_pq),
                blob(&parsed.vk_trad),
                blob(&parsed.cert.vk_fast),
                blob(&parsed.certificate),
                integer(parsed.cert.not_before)?,
                integer(parsed.cert.not_after)?,
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
            "epochs:rw",
        )
        .await?
        {
            return Ok(response);
        }
        if epoch_id_exists(&database, parsed.cert.epoch_id.as_bytes()).await? {
            return conflict("epoch_exists", "epoch id already exists");
        }
        return Err(error);
    }
    finish_new_operation(env, &database, principal, &request_id).await
}

async fn revoke(request: &mut Request, env: &Env, encoded_id: &str) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "epochs:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let Some(id) = crate::admin::decode_hex_id(encoded_id, EpochId::LEN) else {
        return invalid_request("epoch id must be 8-byte hexadecimal");
    };
    let dry_run = match parse_dry_run(request)? {
        Some(value) => value,
        None => return response::api_error_no_store(400, "invalid_query", "dry_run is invalid"),
    };
    let body = match read_json::<RevokeBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    let Some(epoch) = load_epoch(&database, &id, &principal.vendor_id).await? else {
        return not_found("epoch not found");
    };
    let replacements = replacement_epoch_ids(&database, &epoch, now_seconds()).await?;
    if dry_run {
        return response::json_no_store(
            200,
            &json!({
                "ok": true,
                "dry_run": true,
                "epoch": epoch,
                "affected_machines_upper_bound": epoch.affected_machines_upper_bound,
                "replacement_ready": !replacements.is_empty(),
                "replacement_epoch_ids": replacements,
                "already_revoked": epoch.revoked_at.is_some(),
                "requires_distinct_actors": 2
            }),
        );
    }

    let revoke_principal = match authorize(request, env, "revoke").await? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    if revoke_principal.vendor_id != principal.vendor_id
        || revoke_principal.actor != principal.actor
    {
        return Err(worker::Error::RustError(
            "Admin authentication changed between scope checks".to_owned(),
        ));
    }
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let Some(confirmed_id) = body.confirm_epoch_id.as_deref() else {
        return invalid_request("confirm_epoch_id must repeat the target epoch id");
    };
    let Some(confirmed) = crate::admin::decode_hex_id(confirmed_id, EpochId::LEN) else {
        return invalid_request("confirm_epoch_id must be 8-byte hexadecimal");
    };
    if confirmed != id {
        return conflict(
            "confirmation_mismatch",
            "confirm_epoch_id does not match the target epoch",
        );
    }
    let target = format!("{}/epochs/{encoded_id}/revoke", epoch.product_id);
    let request_value = serde_json::to_value(&body)?;
    let request_hash =
        admin_operations::request_hash("epoch:revoke-confirm", &target, &request_value)?;
    if let Some(response) = replay_operation(
        env,
        &database,
        &principal,
        &request_id,
        &request_hash,
        "epochs:rw",
    )
    .await?
    {
        return Ok(response);
    }
    if epoch.revoked_at.is_some() {
        return conflict("already_revoked", "epoch is already revoked");
    }
    if replacements.is_empty() {
        return conflict(
            "replacement_epoch_required",
            "a different active epoch must be ready before revocation",
        );
    }
    let approval = load_approval(&database, &id, &principal.vendor_id).await?;
    let now = now_seconds();
    let context = ApprovalContext {
        env,
        database: &database,
        principal: &principal,
        request_id: &request_id,
        request_hash: &request_hash,
        epoch: &epoch,
        now,
    };
    match approval {
        Some(approval) if approval.second_actor.is_some() => {
            conflict("already_revoked", "epoch revocation was already approved")
        }
        Some(approval) if approval.expires_at > now && approval.first_actor == principal.actor => {
            conflict(
                "second_actor_required",
                "a distinct Admin actor must provide the second confirmation",
            )
        }
        Some(approval) if approval.expires_at > now => {
            persist_second_approval(context, &approval).await
        }
        approval => persist_first_approval(context, approval.as_ref()).await,
    }
}

#[derive(Clone, Copy, Debug)]
struct ApprovalContext<'a> {
    env: &'a Env,
    database: &'a D1Database,
    principal: &'a AdminPrincipal,
    request_id: &'a str,
    request_hash: &'a [u8],
    epoch: &'a EpochView,
    now: i64,
}

async fn persist_first_approval(
    context: ApprovalContext<'_>,
    previous: Option<&ApprovalRow>,
) -> Result<Response> {
    let ApprovalContext {
        env,
        database,
        principal,
        request_id,
        request_hash,
        epoch,
        now,
    } = context;
    let expires_at = now
        .checked_add(APPROVAL_WINDOW_SECONDS)
        .ok_or_else(|| worker::Error::RustError("approval expiry overflow".to_owned()))?;
    let approval_version =
        admin_operations::current_entity_version(database, "epoch_approval", &epoch.epoch_id)
            .await?;
    let next_approval_version = approval_version
        .checked_add(1)
        .ok_or_else(|| worker::Error::RustError("approval version is exhausted".to_owned()))?;
    let approval = json!({
        "state": "pending_second_actor",
        "first_actor": principal.actor,
        "first_approved_at": now,
        "expires_at": expires_at
    });
    let before = json!({"epoch": epoch, "approval": previous});
    let after = json!({"epoch": epoch, "approval": approval});
    let result = json!({
        "ok": true,
        "dry_run": false,
        "approval_pending": true,
        "epoch_id": epoch.epoch_id,
        "first_actor": principal.actor,
        "approval_expires_at": expires_at,
        "required_confirmations": 2,
        "received_confirmations": 1
    });
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.to_owned(),
        actor: principal.actor.clone(),
        required_scope: "epochs:rw".to_owned(),
        action: "epoch:revoke-confirm".to_owned(),
        target: format!("{}/epochs/{}/revoke", epoch.product_id, epoch.epoch_id),
        source_kind: "epoch_approval".to_owned(),
        source_id: epoch.epoch_id.clone(),
        request_hash: request_hash.to_vec(),
        before,
        after,
        result,
        response_status: 202,
        side_effect: None,
        created_at: now,
    };
    let approval_statement = if previous.is_some() {
        database
            .prepare(
                "UPDATE epoch_revocation_approvals SET \
                   first_actor = ?, first_request_id = ?, first_approved_at = ?, expires_at = ?, \
                   second_actor = NULL, second_request_id = NULL, second_approved_at = NULL, \
                   revocation_seq = NULL \
                 WHERE epoch_id = ? AND vendor_id = ? AND second_actor IS NULL AND expires_at <= ?",
            )
            .bind(&[
                text(&principal.actor),
                text(request_id),
                integer(now)?,
                integer(expires_at)?,
                blob(&decode_epoch_id(&epoch.epoch_id)?),
                text(&principal.vendor_id),
                integer(now)?,
            ])?
    } else {
        database
            .prepare(
                "INSERT INTO epoch_revocation_approvals(\
                   epoch_id, vendor_id, first_actor, first_request_id, first_approved_at, expires_at\
                 ) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&[
                blob(&decode_epoch_id(&epoch.epoch_id)?),
                text(&principal.vendor_id),
                text(&principal.actor),
                text(request_id),
                integer(now)?,
                integer(expires_at)?,
            ])?
    };
    let statements = vec![
        admin_operations::insert_statement(database, &operation)?,
        admin_operations::version_statement(
            database,
            &operation.operation_id(),
            "epoch_approval",
            &epoch.epoch_id,
            next_approval_version,
            now,
        )?,
        approval_statement,
    ];
    match database.batch(statements).await {
        Ok(results) if result_changed(results.get(2))? => {
            finish_new_operation(env, database, principal, request_id).await
        }
        Ok(_) => Err(worker::Error::RustError(
            "epoch approval did not change its durable row".to_owned(),
        )),
        Err(error) => {
            if let Some(response) = replay_operation(
                env,
                database,
                principal,
                request_id,
                request_hash,
                "epochs:rw",
            )
            .await?
            {
                return Ok(response);
            }
            let current = admin_operations::current_entity_version(
                database,
                "epoch_approval",
                &epoch.epoch_id,
            )
            .await?;
            if current != approval_version {
                return conflict(
                    "concurrent_approval",
                    "another actor changed the epoch approval; retry with a new Idempotency-Key",
                );
            }
            Err(error)
        }
    }
}

async fn persist_second_approval(
    context: ApprovalContext<'_>,
    approval: &ApprovalRow,
) -> Result<Response> {
    let ApprovalContext {
        env,
        database,
        principal,
        request_id,
        request_hash,
        epoch,
        now,
    } = context;
    let head = revocation_head(database).await?;
    if head.pending != 0 {
        return conflict(
            "revocation_in_progress",
            "another revocation must finish before this epoch can be revoked",
        );
    }
    let revocation_seq = head
        .value
        .checked_add(1)
        .ok_or_else(|| worker::Error::RustError("revocation epoch is exhausted".to_owned()))?;
    let epoch_version =
        admin_operations::current_entity_version(database, "epoch", &epoch.epoch_id).await?;
    let next_epoch_version = epoch_version
        .checked_add(1)
        .ok_or_else(|| worker::Error::RustError("epoch version is exhausted".to_owned()))?;
    let mut revoked = epoch.clone();
    revoked.revoked_at = Some(now);
    revoked.status = "revoked".to_owned();
    let after = json!({
        "epoch": revoked,
        "approval": {
            "state": "approved",
            "first_actor": approval.first_actor,
            "second_actor": principal.actor,
            "first_approved_at": approval.first_approved_at,
            "second_approved_at": now,
            "revocation_epoch": revocation_seq
        }
    });
    let result = json!({
        "ok": true,
        "dry_run": false,
        "approval_pending": false,
        "epoch_id": epoch.epoch_id,
        "revocation_epoch": revocation_seq,
        "first_actor": approval.first_actor,
        "second_actor": principal.actor,
        "required_confirmations": 2,
        "received_confirmations": 2
    });
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.to_owned(),
        actor: principal.actor.clone(),
        required_scope: "epochs:rw".to_owned(),
        action: "epoch:revoke-confirm".to_owned(),
        target: format!("{}/epochs/{}/revoke", epoch.product_id, epoch.epoch_id),
        source_kind: "epoch".to_owned(),
        source_id: epoch.epoch_id.clone(),
        request_hash: request_hash.to_vec(),
        before: json!({"epoch": epoch, "approval": approval}),
        after,
        result,
        response_status: 200,
        side_effect: Some(serde_json::to_value(SideEffect::PublishRevocation {
            revocation_seq,
            epoch_id: decode_epoch_id(&epoch.epoch_id)?,
            product_id: epoch.product_id.clone(),
        })?),
        created_at: now,
    };
    let statements = vec![
        admin_operations::insert_statement(database, &operation)?,
        admin_operations::version_statement(
            database,
            &operation.operation_id(),
            "epoch",
            &epoch.epoch_id,
            next_epoch_version,
            now,
        )?,
        database
            .prepare(
                "UPDATE epoch_revocation_approvals SET \
                   second_actor = ?, second_request_id = ?, second_approved_at = ?, \
                   revocation_seq = ? \
                 WHERE epoch_id = ? AND vendor_id = ? AND second_actor IS NULL \
                   AND first_actor <> ? AND expires_at > ?",
            )
            .bind(&[
                text(&principal.actor),
                text(request_id),
                integer(now)?,
                integer(revocation_seq)?,
                blob(&decode_epoch_id(&epoch.epoch_id)?),
                text(&principal.vendor_id),
                text(&principal.actor),
                integer(now)?,
            ])?,
        database
            .prepare("UPDATE epochs SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(&[integer(now)?, blob(&decode_epoch_id(&epoch.epoch_id)?)])?,
        database
            .prepare(
                "INSERT INTO revocations(\
                   seq, kind, target, reason, actor, created_at, request_id\
                 ) VALUES (?, 'epoch', ?, ?, ?, ?, ?)",
            )
            .bind(&[
                integer(revocation_seq)?,
                blob(&decode_epoch_id(&epoch.epoch_id)?),
                integer(i64::from(KillReason::EpochRevoked as u8))?,
                text(&principal.actor),
                integer(now)?,
                text(request_id),
            ])?,
    ];
    match database.batch(statements).await {
        Ok(results)
            if result_changed(results.get(2))?
                && result_changed(results.get(3))?
                && result_changed(results.get(4))? =>
        {
            finish_new_operation(env, database, principal, request_id).await
        }
        Ok(_) => Err(worker::Error::RustError(
            "epoch revocation did not change every durable row".to_owned(),
        )),
        Err(error) => {
            if let Some(response) = replay_operation(
                env,
                database,
                principal,
                request_id,
                request_hash,
                "epochs:rw",
            )
            .await?
            {
                return Ok(response);
            }
            let head = revocation_head(database).await?;
            if head.pending != 0 || head.value >= revocation_seq {
                return conflict(
                    "revocation_in_progress",
                    "another revocation won the sequence; retry after it completes",
                );
            }
            Err(error)
        }
    }
}

async fn publish_epoch_revocation(
    env: &Env,
    database: &D1Database,
    operation: &admin_operations::StoredOperation,
    revocation_seq: i64,
    epoch_id: &[u8],
    product_id: &str,
) -> Result<()> {
    if revocation_seq <= 0 || epoch_id.len() != EpochId::LEN || !valid_identifier(product_id) {
        return Err(worker::Error::RustError(
            "epoch revocation side effect is invalid".to_owned(),
        ));
    }
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT kind, target, reason, request_id, created_at, applied_at, published_at \
             FROM revocations WHERE seq = ?",
        )
        .bind(&[integer(revocation_seq)?])?
        .first::<EpochRevocationRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("epoch revocation row is missing".to_owned()))?;
    if row.kind != "epoch"
        || row.target != epoch_id
        || row.reason != i64::from(KillReason::EpochRevoked as u8)
        || row.request_id.as_deref() != Some(operation.request_id.as_str())
        || row.created_at < 0
    {
        return Err(worker::Error::RustError(
            "epoch revocation row conflicts with its operation".to_owned(),
        ));
    }
    if row.applied_at.is_none() {
        database
            .prepare(
                "UPDATE revocations SET applied_at = COALESCE(applied_at, ?) \
                 WHERE seq = ? AND request_id = ?",
            )
            .bind(&[
                integer(now_seconds())?,
                integer(revocation_seq)?,
                text(&operation.request_id),
            ])?
            .run()
            .await?;
    }
    if row.published_at.is_none() {
        let sequence = u64::try_from(revocation_seq).map_err(|_| {
            worker::Error::RustError("epoch revocation sequence is invalid".to_owned())
        })?;
        let epoch = EpochId::from_slice(epoch_id).ok_or_else(|| {
            worker::Error::RustError("epoch revocation target is invalid".to_owned())
        })?;
        let batch = RevocationBatch {
            proto_ver: PROTO_VER,
            suite_id: CL_STD_1_SUITE_ID,
            from_epoch: sequence,
            to_epoch: sequence,
            issued_at: row.created_at,
            revoked_license_ids: Vec::new(),
            revoked_machine_ids: Vec::new(),
            revoked_epoch_ids: vec![epoch],
            bloom_filter: None,
        };
        let tbs = batch
            .to_canonical()
            .map_err(|_| worker::Error::RustError("revocation batch encoding failed".to_owned()))?;
        let digest = Sha256Scheme::hash_parts(&[
            b"copylocker/epoch-revocation-route/v1",
            product_id.as_bytes(),
            epoch_id,
        ]);
        let routing_id = LicenseId(
            digest
                .as_bytes()
                .get(..LicenseId::LEN)
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| {
                    worker::Error::RustError("routing id derivation failed".to_owned())
                })?,
        );
        let envelope = crate::router::issue_artifact(
            env,
            routing_id,
            product_id,
            epoch_id.to_vec(),
            ArtifactKind::RevocationBatch,
            tbs,
        )
        .await?;
        let parsed = Envelope::decode(&envelope).map_err(|_| {
            worker::Error::RustError("Issuer returned an invalid revocation envelope".to_owned())
        })?;
        let signer = parsed.epoch_ref.ok_or_else(|| {
            worker::Error::RustError("revocation envelope has no signing epoch".to_owned())
        })?;
        if signer == epoch {
            return Err(worker::Error::RustError(
                "a revoked epoch cannot sign its own revocation; rotate Worker secrets first"
                    .to_owned(),
            ));
        }
        let signer_ready = database
            .prepare(
                "SELECT 1 AS value FROM epochs WHERE id = ? AND revoked_at IS NULL \
                   AND (product_scope IS NULL OR product_scope = ?) LIMIT 1",
            )
            .bind(&[blob(signer.as_bytes()), text(product_id)])?
            .first::<ExistsRow>(None)
            .await?
            .is_some();
        if !signer_ready {
            return Err(worker::Error::RustError(
                "revocation signer is not an active registered epoch".to_owned(),
            ));
        }
        crate::admin::publish_batch(env, sequence, &envelope).await?;
        let updated = database
            .prepare(
                "UPDATE revocations SET published_at = COALESCE(published_at, ?) \
                 WHERE seq = ? AND request_id = ? AND applied_at IS NOT NULL",
            )
            .bind(&[
                integer(now_seconds())?,
                integer(revocation_seq)?,
                text(&operation.request_id),
            ])?
            .run()
            .await?;
        if !result_changed(Some(&updated))? {
            return Err(worker::Error::RustError(
                "epoch revocation publication checkpoint was lost".to_owned(),
            ));
        }
    }
    rebuild_keyset(env, database).await
}

async fn rebuild_keyset(env: &Env, database: &D1Database) -> Result<()> {
    let rows = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT cert FROM epochs WHERE revoked_at IS NULL \
             ORDER BY product_scope, not_before, id LIMIT 1000",
        )
        .all()
        .await?
        .results::<CertRow>()?;
    let revocation_epoch = database
        .prepare(
            "SELECT COALESCE(MAX(seq), 0) AS value FROM revocations \
             WHERE published_at IS NOT NULL",
        )
        .first::<IntegerRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("revocation epoch query failed".to_owned()))?;
    if !(0..=MAX_SAFE_INTEGER).contains(&revocation_epoch.value) {
        return Err(worker::Error::RustError(
            "published revocation epoch is invalid".to_owned(),
        ));
    }
    let mut builder = MapBuilder::new();
    builder.put(0, CborValue::Uint(u64::from(PROTO_VER)));
    builder.put(
        1,
        CborValue::Array(
            rows.into_iter()
                .map(|row| CborValue::Bytes(row.cert))
                .collect(),
        ),
    );
    builder.put(
        2,
        CborValue::Uint(u64::try_from(revocation_epoch.value).map_err(|_| {
            worker::Error::RustError("published revocation epoch is invalid".to_owned())
        })?),
    );
    env.kv("CACHE")?
        .put_bytes("keys:current", &builder.finish())?
        .execute()
        .await?;
    Ok(())
}

async fn load_epoch(
    database: &D1Database,
    id: &[u8],
    vendor_id: &str,
) -> Result<Option<EpochView>> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT e.id, e.product_scope, e.suite_id, e.not_before, e.not_after, \
                    e.revoked_at, e.created_at, \
                    (SELECT COUNT(*) FROM machines m JOIN licenses l ON l.id = m.license_id \
                     WHERE l.product_id = e.product_scope \
                       AND m.status IN ('active', 'pending')) AS affected_machines \
             FROM epochs e JOIN products p ON p.id = e.product_scope \
             WHERE e.id = ? AND p.vendor_id = ?",
        )
        .bind(&[blob(id), text(vendor_id)])?
        .first::<EpochDbRow>(None)
        .await?;
    row.map(|row| EpochView::try_from_row(row, now_seconds()))
        .transpose()
}

async fn replacement_epoch_ids(
    database: &D1Database,
    epoch: &EpochView,
    now: i64,
) -> Result<Vec<String>> {
    let rows = database
        .prepare(
            "SELECT id FROM epochs WHERE id <> ? AND revoked_at IS NULL \
               AND not_before <= ? AND not_after > ? \
               AND (product_scope IS NULL OR product_scope = ?) \
             ORDER BY CASE WHEN product_scope = ? THEN 0 ELSE 1 END, not_before DESC LIMIT 10",
        )
        .bind(&[
            blob(&decode_epoch_id(&epoch.epoch_id)?),
            integer(now)?,
            integer(now)?,
            text(&epoch.product_id),
            text(&epoch.product_id),
        ])?
        .all()
        .await?
        .results::<IdRow>()?;
    rows.into_iter()
        .map(|row| {
            EpochId::from_slice(&row.id)
                .map(|id| id.to_hex())
                .ok_or_else(|| worker::Error::RustError("epoch id is corrupt".to_owned()))
        })
        .collect()
}

async fn load_approval(
    database: &D1Database,
    epoch_id: &[u8],
    vendor_id: &str,
) -> Result<Option<ApprovalRow>> {
    database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT first_actor, first_request_id, first_approved_at, expires_at, \
                    second_actor, second_request_id, second_approved_at, revocation_seq \
             FROM epoch_revocation_approvals WHERE epoch_id = ? AND vendor_id = ?",
        )
        .bind(&[blob(epoch_id), text(vendor_id)])?
        .first::<ApprovalRow>(None)
        .await
}

async fn epoch_id_exists(database: &D1Database, epoch_id: &[u8]) -> Result<bool> {
    Ok(database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT 1 AS value FROM epochs WHERE id = ?")
        .bind(&[blob(epoch_id)])?
        .first::<ExistsRow>(None)
        .await?
        .is_some())
}

async fn revocation_head(database: &D1Database) -> Result<RevocationHeadRow> {
    database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT COALESCE(MAX(seq), 0) AS value, \
                    EXISTS(SELECT 1 FROM revocations WHERE published_at IS NULL) AS pending \
             FROM revocations",
        )
        .first::<RevocationHeadRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("revocation head query failed".to_owned()))
}

fn parse_dry_run(request: &Request) -> Result<Option<bool>> {
    let mut value = true;
    let mut seen = false;
    for (name, raw) in request.url()?.query_pairs() {
        if name != "dry_run" || seen {
            return Ok(None);
        }
        seen = true;
        value = match raw.as_ref() {
            "true" => true,
            "false" => false,
            _ => return Ok(None),
        };
    }
    Ok(Some(value))
}

fn result_changed(result: Option<&worker::D1Result>) -> Result<bool> {
    let Some(result) = result else {
        return Ok(false);
    };
    Ok(result.meta()?.and_then(|meta| meta.changes) == Some(1))
}

fn decode_epoch_id(value: &str) -> Result<Vec<u8>> {
    crate::admin::decode_hex_id(value, EpochId::LEN)
        .ok_or_else(|| worker::Error::RustError("epoch id is corrupt".to_owned()))
}

fn decode_hex(value: &str, max_bytes: usize) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || value.len() / 2 > max_bytes {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_nibble(*pair.first()?)? << 4) | hex_nibble(*pair.get(1)?)?))
        .collect()
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UploadBody {
    certificate_hex: String,
    root_verifying_key_hex: String,
}

struct ParsedEpoch {
    certificate: Vec<u8>,
    cert: EpochCert,
    vk_pq: Vec<u8>,
    vk_trad: Vec<u8>,
}

impl ParsedEpoch {
    fn parse(body: &UploadBody) -> std::result::Result<Self, String> {
        let certificate = decode_hex(&body.certificate_hex, MAX_EPOCH_CERT_BYTES)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "certificate_hex is invalid or too large".to_owned())?;
        let root_bytes = decode_hex(&body.root_verifying_key_hex, HybridSig::VK_LEN)
            .ok_or_else(|| "root_verifying_key_hex is invalid".to_owned())?;
        let root_key = HybridSig::decode_vk(&root_bytes)
            .map_err(|_| "root verifying key has the wrong shape".to_owned())?;
        let envelope = Envelope::decode(&certificate)
            .map_err(|_| "certificate is not a canonical envelope".to_owned())?;
        if envelope.encode() != certificate
            || envelope.proto_ver != PROTO_VER
            || envelope.suite_id != CL_STD_1_SUITE_ID
            || envelope.kind != ArtifactKind::EpochCert
            || envelope.epoch_ref.is_some()
        {
            return Err("certificate envelope metadata is invalid".to_owned());
        }
        let inspected = envelope
            .peek_unverified::<EpochCert>()
            .map_err(|_| "certificate body is invalid".to_owned())?;
        let product_id = inspected
            .product_scope
            .as_deref()
            .filter(|value| valid_identifier(value))
            .ok_or_else(|| "epoch certificate must have a valid product scope".to_owned())?;
        if inspected.proto_ver != PROTO_VER
            || inspected.suite_id != CL_STD_1_SUITE_ID
            || inspected.not_before < 0
            || inspected.not_after <= inspected.not_before
            || inspected.not_after > MAX_SAFE_INTEGER
            || Sha256Scheme::hash(&root_bytes) != inspected.issuer_vk_digest
            || HybridSig::decode_vk(&inspected.vk).is_err()
            || FastSig::decode_vk(&inspected.vk_fast).is_err()
        {
            return Err("epoch certificate fields or verifying keys are invalid".to_owned());
        }
        let cert = envelope
            .open::<HybridSig, EpochCert>(product_id, &root_key)
            .map_err(|_| "epoch certificate root signature is invalid".to_owned())?;
        if cert != inspected {
            return Err("verified epoch certificate changed while decoding".to_owned());
        }
        let split = cert
            .vk
            .len()
            .checked_sub(FastSig::VK_LEN)
            .ok_or_else(|| "hybrid epoch verifying key is too short".to_owned())?;
        let (vk_pq, vk_trad) = cert
            .vk
            .split_at_checked(split)
            .ok_or_else(|| "hybrid epoch verifying key split is invalid".to_owned())?;
        let vk_pq = vk_pq.to_vec();
        let vk_trad = vk_trad.to_vec();
        Ok(Self {
            certificate,
            cert,
            vk_pq,
            vk_trad,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct EpochView {
    epoch_id: String,
    product_id: String,
    suite_id: String,
    not_before: i64,
    not_after: i64,
    revoked_at: Option<i64>,
    created_at: i64,
    status: String,
    affected_machines_upper_bound: u64,
}

impl EpochView {
    fn from_cert(
        cert: &EpochCert,
        revoked_at: Option<i64>,
        created_at: i64,
        affected_machines: u64,
    ) -> Self {
        Self {
            epoch_id: cert.epoch_id.to_hex(),
            product_id: cert.product_scope.clone().unwrap_or_default(),
            suite_id: crate::admin::hex_encode(cert.suite_id.as_bytes()),
            not_before: cert.not_before,
            not_after: cert.not_after,
            revoked_at,
            created_at,
            status: epoch_status(revoked_at, cert.not_before, cert.not_after, now_seconds()),
            affected_machines_upper_bound: affected_machines,
        }
    }

    fn try_from_row(row: EpochDbRow, now: i64) -> Result<Self> {
        let epoch_id = EpochId::from_slice(&row.id)
            .ok_or_else(|| worker::Error::RustError("epoch id is invalid".to_owned()))?;
        let suite_id = copylocker_types::SuiteId::from_slice(&row.suite_id)
            .ok_or_else(|| worker::Error::RustError("epoch suite id is invalid".to_owned()))?;
        let product_id = row.product_scope.ok_or_else(|| {
            worker::Error::RustError("tenant epoch has no product scope".to_owned())
        })?;
        if !valid_identifier(&product_id)
            || row.not_before < 0
            || row.not_after <= row.not_before
            || row.revoked_at.is_some_and(|value| value < 0)
            || row.created_at < 0
            || row.affected_machines < 0
        {
            return Err(worker::Error::RustError(
                "epoch row contains invalid data".to_owned(),
            ));
        }
        Ok(Self {
            epoch_id: epoch_id.to_hex(),
            product_id,
            suite_id: crate::admin::hex_encode(suite_id.as_bytes()),
            not_before: row.not_before,
            not_after: row.not_after,
            revoked_at: row.revoked_at,
            created_at: row.created_at,
            status: epoch_status(row.revoked_at, row.not_before, row.not_after, now),
            affected_machines_upper_bound: u64::try_from(row.affected_machines).map_err(|_| {
                worker::Error::RustError("epoch machine impact is invalid".to_owned())
            })?,
        })
    }
}

fn epoch_status(revoked_at: Option<i64>, not_before: i64, not_after: i64, now: i64) -> String {
    if revoked_at.is_some() {
        "revoked"
    } else if now < not_before {
        "upcoming"
    } else if now >= not_after {
        "expired"
    } else {
        "active"
    }
    .to_owned()
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    #[serde(default)]
    confirm_epoch_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SideEffect {
    PublishKeyset,
    PublishRevocation {
        revocation_seq: i64,
        epoch_id: Vec<u8>,
        product_id: String,
    },
}

#[derive(Debug, Deserialize)]
struct EpochDbRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    product_scope: Option<String>,
    #[serde(with = "serde_bytes")]
    suite_id: Vec<u8>,
    not_before: i64,
    not_after: i64,
    revoked_at: Option<i64>,
    created_at: i64,
    affected_machines: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct ApprovalRow {
    first_actor: String,
    first_request_id: String,
    first_approved_at: i64,
    expires_at: i64,
    second_actor: Option<String>,
    second_request_id: Option<String>,
    second_approved_at: Option<i64>,
    revocation_seq: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RevocationHeadRow {
    value: i64,
    pending: i64,
}

#[derive(Debug, Deserialize)]
struct EpochRevocationRow {
    kind: String,
    #[serde(with = "serde_bytes")]
    target: Vec<u8>,
    reason: i64,
    request_id: Option<String>,
    created_at: i64,
    applied_at: Option<i64>,
    published_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CertRow {
    #[serde(with = "serde_bytes")]
    cert: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct IdRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ExistsRow {
    #[serde(rename = "value")]
    _value: i64,
}
