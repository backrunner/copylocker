use copylocker_proto::RevocationBatch;
use copylocker_suite::{Artifact, Secret};
use copylocker_types::{ArtifactKind, KillReason, LicenseId, MachineId};
use hmac::{Hmac, KeyInit, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use worker::wasm_bindgen::JsValue;
use worker::{
    D1Database, D1SessionConstraint, D1Type, Date, Env, Headers, Method, Request, RequestInit,
    Response, Result,
};
use zeroize::Zeroize;

use crate::durable::{append_admin_audit, AdminAuditAppendRequest};
use crate::events::{AdminAuditEvent, AdminRevocationSnapshot};
use crate::middleware::body::{self, BodyError};
use crate::{response, router};

const ADMIN_TOKEN_PEPPER_BINDING: &str = "ADMIN_TOKEN_PEPPER";
const TEST_ADMIN_TOKEN_PEPPER_BINDING: &str = "TEST_ADMIN_TOKEN_PEPPER";
const TOKEN_PREFIX: &str = "clat_";
const TOKEN_LENGTH: usize = 48;
const SECRET_LENGTH: usize = 32;
const MAX_ADMIN_BODY: usize = 4 * 1024;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const UNDO_WINDOW_SECONDS: i64 = 24 * 60 * 60;

const ADMIN_SCOPES: &[&str] = &[
    "products:rw",
    "catalog:rw",
    "policies:rw",
    "licenses:rw",
    "machines:rw",
    "revoke",
    "releases:rw",
    "epochs:rw",
    "audit:r",
    "analytics:r",
    "sign:manifest",
];

pub(crate) async fn route(request: &mut Request, env: &Env) -> Result<Response> {
    let path = request.path();
    let Some((kind, encoded_target)) = parse_revoke_path(&path) else {
        return crate::admin_resources::route(request, env).await;
    };
    if request.method() != Method::Post {
        return response::api_error_no_store(405, "method_not_allowed", "HTTP method not allowed");
    }

    let principal = match authenticate_scope(request, env, "revoke").await? {
        AuthResult::Authenticated(principal) => principal,
        AuthResult::Unauthorized => return unauthorized(),
        AuthResult::Forbidden => {
            return response::api_error_no_store(
                403,
                "insufficient_scope",
                "the token does not grant the revoke scope",
            );
        }
    };
    let Some(target_bytes) = decode_hex_id(encoded_target, 16) else {
        return response::api_error_no_store(
            400,
            "invalid_target",
            "target must be a 16-byte hexadecimal identifier",
        );
    };
    let dry_run = match parse_dry_run(request)? {
        Some(value) => value,
        None => {
            return response::api_error_no_store(
                400,
                "invalid_query",
                "dry_run must be true or false",
            );
        }
    };
    let body = match read_revoke_body(request).await? {
        RevokeBodyRead::Body(body) => body,
        RevokeBodyRead::Invalid => {
            return response::api_error_no_store(
                400,
                "invalid_request",
                "request body must be a JSON object",
            );
        }
        RevokeBodyRead::TooLarge => {
            return response::api_error_no_store(
                413,
                "payload_too_large",
                "request body exceeds the 4096-byte limit",
            );
        }
        RevokeBodyRead::UnsupportedMediaType => {
            return response::api_error_no_store(
                415,
                "unsupported_media_type",
                "Content-Type must be application/json",
            );
        }
        RevokeBodyRead::UnsupportedEncoding => {
            return response::api_error_no_store(
                415,
                "unsupported_content_encoding",
                "Content-Encoding must be identity",
            );
        }
    };
    let reason = body.reason.unwrap_or_else(|| kind.default_reason() as u8);
    if KillReason::from_u8(reason).is_none() {
        return response::api_error_no_store(
            400,
            "invalid_reason",
            "reason must be a recognized revocation reason",
        );
    }

    let database = env.d1("DB")?;
    let Some(target) =
        load_target(&database, kind, &target_bytes, principal.vendor_id.as_str()).await?
    else {
        return response::api_error_no_store(404, "not_found", "target not found");
    };

    if dry_run {
        return response::json_no_store(
            200,
            &DryRunResponse {
                ok: true,
                dry_run: true,
                kind: kind.as_str(),
                target: hex_encode(&target.target_id),
                affected_machines: target.affected_machines,
                already_revoked: target.status == "revoked",
            },
        );
    }

    let Some(request_id) = idempotency_key(request)? else {
        return response::api_error_no_store(
            400,
            "missing_idempotency_key",
            "confirmed revocations require Idempotency-Key",
        );
    };
    let revocation = match reserve_revocation(
        &database,
        &target,
        reason,
        principal.actor.as_str(),
        &request_id,
        now_seconds(),
    )
    .await?
    {
        Reservation::Ready(row) => row,
        Reservation::AlreadyRevoked => {
            return response::api_error_no_store(
                409,
                "already_revoked",
                "target is already revoked",
            );
        }
        Reservation::IdempotencyConflict => {
            return response::api_error_no_store(
                409,
                "idempotency_conflict",
                "Idempotency-Key was already used for another request",
            );
        }
        Reservation::AnotherPending => {
            return response::api_error_no_store(
                409,
                "revocation_in_progress",
                "another revocation must finish before this request can run",
            );
        }
    };

    if revocation.published_at.is_none() {
        apply_and_publish(env, &database, &target, &revocation, &request_id).await?;
    }

    response::json_no_store(
        200,
        &ConfirmedResponse {
            ok: true,
            dry_run: false,
            kind: kind.as_str(),
            target: hex_encode(&target.target_id),
            revocation_epoch: revocation.seq,
        },
    )
}

pub(crate) async fn current_revocation_epoch(env: &Env) -> Result<u64> {
    let row = env
        .d1("DB")?
        .prepare(
            "SELECT COALESCE(MAX(seq), 0) AS value FROM revocations \
             WHERE applied_at IS NOT NULL",
        )
        .first::<MaxEpochRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("revocation epoch query returned no row".into()))?;
    u64::try_from(row.value)
        .map_err(|_| worker::Error::RustError("global revocation epoch is invalid".into()))
}

pub(crate) async fn revoke_refunded_license(
    env: &Env,
    license_id: &[u8],
    request_id: &str,
) -> Result<()> {
    if license_id.len() != 16 || !valid_idempotency_key(request_id) {
        return Err(worker::Error::RustError(
            "billing revocation identity is invalid".into(),
        ));
    }
    let database = env.d1("DB")?;
    let session = database.with_session_constraint(D1SessionConstraint::FirstPrimary)?;
    let Some(target) =
        load_target_in_session(&session, TargetKind::License, license_id, None).await?
    else {
        return Err(worker::Error::RustError(
            "refunded license no longer exists".into(),
        ));
    };
    let reservation = reserve_revocation(
        &database,
        &target,
        KillReason::Refund as u8,
        "billing-webhook",
        request_id,
        now_seconds(),
    )
    .await?;
    match reservation {
        Reservation::Ready(row) => {
            if row.published_at.is_none() {
                apply_and_publish(env, &database, &target, &row, request_id).await?;
            }
            Ok(())
        }
        Reservation::AlreadyRevoked => Ok(()),
        Reservation::AnotherPending => Err(worker::Error::RustError(
            "another revocation must finish before the refund can be finalized".into(),
        )),
        Reservation::IdempotencyConflict => Err(worker::Error::RustError(
            "billing refund request id conflicts with another revocation".into(),
        )),
    }
}

pub(crate) async fn reconcile_pending(env: &Env) -> Result<bool> {
    let database = env.d1("DB")?;
    let session = database.with_session_constraint(D1SessionConstraint::FirstPrimary)?;
    let Some(row) = session
        .prepare(
            "SELECT seq, kind, target, reason, actor, created_at, applied_at, published_at, \
                    request_id \
             FROM revocations WHERE published_at IS NULL ORDER BY seq LIMIT 1",
        )
        .first::<PendingRevocationDbRow>(None)
        .await?
    else {
        return Ok(false);
    };
    let request_id = row.request_id.ok_or_else(|| {
        worker::Error::RustError("pending revocation has no idempotency key".into())
    })?;
    if !valid_idempotency_key(&request_id) {
        return Err(worker::Error::RustError(
            "pending revocation has an invalid idempotency key".into(),
        ));
    }
    // Epoch revocations are owned by the recoverable Admin operation journal,
    // whose side effect reconciliation runs before this legacy revocation path.
    if row.kind == "epoch" {
        return Ok(false);
    }
    let revocation = RevocationRow::try_from(RevocationDbRow {
        seq: row.seq,
        kind: row.kind,
        target: row.target,
        reason: row.reason,
        actor: row.actor,
        created_at: row.created_at,
        applied_at: row.applied_at,
        published_at: row.published_at,
    })?;
    let kind = TargetKind::from_str(&revocation.kind).ok_or_else(|| {
        worker::Error::RustError("pending revocation has an invalid target kind".into())
    })?;
    let target = load_target_in_session(&session, kind, &revocation.target, None)
        .await?
        .ok_or_else(|| worker::Error::RustError("pending revocation target is missing".into()))?;

    apply_and_publish(env, &database, &target, &revocation, &request_id).await?;
    Ok(true)
}

async fn apply_and_publish(
    env: &Env,
    database: &D1Database,
    target: &TargetContext,
    revocation: &RevocationRow,
    request_id: &str,
) -> Result<()> {
    let audit_event =
        load_or_create_admin_audit(env, database, target, revocation, request_id).await?;
    if revocation.applied_at.is_none() {
        let init = InitLicenseRequest {
            license_id: target.license_id.as_bytes().to_vec(),
            product_id: target.product_id.clone(),
            suite_id: copylocker_suite_std::CL_STD_1_SUITE_ID.as_bytes().to_vec(),
            seats: target.seats,
            heartbeat_sec: target.heartbeat_sec,
            expires_at: target.expires_at,
        };
        match call_license::<_, OkDoResponse>(env, &target.license_id, "/init", &init).await? {
            DoCall::Success(result) if result.ok => {}
            DoCall::Success(_) => {
                return Err(worker::Error::RustError(
                    "LicenseDO returned an unsuccessful initialization".into(),
                ));
            }
            DoCall::Rejected { status, error } => {
                return Err(worker::Error::RustError(format!(
                    "LicenseDO initialization failed ({status}): {error}"
                )));
            }
        }

        let revoke = RevokeDoRequest {
            license_id: target.license_id.as_bytes().to_vec(),
            kind: target.kind.as_str(),
            machine_id: (target.kind == TargetKind::Machine).then(|| target.target_id.clone()),
            revocation_epoch: revocation.seq,
        };
        match call_license::<_, RevokeDoResponse>(env, &target.license_id, "/revoke", &revoke)
            .await?
        {
            DoCall::Success(result) if result.ok && result.revocation_epoch == revocation.seq => {}
            DoCall::Success(_) => {
                return Err(worker::Error::RustError(
                    "LicenseDO returned inconsistent revocation state".into(),
                ));
            }
            DoCall::Rejected { status, error } => {
                return Err(worker::Error::RustError(format!(
                    "LicenseDO revocation failed ({status}): {error}"
                )));
            }
        }

        let updated = database
            .prepare(
                "UPDATE revocations SET applied_at = COALESCE(applied_at, ?) \
                 WHERE seq = ? AND request_id = ?",
            )
            .bind(&[
                integer(now_seconds())?,
                integer_u64(revocation.seq)?,
                text(request_id),
            ])?
            .run()
            .await?;
        require_single_change(updated, "revocation disappeared before apply checkpoint")?;
    }

    let batch = RevocationBatch {
        proto_ver: copylocker_types::PROTO_VER,
        suite_id: copylocker_suite_std::CL_STD_1_SUITE_ID,
        from_epoch: revocation.seq,
        to_epoch: revocation.seq,
        issued_at: revocation.created_at,
        revoked_license_ids: (target.kind == TargetKind::License)
            .then_some(target.license_id)
            .into_iter()
            .collect(),
        revoked_machine_ids: (target.kind == TargetKind::Machine)
            .then(|| MachineId::from_slice(&target.target_id))
            .flatten()
            .into_iter()
            .collect(),
        revoked_epoch_ids: Vec::new(),
        bloom_filter: None,
    };
    let tbs = batch
        .to_canonical()
        .map_err(|_| worker::Error::RustError("revocation batch encoding failed".into()))?;
    let envelope = router::issue_artifact(
        env,
        target.license_id,
        &target.product_id,
        target.target_id.clone(),
        ArtifactKind::RevocationBatch,
        tbs,
    )
    .await?;
    publish_batch(env, revocation.seq, &envelope).await?;
    enqueue_admin_audit(env, database, &audit_event).await?;

    let updated = database
        .prepare(
            "UPDATE revocations SET published_at = COALESCE(published_at, ?) \
             WHERE seq = ? AND request_id = ? AND applied_at IS NOT NULL",
        )
        .bind(&[
            integer(now_seconds())?,
            integer_u64(revocation.seq)?,
            text(request_id),
        ])?
        .run()
        .await?;
    require_single_change(
        updated,
        "revocation disappeared before publication checkpoint",
    )?;
    Ok(())
}

async fn load_or_create_admin_audit(
    env: &Env,
    database: &D1Database,
    target: &TargetContext,
    revocation: &RevocationRow,
    request_id: &str,
) -> Result<StoredAdminAudit> {
    let operation_id = admin_operation_id(&target.vendor_id, request_id);
    if let Some(stored) = load_admin_audit(database, &operation_id).await? {
        if stored.matches(target, revocation, request_id) {
            return Ok(stored);
        }
        return Err(worker::Error::RustError(
            "stored Admin audit event conflicts with the revocation".into(),
        ));
    }

    let previous = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT seq, hash FROM admin_audit_events ORDER BY seq DESC LIMIT 1")
        .first::<AdminAuditHeadRow>(None)
        .await?;
    let (bootstrap_seq, bootstrap_hash) = match previous {
        Some(row)
            if (1..=MAX_SAFE_INTEGER).contains(&row.seq)
                && row.hash.len() == copylocker_types::Digest::LEN =>
        {
            (row.seq, row.hash)
        }
        Some(_) => {
            return Err(worker::Error::RustError(
                "Admin audit chain head is corrupt".into(),
            ));
        }
        None => (0, vec![0; copylocker_types::Digest::LEN]),
    };
    let before_epoch = revocation
        .seq
        .checked_sub(1)
        .ok_or_else(|| worker::Error::RustError("revocation epoch must be nonzero".into()))?;
    let before = target.audit_snapshot(&target.status, target.affected_machines, before_epoch);
    let after = target.audit_snapshot("revoked", 0, revocation.seq);
    let event = append_admin_audit(
        env,
        &AdminAuditAppendRequest {
            operation_id: operation_id.clone(),
            occurred_at: revocation.created_at,
            vendor_id: target.vendor_id.clone(),
            actor: revocation.actor.clone(),
            action: format!("revoke:{}", target.kind.as_str()),
            target: hex_encode(&target.target_id),
            reason: Some(revocation.reason),
            request_id: request_id.to_owned(),
            before: serde_json::to_value(before)?,
            after: serde_json::to_value(after)?,
            bootstrap_seq,
            bootstrap_hash,
        },
    )
    .await?;
    let event_json = serde_json::to_string(&event)?;
    let result = database
        .prepare(
            "INSERT INTO admin_audit_events(\
               seq, operation_id, source_kind, source_id, event_json, prev_hash, hash, r2_key, \
               created_at\
             ) VALUES (?, ?, 'revocation', ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(operation_id) DO NOTHING",
        )
        .bind(&[
            integer(event.seq)?,
            text(&operation_id),
            text(&revocation.seq.to_string()),
            text(&event_json),
            blob(&event.prev_hash),
            blob(&event.hash),
            text(&event.r2_key),
            integer(revocation.created_at)?,
        ])?
        .run()
        .await?;
    if d1_changes(&result)? == Some(1) {
        return Ok(StoredAdminAudit {
            event,
            enqueued_at: None,
        });
    }

    let stored = load_admin_audit(database, &operation_id)
        .await?
        .ok_or_else(|| worker::Error::RustError("Admin audit event disappeared".into()))?;
    if stored.event == event {
        Ok(stored)
    } else {
        Err(worker::Error::RustError(
            "Admin audit sequence conflicts with an existing event".into(),
        ))
    }
}

async fn load_admin_audit(
    database: &D1Database,
    operation_id: &str,
) -> Result<Option<StoredAdminAudit>> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT event_json, prev_hash, hash, r2_key, enqueued_at \
             FROM admin_audit_events WHERE operation_id = ?",
        )
        .bind(&[text(operation_id)])?
        .first::<AdminAuditDbRow>(None)
        .await?;
    row.map(StoredAdminAudit::try_from).transpose()
}

fn admin_operation_id(vendor_id: &str, request_id: &str) -> String {
    format!("{vendor_id}/{request_id}")
}

async fn enqueue_admin_audit(
    env: &Env,
    database: &D1Database,
    stored: &StoredAdminAudit,
) -> Result<()> {
    if stored.enqueued_at.is_some() {
        return Ok(());
    }
    env.queue("EVENTS")?.send(stored.event.clone()).await?;
    let updated = database
        .prepare(
            "UPDATE admin_audit_events SET enqueued_at = COALESCE(enqueued_at, ?) \
             WHERE seq = ?",
        )
        .bind(&[integer(now_seconds())?, integer(stored.event.seq)?])?
        .run()
        .await?;
    require_single_change(
        updated,
        "Admin audit event disappeared before enqueue checkpoint",
    )
}

fn require_single_change(result: worker::D1Result, message: &str) -> Result<()> {
    let changes = d1_changes(&result)?;
    if changes == Some(1) {
        Ok(())
    } else {
        Err(worker::Error::RustError(message.into()))
    }
}

fn d1_changes(result: &worker::D1Result) -> Result<Option<usize>> {
    Ok(result.meta()?.and_then(|meta| meta.changes))
}

pub(crate) async fn publish_batch(env: &Env, epoch: u64, envelope: &[u8]) -> Result<()> {
    let cache = env.kv("CACHE")?;
    let cursor = epoch
        .checked_sub(1)
        .ok_or_else(|| worker::Error::RustError("revocation epoch must be nonzero".into()))?;
    let key = format!("rev:batch:{cursor}");
    if let Some(existing) = cache.get(&key).bytes().await? {
        if existing != envelope {
            return Err(worker::Error::RustError(
                "immutable revocation batch key contains different bytes".into(),
            ));
        }
    } else {
        cache.put_bytes(&key, envelope)?.execute().await?;
    }

    let current = match cache.get("rev:epoch").text().await? {
        Some(value) => value.parse::<u64>().map_err(|_| {
            worker::Error::RustError("KV revocation epoch is not an integer".into())
        })?,
        None => 0,
    };
    if current > epoch {
        return Err(worker::Error::RustError(
            "KV revocation epoch is ahead of the pending operation".into(),
        ));
    }
    if current < cursor {
        return Err(worker::Error::RustError(
            "KV revocation epoch has a publication gap".into(),
        ));
    }
    if current < epoch {
        cache.put("rev:epoch", epoch.to_string())?.execute().await?;
    }
    Ok(())
}

async fn reserve_revocation(
    database: &D1Database,
    target: &TargetContext,
    reason: u8,
    actor: &str,
    request_id: &str,
    now: i64,
) -> Result<Reservation> {
    let session = database.with_session_constraint(D1SessionConstraint::FirstPrimary)?;
    if let Some(existing) = load_revocation(&session, request_id).await? {
        return Ok(if existing.matches(target, reason, actor) {
            Reservation::Ready(existing)
        } else {
            Reservation::IdempotencyConflict
        });
    }
    if has_published_revocation(&session, target).await? {
        return Ok(Reservation::AlreadyRevoked);
    }
    if target.status == "revoked" {
        return Ok(Reservation::AlreadyRevoked);
    }

    let undo_until = now
        .checked_add(UNDO_WINDOW_SECONDS)
        .ok_or_else(|| worker::Error::RustError("revocation undo window overflow".into()))?;
    let inserted = session
        .prepare(
            "INSERT INTO revocations(\
               kind, target, reason, actor, undo_until, created_at, request_id\
             ) \
             SELECT ?, ?, ?, ?, ?, ?, ? \
             WHERE NOT EXISTS (SELECT 1 FROM revocations WHERE request_id = ?) \
               AND NOT EXISTS (SELECT 1 FROM revocations WHERE published_at IS NULL) \
             RETURNING seq, kind, target, reason, actor, created_at, applied_at, published_at",
        )
        .bind(&[
            text(target.kind.as_str()),
            blob(&target.target_id),
            integer(i64::from(reason))?,
            text(actor),
            integer(undo_until)?,
            integer(now)?,
            text(request_id),
            text(request_id),
        ])?
        .first::<RevocationDbRow>(None)
        .await?
        .map(RevocationRow::try_from)
        .transpose()?;
    if let Some(inserted) = inserted {
        return Ok(Reservation::Ready(inserted));
    }
    match load_revocation(&session, request_id).await? {
        Some(existing) if existing.matches(target, reason, actor) => {
            Ok(Reservation::Ready(existing))
        }
        Some(_) => Ok(Reservation::IdempotencyConflict),
        None => Ok(Reservation::AnotherPending),
    }
}

async fn has_published_revocation(
    session: &worker::D1DatabaseSession,
    target: &TargetContext,
) -> Result<bool> {
    Ok(session
        .prepare(
            "SELECT 1 AS value FROM revocations \
             WHERE kind = ? AND target = ? AND undone_at IS NULL AND published_at IS NOT NULL \
             LIMIT 1",
        )
        .bind(&[text(target.kind.as_str()), blob(&target.target_id)])?
        .first::<ExistsRow>(None)
        .await?
        .is_some())
}

async fn load_revocation(
    session: &worker::D1DatabaseSession,
    request_id: &str,
) -> Result<Option<RevocationRow>> {
    session
        .prepare(
            "SELECT seq, kind, target, reason, actor, created_at, applied_at, published_at \
             FROM revocations WHERE request_id = ?",
        )
        .bind(&[text(request_id)])?
        .first::<RevocationDbRow>(None)
        .await?
        .map(RevocationRow::try_from)
        .transpose()
}

async fn load_target(
    database: &D1Database,
    kind: TargetKind,
    target: &[u8],
    vendor_id: &str,
) -> Result<Option<TargetContext>> {
    let session = database.with_session_constraint(D1SessionConstraint::FirstPrimary)?;
    load_target_in_session(&session, kind, target, Some(vendor_id)).await
}

async fn load_target_in_session(
    session: &worker::D1DatabaseSession,
    kind: TargetKind,
    target: &[u8],
    vendor_id: Option<&str>,
) -> Result<Option<TargetContext>> {
    let base_query = match kind {
        TargetKind::License => {
            "SELECT l.id AS target_id, l.id AS license_id, l.product_id, \
                    product.vendor_id, l.status, \
                    COALESCE(l.seats_override, policy.seats) AS seats, \
                    policy.heartbeat_sec, l.expires_at, \
                    (SELECT COUNT(*) FROM machines m \
                     WHERE m.license_id = l.id AND m.status IN ('active', 'pending')) \
                       AS affected_machines \
             FROM licenses l \
             JOIN products product ON product.id = l.product_id \
             JOIN policies policy ON policy.id = l.policy_id AND policy.product_id = l.product_id \
             WHERE l.id = ?"
        }
        TargetKind::Machine => {
            "SELECT m.id AS target_id, l.id AS license_id, l.product_id, \
                    product.vendor_id, m.status, \
                    COALESCE(l.seats_override, policy.seats) AS seats, \
                    policy.heartbeat_sec, l.expires_at, \
                    CASE WHEN m.status = 'revoked' THEN 0 ELSE 1 END AS affected_machines \
             FROM machines m \
             JOIN licenses l ON l.id = m.license_id \
             JOIN products product ON product.id = l.product_id \
             JOIN policies policy ON policy.id = l.policy_id AND policy.product_id = l.product_id \
             WHERE m.id = ?"
        }
    };
    let query = if vendor_id.is_some() {
        format!("{base_query} AND product.vendor_id = ?")
    } else {
        base_query.to_owned()
    };
    let mut bindings = vec![blob(target)];
    if let Some(vendor_id) = vendor_id {
        bindings.push(text(vendor_id));
    }
    session
        .prepare(&query)
        .bind(&bindings)?
        .first::<TargetRow>(None)
        .await?
        .map(|row| TargetContext::try_from_row(kind, row))
        .transpose()
}

pub(crate) async fn authenticate_scope(
    request: &Request,
    env: &Env,
    required_scope: &str,
) -> Result<AuthResult> {
    if !ADMIN_SCOPES.contains(&required_scope) {
        return Err(worker::Error::RustError(
            "Admin route requested an unknown scope".into(),
        ));
    }
    let Some(header) = request.headers().get("Authorization")? else {
        return Ok(AuthResult::Unauthorized);
    };
    let mut parts = header.split_ascii_whitespace();
    let (Some(scheme), Some(token), None) = (parts.next(), parts.next(), parts.next()) else {
        return Ok(AuthResult::Unauthorized);
    };
    if !scheme.eq_ignore_ascii_case("Bearer") || !valid_token_format(token) {
        return Ok(AuthResult::Unauthorized);
    }

    let pepper = load_admin_pepper(env).await?;
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper.expose())
        .map_err(|_| worker::Error::RustError("admin token pepper is invalid".into()))?;
    mac.update(token.as_bytes());
    let token_hmac = mac.finalize().into_bytes();
    let row = env
        .d1("DB")?
        .prepare(
            "SELECT id, vendor_id, actor, scopes_json, not_before, expires_at, revoked_at \
             FROM admin_tokens WHERE token_hmac = ?",
        )
        .bind(&[blob(&token_hmac)])?
        .first::<AdminTokenRow>(None)
        .await?;
    let Some(row) = row else {
        return Ok(AuthResult::Unauthorized);
    };
    let now = now_seconds();
    if row.revoked_at.is_some() || row.not_before > now || row.expires_at <= now {
        return Ok(AuthResult::Unauthorized);
    }
    if !valid_identifier(&row.id)
        || !valid_identifier(&row.vendor_id)
        || row.actor.is_empty()
        || row.actor.len() > 128
    {
        return Err(worker::Error::RustError(
            "admin token row contains invalid identity data".into(),
        ));
    }
    let scopes = serde_json::from_str::<Vec<String>>(&row.scopes_json)
        .map_err(|_| worker::Error::RustError("admin token scopes are invalid".into()))?;
    if scopes
        .iter()
        .any(|scope| !ADMIN_SCOPES.contains(&scope.as_str()))
    {
        return Err(worker::Error::RustError(
            "admin token row contains an unknown scope".into(),
        ));
    }
    if !scopes.iter().any(|scope| scope == required_scope) {
        return Ok(AuthResult::Forbidden);
    }
    Ok(AuthResult::Authenticated(AdminPrincipal {
        vendor_id: row.vendor_id,
        actor: row.actor,
    }))
}

async fn load_admin_pepper(env: &Env) -> Result<Secret<[u8; SECRET_LENGTH]>> {
    let mut value = if is_test_environment(env) {
        env.var(TEST_ADMIN_TOKEN_PEPPER_BINDING)?.to_string()
    } else {
        env.secret_store(ADMIN_TOKEN_PEPPER_BINDING)?
            .get()
            .await?
            .ok_or_else(|| worker::Error::RustError("admin token pepper is missing".into()))?
    };
    let parsed = parse_secret(&value);
    value.zeroize();
    parsed.map(Secret::new)
}

fn parse_secret(value: &str) -> Result<[u8; SECRET_LENGTH]> {
    let mut bytes = match serde_json::from_str::<SecretWire>(value) {
        Ok(SecretWire::Payload {
            schema_version: 1,
            key,
        }) => key,
        Ok(SecretWire::Bytes(bytes)) => bytes,
        Ok(SecretWire::Hex(value)) => decode_hex(&value)
            .ok_or_else(|| worker::Error::RustError("admin token pepper hex is invalid".into()))?,
        _ => {
            return Err(worker::Error::RustError(
                "admin token pepper payload is invalid".into(),
            ));
        }
    };
    let key = bytes.as_slice().try_into().map_err(|_| {
        worker::Error::RustError("admin token pepper must contain exactly 32 bytes".into())
    })?;
    bytes.zeroize();
    Ok(key)
}

fn parse_revoke_path(path: &str) -> Option<(TargetKind, &str)> {
    let rest = path.strip_prefix("/v1/admin/")?;
    let mut parts = rest.split('/');
    let collection = parts.next()?;
    let target = parts.next()?;
    let action = parts.next()?;
    if parts.next().is_some() || action != "revoke" || target.is_empty() {
        return None;
    }
    let kind = match collection {
        "licenses" => TargetKind::License,
        "machines" => TargetKind::Machine,
        _ => return None,
    };
    Some((kind, target))
}

fn parse_dry_run(request: &Request) -> Result<Option<bool>> {
    let url = request.url()?;
    let mut dry_run = true;
    let mut seen = false;
    for (name, value) in url.query_pairs() {
        if name != "dry_run" || seen {
            return Ok(None);
        }
        seen = true;
        dry_run = match value.as_ref() {
            "true" => true,
            "false" => false,
            _ => return Ok(None),
        };
    }
    Ok(Some(dry_run))
}

async fn read_revoke_body(request: &mut Request) -> Result<RevokeBodyRead> {
    let Some(content_type) = request.headers().get("Content-Type")? else {
        return Ok(RevokeBodyRead::UnsupportedMediaType);
    };
    let media_type = content_type
        .split_once(';')
        .map_or(content_type.as_str(), |(value, _)| value)
        .trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Ok(RevokeBodyRead::UnsupportedMediaType);
    }
    if request
        .headers()
        .get("Content-Encoding")?
        .is_some_and(|value| !value.trim().is_empty() && !value.eq_ignore_ascii_case("identity"))
    {
        return Ok(RevokeBodyRead::UnsupportedEncoding);
    }
    let bytes = match body::read_raw(request, MAX_ADMIN_BODY).await {
        Ok(bytes) => bytes,
        Err(BodyError::Read(error)) => return Err(error),
        Err(BodyError::TooLarge) => return Ok(RevokeBodyRead::TooLarge),
        Err(BodyError::UnsupportedEncoding) => return Ok(RevokeBodyRead::UnsupportedEncoding),
        Err(BodyError::UnsupportedMediaType) => {
            return Ok(RevokeBodyRead::UnsupportedMediaType);
        }
        Err(
            BodyError::InvalidContentLength
            | BodyError::MissingBody
            | BodyError::InvalidCompressedBody,
        ) => return Ok(RevokeBodyRead::Invalid),
    };
    Ok(serde_json::from_slice(&bytes)
        .map(RevokeBodyRead::Body)
        .unwrap_or(RevokeBodyRead::Invalid))
}

async fn call_license<T, U>(
    env: &Env,
    license_id: &LicenseId,
    path: &str,
    payload: &T,
) -> Result<DoCall<U>>
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
        return Ok(DoCall::Success(result.json::<U>().await?));
    }
    let error = result.json::<InternalDoError>().await?.error;
    Ok(DoCall::Rejected { status, error })
}

pub(crate) fn unauthorized() -> Result<Response> {
    let mut response = response::api_error_no_store(
        401,
        "invalid_token",
        "a valid Admin bearer token is required",
    )?;
    response
        .headers_mut()
        .set("WWW-Authenticate", "Bearer realm=\"copylocker-admin\"")?;
    Ok(response)
}

pub(crate) fn idempotency_key(request: &Request) -> Result<Option<String>> {
    let value = request.headers().get("Idempotency-Key")?;
    Ok(value.filter(|value| valid_idempotency_key(value)))
}

pub(crate) fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_token_format(token: &str) -> bool {
    if token.len() != TOKEN_LENGTH || !token.starts_with(TOKEN_PREFIX) {
        return false;
    }
    let Some(payload) = token.as_bytes().get(TOKEN_PREFIX.len()..) else {
        return false;
    };
    payload.iter().all(|byte| base64url_value(*byte).is_some())
        && payload
            .last()
            .and_then(|byte| base64url_value(*byte))
            .is_some_and(|value| value & 0b11 == 0)
}

fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

pub(crate) fn decode_hex_id(value: &str, expected_bytes: usize) -> Option<Vec<u8>> {
    if value.len() != expected_bytes.checked_mul(2)? {
        return None;
    }
    decode_hex(value)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair.first().copied()?)?;
            let low = hex_nibble(pair.get(1).copied()?)?;
            Some((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let low = HEX.get(usize::from(byte & 0x0f)).copied().unwrap_or(b'0');
        encoded.push(char::from(high));
        encoded.push(char::from(low));
    }
    encoded
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_test_environment(env: &Env) -> bool {
    env.var("ENVIRONMENT")
        .ok()
        .is_some_and(|value| value.to_string() == "test")
}

pub(crate) fn now_seconds() -> i64 {
    i64::try_from(Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
}

fn blob(value: &[u8]) -> JsValue {
    JsValue::from(&D1Type::Blob(value))
}

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn integer(value: i64) -> Result<JsValue> {
    if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
        return Err(worker::Error::RustError(
            "Admin integer exceeds JavaScript safe range".into(),
        ));
    }
    Ok(JsValue::from_f64(value as f64))
}

fn integer_u64(value: u64) -> Result<JsValue> {
    let value = i64::try_from(value)
        .map_err(|_| worker::Error::RustError("revocation epoch is too large".into()))?;
    integer(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetKind {
    License,
    Machine,
}

impl TargetKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::License => "license",
            Self::Machine => "machine",
        }
    }

    const fn default_reason(self) -> KillReason {
        match self {
            Self::License => KillReason::RevokedLicense,
            Self::Machine => KillReason::RevokedActivation,
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "license" => Some(Self::License),
            "machine" => Some(Self::Machine),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AdminPrincipal {
    pub(crate) vendor_id: String,
    pub(crate) actor: String,
}

pub(crate) enum AuthResult {
    Authenticated(AdminPrincipal),
    Unauthorized,
    Forbidden,
}

#[derive(Debug)]
struct TargetContext {
    kind: TargetKind,
    target_id: Vec<u8>,
    license_id: LicenseId,
    product_id: String,
    vendor_id: String,
    status: String,
    seats: u32,
    heartbeat_sec: Option<u64>,
    expires_at: Option<i64>,
    affected_machines: u64,
}

impl TargetContext {
    fn try_from_row(kind: TargetKind, row: TargetRow) -> Result<Self> {
        let license_id = LicenseId::from_slice(&row.license_id).ok_or_else(|| {
            worker::Error::RustError("Admin target has an invalid license id".into())
        })?;
        let valid_status = match kind {
            TargetKind::License => matches!(
                row.status.as_str(),
                "active" | "suspended" | "expired" | "revoked"
            ),
            TargetKind::Machine => {
                matches!(
                    row.status.as_str(),
                    "active" | "pending" | "released" | "revoked"
                )
            }
        };
        if row.target_id.len() != 16
            || !valid_identifier(&row.product_id)
            || !valid_identifier(&row.vendor_id)
            || !valid_status
            || !(1..=100_000).contains(&row.seats)
            || row.heartbeat_sec.is_some_and(|value| value <= 0)
            || row.expires_at.is_some_and(|value| value < 0)
            || row.affected_machines < 0
        {
            return Err(worker::Error::RustError(
                "Admin target row contains invalid data".into(),
            ));
        }
        Ok(Self {
            kind,
            target_id: row.target_id,
            license_id,
            product_id: row.product_id,
            vendor_id: row.vendor_id,
            status: row.status,
            seats: u32::try_from(row.seats)
                .map_err(|_| worker::Error::RustError("license seats are invalid".into()))?,
            heartbeat_sec: row
                .heartbeat_sec
                .map(u64::try_from)
                .transpose()
                .map_err(|_| worker::Error::RustError("heartbeat interval is invalid".into()))?,
            expires_at: row.expires_at,
            affected_machines: u64::try_from(row.affected_machines).map_err(|_| {
                worker::Error::RustError("affected machine count is invalid".into())
            })?,
        })
    }

    fn audit_snapshot(
        &self,
        status: &str,
        affected_machines: u64,
        revocation_epoch: u64,
    ) -> AdminRevocationSnapshot {
        AdminRevocationSnapshot {
            kind: self.kind.as_str().to_owned(),
            target: hex_encode(&self.target_id),
            license_id: self.license_id.to_hex(),
            product_id: self.product_id.clone(),
            status: status.to_owned(),
            seats: self.seats,
            heartbeat_sec: self.heartbeat_sec,
            expires_at: self.expires_at,
            affected_machines,
            revocation_epoch,
        }
    }
}

#[derive(Debug)]
struct RevocationRow {
    seq: u64,
    kind: String,
    target: Vec<u8>,
    reason: u8,
    actor: String,
    created_at: i64,
    applied_at: Option<i64>,
    published_at: Option<i64>,
}

impl RevocationRow {
    fn matches(&self, target: &TargetContext, reason: u8, actor: &str) -> bool {
        self.kind == target.kind.as_str()
            && self.target == target.target_id
            && self.reason == reason
            && self.actor == actor
    }
}

impl TryFrom<RevocationDbRow> for RevocationRow {
    type Error = worker::Error;

    fn try_from(row: RevocationDbRow) -> std::result::Result<Self, Self::Error> {
        if row.seq <= 0
            || row.seq > MAX_SAFE_INTEGER
            || row.target.len() != 16
            || !matches!(row.kind.as_str(), "license" | "machine")
            || KillReason::from_u8(u8::try_from(row.reason).unwrap_or(0)).is_none()
            || row.actor.is_empty()
            || row.actor.len() > 128
            || row.created_at < 0
            || row.applied_at.is_some_and(|value| value < 0)
            || row.published_at.is_some_and(|value| value < 0)
        {
            return Err(worker::Error::RustError(
                "revocation row contains invalid data".into(),
            ));
        }
        Ok(Self {
            seq: u64::try_from(row.seq)
                .map_err(|_| worker::Error::RustError("revocation epoch is invalid".into()))?,
            kind: row.kind,
            target: row.target,
            reason: u8::try_from(row.reason)
                .map_err(|_| worker::Error::RustError("revocation reason is invalid".into()))?,
            actor: row.actor,
            created_at: row.created_at,
            applied_at: row.applied_at,
            published_at: row.published_at,
        })
    }
}

enum Reservation {
    Ready(RevocationRow),
    AlreadyRevoked,
    IdempotencyConflict,
    AnotherPending,
}

enum RevokeBodyRead {
    Body(RevokeBody),
    Invalid,
    TooLarge,
    UnsupportedMediaType,
    UnsupportedEncoding,
}

enum DoCall<T> {
    Success(T),
    Rejected { status: u16, error: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    #[serde(default)]
    reason: Option<u8>,
}

#[derive(Debug, Serialize)]
struct DryRunResponse<'a> {
    ok: bool,
    dry_run: bool,
    kind: &'a str,
    target: String,
    affected_machines: u64,
    already_revoked: bool,
}

#[derive(Debug, Serialize)]
struct ConfirmedResponse<'a> {
    ok: bool,
    dry_run: bool,
    kind: &'a str,
    target: String,
    revocation_epoch: u64,
}

#[derive(Debug, Serialize)]
struct InitLicenseRequest {
    license_id: Vec<u8>,
    product_id: String,
    suite_id: Vec<u8>,
    seats: u32,
    heartbeat_sec: Option<u64>,
    expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
struct RevokeDoRequest {
    license_id: Vec<u8>,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_id: Option<Vec<u8>>,
    revocation_epoch: u64,
}

#[derive(Debug, Deserialize)]
struct OkDoResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct RevokeDoResponse {
    ok: bool,
    #[serde(rename = "changed")]
    _changed: bool,
    revocation_epoch: u64,
}

#[derive(Debug, Deserialize)]
struct InternalDoError {
    error: String,
}

#[derive(Debug, Deserialize)]
struct AdminTokenRow {
    id: String,
    vendor_id: String,
    actor: String,
    scopes_json: String,
    not_before: i64,
    expires_at: i64,
    revoked_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TargetRow {
    #[serde(with = "serde_bytes")]
    target_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    license_id: Vec<u8>,
    product_id: String,
    vendor_id: String,
    status: String,
    seats: i64,
    heartbeat_sec: Option<i64>,
    expires_at: Option<i64>,
    affected_machines: i64,
}

#[derive(Debug, Deserialize)]
struct RevocationDbRow {
    seq: i64,
    kind: String,
    #[serde(with = "serde_bytes")]
    target: Vec<u8>,
    reason: i64,
    actor: String,
    created_at: i64,
    applied_at: Option<i64>,
    published_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct PendingRevocationDbRow {
    seq: i64,
    kind: String,
    #[serde(with = "serde_bytes")]
    target: Vec<u8>,
    reason: i64,
    actor: String,
    created_at: i64,
    applied_at: Option<i64>,
    published_at: Option<i64>,
    request_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MaxEpochRow {
    value: i64,
}

#[derive(Debug, Deserialize)]
struct AdminAuditDbRow {
    event_json: String,
    #[serde(with = "serde_bytes")]
    prev_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
    r2_key: String,
    enqueued_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AdminAuditHeadRow {
    seq: i64,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
}

struct StoredAdminAudit {
    event: AdminAuditEvent,
    enqueued_at: Option<i64>,
}

impl StoredAdminAudit {
    fn matches(
        &self,
        target: &TargetContext,
        revocation: &RevocationRow,
        request_id: &str,
    ) -> bool {
        let Some((before, after)) = self.event.revocation_snapshots() else {
            return false;
        };
        self.event.is_valid()
            && self.event.vendor_id == target.vendor_id
            && self.event.actor == revocation.actor
            && self.event.action == format!("revoke:{}", target.kind.as_str())
            && self.event.target == hex_encode(&target.target_id)
            && self.event.reason == Some(revocation.reason)
            && self.event.request_id == request_id
            && before.kind == target.kind.as_str()
            && before.target == hex_encode(&target.target_id)
            && before.license_id == target.license_id.to_hex()
            && before.product_id == target.product_id
            && after.status == "revoked"
            && after.revocation_epoch == revocation.seq
    }
}

impl TryFrom<AdminAuditDbRow> for StoredAdminAudit {
    type Error = worker::Error;

    fn try_from(row: AdminAuditDbRow) -> std::result::Result<Self, Self::Error> {
        let event = serde_json::from_str::<AdminAuditEvent>(&row.event_json)
            .map_err(|_| worker::Error::RustError("Admin audit event JSON is corrupt".into()))?;
        if !event.is_valid()
            || event.prev_hash != row.prev_hash
            || event.hash != row.hash
            || event.r2_key != row.r2_key
            || row.enqueued_at.is_some_and(|value| value < 0)
        {
            return Err(worker::Error::RustError(
                "Admin audit event row is corrupt".into(),
            ));
        }
        Ok(Self {
            event,
            enqueued_at: row.enqueued_at,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ExistsRow {
    #[serde(rename = "value")]
    _value: i64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SecretWire {
    Payload { schema_version: u8, key: Vec<u8> },
    Bytes(Vec<u8>),
    Hex(String),
}
