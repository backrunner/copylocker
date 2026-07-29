use copylocker_suite::HashScheme;
use copylocker_suite_std::Sha256Scheme;
use serde::Deserialize;
use serde_json::Value;
use worker::wasm_bindgen::JsValue;
use worker::{D1Database, D1SessionConstraint, D1Type, Env, Result};

use crate::admin::{now_seconds, valid_idempotency_key, valid_identifier};
use crate::durable::{append_admin_audit, AdminAuditAppendRequest};
use crate::events::{admin_snapshot_canonical, AdminAuditEvent};

const REQUEST_HASH_DOMAIN: &[u8] = b"copylocker/admin-operation-request/v1";
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_OPERATION_JSON: usize = 256 * 1024;

pub(crate) struct NewOperation {
    pub(crate) vendor_id: String,
    pub(crate) request_id: String,
    pub(crate) actor: String,
    pub(crate) required_scope: String,
    pub(crate) action: String,
    pub(crate) target: String,
    pub(crate) source_kind: String,
    pub(crate) source_id: String,
    pub(crate) request_hash: Vec<u8>,
    pub(crate) before: Value,
    pub(crate) after: Value,
    pub(crate) result: Value,
    pub(crate) response_status: u16,
    pub(crate) side_effect: Option<Value>,
    pub(crate) created_at: i64,
}

impl NewOperation {
    pub(crate) fn operation_id(&self) -> String {
        operation_id(&self.vendor_id, &self.request_id)
    }

    fn validate(&self) -> Result<()> {
        let valid_action = !self.action.is_empty()
            && self.action.len() <= 128
            && self.action.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.')
            });
        let valid_target = !self.target.is_empty()
            && self.target.len() <= 256
            && self.target.bytes().all(|byte| byte.is_ascii_graphic());
        if !valid_identifier(&self.vendor_id)
            || !valid_idempotency_key(&self.request_id)
            || self.actor.is_empty()
            || self.actor.len() > 128
            || !valid_identifier(&self.required_scope.replace(':', "_"))
            || !valid_action
            || !valid_target
            || !valid_identifier(&self.source_kind)
            || self.source_id.is_empty()
            || self.source_id.len() > 256
            || self.source_id.bytes().any(|byte| !byte.is_ascii_graphic())
            || self.request_hash.len() != copylocker_types::Digest::LEN
            || self.before == self.after
            || admin_snapshot_canonical(&self.before).is_none()
            || admin_snapshot_canonical(&self.after).is_none()
            || !(200..=299).contains(&self.response_status)
            || !(0..=MAX_SAFE_INTEGER).contains(&self.created_at)
        {
            return Err(worker::Error::RustError(
                "Admin operation contains invalid immutable data".to_owned(),
            ));
        }
        for value in [
            &self.result,
            self.side_effect.as_ref().unwrap_or(&Value::Null),
        ] {
            if serde_json::to_vec(value)?.len() > MAX_OPERATION_JSON {
                return Err(worker::Error::RustError(
                    "Admin operation result exceeds its size limit".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StoredOperation {
    pub(crate) operation_id: String,
    pub(crate) vendor_id: String,
    pub(crate) request_id: String,
    pub(crate) actor: String,
    pub(crate) required_scope: String,
    pub(crate) action: String,
    pub(crate) target: String,
    pub(crate) source_kind: String,
    pub(crate) source_id: String,
    pub(crate) request_hash: Vec<u8>,
    pub(crate) before: Value,
    pub(crate) after: Value,
    pub(crate) result: Value,
    pub(crate) response_status: u16,
    pub(crate) side_effect: Option<Value>,
    pub(crate) created_at: i64,
    pub(crate) applied_at: i64,
    pub(crate) side_effect_at: Option<i64>,
    pub(crate) audit_seq: Option<i64>,
    pub(crate) enqueued_at: Option<i64>,
    pub(crate) completed_at: Option<i64>,
}

impl StoredOperation {
    pub(crate) fn matches_request(&self, request_hash: &[u8]) -> bool {
        self.request_hash == request_hash
    }

    pub(crate) fn side_effect_pending(&self) -> bool {
        self.side_effect.is_some() && self.side_effect_at.is_none()
    }

    fn validate(&self) -> Result<()> {
        let expected_id = operation_id(&self.vendor_id, &self.request_id);
        if self.operation_id != expected_id
            || !valid_identifier(&self.vendor_id)
            || !valid_idempotency_key(&self.request_id)
            || self.actor.is_empty()
            || self.actor.len() > 128
            || self.request_hash.len() != copylocker_types::Digest::LEN
            || self.before == self.after
            || admin_snapshot_canonical(&self.before).is_none()
            || admin_snapshot_canonical(&self.after).is_none()
            || !(200..=299).contains(&self.response_status)
            || !(0..=MAX_SAFE_INTEGER).contains(&self.created_at)
            || !(0..=MAX_SAFE_INTEGER).contains(&self.applied_at)
            || self.side_effect_at.is_some_and(|value| value < 0)
            || self.audit_seq.is_some_and(|value| value <= 0)
            || self.enqueued_at.is_some_and(|value| value < 0)
            || self.completed_at.is_some_and(|value| value < 0)
            || self.completed_at.is_some() && self.enqueued_at.is_none()
            || self.enqueued_at.is_some() && self.audit_seq.is_none()
        {
            return Err(worker::Error::RustError(
                "Admin operation row is corrupt".to_owned(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn operation_id(vendor_id: &str, request_id: &str) -> String {
    format!("{vendor_id}/{request_id}")
}

pub(crate) fn request_hash(action: &str, target: &str, request: &Value) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(request)?;
    Ok(Sha256Scheme::hash_parts(&[
        REQUEST_HASH_DOMAIN,
        action.as_bytes(),
        target.as_bytes(),
        &body,
    ])
    .as_bytes()
    .to_vec())
}

pub(crate) fn insert_statement(
    database: &D1Database,
    operation: &NewOperation,
) -> Result<worker::D1PreparedStatement> {
    operation.validate()?;
    let before = serde_json::to_string(&operation.before)?;
    let after = serde_json::to_string(&operation.after)?;
    let result = serde_json::to_string(&operation.result)?;
    let side_effect = operation
        .side_effect
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    database
        .prepare(
            "INSERT INTO admin_operations(\
               operation_id, vendor_id, request_id, actor, required_scope, action, target, \
               source_kind, source_id, request_hash, before_json, after_json, result_json, \
               response_status, side_effect_json, created_at, applied_at\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&[
            text(&operation.operation_id()),
            text(&operation.vendor_id),
            text(&operation.request_id),
            text(&operation.actor),
            text(&operation.required_scope),
            text(&operation.action),
            text(&operation.target),
            text(&operation.source_kind),
            text(&operation.source_id),
            blob(&operation.request_hash),
            text(&before),
            text(&after),
            text(&result),
            integer(i64::from(operation.response_status))?,
            optional_text(side_effect.as_deref()),
            integer(operation.created_at)?,
            integer(operation.created_at)?,
        ])
}

pub(crate) fn version_statement(
    database: &D1Database,
    operation_id: &str,
    entity_kind: &str,
    entity_id: &str,
    version: i64,
    created_at: i64,
) -> Result<worker::D1PreparedStatement> {
    if !valid_identifier(entity_kind)
        || entity_id.is_empty()
        || entity_id.len() > 256
        || version <= 0
    {
        return Err(worker::Error::RustError(
            "Admin entity version contains invalid data".to_owned(),
        ));
    }
    database
        .prepare(
            "INSERT INTO admin_entity_versions(\
               entity_kind, entity_id, version, operation_id, created_at\
             ) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&[
            text(entity_kind),
            text(entity_id),
            integer(version)?,
            text(operation_id),
            integer(created_at)?,
        ])
}

pub(crate) async fn current_entity_version(
    database: &D1Database,
    entity_kind: &str,
    entity_id: &str,
) -> Result<i64> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT COALESCE(MAX(version), 0) AS value FROM admin_entity_versions \
             WHERE entity_kind = ? AND entity_id = ?",
        )
        .bind(&[text(entity_kind), text(entity_id)])?
        .first::<IntegerRow>(None)
        .await?
        .ok_or_else(|| {
            worker::Error::RustError("Admin entity version query returned no row".to_owned())
        })?;
    if (0..=MAX_SAFE_INTEGER).contains(&row.value) {
        Ok(row.value)
    } else {
        Err(worker::Error::RustError(
            "Admin entity version is invalid".to_owned(),
        ))
    }
}

pub(crate) async fn load(
    database: &D1Database,
    vendor_id: &str,
    request_id: &str,
) -> Result<Option<StoredOperation>> {
    let id = operation_id(vendor_id, request_id);
    load_by_id(database, &id).await
}

async fn load_by_id(database: &D1Database, operation_id: &str) -> Result<Option<StoredOperation>> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT operation_id, vendor_id, request_id, actor, required_scope, action, target, \
                    source_kind, source_id, request_hash, before_json, after_json, result_json, \
                    response_status, side_effect_json, created_at, applied_at, side_effect_at, \
                    audit_seq, enqueued_at, completed_at \
             FROM admin_operations WHERE operation_id = ?",
        )
        .bind(&[text(operation_id)])?
        .first::<OperationDbRow>(None)
        .await?;
    row.map(StoredOperation::try_from).transpose()
}

pub(crate) async fn mark_side_effect_complete(
    database: &D1Database,
    operation: &StoredOperation,
) -> Result<StoredOperation> {
    if !operation.side_effect_pending() {
        return Ok(operation.clone());
    }
    database
        .prepare(
            "UPDATE admin_operations SET side_effect_at = COALESCE(side_effect_at, ?) \
             WHERE operation_id = ?",
        )
        .bind(&[integer(now_seconds())?, text(&operation.operation_id)])?
        .run()
        .await?;
    load_by_id(database, &operation.operation_id)
        .await?
        .ok_or_else(|| worker::Error::RustError("Admin operation disappeared".to_owned()))
}

pub(crate) async fn finalize(
    env: &Env,
    database: &D1Database,
    operation: &StoredOperation,
) -> Result<StoredOperation> {
    operation.validate()?;
    if operation.side_effect_pending() {
        return Err(worker::Error::RustError(
            "Admin operation side effect has not completed".to_owned(),
        ));
    }
    if operation.completed_at.is_some() {
        return Ok(operation.clone());
    }

    let stored_audit = ensure_audit(env, database, operation).await?;
    if operation.enqueued_at.is_none() {
        env.queue("EVENTS")?
            .send(stored_audit.event.clone())
            .await?;
        let checkpoint = now_seconds();
        database
            .batch(vec![
                database
                    .prepare(
                        "UPDATE admin_audit_events SET enqueued_at = COALESCE(enqueued_at, ?) \
                         WHERE operation_id = ? AND seq = ?",
                    )
                    .bind(&[
                        integer(checkpoint)?,
                        text(&operation.operation_id),
                        integer(stored_audit.event.seq)?,
                    ])?,
                database
                    .prepare(
                        "UPDATE admin_operations SET \
                           audit_seq = COALESCE(audit_seq, ?), \
                           enqueued_at = COALESCE(enqueued_at, ?), \
                           completed_at = COALESCE(completed_at, ?) \
                         WHERE operation_id = ?",
                    )
                    .bind(&[
                        integer(stored_audit.event.seq)?,
                        integer(checkpoint)?,
                        integer(checkpoint)?,
                        text(&operation.operation_id),
                    ])?,
            ])
            .await?;
    }

    let completed = load_by_id(database, &operation.operation_id)
        .await?
        .ok_or_else(|| worker::Error::RustError("Admin operation disappeared".to_owned()))?;
    if completed.completed_at.is_none() {
        return Err(worker::Error::RustError(
            "Admin operation completion checkpoint was not persisted".to_owned(),
        ));
    }
    Ok(completed)
}

pub(crate) async fn reconcile_pending(env: &Env) -> Result<bool> {
    let database = env.d1("DB")?;
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT operation_id FROM admin_operations \
             WHERE completed_at IS NULL AND (side_effect_json IS NULL OR side_effect_at IS NOT NULL) \
             ORDER BY created_at, operation_id LIMIT 1",
        )
        .first::<OperationIdRow>(None)
        .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let operation = load_by_id(&database, &row.operation_id)
        .await?
        .ok_or_else(|| {
            worker::Error::RustError("pending Admin operation disappeared".to_owned())
        })?;
    finalize(env, &database, &operation).await?;
    Ok(true)
}

pub(crate) async fn load_pending_side_effect(
    database: &D1Database,
) -> Result<Option<StoredOperation>> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT operation_id FROM admin_operations \
             WHERE completed_at IS NULL AND side_effect_json IS NOT NULL \
               AND side_effect_at IS NULL \
             ORDER BY created_at, operation_id LIMIT 1",
        )
        .first::<OperationIdRow>(None)
        .await?;
    match row {
        Some(row) => load_by_id(database, &row.operation_id).await,
        None => Ok(None),
    }
}

async fn ensure_audit(
    env: &Env,
    database: &D1Database,
    operation: &StoredOperation,
) -> Result<StoredAudit> {
    if let Some(stored) = load_audit(database, &operation.operation_id).await? {
        stored.validate_for(operation)?;
        return Ok(stored);
    }

    let previous = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT seq, hash FROM admin_audit_events ORDER BY seq DESC LIMIT 1")
        .first::<AuditHeadRow>(None)
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
                "Admin audit chain head is corrupt".to_owned(),
            ));
        }
        None => (0, vec![0; copylocker_types::Digest::LEN]),
    };
    let event = append_admin_audit(
        env,
        &AdminAuditAppendRequest {
            operation_id: operation.operation_id.clone(),
            occurred_at: operation.created_at,
            vendor_id: operation.vendor_id.clone(),
            actor: operation.actor.clone(),
            action: operation.action.clone(),
            target: operation.target.clone(),
            reason: None,
            request_id: operation.request_id.clone(),
            before: operation.before.clone(),
            after: operation.after.clone(),
            bootstrap_seq,
            bootstrap_hash,
        },
    )
    .await?;
    let event_json = serde_json::to_string(&event)?;
    database
        .batch(vec![
            database
                .prepare(
                    "INSERT INTO admin_audit_events(\
                       seq, operation_id, source_kind, source_id, event_json, prev_hash, hash, \
                       r2_key, created_at\
                     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
                     ON CONFLICT(operation_id) DO NOTHING",
                )
                .bind(&[
                    integer(event.seq)?,
                    text(&operation.operation_id),
                    text(&operation.source_kind),
                    text(&operation.source_id),
                    text(&event_json),
                    blob(&event.prev_hash),
                    blob(&event.hash),
                    text(&event.r2_key),
                    integer(operation.created_at)?,
                ])?,
            database
                .prepare(
                    "UPDATE admin_operations SET audit_seq = COALESCE(audit_seq, ?) \
                     WHERE operation_id = ?",
                )
                .bind(&[integer(event.seq)?, text(&operation.operation_id)])?,
        ])
        .await?;

    let stored = load_audit(database, &operation.operation_id)
        .await?
        .ok_or_else(|| worker::Error::RustError("Admin audit mirror disappeared".to_owned()))?;
    stored.validate_for(operation)?;
    Ok(stored)
}

async fn load_audit(database: &D1Database, operation_id: &str) -> Result<Option<StoredAudit>> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT event_json, prev_hash, hash, r2_key, enqueued_at \
             FROM admin_audit_events WHERE operation_id = ?",
        )
        .bind(&[text(operation_id)])?
        .first::<AuditDbRow>(None)
        .await?;
    row.map(StoredAudit::try_from).transpose()
}

struct StoredAudit {
    event: AdminAuditEvent,
    #[allow(dead_code)]
    enqueued_at: Option<i64>,
}

impl StoredAudit {
    fn validate_for(&self, operation: &StoredOperation) -> Result<()> {
        if self.event.is_valid()
            && self.event.vendor_id == operation.vendor_id
            && self.event.actor == operation.actor
            && self.event.action == operation.action
            && self.event.target == operation.target
            && self.event.reason.is_none()
            && self.event.request_id == operation.request_id
            && self.event.before == operation.before
            && self.event.after == operation.after
        {
            Ok(())
        } else {
            Err(worker::Error::RustError(
                "Admin audit event conflicts with its operation".to_owned(),
            ))
        }
    }
}

impl TryFrom<AuditDbRow> for StoredAudit {
    type Error = worker::Error;

    fn try_from(row: AuditDbRow) -> std::result::Result<Self, Self::Error> {
        let event = serde_json::from_str::<AdminAuditEvent>(&row.event_json).map_err(|_| {
            worker::Error::RustError("Admin audit event JSON is corrupt".to_owned())
        })?;
        if !event.is_valid()
            || event.prev_hash != row.prev_hash
            || event.hash != row.hash
            || event.r2_key != row.r2_key
            || row.enqueued_at.is_some_and(|value| value < 0)
        {
            return Err(worker::Error::RustError(
                "Admin audit event row is corrupt".to_owned(),
            ));
        }
        Ok(Self {
            event,
            enqueued_at: row.enqueued_at,
        })
    }
}

impl TryFrom<OperationDbRow> for StoredOperation {
    type Error = worker::Error;

    fn try_from(row: OperationDbRow) -> std::result::Result<Self, Self::Error> {
        let response_status = u16::try_from(row.response_status).map_err(|_| {
            worker::Error::RustError("Admin operation response status is invalid".to_owned())
        })?;
        let operation = Self {
            operation_id: row.operation_id,
            vendor_id: row.vendor_id,
            request_id: row.request_id,
            actor: row.actor,
            required_scope: row.required_scope,
            action: row.action,
            target: row.target,
            source_kind: row.source_kind,
            source_id: row.source_id,
            request_hash: row.request_hash,
            before: parse_json(&row.before_json, "before snapshot")?,
            after: parse_json(&row.after_json, "after snapshot")?,
            result: parse_json(&row.result_json, "result")?,
            response_status,
            side_effect: row
                .side_effect_json
                .as_deref()
                .map(|value| parse_json(value, "side effect"))
                .transpose()?,
            created_at: row.created_at,
            applied_at: row.applied_at,
            side_effect_at: row.side_effect_at,
            audit_seq: row.audit_seq,
            enqueued_at: row.enqueued_at,
            completed_at: row.completed_at,
        };
        operation.validate()?;
        Ok(operation)
    }
}

fn parse_json(value: &str, field: &str) -> Result<Value> {
    if value.len() > MAX_OPERATION_JSON {
        return Err(worker::Error::RustError(format!(
            "Admin operation {field} exceeds its size limit"
        )));
    }
    serde_json::from_str(value)
        .map_err(|_| worker::Error::RustError(format!("Admin operation {field} is corrupt")))
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
            "Admin operation integer exceeds JavaScript safe range".to_owned(),
        ));
    }
    Ok(JsValue::from_f64(value as f64))
}

#[derive(Debug, Deserialize)]
struct OperationDbRow {
    operation_id: String,
    vendor_id: String,
    request_id: String,
    actor: String,
    required_scope: String,
    action: String,
    target: String,
    source_kind: String,
    source_id: String,
    #[serde(with = "serde_bytes")]
    request_hash: Vec<u8>,
    before_json: String,
    after_json: String,
    result_json: String,
    response_status: i64,
    side_effect_json: Option<String>,
    created_at: i64,
    applied_at: i64,
    side_effect_at: Option<i64>,
    audit_seq: Option<i64>,
    enqueued_at: Option<i64>,
    completed_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AuditDbRow {
    event_json: String,
    #[serde(with = "serde_bytes")]
    prev_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
    r2_key: String,
    enqueued_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AuditHeadRow {
    seq: i64,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct IntegerRow {
    value: i64,
}

#[derive(Debug, Deserialize)]
struct OperationIdRow {
    operation_id: String,
}
