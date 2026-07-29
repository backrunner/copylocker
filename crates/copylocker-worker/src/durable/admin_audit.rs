use copylocker_types::Digest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use worker::wasm_bindgen::JsValue;
use worker::{
    durable_object, wasm_bindgen, DurableObject, Env, Headers, Method, Request, RequestInit,
    Response, Result, SqlStorage, State,
};

use super::{ready, unavailable};
use crate::events::{admin_append_request_hash, admin_snapshot_canonical, AdminAuditEvent};
use crate::middleware::body::{self, BodyError};
use crate::response;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS _sql_schema_migrations (
  id INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS chain_base (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  seq INTEGER NOT NULL,
  hash BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  request_hash BLOB NOT NULL,
  event_json TEXT NOT NULL,
  hash BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
INSERT OR IGNORE INTO _sql_schema_migrations(id) VALUES (1);
"#;

const ADMIN_AUDIT_SCHEMA_VERSION: i32 = 1;
const MAX_INTERNAL_BODY: usize = 256 * 1024;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const ADMIN_AUDIT_OBJECT_NAME: &str = "global";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AdminAuditAppendRequest {
    pub(crate) operation_id: String,
    pub(crate) occurred_at: i64,
    pub(crate) vendor_id: String,
    pub(crate) actor: String,
    pub(crate) action: String,
    pub(crate) target: String,
    pub(crate) reason: Option<u8>,
    pub(crate) request_id: String,
    pub(crate) before: serde_json::Value,
    pub(crate) after: serde_json::Value,
    pub(crate) bootstrap_seq: i64,
    pub(crate) bootstrap_hash: Vec<u8>,
}

#[durable_object]
#[derive(Debug)]
pub struct AdminAuditDO {
    state: State,
    initialization_error: Option<String>,
}

impl DurableObject for AdminAuditDO {
    fn new(state: State, _env: Env) -> Self {
        let initialization_error = initialize(&state.storage().sql())
            .err()
            .map(|error| error.to_string());
        Self {
            state,
            initialization_error,
        }
    }

    async fn fetch(&self, mut request: Request) -> Result<Response> {
        if let Some(error) = self.initialization_error.as_deref() {
            return unavailable("AdminAuditDO", error);
        }

        match (request.method(), request.path().as_str()) {
            (Method::Get, "/health") => ready("AdminAuditDO", ADMIN_AUDIT_SCHEMA_VERSION),
            (Method::Post, "/append") => self.append(&mut request).await,
            (Method::Post, "/verify") => self.verify(&mut request).await,
            (Method::Get, _) => internal_error(404, "not_found"),
            _ => internal_error(405, "method_not_allowed"),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        Response::empty()
    }
}

impl AdminAuditDO {
    async fn append(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<AdminAuditAppendRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        let Some((before, after)) = validate_append(&input) else {
            return internal_error(400, "invalid_request");
        };
        let request_hash = admin_append_request_hash(
            input.occurred_at,
            &input.vendor_id,
            &input.actor,
            &input.action,
            &input.target,
            input.reason,
            &input.request_id,
            &before,
            &after,
        );
        let sql = self.state.storage().sql();
        if let Some(row) = load_operation(&sql, &input.operation_id)? {
            if row.request_hash != request_hash.as_bytes() {
                return internal_error(409, "idempotency_conflict");
            }
            let event = parse_stored_event(&row.event_json)?;
            return response::json(200, &event);
        }

        let head = match load_or_initialize_head(&sql, &input)? {
            HeadResult::Ready(head) => head,
            HeadResult::Stale => return internal_error(409, "stale_chain_head"),
        };
        let seq = head
            .seq
            .checked_add(1)
            .filter(|seq| *seq <= MAX_SAFE_INTEGER)
            .ok_or_else(|| worker::Error::RustError("Admin audit sequence exhausted".to_owned()))?;
        let event = AdminAuditEvent::new_v2(
            seq,
            input.occurred_at,
            input.vendor_id,
            input.actor,
            input.action,
            input.target,
            input.reason,
            input.request_id,
            input.before,
            input.after,
            head.hash,
        )
        .ok_or_else(|| {
            worker::Error::RustError("AdminAuditDO generated an invalid event".to_owned())
        })?;
        let event_json = serde_json::to_string(&event)?;

        sql.exec(
            "INSERT INTO events(\
               seq, operation_id, request_hash, event_json, hash, created_at\
             ) VALUES (?, ?, ?, ?, ?, ?)",
            Some(vec![
                event.seq.into(),
                input.operation_id.into(),
                request_hash.as_bytes().to_vec().into(),
                event_json.into(),
                event.hash.clone().into(),
                event.occurred_at.into(),
            ]),
        )?;
        response::json(201, &event)
    }

    async fn verify(&self, request: &mut Request) -> Result<Response> {
        let Some(event) = parse_json::<AdminAuditEvent>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        if !event.is_valid() {
            return internal_error(400, "invalid_event");
        }
        let row = self
            .state
            .storage()
            .sql()
            .exec(
                "SELECT event_json FROM events WHERE seq = ?",
                Some(vec![event.seq.into()]),
            )?
            .to_array::<StoredEventJson>()?
            .into_iter()
            .next();
        let Some(row) = row else {
            return internal_error(404, "event_not_found");
        };
        if parse_stored_event(&row.event_json)? != event {
            return internal_error(409, "event_conflict");
        }
        response::json(200, &VerifyResponse { ok: true })
    }
}

fn validate_append(input: &AdminAuditAppendRequest) -> Option<(Vec<u8>, Vec<u8>)> {
    let valid = !input.operation_id.is_empty()
        && input.operation_id.len() <= 512
        && input
            .operation_id
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        && (0..=MAX_SAFE_INTEGER).contains(&input.bootstrap_seq)
        && input.bootstrap_hash.len() == Digest::LEN;
    valid.then(|| {
        Some((
            admin_snapshot_canonical(&input.before)?,
            admin_snapshot_canonical(&input.after)?,
        ))
    })?
}

fn load_operation(sql: &SqlStorage, operation_id: &str) -> Result<Option<StoredOperation>> {
    Ok(sql
        .exec(
            "SELECT request_hash, event_json FROM events WHERE operation_id = ?",
            Some(vec![operation_id.into()]),
        )?
        .to_array::<StoredOperation>()?
        .into_iter()
        .next())
}

fn load_or_initialize_head(
    sql: &SqlStorage,
    input: &AdminAuditAppendRequest,
) -> Result<HeadResult> {
    let mut base = sql
        .exec("SELECT seq, hash FROM chain_base WHERE singleton = 1", None)?
        .to_array::<ChainHead>()?
        .into_iter()
        .next();
    if base.is_none() {
        sql.exec(
            "INSERT INTO chain_base(singleton, seq, hash) VALUES (1, ?, ?)",
            Some(vec![
                input.bootstrap_seq.into(),
                input.bootstrap_hash.clone().into(),
            ]),
        )?;
        base = Some(ChainHead {
            seq: input.bootstrap_seq,
            hash: input.bootstrap_hash.clone(),
        });
    }
    let base = base.ok_or_else(|| {
        worker::Error::RustError("Admin audit chain base initialization failed".to_owned())
    })?;
    validate_head(&base)?;

    let head = sql
        .exec(
            "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1",
            None,
        )?
        .to_array::<ChainHead>()?
        .into_iter()
        .next()
        .unwrap_or_else(|| base.clone());
    validate_head(&head)?;
    if input.bootstrap_seq == head.seq && input.bootstrap_hash == head.hash {
        Ok(HeadResult::Ready(head))
    } else {
        Ok(HeadResult::Stale)
    }
}

fn validate_head(head: &ChainHead) -> Result<()> {
    if (0..=MAX_SAFE_INTEGER).contains(&head.seq) && head.hash.len() == Digest::LEN {
        Ok(())
    } else {
        Err(worker::Error::RustError(
            "Admin audit chain head is corrupt".to_owned(),
        ))
    }
}

fn parse_stored_event(value: &str) -> Result<AdminAuditEvent> {
    let event = serde_json::from_str::<AdminAuditEvent>(value)
        .map_err(|_| worker::Error::RustError("Admin audit event JSON is corrupt".to_owned()))?;
    if event.is_valid() {
        Ok(event)
    } else {
        Err(worker::Error::RustError(
            "Admin audit event is corrupt".to_owned(),
        ))
    }
}

async fn parse_json<T: DeserializeOwned>(request: &mut Request) -> Result<Option<T>> {
    let bytes = match body::read_raw(request, MAX_INTERNAL_BODY).await {
        Ok(bytes) => bytes,
        Err(BodyError::Read(error)) => return Err(error),
        Err(_) => return Ok(None),
    };
    Ok(serde_json::from_slice(&bytes).ok())
}

fn initialize(sql: &SqlStorage) -> Result<()> {
    sql.exec(SCHEMA, None)?;
    Ok(())
}

fn internal_error(status: u16, code: &str) -> Result<Response> {
    response::json(
        status,
        &InternalError {
            ok: false,
            error: code,
        },
    )
}

pub(crate) async fn append_event(
    env: &Env,
    input: &AdminAuditAppendRequest,
) -> Result<AdminAuditEvent> {
    let mut response = call(env, "/append", input).await?;
    if (200..300).contains(&response.status_code()) {
        let event = response.json::<AdminAuditEvent>().await?;
        if event.is_valid() {
            return Ok(event);
        }
        return Err(worker::Error::RustError(
            "AdminAuditDO returned an invalid event".to_owned(),
        ));
    }
    let status = response.status_code();
    let error = response
        .json::<OwnedInternalError>()
        .await
        .map(|error| error.error)
        .unwrap_or_else(|_| "invalid_error_response".to_owned());
    Err(worker::Error::RustError(format!(
        "AdminAuditDO append failed ({status}): {error}"
    )))
}

pub(crate) async fn verify_event(env: &Env, event: &AdminAuditEvent) -> Result<()> {
    let mut response = call(env, "/verify", event).await?;
    if response.status_code() == 200
        && response
            .json::<VerifyResponse>()
            .await
            .is_ok_and(|response| response.ok)
    {
        Ok(())
    } else {
        Err(worker::Error::RustError(
            "Admin audit event conflicts with AdminAuditDO".to_owned(),
        ))
    }
}

async fn call<T: Serialize>(env: &Env, path: &str, payload: &T) -> Result<Response> {
    let namespace = env.durable_object("ADMIN_AUDIT")?;
    let stub = namespace.get_by_name(ADMIN_AUDIT_OBJECT_NAME)?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&serde_json::to_string(payload)?)));
    let request = Request::new_with_init(&format!("https://admin-audit.internal{path}"), &init)?;
    stub.fetch_with_request(request).await
}

#[derive(Clone, Debug, Deserialize)]
struct ChainHead {
    seq: i64,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
}

enum HeadResult {
    Ready(ChainHead),
    Stale,
}

#[derive(Debug, Deserialize)]
struct StoredOperation {
    #[serde(with = "serde_bytes")]
    request_hash: Vec<u8>,
    event_json: String,
}

#[derive(Debug, Deserialize)]
struct StoredEventJson {
    event_json: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VerifyResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct OwnedInternalError {
    error: String,
}

#[derive(Debug, Serialize)]
struct InternalError<'a> {
    ok: bool,
    error: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_validation_rejects_floats_and_accepts_integer_snapshots() {
        let base = AdminAuditAppendRequest {
            operation_id: "vendor/request".to_owned(),
            occurred_at: 1,
            vendor_id: "vendor".to_owned(),
            actor: "admin".to_owned(),
            action: "license:suspend".to_owned(),
            target: "01".repeat(16),
            reason: None,
            request_id: "request".to_owned(),
            before: serde_json::json!({"status": "active", "version": 1}),
            after: serde_json::json!({"status": "suspended", "version": 2}),
            bootstrap_seq: 0,
            bootstrap_hash: vec![0; Digest::LEN],
        };
        assert!(validate_append(&base).is_some());
        let invalid = AdminAuditAppendRequest {
            after: serde_json::json!({"ratio": 0.5}),
            ..base
        };
        assert!(validate_append(&invalid).is_none());
    }
}
