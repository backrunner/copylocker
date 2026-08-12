//! Mode E account session authority (`data-model.md §11`, `10-server-worker.md §5`).
//!
//! One `AccountDO` instance per account id keeps every session-state decision strongly
//! consistent: login throttling, session issuance with the concurrent-session limit, refresh
//! rotation, and logout. The account profile (email, Argon2id password hash) lives in D1 and is
//! only ever read by the Worker route handlers; this object stores token *hashes* only, never a
//! bearer token itself.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use worker::{
    durable_object, wasm_bindgen, Date, DurableObject, Env, Method, Request, Response, Result,
    SqlStorage, State,
};

use super::{ready, unavailable};
use crate::middleware::body::{self, BodyError};
use crate::response;

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS _sql_schema_migrations (
  id INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash BLOB PRIMARY KEY,
  machine_id BLOB,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS login_attempts (
  at INTEGER NOT NULL,
  ok INTEGER NOT NULL,
  ip_hash BLOB
);
INSERT OR IGNORE INTO _sql_schema_migrations(id) VALUES (1);
"#;

/// v2 adds the session kind (access vs refresh) and the refresh pair link used to rotate or
/// revoke a whole session in one statement.
const SCHEMA_V2: &str = r#"
ALTER TABLE sessions ADD COLUMN kind INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN pair BLOB;
CREATE INDEX IF NOT EXISTS idx_sessions_pair ON sessions(pair);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_at ON login_attempts(at);
INSERT INTO _sql_schema_migrations(id) VALUES (2);
"#;

const ACCOUNT_SCHEMA_VERSION: i32 = 2;
const MAX_INTERNAL_BODY: usize = 16 * 1024;
const TOKEN_HASH_LEN: usize = 32;
const MAX_IP_HASH_LEN: usize = 32;
/// Login throttle: at most this many failed attempts inside the window (`10-server-worker.md §5`).
const MAX_FAILED_ATTEMPTS: i64 = 10;
const FAILURE_WINDOW_SECS: i64 = 15 * 60;
const ATTEMPT_RETENTION_SECS: i64 = 24 * 60 * 60;
const SESSION_KIND_ACCESS: i64 = 0;
const SESSION_KIND_REFRESH: i64 = 1;

#[durable_object]
#[derive(Debug)]
pub struct AccountDO {
    state: State,
    initialization_error: Option<String>,
}

impl DurableObject for AccountDO {
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
            return unavailable("AccountDO", error);
        }

        match (request.method(), request.path().as_str()) {
            (Method::Get, "/health") => ready("AccountDO", ACCOUNT_SCHEMA_VERSION),
            (Method::Post, "/login-gate") => self.login_gate(&mut request).await,
            (Method::Post, "/login-record") => self.login_record(&mut request).await,
            (Method::Post, "/session/issue") => self.session_issue(&mut request).await,
            (Method::Post, "/session/resolve") => self.session_resolve(&mut request).await,
            (Method::Post, "/session/refresh") => self.session_refresh(&mut request).await,
            (Method::Post, "/session/revoke") => self.session_revoke(&mut request).await,
            (Method::Get, _) => internal_error(404, "not_found"),
            _ => internal_error(405, "method_not_allowed"),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        if let Some(error) = self.initialization_error.as_deref() {
            return unavailable("AccountDO", error);
        }
        let now = now_seconds();
        self.reclaim(now)?;
        self.schedule_next_alarm(now).await?;
        Response::empty()
    }
}

impl AccountDO {
    /// Throttle check executed before any password work. Only failed attempts count, so a
    /// successful login immediately restores access for a legitimate user.
    async fn login_gate(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<LoginGateRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        if input.now < 0 {
            return internal_error(400, "invalid_request");
        }
        let sql = self.state.storage().sql();
        let failures = recent_failures(&sql, input.now)?;
        if failures.count < MAX_FAILED_ATTEMPTS {
            return response::json(200, &LoginGateResponse::allowed());
        }
        // Exponential backoff capped at one hour (`10-server-worker.md §5`).
        let shift = u32::try_from((failures.count - MAX_FAILED_ATTEMPTS).min(7)).unwrap_or(0);
        let backoff = 30_i64.saturating_mul(1_i64 << shift).min(3600);
        let retry_after = failures
            .latest
            .saturating_add(backoff)
            .saturating_sub(input.now)
            .max(1);
        response::json(200, &LoginGateResponse::throttled(retry_after))
    }

    async fn login_record(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<LoginRecordRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        if input.now < 0
            || input
                .ip_hash
                .as_ref()
                .is_some_and(|hash| hash.is_empty() || hash.len() > MAX_IP_HASH_LEN)
        {
            return internal_error(400, "invalid_request");
        }
        let sql = self.state.storage().sql();
        sql.exec(
            "INSERT INTO login_attempts(at, ok, ip_hash) VALUES (?, ?, ?)",
            Some(vec![
                input.now.into(),
                i64::from(input.ok).into(),
                input.ip_hash.into(),
            ]),
        )?;
        self.schedule_next_alarm(input.now).await?;
        response::json(200, &OkResponse { ok: true })
    }

    /// Issue a fresh session pair. `max_devices` caps the number of concurrent access sessions
    /// for the account; zero means unlimited (the license seat limit still applies).
    async fn session_issue(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<SessionIssueRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        let Some(max_devices) = validate_session_issue(&input) else {
            return internal_error(400, "invalid_request");
        };
        let sql = self.state.storage().sql();
        if max_devices > 0 {
            let active = sql
                .exec(
                    "SELECT COUNT(*) AS value FROM sessions \
                     WHERE kind = 0 AND revoked_at IS NULL AND expires_at > ?",
                    Some(vec![input.now.into()]),
                )?
                .one::<IntRow>()?
                .value;
            if active >= max_devices {
                return internal_error(409, "device_limit");
            }
        }
        insert_session(
            &sql,
            &input.access_hash,
            SESSION_KIND_ACCESS,
            &input.refresh_hash,
            input.now,
            input.access_expires_at,
        )?;
        insert_session(
            &sql,
            &input.refresh_hash,
            SESSION_KIND_REFRESH,
            &input.refresh_hash,
            input.now,
            input.refresh_expires_at,
        )?;
        self.schedule_next_alarm(input.now).await?;
        response::json(200, &OkResponse { ok: true })
    }

    /// Resolve an access token hash for activation. Reveals only whether the session is
    /// currently usable; expiry details stay inside the object.
    async fn session_resolve(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<SessionTokenRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        if input.token_hash.len() != TOKEN_HASH_LEN || input.now < 0 {
            return internal_error(400, "invalid_request");
        }
        let sql = self.state.storage().sql();
        let active = session_is_active(&sql, &input.token_hash, SESSION_KIND_ACCESS, input.now)?;
        response::json(200, &ResolveResponse { active })
    }

    /// Rotate a session: the presented refresh token and its paired access token are revoked and
    /// replaced atomically, so a replayed refresh token can never extend a session.
    async fn session_refresh(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<SessionRefreshRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        if input.refresh_hash.len() != TOKEN_HASH_LEN
            || input.access_hash.len() != TOKEN_HASH_LEN
            || input.new_refresh_hash.len() != TOKEN_HASH_LEN
            || input.now < 0
            || input.access_expires_at <= input.now
            || input.refresh_expires_at <= input.now
        {
            return internal_error(400, "invalid_request");
        }
        let sql = self.state.storage().sql();
        if !session_is_active(&sql, &input.refresh_hash, SESSION_KIND_REFRESH, input.now)? {
            return internal_error(401, "invalid_session");
        }
        // Synchronous writes are coalesced atomically by Durable Object storage.
        sql.exec(
            "UPDATE sessions SET revoked_at = ? WHERE pair = ? AND revoked_at IS NULL",
            Some(vec![input.now.into(), input.refresh_hash.clone().into()]),
        )?;
        insert_session(
            &sql,
            &input.access_hash,
            SESSION_KIND_ACCESS,
            &input.new_refresh_hash,
            input.now,
            input.access_expires_at,
        )?;
        insert_session(
            &sql,
            &input.new_refresh_hash,
            SESSION_KIND_REFRESH,
            &input.new_refresh_hash,
            input.now,
            input.refresh_expires_at,
        )?;
        self.schedule_next_alarm(input.now).await?;
        response::json(200, &OkResponse { ok: true })
    }

    /// Revoke a whole session by its refresh token. Always succeeds: logout must not reveal
    /// whether the token ever existed.
    async fn session_revoke(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<SessionTokenRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        if input.token_hash.len() != TOKEN_HASH_LEN || input.now < 0 {
            return internal_error(400, "invalid_request");
        }
        let sql = self.state.storage().sql();
        sql.exec(
            "UPDATE sessions SET revoked_at = ? WHERE pair = ? AND revoked_at IS NULL",
            Some(vec![input.now.into(), input.token_hash.into()]),
        )?;
        response::json(200, &OkResponse { ok: true })
    }

    fn reclaim(&self, now: i64) -> Result<()> {
        let sql = self.state.storage().sql();
        sql.exec(
            "DELETE FROM sessions WHERE expires_at <= ?",
            Some(vec![now.into()]),
        )?;
        sql.exec(
            "DELETE FROM login_attempts WHERE at <= ?",
            Some(vec![now.saturating_sub(ATTEMPT_RETENTION_SECS).into()]),
        )?;
        Ok(())
    }

    async fn schedule_next_alarm(&self, now: i64) -> Result<()> {
        let sql = self.state.storage().sql();
        let next = sql
            .exec(
                "SELECT MIN(at) AS value FROM (\
                   SELECT MIN(expires_at) AS at FROM sessions \
                   UNION ALL \
                   SELECT MIN(at + 86400) AS at FROM login_attempts\
                 )",
                None,
            )?
            .one::<OptionalIntRow>()?
            .value;
        let storage = self.state.storage();
        if let Some(next) = next {
            let delay = u64::try_from(next.saturating_sub(now)).unwrap_or_default();
            storage.set_alarm(Duration::from_secs(delay)).await
        } else {
            storage.delete_alarm().await
        }
    }
}

#[derive(Debug, Deserialize)]
struct LoginGateRequest {
    now: i64,
}

#[derive(Debug, Serialize)]
struct LoginGateResponse {
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<i64>,
}

impl LoginGateResponse {
    fn allowed() -> Self {
        Self {
            allowed: true,
            retry_after: None,
        }
    }

    fn throttled(retry_after: i64) -> Self {
        Self {
            allowed: false,
            retry_after: Some(retry_after),
        }
    }
}

#[derive(Debug, Deserialize)]
struct LoginRecordRequest {
    ok: bool,
    #[serde(default)]
    ip_hash: Option<Vec<u8>>,
    now: i64,
}

#[derive(Debug, Deserialize)]
struct SessionIssueRequest {
    #[serde(with = "serde_bytes")]
    access_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    refresh_hash: Vec<u8>,
    access_expires_at: i64,
    refresh_expires_at: i64,
    max_devices: i64,
    now: i64,
}

#[derive(Debug, Deserialize)]
struct SessionTokenRequest {
    #[serde(with = "serde_bytes")]
    token_hash: Vec<u8>,
    now: i64,
}

#[derive(Debug, Deserialize)]
struct SessionRefreshRequest {
    #[serde(with = "serde_bytes")]
    refresh_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    access_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    new_refresh_hash: Vec<u8>,
    access_expires_at: i64,
    refresh_expires_at: i64,
    now: i64,
}

#[derive(Debug, Serialize)]
struct OkResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct ResolveResponse {
    active: bool,
}

#[derive(Debug, Serialize)]
struct InternalError<'a> {
    ok: bool,
    error: &'a str,
}

#[derive(Debug, Deserialize)]
struct IntRow {
    value: i64,
}

#[derive(Debug, Deserialize)]
struct OptionalIntRow {
    value: Option<i64>,
}

#[derive(Debug)]
struct FailureCount {
    count: i64,
    latest: i64,
}

fn validate_session_issue(input: &SessionIssueRequest) -> Option<i64> {
    let valid = input.access_hash.len() == TOKEN_HASH_LEN
        && input.refresh_hash.len() == TOKEN_HASH_LEN
        && input.access_hash != input.refresh_hash
        && input.now >= 0
        && input.access_expires_at > input.now
        && input.refresh_expires_at > input.access_expires_at
        && (0..=1000).contains(&input.max_devices);
    valid.then_some(input.max_devices)
}

fn recent_failures(sql: &SqlStorage, now: i64) -> Result<FailureCount> {
    let rows = sql
        .exec(
            "SELECT COUNT(*) AS value, COALESCE(MAX(at), 0) AS latest FROM login_attempts \
             WHERE ok = 0 AND at > ?",
            Some(vec![now.saturating_sub(FAILURE_WINDOW_SECS).into()]),
        )?
        .one::<FailureRow>()?;
    Ok(FailureCount {
        count: rows.value,
        latest: rows.latest,
    })
}

#[derive(Debug, Deserialize)]
struct FailureRow {
    value: i64,
    latest: i64,
}

fn session_is_active(sql: &SqlStorage, token_hash: &[u8], kind: i64, now: i64) -> Result<bool> {
    let count = sql
        .exec(
            "SELECT COUNT(*) AS value FROM sessions \
             WHERE token_hash = ? AND kind = ? AND revoked_at IS NULL AND expires_at > ?",
            Some(vec![token_hash.to_vec().into(), kind.into(), now.into()]),
        )?
        .one::<IntRow>()?
        .value;
    Ok(count > 0)
}

fn insert_session(
    sql: &SqlStorage,
    token_hash: &[u8],
    kind: i64,
    pair: &[u8],
    issued_at: i64,
    expires_at: i64,
) -> Result<()> {
    sql.exec(
        "INSERT INTO sessions(token_hash, kind, pair, machine_id, issued_at, expires_at) \
         VALUES (?, ?, ?, NULL, ?, ?)",
        Some(vec![
            token_hash.to_vec().into(),
            kind.into(),
            pair.to_vec().into(),
            issued_at.into(),
            expires_at.into(),
        ]),
    )?;
    Ok(())
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
    sql.exec(SCHEMA_V1, None)?;
    let version = sql
        .exec(
            "SELECT COALESCE(MAX(id), 0) AS value FROM _sql_schema_migrations",
            None,
        )?
        .one::<IntRow>()?
        .value;
    if version < i64::from(ACCOUNT_SCHEMA_VERSION) {
        sql.exec(SCHEMA_V2, None)?;
    }
    Ok(())
}

fn now_seconds() -> i64 {
    i64::try_from(Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn issue_request() -> SessionIssueRequest {
        SessionIssueRequest {
            access_hash: vec![1; 32],
            refresh_hash: vec![2; 32],
            access_expires_at: 3_700,
            refresh_expires_at: 2_592_100,
            max_devices: 3,
            now: 100,
        }
    }

    #[test]
    fn session_issue_validation_bounds_every_field() {
        assert_eq!(validate_session_issue(&issue_request()), Some(3));

        let mut same_hashes = issue_request();
        same_hashes.refresh_hash = same_hashes.access_hash.clone();
        assert_eq!(validate_session_issue(&same_hashes), None);

        let mut expired = issue_request();
        expired.access_expires_at = expired.now;
        assert_eq!(validate_session_issue(&expired), None);

        let mut inverted = issue_request();
        inverted.refresh_expires_at = inverted.access_expires_at;
        assert_eq!(validate_session_issue(&inverted), None);

        let mut unlimited = issue_request();
        unlimited.max_devices = 0;
        assert_eq!(validate_session_issue(&unlimited), Some(0));

        let mut negative = issue_request();
        negative.max_devices = -1;
        assert_eq!(validate_session_issue(&negative), None);
    }
}
