//! Mode E account session endpoints (`/v1/account/*`, FR-SRV-017).
//!
//! The account profile lives in D1 (Argon2id password hash only); every session decision goes
//! through the per-account `AccountDO` so throttling, issuance limits, rotation, and revocation
//! are strongly consistent. Bearer tokens are 32 bytes: 16 routing bytes derived from the
//! account id plus 16 secret bytes. Only SHA-256 token hashes ever reach storage.

use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use copylocker_proto::{
    AccountLoginRequest, AccountLogoutRequest, AccountRefreshRequest, AccountSession,
    ACCOUNT_TOKEN_LEN,
};
use copylocker_suite::cbor::{CborValue, MapBuilder};
use copylocker_suite::HashScheme;
use copylocker_suite_std::Sha256Scheme;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use worker::wasm_bindgen::JsValue;
use worker::{Date, Env, Error, Headers, Method, Request, RequestInit, Response, Result};
use zeroize::Zeroize;

use crate::bindings::rng::WorkerRng;
use crate::middleware::body::{self, BodyError};
use crate::response;

pub(crate) const ACCOUNT_ID_PREFIX: &str = "acct_";
const ACCOUNT_ROUTING_LEN: usize = 16;
/// Access tokens live one hour; refresh tokens thirty days. Neither extends the machine
/// credential's refresh/grace deadlines, which are owned by the license policy.
const ACCESS_TOKEN_TTL_SECS: i64 = 3_600;
const REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 60 * 60;
const INVALID_CREDENTIAL: u64 = 1000;
const SEAT_EXHAUSTED: u64 = 1001;
const NEEDS_LOGIN: u64 = 1003;
const RATE_LIMITED: u64 = 1005;
const SERVER_ERROR: u64 = 5000;

/// OWASP-aligned Argon2id parameters for account passwords. Verification parameters always
/// come from the stored PHC string; these apply to newly created hashes.
const ARGON2_M_COST_KIB: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;

pub(crate) fn argon2id() -> Result<Argon2<'static>> {
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|_| Error::RustError("account password parameters are invalid".to_owned()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derive the public account identifier from its 16-byte routing key.
#[must_use]
pub(crate) fn account_id_from_routing(routing: &[u8; ACCOUNT_ROUTING_LEN]) -> String {
    format!("{ACCOUNT_ID_PREFIX}{}", crate::admin::hex_encode(routing))
}

/// Extract the routing key embedded in an account id.
pub(crate) fn routing_from_account_id(account_id: &str) -> Option<[u8; ACCOUNT_ROUTING_LEN]> {
    let hex = account_id.strip_prefix(ACCOUNT_ID_PREFIX)?;
    let bytes = crate::admin::decode_hex_id(hex, ACCOUNT_ROUTING_LEN)?;
    bytes.try_into().ok()
}

/// Split a bearer token into its routing key and secret half.
fn token_routing(token: &[u8]) -> Option<[u8; ACCOUNT_ROUTING_LEN]> {
    if token.len() != ACCOUNT_TOKEN_LEN {
        return None;
    }
    token.get(..ACCOUNT_ROUTING_LEN)?.try_into().ok()
}

fn token_hash(token: &[u8]) -> Vec<u8> {
    Sha256Scheme::hash(token).as_bytes().to_vec()
}

pub(crate) async fn login(mut request: Request, env: &Env) -> Result<Response> {
    let bytes = match body::read_cbor(&mut request).await {
        Ok(bytes) => bytes,
        Err(error) => return body_error(error),
    };
    let credentials = match AccountLoginRequest::decode(&bytes) {
        Ok(credentials) => credentials,
        Err(_) => return response::protocol_error(400, INVALID_CREDENTIAL, None, None),
    };
    let email = credentials.email.trim().to_lowercase();
    let now = now_seconds();
    let database = env.d1("DB")?;
    let account = database
        .prepare(
            "SELECT id, pwd_hash, status, max_devices FROM accounts \
             WHERE product_id = ? AND email = ?",
        )
        .bind(&[
            JsValue::from_str(&credentials.product_id),
            JsValue::from_str(&email),
        ])?
        .first::<AccountRow>(None)
        .await?;
    let ip_hash = request
        .headers()
        .get("CF-Connecting-IP")?
        .map(|ip| Sha256Scheme::hash(ip.as_bytes()).as_bytes().to_vec());

    // Throttle unknown accounts too, keyed by a hash of the attempted identity, so the gate
    // never reveals whether the account exists.
    let object_name = account.as_ref().map_or_else(
        || {
            let digest = Sha256Scheme::hash_parts(&[
                b"copylocker/unknown-account/v1",
                credentials.product_id.as_bytes(),
                email.as_bytes(),
            ]);
            format!("unknown:{}", crate::admin::hex_encode(digest.as_bytes()))
        },
        |row| row.id.clone(),
    );

    match call_account::<LoginGateRequest, LoginGateResponse>(
        env,
        &object_name,
        "/login-gate",
        &LoginGateRequest { now },
    )
    .await?
    {
        AccountCall::Success(gate) if gate.allowed => {}
        AccountCall::Success(gate) => {
            let retry_after = gate
                .retry_after
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(60);
            return response::protocol_error(429, RATE_LIMITED, None, Some(retry_after));
        }
        AccountCall::Rejected { .. } => {
            return response::protocol_error(503, SERVER_ERROR, None, Some(1));
        }
    }

    let password_ok = match account
        .as_ref()
        .filter(|row| row.status == "active")
        .and_then(|row| row.pwd_hash.as_deref())
    {
        Some(phc) => verify_password(phc, &credentials.password),
        // Unknown or passwordless account: run the same KDF against a dummy hash so the
        // response time does not reveal which path failed.
        None => {
            let phc = dummy_password_hash()?;
            let _ = verify_password(&phc, &credentials.password);
            false
        }
    };
    let mut credentials = credentials;
    credentials.password.zeroize();
    if let Err(error) = record_login_attempt(env, &object_name, password_ok, ip_hash, now).await {
        worker::console_error!(
            "{}",
            serde_json::json!({
                "level": "error",
                "message": "login attempt could not be recorded",
                "error": error.to_string()
            })
        );
    }
    if !password_ok {
        return response::protocol_error(401, NEEDS_LOGIN, None, None);
    }
    let Some(account) = account else {
        return response::protocol_error(401, NEEDS_LOGIN, None, None);
    };
    let Some(routing) = routing_from_account_id(&account.id) else {
        return Err(Error::RustError(
            "account row has an invalid routing key".to_owned(),
        ));
    };
    let max_devices = account.max_devices.unwrap_or(0);
    if !(0..=1000).contains(&max_devices) {
        return Err(Error::RustError(
            "account device limit is invalid".to_owned(),
        ));
    }

    let mut rng = WorkerRng::new()?;
    let session =
        match issue_session(env, &account.id, &routing, max_devices, now, &mut rng).await? {
            Ok(session) => session,
            Err(SessionIssueError::DeviceLimit) => {
                return response::protocol_error(409, SEAT_EXHAUSTED, None, None);
            }
            Err(SessionIssueError::Server(error)) => return Err(error),
        };
    response::cbor(200, session.encode(), "no-store")
}

pub(crate) async fn refresh(mut request: Request, env: &Env) -> Result<Response> {
    let bytes = match body::read_cbor(&mut request).await {
        Ok(bytes) => bytes,
        Err(error) => return body_error(error),
    };
    let refresh_request = match AccountRefreshRequest::decode(&bytes) {
        Ok(request) => request,
        Err(_) => return response::protocol_error(400, INVALID_CREDENTIAL, None, None),
    };
    let Some(routing) = token_routing(&refresh_request.refresh_token) else {
        return response::protocol_error(401, NEEDS_LOGIN, None, None);
    };
    let account_id = account_id_from_routing(&routing);
    let now = now_seconds();
    let database = env.d1("DB")?;
    let account = database
        .prepare("SELECT status FROM accounts WHERE id = ?")
        .bind(&[JsValue::from_str(&account_id)])?
        .first::<AccountStatusRow>(None)
        .await?;
    if account.as_ref().is_none_or(|row| row.status != "active") {
        return response::protocol_error(401, NEEDS_LOGIN, None, None);
    }

    let mut rng = WorkerRng::new()?;
    let access_token = new_token(&routing, &mut rng)?;
    let refresh_token = new_token(&routing, &mut rng)?;
    let call = SessionRefreshCall {
        refresh_hash: token_hash(&refresh_request.refresh_token),
        access_hash: token_hash(&access_token),
        new_refresh_hash: token_hash(&refresh_token),
        access_expires_at: now.saturating_add(ACCESS_TOKEN_TTL_SECS),
        refresh_expires_at: now.saturating_add(REFRESH_TOKEN_TTL_SECS),
        now,
    };
    match call_account::<_, OkDoResponse>(env, &account_id, "/session/refresh", &call).await? {
        AccountCall::Success(_) => {}
        AccountCall::Rejected { status: 401, .. } => {
            return response::protocol_error(401, NEEDS_LOGIN, None, None);
        }
        AccountCall::Rejected { .. } => {
            return response::protocol_error(503, SERVER_ERROR, None, Some(1));
        }
    }
    let session = AccountSession {
        account_token: access_token,
        refresh_token,
        expires_at: now.saturating_add(ACCESS_TOKEN_TTL_SECS),
        refresh_expires_at: now.saturating_add(REFRESH_TOKEN_TTL_SECS),
    };
    response::cbor(200, session.encode(), "no-store")
}

pub(crate) async fn logout(mut request: Request, env: &Env) -> Result<Response> {
    let bytes = match body::read_cbor(&mut request).await {
        Ok(bytes) => bytes,
        Err(error) => return body_error(error),
    };
    let logout_request = match AccountLogoutRequest::decode(&bytes) {
        Ok(request) => request,
        Err(_) => return response::protocol_error(400, INVALID_CREDENTIAL, None, None),
    };
    let Some(routing) = token_routing(&logout_request.refresh_token) else {
        return response::protocol_error(401, NEEDS_LOGIN, None, None);
    };
    let account_id = account_id_from_routing(&routing);
    let call = SessionTokenCall {
        token_hash: token_hash(&logout_request.refresh_token),
        now: now_seconds(),
    };
    if let AccountCall::Rejected { .. } =
        call_account::<_, OkDoResponse>(env, &account_id, "/session/revoke", &call).await?
    {
        return response::protocol_error(503, SERVER_ERROR, None, Some(1));
    }
    let mut body = MapBuilder::new();
    body.put(0, CborValue::Bool(true));
    response::cbor(200, body.finish(), "no-store")
}

/// Resolve an activation credential's account token to its account id, or `None` when the
/// session is expired, revoked, or unknown.
pub(crate) async fn resolve_session(env: &Env, token: &[u8]) -> Result<Option<String>> {
    let Some(routing) = token_routing(token) else {
        return Ok(None);
    };
    let account_id = account_id_from_routing(&routing);
    let call = SessionTokenCall {
        token_hash: token_hash(token),
        now: now_seconds(),
    };
    match call_account::<_, ResolveDoResponse>(env, &account_id, "/session/resolve", &call).await? {
        AccountCall::Success(resolution) => Ok(resolution.active.then_some(account_id)),
        AccountCall::Rejected { .. } => Err(Error::RustError(
            "account session resolution failed".to_owned(),
        )),
    }
}

#[derive(Debug)]
pub(crate) enum SessionIssueError {
    DeviceLimit,
    Server(Error),
}

/// Issue a fresh session pair for a successfully authenticated account.
pub(crate) async fn issue_session(
    env: &Env,
    account_id: &str,
    routing: &[u8; ACCOUNT_ROUTING_LEN],
    max_devices: i64,
    now: i64,
    rng: &mut WorkerRng,
) -> Result<std::result::Result<AccountSession, SessionIssueError>> {
    let access_token = new_token(routing, rng)?;
    let refresh_token = new_token(routing, rng)?;
    let call = SessionIssueCall {
        access_hash: token_hash(&access_token),
        refresh_hash: token_hash(&refresh_token),
        access_expires_at: now.saturating_add(ACCESS_TOKEN_TTL_SECS),
        refresh_expires_at: now.saturating_add(REFRESH_TOKEN_TTL_SECS),
        max_devices,
        now,
    };
    match call_account::<_, OkDoResponse>(env, account_id, "/session/issue", &call).await? {
        AccountCall::Success(_) => {}
        AccountCall::Rejected { status: 409, .. } => {
            return Ok(Err(SessionIssueError::DeviceLimit));
        }
        AccountCall::Rejected { status, error } => {
            return Ok(Err(SessionIssueError::Server(Error::RustError(format!(
                "account session issuance failed ({status}): {error}"
            )))));
        }
    }
    Ok(Ok(AccountSession {
        account_token: access_token,
        refresh_token,
        expires_at: now.saturating_add(ACCESS_TOKEN_TTL_SECS),
        refresh_expires_at: now.saturating_add(REFRESH_TOKEN_TTL_SECS),
    }))
}

async fn record_login_attempt(
    env: &Env,
    object_name: &str,
    ok: bool,
    ip_hash: Option<Vec<u8>>,
    now: i64,
) -> Result<()> {
    let call = LoginRecordCall { ok, ip_hash, now };
    match call_account::<_, OkDoResponse>(env, object_name, "/login-record", &call).await? {
        AccountCall::Success(_) => Ok(()),
        AccountCall::Rejected { status, error } => Err(Error::RustError(format!(
            "login attempt recording failed ({status}): {error}"
        ))),
    }
}

fn new_token(routing: &[u8; ACCOUNT_ROUTING_LEN], rng: &mut WorkerRng) -> Result<[u8; 32]> {
    let secret = rng.random_array::<16>()?;
    let mut token = [0_u8; ACCOUNT_TOKEN_LEN];
    let (head, tail) = token.split_at_mut(ACCOUNT_ROUTING_LEN);
    head.copy_from_slice(routing);
    tail.copy_from_slice(&secret);
    Ok(token)
}

fn verify_password(phc: &str, password: &str) -> bool {
    match argon2id() {
        Ok(hasher) => hasher.verify_password(password.as_bytes(), phc).is_ok(),
        Err(_) => false,
    }
}

/// Hash an account password for D1 storage as a PHC string (Admin account creation).
pub(crate) fn hash_account_password(password: &str, salt: &[u8; 16]) -> Result<String> {
    let hash = argon2id()?
        .hash_password_with_salt(password.as_bytes(), salt)
        .map_err(|_| Error::RustError("account password hashing failed".to_owned()))?;
    Ok(hash.to_string())
}

/// A syntactically valid Argon2id hash of a fixed dummy password, used to keep unknown-account
/// logins on the same code path and timing class as real ones.
fn dummy_password_hash() -> Result<String> {
    hash_account_password("copylocker-dummy-password", b"copylocker-dummy")
}

async fn call_account<T, U>(
    env: &Env,
    object_name: &str,
    path: &str,
    payload: &T,
) -> Result<AccountCall<U>>
where
    T: Serialize,
    U: DeserializeOwned,
{
    let namespace = env.durable_object("ACCOUNT")?;
    let stub = namespace.get_by_name(object_name)?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&serde_json::to_string(payload)?)));
    let request = Request::new_with_init(&format!("https://account.internal{path}"), &init)?;
    let mut result = stub.fetch_with_request(request).await?;
    let status = result.status_code();
    if (200..300).contains(&status) {
        return Ok(AccountCall::Success(result.json::<U>().await?));
    }
    let error = result.json::<InternalDoError>().await?.error;
    Ok(AccountCall::Rejected { status, error })
}

fn body_error(error: BodyError) -> Result<Response> {
    match error {
        BodyError::Read(error) => Err(error),
        BodyError::TooLarge => response::protocol_error(413, INVALID_CREDENTIAL, None, None),
        BodyError::UnsupportedEncoding | BodyError::UnsupportedMediaType => {
            response::protocol_error(415, INVALID_CREDENTIAL, None, None)
        }
        BodyError::InvalidContentLength
        | BodyError::MissingBody
        | BodyError::InvalidCompressedBody => {
            response::protocol_error(400, INVALID_CREDENTIAL, None, None)
        }
    }
}

fn now_seconds() -> i64 {
    i64::try_from(Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
}

#[derive(Debug, Deserialize)]
struct AccountRow {
    id: String,
    pwd_hash: Option<String>,
    status: String,
    max_devices: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AccountStatusRow {
    status: String,
}

#[derive(Debug, Serialize)]
struct LoginGateRequest {
    now: i64,
}

#[derive(Debug, Deserialize)]
struct LoginGateResponse {
    allowed: bool,
    retry_after: Option<i64>,
}

#[derive(Debug, Serialize)]
struct LoginRecordCall {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_hash: Option<Vec<u8>>,
    now: i64,
}

#[derive(Debug, Serialize)]
struct SessionIssueCall {
    #[serde(with = "serde_bytes")]
    access_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    refresh_hash: Vec<u8>,
    access_expires_at: i64,
    refresh_expires_at: i64,
    max_devices: i64,
    now: i64,
}

#[derive(Debug, Serialize)]
struct SessionTokenCall {
    #[serde(with = "serde_bytes")]
    token_hash: Vec<u8>,
    now: i64,
}

#[derive(Debug, Serialize)]
struct SessionRefreshCall {
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

#[derive(Debug, Deserialize)]
struct OkDoResponse {
    #[allow(dead_code)]
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct ResolveDoResponse {
    active: bool,
}

#[derive(Debug, Deserialize)]
struct InternalDoError {
    error: String,
}

#[derive(Debug)]
enum AccountCall<T> {
    Success(T),
    Rejected { status: u16, error: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_ids_round_trip_their_routing_key() {
        let routing = [0xab; ACCOUNT_ROUTING_LEN];
        let id = account_id_from_routing(&routing);
        assert!(id.starts_with(ACCOUNT_ID_PREFIX));
        assert_eq!(routing_from_account_id(&id), Some(routing));
        assert_eq!(routing_from_account_id("acct_short"), None);
        assert_eq!(
            routing_from_account_id("other_00000000000000000000000000000000"),
            None
        );
    }

    #[test]
    fn argon2id_hashes_verify_and_reject_wrong_passwords() {
        // Worker tests stay no-panic: a hashing failure fails the assertions below instead of
        // unwrapping.
        let hash =
            hash_account_password("correct horse battery", b"clovertestsalt16").unwrap_or_default();
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password(&hash, "correct horse battery"));
        assert!(!verify_password(&hash, "correct horse batterz"));
        assert!(!verify_password("not-a-phc-string", "anything"));
    }

    #[test]
    fn dummy_password_hash_is_verifiable_and_never_matches() {
        let phc = dummy_password_hash().unwrap_or_default();
        assert!(phc.starts_with("$argon2id$"));
        assert!(!verify_password(&phc, "copylocker-dummy-password-wrong"));
    }
}
