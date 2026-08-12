//! Mode E account administration (`/v1/admin/accounts`).
//!
//! Accounts are created here with an Argon2id password hash; plaintext passwords never touch
//! storage, the journal, or a response. The profile lives in D1 while sessions and throttling
//! live in the per-account `AccountDO`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroize as _;

use super::*;
use crate::account::{account_id_from_routing, hash_account_password};
use crate::bindings::rng::WorkerRng;

const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = copylocker_proto::MAX_ACCOUNT_PASSWORD_BYTES;
const MAX_ACCOUNT_EMAIL_BYTES: usize = copylocker_proto::MAX_ACCOUNT_EMAIL_BYTES;

pub(super) async fn route(request: &mut Request, env: &Env, segments: &[&str]) -> Result<Response> {
    match segments {
        ["accounts"] => collection(request, env).await,
        _ => not_found("account route not found"),
    }
}

async fn collection(request: &mut Request, env: &Env) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Post) {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "accounts:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    if request.method() == Method::Get {
        return list(request, env, &principal).await;
    }
    let body = match read_json::<CreateAccountBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    create(request, env, &principal, body).await
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
        .prepare(
            "SELECT id, email, status, max_devices, created_at FROM accounts \
             WHERE product_id = ? ORDER BY created_at DESC, id LIMIT 1001",
        )
        .bind(&[text(&product_id)])?
        .all()
        .await?
        .results::<AccountDbRow>()?;
    if rows.len() > MAX_LIST_ITEMS {
        return response::api_error_no_store(
            413,
            "result_too_large",
            "account list exceeds 1000 items",
        );
    }
    let items = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id,
                "email": row.email,
                "status": row.status,
                "max_devices": row.max_devices,
                "created_at": row.created_at,
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

async fn create(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    mut body: CreateAccountBody,
) -> Result<Response> {
    body.email = body.email.trim().to_lowercase();
    let password_valid = body.password.chars().count() >= MIN_PASSWORD_CHARS
        && body.password.len() <= MAX_PASSWORD_BYTES
        && !body.password.as_bytes().contains(&0);
    if !valid_identifier(&body.product_id)
        || !is_account_email(&body.email)
        || !password_valid
        || body
            .max_devices
            .is_some_and(|value| !(1..=1000).contains(&value))
    {
        body.password.zeroize();
        return invalid_request("account create request contains invalid data");
    }
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => {
            body.password.zeroize();
            return Ok(rejection);
        }
    };
    let action = "account:create";
    let target = format!("{}/accounts/{}", body.product_id, body.email);

    // The idempotency identity of an account creation is its (product, email) pair plus the
    // non-secret options; the password never enters the request hash, so a network retry with
    // the same key replays the stored result while no password-derived material is journaled.
    let request_value = json!({
        "product_id": body.product_id,
        "email": body.email,
        "max_devices": body.max_devices,
    });
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    let database = env.d1("DB")?;
    if let Some(response) = replay_operation(
        env,
        &database,
        principal,
        &request_id,
        &request_hash,
        "accounts:rw",
    )
    .await?
    {
        body.password.zeroize();
        return Ok(response);
    }
    let mut rng = WorkerRng::new()?;
    let salt = rng.random_array::<16>()?;
    let pwd_hash = match hash_account_password(&body.password, &salt) {
        Ok(hash) => hash,
        Err(error) => {
            body.password.zeroize();
            return Err(error);
        }
    };
    body.password.zeroize();
    if !product_owned(&database, &body.product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let exists = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT id FROM accounts WHERE product_id = ? AND email = ?")
        .bind(&[text(&body.product_id), text(&body.email)])?
        .first::<AccountIdRow>(None)
        .await?
        .is_some();
    if exists {
        return conflict(
            "already_exists",
            "an account with this email already exists",
        );
    }

    let routing = rng.random_array::<16>()?;
    let account_id = account_id_from_routing(&routing);
    let now = now_seconds();
    let account = json!({
        "id": account_id,
        "product_id": body.product_id,
        "email": body.email,
        "status": "active",
        "max_devices": body.max_devices,
        "created_at": now,
    });
    let result = json!({
        "ok": true,
        "account": account,
    });
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "accounts:rw".to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "account".to_owned(),
        source_id: account_id.clone(),
        request_hash: request_hash.clone(),
        before: Value::Null,
        after: redacted_value(&account),
        result,
        response_status: 201,
        side_effect: None,
        created_at: now,
    };
    let statements = vec![
        admin_operations::insert_statement(&database, &operation)?,
        database
            .prepare(
                "INSERT INTO accounts(\
                   id, product_id, email, pwd_hash, oauth_subject, status, max_devices, created_at\
                 ) VALUES (?, ?, ?, ?, NULL, 'active', ?, ?)",
            )
            .bind(&[
                text(&account_id),
                text(&body.product_id),
                text(&body.email),
                text(&pwd_hash),
                optional_integer(body.max_devices.map(i64::from))?,
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
            "accounts:rw",
        )
        .await?
        {
            return Ok(response);
        }
        return Err(error);
    }
    finish_new_operation(env, &database, principal, &request_id).await
}

fn is_account_email(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= MAX_ACCOUNT_EMAIL_BYTES
        && value.bytes().any(|byte| byte == b'@')
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
}

fn redacted_value(account: &Value) -> Value {
    json!({
        "kind": "account",
        "account": account,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateAccountBody {
    product_id: String,
    email: String,
    password: String,
    #[serde(default)]
    max_devices: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct AccountDbRow {
    id: String,
    email: String,
    status: String,
    max_devices: Option<i64>,
    created_at: i64,
}

#[derive(Debug, Deserialize)]
struct AccountIdRow {
    #[allow(dead_code)]
    id: String,
}
