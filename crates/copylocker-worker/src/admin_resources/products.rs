//! Product-level operations configuration (M5-A): the anomaly alert webhook.
//!
//! Vendors point `alert_webhook_url` at their own endpoint; when a license's suspicion score
//! crosses the configured threshold the worker POSTs a signed-event JSON payload there
//! (`10-server-worker.md` §2.5). A NULL URL means "record only" — the crossing is logged but
//! nothing is delivered.

use serde::Deserialize;
use serde_json::{json, Value};
use worker::{D1Database, Env, Method, Request, Response, Result};

use super::*;

const MAX_WEBHOOK_URL: usize = 2048;

pub(super) async fn alert_webhook(
    request: &mut Request,
    env: &Env,
    product_id: &str,
) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Patch) {
        return method_not_allowed();
    }
    if !valid_identifier(product_id) {
        return invalid_request("product id is invalid");
    }
    let principal = match authorize(request, env, "products:rw").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    if request.method() == Method::Get {
        let current = load_alert_config(&database, product_id).await?;
        return alert_config_response(200, product_id, &current);
    }

    let body = match read_json::<AlertWebhookBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    let url = match body.url.as_deref() {
        None => None,
        Some(url) if valid_webhook_url(url) => Some(url.to_owned()),
        Some(_) => {
            return invalid_request(
                "url must be an HTTPS URL without credentials, query, or fragment",
            );
        }
    };
    let threshold = match body.threshold {
        None => None,
        Some(value) if (1..=100).contains(&value) => Some(value),
        Some(_) => return invalid_request("threshold must be between 1 and 100"),
    };
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let action = "product:alert-webhook";
    let target = format!("{product_id}/alert-webhook");
    let request_value = json!({
        "url": url,
        "threshold": threshold,
    });
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    // A retried confirm returns the stored result instead of a no_change conflict.
    if let Some(response) = replay_operation(
        env,
        &database,
        &principal,
        &request_id,
        &request_hash,
        "products:rw",
    )
    .await?
    {
        return Ok(response);
    }
    let current = load_alert_config(&database, product_id).await?;
    let next = AlertConfig {
        url: url.clone(),
        threshold,
    };
    if current == next {
        return conflict("no_change", "alert webhook configuration is unchanged");
    }

    let now = now_seconds();
    let result = json!({
        "ok": true,
        "product_id": product_id,
        "alert_webhook_url": url,
        "alert_suspicion_threshold": threshold,
    });
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "products:rw".to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "product".to_owned(),
        source_id: product_id.to_owned(),
        request_hash: request_hash.clone(),
        before: alert_config_value(&current),
        after: alert_config_value(&next),
        result,
        response_status: 200,
        side_effect: None,
        created_at: now,
    };
    let statements = vec![
        admin_operations::insert_statement(&database, &operation)?,
        database
            .prepare(
                "UPDATE products SET alert_webhook_url = ?, alert_suspicion_threshold = ? \
                 WHERE id = ?",
            )
            .bind(&[
                optional_text(url.as_deref()),
                optional_integer(threshold)?,
                text(product_id),
            ])?,
    ];
    if let Err(error) = database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &database,
            &principal,
            &request_id,
            &request_hash,
            "products:rw",
        )
        .await?
        {
            return Ok(response);
        }
        return Err(error);
    }
    finish_new_operation(env, &database, &principal, &request_id).await
}

/// The alert configuration the validate path enforces; `None` threshold means the default 70.
pub(crate) async fn load_alert_config(
    database: &D1Database,
    product_id: &str,
) -> Result<AlertConfig> {
    let row = database
        .with_session_constraint(worker::D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT alert_webhook_url, alert_suspicion_threshold FROM products WHERE id = ?")
        .bind(&[text(product_id)])?
        .first::<AlertConfigRow>(None)
        .await?;
    let Some(row) = row else {
        return Err(worker::Error::RustError(
            "product row is missing".to_owned(),
        ));
    };
    let url = match row.alert_webhook_url {
        Some(url) if valid_webhook_url(&url) => Some(url),
        Some(_) => {
            return Err(worker::Error::RustError(
                "stored alert webhook URL is invalid".to_owned(),
            ));
        }
        None => None,
    };
    let threshold = row
        .alert_suspicion_threshold
        .map(|value| {
            if (1..=100).contains(&value) {
                Ok(value)
            } else {
                Err(worker::Error::RustError(
                    "stored alert suspicion threshold is invalid".to_owned(),
                ))
            }
        })
        .transpose()?;
    Ok(AlertConfig { url, threshold })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AlertConfig {
    pub(crate) url: Option<String>,
    pub(crate) threshold: Option<i64>,
}

fn alert_config_value(config: &AlertConfig) -> Value {
    json!({
        "url": config.url,
        "threshold": config.threshold,
    })
}

fn alert_config_response(status: u16, product_id: &str, config: &AlertConfig) -> Result<Response> {
    response::json_no_store(
        status,
        &json!({
            "ok": true,
            "product_id": product_id,
            "alert_webhook_url": config.url,
            "alert_suspicion_threshold": config.threshold,
        }),
    )
}

fn valid_webhook_url(value: &str) -> bool {
    if value.len() > MAX_WEBHOOK_URL {
        return false;
    }
    let Ok(url) = worker::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some_and(|host| !host.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertWebhookBody {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    threshold: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AlertConfigRow {
    alert_webhook_url: Option<String>,
    alert_suspicion_threshold: Option<i64>,
}
