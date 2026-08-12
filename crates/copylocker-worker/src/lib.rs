//! Cloudflare Workers bindings for the CopyLocker server.

#![forbid(unsafe_code)]

mod account;
mod admin;
mod admin_operations;
mod admin_resources;
mod analytics;
mod audit;
mod bindings;
mod consumer;
mod durable;
mod events;
mod json_cbor;
mod middleware;
mod offline;
mod oidc;
mod projection;
mod response;
mod router;
mod suites;
mod webhook;

pub use durable::{AccountDO, AdminAuditDO, IssuerDO, LicenseDO};

use worker::{
    event, Context, Env, MessageBatch, Request, Response, Result, ScheduleContext, ScheduledEvent,
};

#[event(fetch)]
pub async fn main(request: Request, env: Env, context: Context) -> Result<Response> {
    let path = request.path();
    let admin_endpoint = path == "/v1/admin" || path.starts_with("/v1/admin/");
    let webhook_endpoint = webhook::BillingProvider::parse_path(&path).is_some();
    let client_endpoint = path.starts_with("/v1/") && !admin_endpoint;
    match router::route(request, env, context).await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!(
                "{}",
                serde_json::json!({
                    "level": "error",
                    "message": "request failed",
                    "error": error.to_string()
                })
            );
            if client_endpoint {
                response::protocol_error(500, 5000, None, None)
            } else if admin_endpoint || webhook_endpoint {
                response::api_error_no_store(
                    500,
                    "internal_error",
                    "the service could not complete the request",
                )
            } else {
                response::api_error(
                    500,
                    "internal_error",
                    "the service could not complete the request",
                )
            }
        }
    }
}

#[event(queue)]
pub(crate) async fn consume_events(
    batch: MessageBatch<serde_json::Value>,
    env: Env,
    _context: Context,
) -> Result<()> {
    consumer::consume(batch, &env).await
}

/// Scheduled dispatch: the every-minute dev trigger (and any other expression) runs the
/// reconciliation sweep exactly as before; the daily analytics rollup
/// (`90-analytics-telemetry.md §4.2`) runs only on its own `15 0 * * *` expression.
#[event(scheduled)]
pub async fn scheduled(event: ScheduledEvent, env: Env, _context: ScheduleContext) {
    if event.cron() == analytics::ROLLUP_CRON {
        if let Err(error) = analytics::rollup_previous_day(&env).await {
            worker::console_error!(
                "{}",
                serde_json::json!({
                    "level": "error",
                    "message": "daily analytics rollup failed",
                    "error": error.to_string()
                })
            );
        }
    }
    match admin_resources::reconcile_pending_side_effect(&env).await {
        Ok(true) => worker::console_log!(
            "{}",
            serde_json::json!({
                "level": "info",
                "message": "reconciled pending Admin side effect"
            })
        ),
        Ok(false) => {}
        Err(error) => worker::console_error!(
            "{}",
            serde_json::json!({
                "level": "error",
                "message": "pending Admin side effect reconciliation failed",
                "error": error.to_string()
            })
        ),
    }
    match admin_operations::reconcile_pending(&env).await {
        Ok(true) => worker::console_log!(
            "{}",
            serde_json::json!({
                "level": "info",
                "message": "reconciled pending Admin operation"
            })
        ),
        Ok(false) => {}
        Err(error) => worker::console_error!(
            "{}",
            serde_json::json!({
                "level": "error",
                "message": "pending Admin operation reconciliation failed",
                "error": error.to_string()
            })
        ),
    }
    match admin::reconcile_pending(&env).await {
        Ok(true) => worker::console_log!(
            "{}",
            serde_json::json!({
                "level": "info",
                "message": "reconciled pending revocation"
            })
        ),
        Ok(false) => {}
        Err(error) => worker::console_error!(
            "{}",
            serde_json::json!({
                "level": "error",
                "message": "pending revocation reconciliation failed",
                "error": error.to_string()
            })
        ),
    }
    match webhook::reconcile_due(&env).await {
        Ok(count) if count > 0 => worker::console_log!(
            "{}",
            serde_json::json!({
                "level": "info",
                "message": "reconciled due billing transitions",
                "count": count
            })
        ),
        Ok(_) => {}
        Err(error) => worker::console_error!(
            "{}",
            serde_json::json!({
                "level": "error",
                "message": "billing transition reconciliation failed",
                "error": error.to_string()
            })
        ),
    }
}
