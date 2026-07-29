mod account;
mod admin_audit;
mod issuer;
mod license;

pub use account::AccountDO;
pub(crate) use admin_audit::AdminAuditAppendRequest;
pub use admin_audit::AdminAuditDO;
pub(crate) use admin_audit::{
    append_event as append_admin_audit, verify_event as verify_admin_audit,
};
pub use issuer::IssuerDO;
pub use license::LicenseDO;

use serde::Serialize;
use worker::{Response, Result};

use crate::response;

#[derive(Debug, Serialize)]
struct DurableHealth<'a> {
    ok: bool,
    class: &'a str,
    schema_version: i32,
}

fn ready(class: &str, schema_version: i32) -> Result<Response> {
    response::json(
        200,
        &DurableHealth {
            ok: true,
            class,
            schema_version,
        },
    )
}

fn unavailable(class: &str, error: &str) -> Result<Response> {
    worker::console_error!(
        "{}",
        serde_json::json!({
            "level": "error",
            "message": "durable object schema initialization failed",
            "class": class,
            "error": error
        })
    );
    response::api_error(503, "storage_unavailable", "durable storage is unavailable")
}
