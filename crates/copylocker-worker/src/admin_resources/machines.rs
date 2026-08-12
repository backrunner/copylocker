//! Cross-license machine administration:
//!
//! - `GET /v1/admin/machines` — cross-license machine listing for one product, with
//!   keyset pagination over `(first_seen_at, id)` (hard limit cap) and license/status
//!   filters. Reads require the `machines:r` scope; a `machines:rw` token satisfies it
//!   because bootstrap tokens predate the read/write scope split.
//! - `DELETE /v1/admin/machines/:id` — the GDPR machine deletion (prd.md §209): a thin
//!   journaled alias over the `dsr:delete` cascade (`dsr.rs`), authorized by
//!   `machines:rw`, dry-run by default, idempotent via `Idempotency-Key`.

use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::{Env, Method, Request, Response, Result};

use super::*;
use crate::admin::{decode_hex_id, hex_encode};

/// Read scopes accepted by the list endpoint: `machines:r`, or its `machines:rw`
/// counterpart (read is implied by read-write).
const MACHINES_READ_SCOPES: &[&str] = &["machines:r", "machines:rw"];
const MACHINES_WRITE_SCOPE: &str = "machines:rw";
const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 100;

pub(super) async fn route(request: &mut Request, env: &Env, segments: &[&str]) -> Result<Response> {
    match segments {
        ["machines"] => list(request, env).await,
        ["machines", machine_id] if !machine_id.is_empty() => {
            gdpr_delete(request, env, machine_id).await
        }
        _ => not_found("machine route not found"),
    }
}

// ---------------------------------------------------------------------------
// GET /v1/admin/machines
// ---------------------------------------------------------------------------

async fn list(request: &Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Get {
        return method_not_allowed();
    }
    let principal = match authorize_any(request, env, MACHINES_READ_SCOPES).await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let query = match MachineListQuery::parse(request)? {
        Ok(query) => query,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &query.product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let (cursor_seen, cursor_id) = query.cursor.as_ref().map_or((None, None), |(seen, id)| {
        (Some(*seen), Some(id.as_slice()))
    });
    let rows = database
        .prepare(
            "SELECT m.id, m.license_id, m.status, m.activation_path, m.first_seen_at, \
                    m.last_seen_at, m.os, m.arch, m.app_version, m.sdk_version, m.release_id, \
                    m.variant_id, m.build_fp, m.geo_country, m.suspicion \
             FROM machines m \
             JOIN licenses l ON l.id = m.license_id \
             JOIN products product ON product.id = l.product_id \
             WHERE l.product_id = ? AND product.vendor_id = ? \
               AND (? IS NULL OR m.license_id = ?) \
               AND (? IS NULL OR m.status = ?) \
               AND (? IS NULL OR m.first_seen_at > ? OR (m.first_seen_at = ? AND m.id > ?)) \
             ORDER BY m.first_seen_at, m.id LIMIT ?",
        )
        .bind(&[
            text(&query.product_id),
            text(&principal.vendor_id),
            query.license_id.as_deref().map_or(JsValue::NULL, blob),
            query.license_id.as_deref().map_or(JsValue::NULL, blob),
            optional_text(query.status.as_deref()),
            optional_text(query.status.as_deref()),
            optional_integer(cursor_seen)?,
            optional_integer(cursor_seen)?,
            optional_integer(cursor_seen)?,
            cursor_id.map_or(JsValue::NULL, blob),
            integer(i64::from(query.limit).saturating_add(1))?,
        ])?
        .all()
        .await?
        .results::<MachineDbRow>()?;
    let mut items = rows
        .into_iter()
        .map(MachineListItem::try_from)
        .collect::<Result<Vec<_>>>()?;
    let next_cursor = if items.len() > usize::try_from(query.limit).unwrap_or(usize::MAX) {
        items.truncate(usize::try_from(query.limit).unwrap_or(usize::MAX));
        items
            .last()
            .map(|item| json!(format!("{}:{}", item.first_seen_at, item.machine_id)))
    } else {
        None
    };
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "product_id": query.product_id,
            "items": items,
            "next_cursor": next_cursor.unwrap_or(serde_json::Value::Null),
        }),
    )
}

struct MachineListQuery {
    product_id: String,
    license_id: Option<Vec<u8>>,
    status: Option<String>,
    limit: u32,
    cursor: Option<(i64, Vec<u8>)>,
}

impl MachineListQuery {
    fn parse(request: &Request) -> Result<std::result::Result<Self, Response>> {
        let invalid = || {
            response::api_error_no_store(
                400,
                "invalid_query",
                "machine list requires exactly one valid product_id and accepts optional \
                 license_id, status, limit (1-100), and cursor parameters",
            )
        };
        let mut product_id = None;
        let mut license_id = None;
        let mut status = None;
        let mut limit = None;
        let mut cursor = None;
        for (name, value) in request.url()?.query_pairs() {
            match name.as_ref() {
                "product_id" if product_id.is_none() && valid_identifier(&value) => {
                    product_id = Some(value.into_owned());
                }
                "license_id" if license_id.is_none() => {
                    let Some(id) = decode_hex_id(&value, 16) else {
                        return Ok(Err(invalid()?));
                    };
                    license_id = Some(id);
                }
                "status"
                    if status.is_none()
                        && matches!(
                            value.as_ref(),
                            "active" | "pending" | "released" | "revoked"
                        ) =>
                {
                    status = Some(value.into_owned());
                }
                "limit" if limit.is_none() => {
                    let Ok(parsed) = value.parse::<u32>() else {
                        return Ok(Err(invalid()?));
                    };
                    if !(1..=MAX_LIST_LIMIT).contains(&parsed) {
                        return Ok(Err(invalid()?));
                    }
                    limit = Some(parsed);
                }
                "cursor" if cursor.is_none() => {
                    let Some(parsed) = parse_cursor(&value) else {
                        return Ok(Err(invalid()?));
                    };
                    cursor = Some(parsed);
                }
                _ => return Ok(Err(invalid()?)),
            }
        }
        Ok(match product_id {
            Some(product_id) => Ok(Self {
                product_id,
                license_id,
                status,
                limit: limit.unwrap_or(DEFAULT_LIST_LIMIT),
                cursor,
            }),
            None => Err(invalid()?),
        })
    }
}

/// The opaque page cursor is the last row's keyset: `{first_seen_at}:{machine_id_hex}`.
fn parse_cursor(value: &str) -> Option<(i64, Vec<u8>)> {
    let (seen, id) = value.split_once(':')?;
    let first_seen_at = seen.parse::<i64>().ok().filter(|parsed| *parsed >= 0)?;
    let id = decode_hex_id(id, 16)?;
    Some((first_seen_at, id))
}

// ---------------------------------------------------------------------------
// DELETE /v1/admin/machines/:id (GDPR, prd.md §209)
// ---------------------------------------------------------------------------

async fn gdpr_delete(request: &Request, env: &Env, encoded_id: &str) -> Result<Response> {
    if request.method() != Method::Delete {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, MACHINES_WRITE_SCOPE).await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let Some(id_bytes) = decode_hex_id(encoded_id, 16) else {
        return invalid_request("machine id must be 16-byte hexadecimal");
    };
    let dry_run = match dsr::dry_run_query(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT l.product_id AS product_id FROM machines m \
             JOIN licenses l ON l.id = m.license_id \
             JOIN products product ON product.id = l.product_id \
             WHERE m.id = ? AND product.vendor_id = ? AND product.archived_at IS NULL",
        )
        .bind(&[blob(&id_bytes), text(&principal.vendor_id)])?
        .first::<ProductIdRow>(None)
        .await?;
    let Some(row) = row else {
        // A confirmed delete replays from the journal after the machine row is gone:
        // the replay leg reconstructs the product from the journaled target.
        if !dry_run {
            if let Some(response) =
                dsr::replay_machine_delete(request, env, &principal, encoded_id).await?
            {
                return Ok(response);
            }
        }
        return not_found("machine not found");
    };
    if !valid_identifier(&row.product_id) {
        return Err(worker::Error::RustError(
            "machine row contains invalid data".to_owned(),
        ));
    }
    dsr::delete_machine(
        request,
        env,
        &principal,
        row.product_id,
        hex_encode(&id_bytes),
        id_bytes,
        dry_run,
    )
    .await
}

// ---------------------------------------------------------------------------
// row + item types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
struct MachineListItem {
    machine_id: String,
    license_id: String,
    status: String,
    activation_path: String,
    first_seen_at: i64,
    last_seen_at: Option<i64>,
    os: Option<String>,
    arch: Option<String>,
    app_version: Option<String>,
    sdk_version: Option<String>,
    release_id: Option<String>,
    variant_id: Option<i64>,
    build_fingerprint: Option<String>,
    geo_country: Option<String>,
    suspicion: i64,
}

impl TryFrom<MachineDbRow> for MachineListItem {
    type Error = worker::Error;

    fn try_from(row: MachineDbRow) -> std::result::Result<Self, Self::Error> {
        if row.id.len() != 16
            || row.license_id.len() != 16
            || !matches!(
                row.status.as_str(),
                "active" | "pending" | "released" | "revoked"
            )
            || row.first_seen_at < 0
            || row.last_seen_at.is_some_and(|value| value < 0)
        {
            return Err(worker::Error::RustError(
                "machine row contains invalid data".to_owned(),
            ));
        }
        Ok(Self {
            machine_id: hex_encode(&row.id),
            license_id: hex_encode(&row.license_id),
            status: row.status,
            activation_path: row.activation_path,
            first_seen_at: row.first_seen_at,
            last_seen_at: row.last_seen_at,
            os: row.os,
            arch: row.arch,
            app_version: row.app_version,
            sdk_version: row.sdk_version,
            release_id: row.release_id,
            variant_id: row.variant_id,
            build_fingerprint: row.build_fp,
            geo_country: row.geo_country,
            suspicion: row.suspicion,
        })
    }
}

#[derive(Debug, Deserialize)]
struct MachineDbRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    license_id: Vec<u8>,
    status: String,
    activation_path: String,
    first_seen_at: i64,
    last_seen_at: Option<i64>,
    os: Option<String>,
    arch: Option<String>,
    app_version: Option<String>,
    sdk_version: Option<String>,
    release_id: Option<String>,
    variant_id: Option<i64>,
    build_fp: Option<String>,
    geo_country: Option<String>,
    suspicion: i64,
}
