//! Admin audit chain endpoints (`data-model.md §13`, ADR-0014), under the `audit:r` scope:
//!
//! - `GET /v1/admin/audit` — vendor-scoped, newest-first page over `admin_audit_events`
//!   (the D1 projection of the Admin audit chain), with optional `target`/`kind` filters
//!   and keyset pagination on `seq`.
//! - `POST /v1/admin/audit/verify` — read-only full-chain verification: every stored
//!   event is re-parsed and its hash recomputed from the canonical event payload and the
//!   `prev_hash` link (via `AdminAuditEvent::is_valid`), then checked against the stored
//!   columns. The response reports the chain head, event count, sequence bounds, and the
//!   first broken link if any. It performs no writes, so it is not journaled.

use serde::Deserialize;
use serde_json::{json, Value};
use worker::{Env, Method, Request, Response, Result};

use super::*;
use crate::admin::hex_encode;
use crate::events::AdminAuditEvent;

const AUDIT_SCOPE: &str = "audit:r";
const DEFAULT_LIST_LIMIT: u32 = 50;
const MAX_LIST_LIMIT: u32 = 100;
/// Bound on chain events verified in one request; beyond it the operator must archive
/// (ADR-0014) before verifying again.
const MAX_VERIFY_EVENTS: usize = 10_000;
const MAX_TARGET_FILTER_LEN: usize = 256;

pub(super) async fn route(request: &mut Request, env: &Env, segments: &[&str]) -> Result<Response> {
    match segments {
        ["audit"] => list(request, env).await,
        ["audit", "verify"] => verify(request, env).await,
        _ => not_found("audit route not found"),
    }
}

// ---------------------------------------------------------------------------
// GET /v1/admin/audit
// ---------------------------------------------------------------------------

async fn list(request: &Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Get {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, AUDIT_SCOPE).await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let query = match AuditListQuery::parse(request)? {
        Ok(query) => query,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    let rows = database
        .prepare(
            "SELECT seq, source_kind, event_json, r2_key FROM admin_audit_events \
             WHERE json_extract(event_json, '$.vendor_id') = ? \
               AND (? IS NULL OR json_extract(event_json, '$.target') = ?) \
               AND (? IS NULL OR source_kind = ?) \
               AND (? IS NULL OR seq < ?) \
             ORDER BY seq DESC LIMIT ?",
        )
        .bind(&[
            text(&principal.vendor_id),
            optional_text(query.target.as_deref()),
            optional_text(query.target.as_deref()),
            optional_text(query.kind.as_deref()),
            optional_text(query.kind.as_deref()),
            optional_integer(query.cursor)?,
            optional_integer(query.cursor)?,
            integer(i64::from(query.limit).saturating_add(1))?,
        ])?
        .all()
        .await?
        .results::<AuditEventDbRow>()?;
    let mut items = rows
        .into_iter()
        .map(audit_item)
        .collect::<Result<Vec<_>>>()?;
    let next_cursor = if items.len() > usize::try_from(query.limit).unwrap_or(usize::MAX) {
        items.truncate(usize::try_from(query.limit).unwrap_or(usize::MAX));
        items
            .last()
            .and_then(|item| item.get("seq").and_then(Value::as_i64))
            .map(|seq| json!(seq.to_string()))
    } else {
        None
    };
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "items": items,
            "next_cursor": next_cursor.unwrap_or(Value::Null),
        }),
    )
}

/// The list projection: summary fields parsed out of the stored canonical event JSON
/// (never the before/after snapshots, which can fill the 64 KiB snapshot cap).
fn audit_item(row: AuditEventDbRow) -> Result<Value> {
    let summary = serde_json::from_str::<AuditSummaryJson>(&row.event_json)
        .map_err(|_| worker::Error::RustError("Admin audit event JSON is corrupt".to_owned()))?;
    if summary.seq != row.seq {
        return Err(worker::Error::RustError(
            "Admin audit event row is corrupt".to_owned(),
        ));
    }
    Ok(json!({
        "seq": row.seq,
        "occurred_at": summary.occurred_at,
        "actor": summary.actor,
        "action": summary.action,
        "target": summary.target,
        "reason": summary.reason,
        "request_id": summary.request_id,
        "source_kind": row.source_kind,
        "r2_key": row.r2_key,
    }))
}

struct AuditListQuery {
    target: Option<String>,
    kind: Option<String>,
    limit: u32,
    cursor: Option<i64>,
}

impl AuditListQuery {
    fn parse(request: &Request) -> Result<std::result::Result<Self, Response>> {
        let invalid = || {
            response::api_error_no_store(
                400,
                "invalid_query",
                "audit list accepts optional target, kind, limit (1-100), and cursor \
                 parameters",
            )
        };
        let mut target = None;
        let mut kind = None;
        let mut limit = None;
        let mut cursor = None;
        for (name, value) in request.url()?.query_pairs() {
            match name.as_ref() {
                "target"
                    if target.is_none()
                        && !value.is_empty()
                        && value.len() <= MAX_TARGET_FILTER_LEN
                        && value.bytes().all(|byte| byte.is_ascii_graphic()) =>
                {
                    target = Some(value.into_owned());
                }
                "kind" if kind.is_none() && valid_identifier(&value) => {
                    kind = Some(value.into_owned());
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
                    let Ok(parsed) = value.parse::<i64>() else {
                        return Ok(Err(invalid()?));
                    };
                    if parsed <= 0 {
                        return Ok(Err(invalid()?));
                    }
                    cursor = Some(parsed);
                }
                _ => return Ok(Err(invalid()?)),
            }
        }
        Ok(Ok(Self {
            target,
            kind,
            limit: limit.unwrap_or(DEFAULT_LIST_LIMIT),
            cursor,
        }))
    }
}

// ---------------------------------------------------------------------------
// POST /v1/admin/audit/verify
// ---------------------------------------------------------------------------

async fn verify(request: &Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    match authorize(request, env, AUDIT_SCOPE).await? {
        Ok(_principal) => {}
        Err(rejection) => return Ok(rejection),
    }
    let database = env.d1("DB")?;
    let rows = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT seq, event_json, prev_hash, hash, r2_key FROM admin_audit_events \
             ORDER BY seq LIMIT ?",
        )
        .bind(&[integer(
            i64::try_from(MAX_VERIFY_EVENTS)
                .unwrap_or(i64::MAX)
                .saturating_add(1),
        )?])?
        .all()
        .await?
        .results::<AuditVerifyRow>()?;
    if rows.len() > MAX_VERIFY_EVENTS {
        return response::api_error_no_store(
            413,
            "result_too_large",
            "audit chain exceeds the verification cap; archive before verifying",
        );
    }

    let mut expected_seq = 1_i64;
    let mut prev_hash = vec![0_u8; copylocker_types::Digest::LEN];
    let mut head: Option<(i64, Vec<u8>)> = None;
    let mut first_broken: Option<Value> = None;
    let mut examined = 0_usize;
    for row in rows {
        examined = examined.saturating_add(1);
        let broken = |reason: &str| json!({"seq": row.seq, "reason": reason});
        let event = match serde_json::from_str::<AdminAuditEvent>(&row.event_json) {
            Ok(event) => event,
            Err(_) => {
                first_broken = Some(broken("event_json_corrupt"));
                break;
            }
        };
        if event.seq != row.seq {
            first_broken = Some(broken("seq_mismatch"));
            break;
        }
        if event.seq != expected_seq {
            first_broken = Some(broken("seq_gap"));
            break;
        }
        if event.prev_hash != row.prev_hash || event.hash != row.hash || event.r2_key != row.r2_key
        {
            first_broken = Some(broken("column_mismatch"));
            break;
        }
        if event.prev_hash != prev_hash {
            first_broken = Some(broken("prev_hash_link"));
            break;
        }
        // Recomputes the event hash from the canonical payload + prev_hash (v1 and v2
        // schemas) and validates the derived r2_key and audit_index sequence mapping.
        if !event.is_valid() {
            first_broken = Some(broken("hash_mismatch"));
            break;
        }
        prev_hash.clone_from(&event.hash);
        head = Some((event.seq, event.hash));
        expected_seq = event.seq.saturating_add(1);
    }

    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "verified": first_broken.is_none(),
            "event_count": examined,
            "first_seq": if examined == 0 { Value::Null } else { json!(1) },
            "last_seq": head.as_ref().map_or(Value::Null, |(seq, _)| json!(seq)),
            "head": head.as_ref().map_or(Value::Null, |(seq, hash)| json!({
                "seq": seq,
                "hash": hex_encode(hash),
            })),
            "first_broken": first_broken.unwrap_or(Value::Null),
        }),
    )
}

// ---------------------------------------------------------------------------
// row types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AuditSummaryJson {
    seq: i64,
    occurred_at: i64,
    actor: String,
    action: String,
    target: String,
    reason: Option<u8>,
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct AuditEventDbRow {
    seq: i64,
    source_kind: String,
    event_json: String,
    r2_key: String,
}

#[derive(Debug, Deserialize)]
struct AuditVerifyRow {
    seq: i64,
    event_json: String,
    #[serde(with = "serde_bytes")]
    prev_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
    r2_key: String,
}
