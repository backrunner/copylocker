//! Data-subject-rights (DSR) endpoints and telemetry retention purge
//! (`data-model.md §14`, `90-analytics-telemetry.md §11`), under the `dsr:rw` scope:
//!
//! - `POST /v1/admin/dsr/export` — everything held about one machine or license.
//! - `POST /v1/admin/dsr/delete` — the §14 GDPR delete cascade, dry-run by default.
//! - `POST /v1/admin/telemetry/purge` — T1 raw detail retention enforcement, dry-run by
//!   default.
//!
//! Documented deviations from `data-model.md §14`:
//!
//! - **Audit PII is not tombstoned.** Both audit chains (`audit_index` + R2 archives and
//!   `admin_audit_events`) hash their contents into the chain links, so replacing a
//!   subject with a tombstone breaks verification, and the schema has no side channel for
//!   redactable PII. The delete cascade therefore leaves audit entries intact (they expire
//!   with audit retention) and says so in its response (`audit_tombstone: false`).
//! - **`dsr/export` is not journaled.** The Admin operation journal requires a before/after
//!   state transition (`admin_operations::NewOperation::validate` rejects
//!   `before == after`), which a read-only access cannot express honestly.
//! - **Aggregate tables are never touched**: `analytics_rollup`, `analytics_hll`, and
//!   (for `dsr delete`) `telemetry_rollup` hold no personal data and are not retroactively
//!   modified (`90-analytics-telemetry.md §11`).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use worker::{D1Database, Env, Headers, Method, Request, RequestInit, Response, Result};

use super::*;
use crate::admin::{decode_hex_id, hex_encode};
use crate::analytics::{machine_key, RAW_PREFIX};
use crate::events::{utc_day_string, AnalyticsDetailEvent};

const DSR_SCOPE: &str = "dsr:rw";
/// The GDPR machine-delete alias shares the `dsr:delete` cascade but is authorized by the
/// machine administration scope (`machines.rs`).
const MACHINE_DELETE_SCOPE: &str = "machines:rw";
/// Bound on machines resolved per DSR request; also keeps the journal's before/after
/// snapshots below the 64 KiB Admin snapshot cap.
const MAX_DSR_MACHINES: usize = 500;
/// Bound on date prefixes listed per raw scan.
const MAX_SCAN_DATES: usize = 400;
/// Bound on raw records read per scan.
const MAX_SCAN_RECORDS: usize = 50_000;
/// Bound on raw records one operation deletes.
const MAX_MATCHED_KEYS: usize = 20_000;
/// Bound on one raw detail record, matching the rollup pipeline.
const MAX_DETAIL_BYTES: u64 = 16 * 1024;
/// Bound on audit references returned by `dsr/export`.
const MAX_AUDIT_REFERENCES: usize = 100;
/// T1 raw retention (`90-analytics-telemetry.md §11`): the default purge cutoff.
const TELEMETRY_RAW_RETENTION_DAYS: i64 = 30;
const DAY_SECONDS: i64 = 86_400;

/// Explained in the module docs: audit chains cannot be tombstoned without a schema change.
const AUDIT_TOMBSTONE_NOTE: &str = "audit chain entries are content-hashed and cannot be \
     tombstoned without a schema change; references to this subject remain in the audit \
     chain until audit retention expires (data-model.md §14 deviation)";

pub(super) async fn route(request: &mut Request, env: &Env, segments: &[&str]) -> Result<Response> {
    match segments {
        ["dsr", "export"] => export(request, env).await,
        ["dsr", "delete"] => delete(request, env).await,
        _ => not_found("dsr route not found"),
    }
}

// ---------------------------------------------------------------------------
// shared selector + raw scan
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DsrBody {
    product_id: String,
    #[serde(default)]
    machine_id: Option<String>,
    #[serde(default)]
    license_id: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubjectKind {
    Machine,
    License,
}

struct Resolved {
    product_id: String,
    kind: SubjectKind,
    /// The selected machine or license id bytes.
    id_bytes: Vec<u8>,
    machines: Vec<DsrMachine>,
}

impl Resolved {
    fn subject_json(&self) -> Value {
        match self.kind {
            SubjectKind::Machine => json!({"machine_id": hex_encode(&self.id_bytes)}),
            SubjectKind::License => json!({"license_id": hex_encode(&self.id_bytes)}),
        }
    }
}

fn dsr_target(product_id: &str, kind: SubjectKind, id: &[u8]) -> String {
    let kind = match kind {
        SubjectKind::Machine => "machine",
        SubjectKind::License => "license",
    };
    format!("{product_id}/dsr/{kind}/{}", hex_encode(id))
}

/// Validate the selector shape (product id plus exactly one hex id) without touching D1,
/// so a confirmed delete can attempt its idempotency replay before resolving anything.
fn validate_selector(
    body: &DsrBody,
) -> Result<std::result::Result<(SubjectKind, Vec<u8>), Response>> {
    if !valid_identifier(&body.product_id) {
        return Ok(Err(invalid_request("product id is invalid")?));
    }
    let machine = body
        .machine_id
        .as_deref()
        .map(|value| decode_hex_id(value, 16));
    let license = body
        .license_id
        .as_deref()
        .map(|value| decode_hex_id(value, 16));
    Ok(match (machine, license) {
        (Some(Some(id)), None) => Ok((SubjectKind::Machine, id)),
        (None, Some(Some(id))) => Ok((SubjectKind::License, id)),
        _ => Err(invalid_request(
            "exactly one of machine_id or license_id (16-byte hexadecimal) is required",
        )?),
    })
}

struct DsrMachine {
    machine_id: Vec<u8>,
    license_id: Vec<u8>,
    status: String,
    first_seen_at: i64,
    last_seen_at: Option<i64>,
}

impl DsrMachine {
    fn journal_json(&self) -> Value {
        json!({
            "id": hex_encode(&self.machine_id),
            "license_id": hex_encode(&self.license_id),
            "status": self.status,
        })
    }
}

async fn resolve_subject(
    database: &D1Database,
    principal: &AdminPrincipal,
    body: &DsrBody,
    kind: SubjectKind,
    id_bytes: &[u8],
) -> Result<std::result::Result<Resolved, Response>> {
    if !product_owned(database, &body.product_id, &principal.vendor_id).await? {
        return Ok(Err(not_found("product not found")?));
    }
    let machines = match kind {
        SubjectKind::Machine => {
            let row = database
                .with_session_constraint(D1SessionConstraint::FirstPrimary)?
                .prepare(
                    "SELECT m.id, m.license_id, m.status, m.first_seen_at, m.last_seen_at \
                     FROM machines m JOIN licenses l ON l.id = m.license_id \
                     WHERE m.id = ? AND l.product_id = ?",
                )
                .bind(&[blob(id_bytes), text(&body.product_id)])?
                .first::<MachineDbRow>(None)
                .await?;
            let Some(row) = row else {
                return Ok(Err(not_found("machine not found")?));
            };
            vec![DsrMachine::try_from(row)?]
        }
        SubjectKind::License => {
            let owns = database
                .with_session_constraint(D1SessionConstraint::FirstPrimary)?
                .prepare("SELECT id FROM licenses WHERE id = ? AND product_id = ?")
                .bind(&[blob(id_bytes), text(&body.product_id)])?
                .first::<LicenseIdRow>(None)
                .await?;
            if owns.is_none() {
                return Ok(Err(not_found("license not found")?));
            }
            let rows = database
                .prepare(
                    "SELECT id, license_id, status, first_seen_at, last_seen_at \
                     FROM machines WHERE license_id = ? ORDER BY first_seen_at LIMIT ?",
                )
                .bind(&[
                    blob(id_bytes),
                    integer(
                        i64::try_from(MAX_DSR_MACHINES)
                            .unwrap_or(i64::MAX)
                            .saturating_add(1),
                    )?,
                ])?
                .all()
                .await?
                .results::<MachineDbRow>()?;
            if rows.len() > MAX_DSR_MACHINES {
                return Ok(Err(response::api_error_no_store(
                    413,
                    "result_too_large",
                    "license has more than 500 machines; narrow the request",
                )?));
            }
            rows.into_iter()
                .map(DsrMachine::try_from)
                .collect::<Result<Vec<_>>>()?
        }
    };
    Ok(Ok(Resolved {
        product_id: body.product_id.clone(),
        kind,
        id_bytes: id_bytes.to_vec(),
        machines,
    }))
}

impl TryFrom<MachineDbRow> for DsrMachine {
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
            machine_id: row.id,
            license_id: row.license_id,
            status: row.status,
            first_seen_at: row.first_seen_at,
            last_seen_at: row.last_seen_at,
        })
    }
}

/// Why a bounded raw scan stopped.
enum ScanFailure {
    /// A scan cap was exceeded; the request path maps this to 413.
    TooLarge(&'static str),
}

/// List, read, and filter R2 raw detail records for a product, returning the keys of
/// records matching `matches`. All listing, reading, and collecting is bounded; the date
/// range is inclusive and lexicographic (`YYYY-MM-DD` sorts).
async fn scan_raw_keys(
    env: &Env,
    product: &str,
    min_date: Option<&str>,
    max_date: Option<&str>,
    matches: &dyn Fn(&AnalyticsDetailEvent) -> bool,
) -> std::result::Result<std::result::Result<Vec<String>, ScanFailure>, worker::Error> {
    let bucket = match env.bucket("ARCHIVE") {
        Ok(bucket) => bucket,
        Err(error) => return Err(error),
    };
    let prefix = format!("{RAW_PREFIX}{product}/");
    let mut dates = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut listing = bucket.list().prefix(&prefix).delimiter("/");
        if let Some(cursor) = cursor.take() {
            listing = listing.cursor(cursor);
        }
        let page = listing.execute().await?;
        for date_prefix in page.delimited_prefixes() {
            let Some(date) = date_prefix
                .strip_prefix(prefix.as_str())
                .and_then(|rest| rest.strip_suffix('/'))
            else {
                continue;
            };
            let in_range =
                min_date.is_none_or(|min| date >= min) && max_date.is_none_or(|max| date <= max);
            if in_range {
                dates.push(date.to_owned());
            }
        }
        if dates.len() > MAX_SCAN_DATES {
            return Ok(Err(ScanFailure::TooLarge(
                "raw detail spans too many days; narrow the window",
            )));
        }
        if !page.truncated() {
            break;
        }
        let Some(next) = page.cursor() else {
            break;
        };
        cursor = Some(next);
    }
    dates.sort();
    dates.dedup();

    let mut keys = Vec::new();
    let mut scanned = 0_usize;
    for date in dates {
        let day_prefix = format!("{prefix}{date}/");
        let mut day_cursor: Option<String> = None;
        loop {
            let mut listing = bucket.list().prefix(&day_prefix);
            if let Some(cursor) = day_cursor.take() {
                listing = listing.cursor(cursor);
            }
            let page = listing.execute().await?;
            for object in page.objects() {
                scanned = scanned.saturating_add(1);
                if scanned > MAX_SCAN_RECORDS {
                    return Ok(Err(ScanFailure::TooLarge(
                        "raw detail scan exceeded its record cap; narrow the window",
                    )));
                }
                if object.size() > MAX_DETAIL_BYTES {
                    continue;
                }
                let key = object.key();
                let Some(object) = bucket.get(&key).execute().await? else {
                    continue; // Deleted between listing and read.
                };
                let Some(body) = object.body() else {
                    continue;
                };
                let bytes = body.bytes().await?;
                if bytes.len() as u64 > MAX_DETAIL_BYTES {
                    continue;
                }
                let Ok(record) = serde_json::from_slice::<AnalyticsDetailEvent>(&bytes) else {
                    continue;
                };
                if !record.is_valid() || record.product_id != product {
                    continue;
                }
                if matches(&record) {
                    keys.push(key);
                    if keys.len() > MAX_MATCHED_KEYS {
                        return Ok(Err(ScanFailure::TooLarge(
                            "raw detail delete matched too many records; narrow the request",
                        )));
                    }
                }
            }
            if !page.truncated() {
                break;
            }
            let Some(next) = page.cursor() else {
                break;
            };
            day_cursor = Some(next);
        }
    }
    keys.sort();
    Ok(Ok(keys))
}

async fn delete_raw_keys(env: &Env, keys: &[String]) -> Result<usize> {
    let bucket = env.bucket("ARCHIVE")?;
    let mut deleted = 0_usize;
    for key in keys {
        bucket.delete(key).await?;
        deleted = deleted.saturating_add(1);
    }
    Ok(deleted)
}

fn scan_rejection(failure: ScanFailure) -> Result<Response> {
    match failure {
        ScanFailure::TooLarge(message) => {
            response::api_error_no_store(413, "result_too_large", message)
        }
    }
}

/// Parse the destructive-action query contract: an optional `dry_run` (default true),
/// mirroring the license/epoch revocation discipline.
pub(super) fn dry_run_query(request: &Request) -> Result<std::result::Result<bool, Response>> {
    let mut dry_run = None;
    for (name, value) in request.url()?.query_pairs() {
        if name != "dry_run" || dry_run.is_some() {
            return Ok(Err(response::api_error_no_store(
                400,
                "invalid_query",
                "only an optional dry_run query parameter is allowed",
            )?));
        }
        dry_run = Some(match value.as_ref() {
            "true" => true,
            "false" => false,
            _ => {
                return Ok(Err(response::api_error_no_store(
                    400,
                    "invalid_query",
                    "dry_run must be true or false",
                )?));
            }
        });
    }
    Ok(Ok(dry_run.unwrap_or(true)))
}

// ---------------------------------------------------------------------------
// dsr/export
// ---------------------------------------------------------------------------

async fn export(request: &mut Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, DSR_SCOPE).await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let body = match read_json::<DsrBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    let (kind, id_bytes) = match validate_selector(&body)? {
        Ok(selector) => selector,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    let resolved = match resolve_subject(&database, &principal, &body, kind, &id_bytes).await? {
        Ok(resolved) => resolved,
        Err(rejection) => return Ok(rejection),
    };

    let mut machines = Vec::with_capacity(resolved.machines.len());
    for machine in &resolved.machines {
        machines.push(load_machine_view(&database, &machine.machine_id).await?);
    }
    let mut licenses = Vec::new();
    let mut seen_licenses = BTreeSet::new();
    for machine in &resolved.machines {
        if seen_licenses.insert(machine.license_id.clone()) {
            licenses.push(load_license_view(&database, &machine.license_id).await?);
        }
    }
    if resolved.machines.is_empty() && resolved.kind == SubjectKind::License {
        licenses.push(load_license_view(&database, &resolved.id_bytes).await?);
    }
    let (audit_references, audit_truncated) = load_audit_references(&database, &resolved).await?;

    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "product_id": resolved.product_id,
            "subject": resolved.subject_json(),
            "generated_at": now_seconds(),
            "machines": machines,
            "licenses": licenses,
            "audit_references": audit_references,
            "audit_truncated": audit_truncated,
        }),
    )
}

async fn load_machine_view(database: &D1Database, machine_id: &[u8]) -> Result<Value> {
    let row = database
        .prepare(
            "SELECT id, license_id, fingerprint, status, activation_path, first_seen_at, \
                    last_seen_at, os, arch, app_version, sdk_version, release_id, variant_id, \
                    build_fp, geo_country, suspicion \
             FROM machines WHERE id = ?",
        )
        .bind(&[blob(machine_id)])?
        .first::<MachineViewRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("machine row disappeared".to_owned()))?;
    if row.id.len() != 16 || row.license_id.len() != 16 || row.fingerprint.len() != 32 {
        return Err(worker::Error::RustError(
            "machine row contains invalid identifiers".to_owned(),
        ));
    }
    Ok(json!({
        "id": hex_encode(&row.id),
        "license_id": hex_encode(&row.license_id),
        "fingerprint": hex_encode(&row.fingerprint),
        "status": row.status,
        "activation_path": row.activation_path,
        "first_seen_at": row.first_seen_at,
        "last_seen_at": row.last_seen_at,
        "os": row.os,
        "arch": row.arch,
        "app_version": row.app_version,
        "sdk_version": row.sdk_version,
        "release_id": row.release_id,
        "variant_id": row.variant_id,
        "build_fp": row.build_fp,
        "geo_country": row.geo_country,
        "suspicion": row.suspicion,
    }))
}

async fn load_license_view(database: &D1Database, license_id: &[u8]) -> Result<Value> {
    let row = database
        .prepare(
            "SELECT id, product_id, policy_id, account_id, status, seats_override, \
                    expires_at, catalog_version, metadata_json, created_at, updated_at, \
                    seats_used, last_seen_at \
             FROM licenses WHERE id = ?",
        )
        .bind(&[blob(license_id)])?
        .first::<LicenseViewRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("license row disappeared".to_owned()))?;
    if row.id.len() != 16
        || !valid_identifier(&row.product_id)
        || !valid_identifier(&row.policy_id)
        || row
            .metadata_json
            .as_ref()
            .is_some_and(|value| value.len() > MAX_DIMS_JSON)
    {
        return Err(worker::Error::RustError(
            "license row contains invalid data".to_owned(),
        ));
    }
    let metadata = row
        .metadata_json
        .as_deref()
        .map(serde_json::from_str::<Value>)
        .transpose()?;
    Ok(json!({
        "id": hex_encode(&row.id),
        "product_id": row.product_id,
        "policy_id": row.policy_id,
        "account_id": row.account_id,
        "status": row.status,
        "seats_override": row.seats_override,
        "expires_at": row.expires_at,
        "catalog_version": row.catalog_version,
        "metadata": metadata,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "seats_used": row.seats_used,
        "last_seen_at": row.last_seen_at,
    }))
}

/// Audit references to the subject: bounded to [`MAX_AUDIT_REFERENCES`] rows over at most
/// as many lookup targets (the D1 bind-variable budget). `audit_truncated` tells the
/// caller more references may exist.
async fn load_audit_references(
    database: &D1Database,
    resolved: &Resolved,
) -> Result<(Vec<Value>, bool)> {
    let mut targets = Vec::with_capacity(resolved.machines.len().saturating_add(1));
    if resolved.kind == SubjectKind::License {
        targets.push(hex_encode(&resolved.id_bytes));
    }
    for machine in &resolved.machines {
        targets.push(hex_encode(&machine.machine_id));
    }
    targets.sort();
    targets.dedup();
    let targets_truncated = targets.len() > MAX_AUDIT_REFERENCES;
    targets.truncate(MAX_AUDIT_REFERENCES);
    if targets.is_empty() {
        return Ok((Vec::new(), false));
    }
    let placeholders = targets.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let mut bindings = targets.iter().map(|value| text(value)).collect::<Vec<_>>();
    bindings.push(integer(
        i64::try_from(MAX_AUDIT_REFERENCES)
            .unwrap_or(i64::MAX)
            .saturating_add(1),
    )?);
    let rows = database
        .prepare(format!(
            "SELECT seq, ts, actor, action, target, r2_key FROM audit_index \
             WHERE target IN ({placeholders}) ORDER BY ts, seq LIMIT ?"
        ))
        .bind(&bindings)?
        .all()
        .await?
        .results::<AuditReferenceRow>()?;
    let truncated = targets_truncated || rows.len() > MAX_AUDIT_REFERENCES;
    let references = rows
        .into_iter()
        .take(MAX_AUDIT_REFERENCES)
        .map(|row| {
            json!({
                "seq": row.seq,
                "ts": row.ts,
                "actor": row.actor,
                "action": row.action,
                "target": row.target,
                "r2_key": row.r2_key,
            })
        })
        .collect();
    Ok((references, truncated))
}

// ---------------------------------------------------------------------------
// dsr/delete
// ---------------------------------------------------------------------------

async fn delete(request: &mut Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, DSR_SCOPE).await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let dry_run = match dry_run_query(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let body = match read_json::<DsrBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    let (kind, id_bytes) = match validate_selector(&body)? {
        Ok(selector) => selector,
        Err(rejection) => return Ok(rejection),
    };
    delete_impl(
        request, env, &principal, body, kind, id_bytes, dry_run, DSR_SCOPE,
    )
    .await
}

/// The GDPR machine-delete alias behind `DELETE /v1/admin/machines/:id` (prd.md §209):
/// the caller resolves the product from the machine row, then this runs the identical
/// journaled `dsr:delete` cascade (DO activation erasure + D1 projection delete + bounded
/// R2 raw-detail deletion). Only the required scope differs (`machines:rw`), so the audit
/// journal records which surface authorized the erasure.
pub(super) async fn delete_machine(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    product_id: String,
    machine_id: String,
    id_bytes: Vec<u8>,
    dry_run: bool,
) -> Result<Response> {
    let body = DsrBody {
        product_id,
        machine_id: Some(machine_id),
        license_id: None,
    };
    delete_impl(
        request,
        env,
        principal,
        body,
        SubjectKind::Machine,
        id_bytes,
        dry_run,
        MACHINE_DELETE_SCOPE,
    )
    .await
}

/// Replay leg of the GDPR alias: after a confirmed delete the machine row is gone, so the
/// product can no longer be resolved from D1. The original request body is reconstructed
/// from the journaled target (`{product}/dsr/machine/{hex}`) and the journal's request
/// hash validates it, so an Idempotency-Key reused for a different request still
/// conflicts with a 409. Returns `None` when this key has no machine-delete journal row.
pub(super) async fn replay_machine_delete(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    machine_id: &str,
) -> Result<Option<Response>> {
    let Some(request_id) = idempotency_key(request)? else {
        return Ok(None);
    };
    let database = env.d1("DB")?;
    let Some(operation) =
        admin_operations::load(&database, &principal.vendor_id, &request_id).await?
    else {
        return Ok(None);
    };
    let conflict = || {
        response::api_error_no_store(
            409,
            "idempotency_conflict",
            "Idempotency-Key was already used for another request",
        )
        .map(Some)
    };
    if operation.action != "dsr:delete" || operation.required_scope != MACHINE_DELETE_SCOPE {
        return conflict();
    }
    let suffix = format!("/dsr/machine/{machine_id}");
    let Some(product_id) = operation.target.strip_suffix(&suffix) else {
        return conflict();
    };
    if !valid_identifier(product_id) {
        return conflict();
    }
    let body = DsrBody {
        product_id: product_id.to_owned(),
        machine_id: Some(machine_id.to_owned()),
        license_id: None,
    };
    let request_value = serde_json::to_value(&body)?;
    let request_hash =
        admin_operations::request_hash("dsr:delete", &operation.target, &request_value)?;
    replay_operation(
        env,
        &database,
        principal,
        &request_id,
        &request_hash,
        MACHINE_DELETE_SCOPE,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn delete_impl(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
    body: DsrBody,
    kind: SubjectKind,
    id_bytes: Vec<u8>,
    dry_run: bool,
    scope: &'static str,
) -> Result<Response> {
    let database = env.d1("DB")?;
    // A confirmed delete replays from the journal before resolving the subject: a replay
    // finds the machine rows already deleted and must answer from the journal, not 404.
    if !dry_run {
        let request_id = match require_idempotency_key(request)? {
            Ok(value) => value,
            Err(rejection) => return Ok(rejection),
        };
        let target = dsr_target(&body.product_id, kind, &id_bytes);
        let request_value = serde_json::to_value(&body)?;
        let request_hash = admin_operations::request_hash("dsr:delete", &target, &request_value)?;
        if let Some(response) =
            replay_operation(env, &database, principal, &request_id, &request_hash, scope).await?
        {
            return Ok(response);
        }
        return delete_confirmed(
            env,
            &database,
            principal,
            &body,
            kind,
            &id_bytes,
            request_id,
            request_hash,
            target,
            scope,
        )
        .await;
    }
    let resolved = match resolve_subject(&database, principal, &body, kind, &id_bytes).await? {
        Ok(resolved) => resolved,
        Err(rejection) => return Ok(rejection),
    };

    let (min_date, max_date) = scan_window(&resolved);
    let mut machine_keys = BTreeSet::new();
    for machine in &resolved.machines {
        machine_keys.insert(machine_key(env, &machine.machine_id).await?);
    }
    let raw_keys = if resolved.machines.is_empty() {
        Vec::new()
    } else {
        match scan_raw_keys(
            env,
            &resolved.product_id,
            min_date.as_deref(),
            max_date.as_deref(),
            &|record| machine_keys.contains(&record.machine_key),
        )
        .await?
        {
            Ok(keys) => keys,
            Err(failure) => return scan_rejection(failure),
        }
    };

    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "dry_run": true,
            "product_id": resolved.product_id,
            "subject": resolved.subject_json(),
            "machines": resolved.machines.iter().map(DsrMachine::journal_json).collect::<Vec<_>>(),
            "raw_records": raw_keys.len(),
            "audit_tombstone": false,
        }),
    )
}

/// The raw-detail scan window follows the machines' observed lifetime.
fn scan_window(resolved: &Resolved) -> (Option<String>, Option<String>) {
    let mut min_seen: Option<i64> = None;
    let mut max_seen: Option<i64> = None;
    for machine in &resolved.machines {
        min_seen = Some(min_seen.map_or(machine.first_seen_at, |v| v.min(machine.first_seen_at)));
        let last = machine.last_seen_at.unwrap_or(machine.first_seen_at);
        max_seen = Some(max_seen.map_or(last, |v| v.max(last)));
    }
    match (min_seen, max_seen) {
        (Some(min), Some(max)) => (
            utc_day_string(min.saturating_sub(DAY_SECONDS)),
            utc_day_string(max.saturating_add(DAY_SECONDS)),
        ),
        _ => (None, None),
    }
}

#[allow(clippy::too_many_arguments)]
async fn delete_confirmed(
    env: &Env,
    database: &D1Database,
    principal: &AdminPrincipal,
    body: &DsrBody,
    kind: SubjectKind,
    id_bytes: &[u8],
    request_id: String,
    request_hash: Vec<u8>,
    target: String,
    scope: &'static str,
) -> Result<Response> {
    let resolved = match resolve_subject(database, principal, body, kind, id_bytes).await? {
        Ok(resolved) => resolved,
        Err(rejection) => return Ok(rejection),
    };

    let (min_date, max_date) = scan_window(&resolved);
    let mut machine_keys = BTreeSet::new();
    for machine in &resolved.machines {
        machine_keys.insert(machine_key(env, &machine.machine_id).await?);
    }
    let raw_keys = if resolved.machines.is_empty() {
        Vec::new()
    } else {
        match scan_raw_keys(
            env,
            &resolved.product_id,
            min_date.as_deref(),
            max_date.as_deref(),
            &|record| machine_keys.contains(&record.machine_key),
        )
        .await?
        {
            Ok(keys) => keys,
            Err(failure) => return scan_rejection(failure),
        }
    };

    let subject = resolved.subject_json();
    let before = json!({
        "machines": resolved.machines.iter().map(DsrMachine::journal_json).collect::<Vec<_>>(),
        "raw_records": raw_keys.len(),
    });
    let after = json!({"machines": [], "raw_records": 0});
    let side_effect = json!({
        "kind": "dsr_forget",
        "product_id": resolved.product_id,
        "from_date": min_date,
        "to_date": max_date,
        "machines": resolved.machines.iter().map(|machine| json!({
            "license_id": hex_encode(&machine.license_id),
            "machine_id": hex_encode(&machine.machine_id),
        })).collect::<Vec<_>>(),
    });
    let result = json!({
        "ok": true,
        "dry_run": false,
        "product_id": resolved.product_id,
        "subject": subject,
        "deleted_machines": resolved.machines.len(),
        "deleted_raw_records": raw_keys.len(),
        "audit_tombstone": false,
        "audit_note": AUDIT_TOMBSTONE_NOTE,
    });
    let now = now_seconds();
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: scope.to_owned(),
        action: "dsr:delete".to_owned(),
        target,
        source_kind: "dsr".to_owned(),
        source_id: request_id.clone(),
        request_hash: request_hash.clone(),
        before,
        after,
        result,
        response_status: 200,
        side_effect: Some(side_effect),
        created_at: now,
    };
    let mut statements = vec![admin_operations::insert_statement(database, &operation)?];
    for machine in &resolved.machines {
        statements.push(
            database
                .prepare("DELETE FROM machines WHERE id = ?")
                .bind(&[blob(&machine.machine_id)])?,
        );
    }
    // One batch: the journal insert and the machine deletes commit or fail together.
    if let Err(error) = database.batch(statements).await {
        if let Some(response) =
            replay_operation(env, database, principal, &request_id, &request_hash, scope).await?
        {
            return Ok(response);
        }
        return Err(error);
    }
    finish_new_operation(env, database, principal, &request_id).await
}

// ---------------------------------------------------------------------------
// telemetry purge
// ---------------------------------------------------------------------------

pub(super) async fn telemetry_purge(request: &mut Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, DSR_SCOPE).await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let dry_run = match dry_run_query(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let body = match read_json::<PurgeBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    if !valid_identifier(&body.product_id) {
        return invalid_request("product id is invalid");
    }
    let explicit_before = match body.before.as_deref() {
        Some(value) => match analytics_api::parse_date(value) {
            Some(days) => Some(days),
            None => return invalid_request("before must be a YYYY-MM-DD date"),
        },
        None => None,
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &body.product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let now_days = now_seconds().div_euclid(DAY_SECONDS);
    let cutoff_days =
        explicit_before.unwrap_or_else(|| now_days.saturating_sub(TELEMETRY_RAW_RETENTION_DAYS));
    let cutoff = analytics_api::date_string(cutoff_days);
    let max_date = analytics_api::date_string(cutoff_days.saturating_sub(1));

    // Raw leg: T1-carrying records older than the cutoff (`90-analytics-telemetry.md §11`).
    let raw_keys = match scan_raw_keys(env, &body.product_id, None, Some(&max_date), &|record| {
        record.telemetry.is_some()
    })
    .await?
    {
        Ok(keys) => keys,
        Err(failure) => return scan_rejection(failure),
    };
    // Rollup leg: only on an explicit `before` — rollups are otherwise kept for the full
    // retention period (design §11).
    let rollup_rows = if explicit_before.is_some() {
        let row = database
            .prepare(
                "SELECT COUNT(*) AS value FROM telemetry_rollup WHERE product_id = ? AND date < ?",
            )
            .bind(&[text(&body.product_id), text(&cutoff)])?
            .first::<IntegerRow>(None)
            .await?
            .ok_or_else(|| {
                worker::Error::RustError("telemetry purge count returned no row".to_owned())
            })?;
        u64::try_from(row.value)
            .map_err(|_| worker::Error::RustError("telemetry purge count is invalid".to_owned()))?
    } else {
        0
    };

    if dry_run {
        return response::json_no_store(
            200,
            &json!({
                "ok": true,
                "dry_run": true,
                "product_id": body.product_id,
                "cutoff": cutoff,
                "raw_records": raw_keys.len(),
                "rollup_rows": rollup_rows,
            }),
        );
    }
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let action = "telemetry:purge";
    let target = format!("{}/telemetry/{cutoff}", body.product_id);
    let request_value = serde_json::to_value(&body)?;
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    // Replay before the no-op check: once a confirmed purge has completed, a retry finds
    // nothing left to delete and must answer with the stored result, not a fresh
    // `journaled: false` zero-count response.
    if let Some(response) = replay_operation(
        env,
        &database,
        &principal,
        &request_id,
        &request_hash,
        DSR_SCOPE,
    )
    .await?
    {
        return Ok(response);
    }
    if raw_keys.is_empty() && rollup_rows == 0 {
        // A no-op purge deletes nothing, so there is no state transition to journal; a
        // first-time empty result is simply recomputed by the next request.
        return response::json_no_store(
            200,
            &json!({
                "ok": true,
                "dry_run": false,
                "product_id": body.product_id,
                "cutoff": cutoff,
                "deleted_raw_records": 0,
                "deleted_rollup_rows": 0,
                "journaled": false,
            }),
        );
    }

    let now = now_seconds();
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: DSR_SCOPE.to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "dsr".to_owned(),
        source_id: request_id.clone(),
        request_hash: request_hash.clone(),
        before: json!({"cutoff": cutoff, "raw_records": raw_keys.len(), "rollup_rows": rollup_rows}),
        after: json!({"cutoff": cutoff, "raw_records": 0, "rollup_rows": 0}),
        result: json!({
            "ok": true,
            "dry_run": false,
            "product_id": body.product_id,
            "cutoff": cutoff,
            "deleted_raw_records": raw_keys.len(),
            "deleted_rollup_rows": rollup_rows,
            "journaled": true,
        }),
        response_status: 200,
        side_effect: Some(json!({
            "kind": "telemetry_purge",
            "product_id": body.product_id,
            "to_date": max_date,
        })),
        created_at: now,
    };
    let mut statements = vec![admin_operations::insert_statement(&database, &operation)?];
    if explicit_before.is_some() {
        statements.push(
            database
                .prepare("DELETE FROM telemetry_rollup WHERE product_id = ? AND date < ?")
                .bind(&[text(&body.product_id), text(&cutoff)])?,
        );
    }
    if let Err(error) = database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &database,
            &principal,
            &request_id,
            &request_hash,
            DSR_SCOPE,
        )
        .await?
        {
            return Ok(response);
        }
        return Err(error);
    }
    finish_new_operation(env, &database, &principal, &request_id).await
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PurgeBody {
    product_id: String,
    #[serde(default)]
    before: Option<String>,
}

// ---------------------------------------------------------------------------
// journaled side effects
// ---------------------------------------------------------------------------

/// The side-effect leg of DSR deletes and telemetry purges: DO activation erasure plus
/// R2 raw detail deletion. Every step is idempotent, so the recovery sweep
/// (`reconcile_pending_side_effect`) can replay it safely.
pub(super) async fn apply_side_effect(
    env: &Env,
    operation: &admin_operations::StoredOperation,
) -> Result<()> {
    let side_effect = operation
        .side_effect
        .clone()
        .ok_or_else(|| worker::Error::RustError("dsr side effect is missing".to_owned()))?;
    let effect = serde_json::from_value::<SideEffect>(side_effect)
        .map_err(|_| worker::Error::RustError("dsr side effect is corrupt".to_owned()))?;
    match effect {
        SideEffect::DsrForget {
            product_id,
            from_date,
            to_date,
            machines,
        } => {
            let mut machine_keys = BTreeSet::new();
            for machine in &machines {
                let license_id = decode_hex_id(&machine.license_id, 16).ok_or_else(|| {
                    worker::Error::RustError("dsr side effect license id is corrupt".to_owned())
                })?;
                let machine_id = decode_hex_id(&machine.machine_id, 16).ok_or_else(|| {
                    worker::Error::RustError("dsr side effect machine id is corrupt".to_owned())
                })?;
                forget_activation(env, &operation.operation_id, &license_id, &machine_id).await?;
                machine_keys.insert(machine_key(env, &machine_id).await?);
            }
            let keys = scan_raw_keys(
                env,
                &product_id,
                from_date.as_deref(),
                to_date.as_deref(),
                &|record| machine_keys.contains(&record.machine_key),
            )
            .await?
            .map_err(|failure| match failure {
                ScanFailure::TooLarge(message) => worker::Error::RustError(message.to_owned()),
            })?;
            delete_raw_keys(env, &keys).await?;
            Ok(())
        }
        SideEffect::TelemetryPurge {
            product_id,
            to_date,
        } => {
            let keys = scan_raw_keys(env, &product_id, None, Some(&to_date), &|record| {
                record.telemetry.is_some()
            })
            .await?
            .map_err(|failure| match failure {
                ScanFailure::TooLarge(message) => worker::Error::RustError(message.to_owned()),
            })?;
            delete_raw_keys(env, &keys).await?;
            Ok(())
        }
    }
}

/// Erase the DO activation (`data-model.md §14` cascade first leg). The per-machine
/// operation id keeps the DO idempotency cache distinct for every machine of a license.
async fn forget_activation(
    env: &Env,
    operation_id: &str,
    license_id: &[u8],
    machine_id: &[u8],
) -> Result<()> {
    let namespace = env.durable_object("LICENSE")?;
    let stub = namespace.get_by_name(&hex_encode(license_id))?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let payload = json!({
        "license_id": license_id,
        "machine_id": machine_id,
        "operation_id": format!("{operation_id}/{}", hex_encode(machine_id)),
    });
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&serde_json::to_string(&payload)?)));
    let request = Request::new_with_init("https://license.internal/admin-forget", &init)?;
    let mut response = stub.fetch_with_request(request).await?;
    if response.status_code() == 200
        && response
            .json::<ForgetDoResponse>()
            .await
            .is_ok_and(|value| value.ok)
    {
        Ok(())
    } else {
        Err(worker::Error::RustError(
            "LicenseDO rejected an admin-forget request".to_owned(),
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SideEffect {
    DsrForget {
        product_id: String,
        #[serde(default)]
        from_date: Option<String>,
        #[serde(default)]
        to_date: Option<String>,
        machines: Vec<SideEffectMachine>,
    },
    TelemetryPurge {
        product_id: String,
        to_date: String,
    },
}

#[derive(Debug, Deserialize)]
struct SideEffectMachine {
    license_id: String,
    machine_id: String,
}

#[derive(Debug, Deserialize)]
struct ForgetDoResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct MachineDbRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    license_id: Vec<u8>,
    status: String,
    first_seen_at: i64,
    last_seen_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct LicenseIdRow {
    #[serde(with = "serde_bytes", rename = "id")]
    _id: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct MachineViewRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    license_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    fingerprint: Vec<u8>,
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

#[derive(Debug, Deserialize)]
struct LicenseViewRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    product_id: String,
    policy_id: String,
    account_id: Option<String>,
    status: String,
    seats_override: Option<i64>,
    expires_at: Option<i64>,
    catalog_version: i64,
    metadata_json: Option<String>,
    created_at: i64,
    updated_at: i64,
    seats_used: i64,
    last_seen_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AuditReferenceRow {
    seq: i64,
    ts: i64,
    actor: String,
    action: String,
    target: Option<String>,
    r2_key: String,
}

#[derive(Debug, Deserialize)]
struct IntegerRow {
    value: i64,
}

const MAX_DIMS_JSON: usize = 4 * 1024;
