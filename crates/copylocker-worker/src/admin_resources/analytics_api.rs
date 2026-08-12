//! Admin analytics endpoints (`90-analytics-telemetry.md §8`), all under the
//! `analytics:r` scope:
//!
//! - `GET /v1/admin/analytics/definitions` — the full metric catalog.
//! - `GET /v1/admin/analytics/metrics` — windowed series over the D1 rollup tables.
//! - `GET /v1/admin/analytics/export` — the same series as bounded CSV/NDJSON.
//! - `POST|GET /v1/admin/analytics/subscriptions` — periodic report configs.
//!
//! Deviations from the design, documented here:
//!
//! - **Exports are served inline**, not via R2 presigned URLs: Workers R2 cannot presign
//!   without S3 credentials. A hard row cap ([`MAX_EXPORT_ROWS`]) bounds the body; larger
//!   exports must page the `metrics` endpoint instead.
//! - **Subscription delivery is pending**: configs are stored and listed, but nothing is
//!   posted to the webhook yet. Stored records carry `"delivery": "pending"`.
//! - **`source=exact|hll` query override**: the design picks exact-vs-HLL from the machine
//!   count (§4.3). The override exists so operators (and tests) can force the HLL path
//!   before the exact path's raw detail has aged out; `auto` keeps the design behavior.
//! - **k-anonymity suppression applies to unique-count buckets only** (`dev.checked_in`):
//!   count metrics (`act.new`, `use.*`) carry no per-machine distinct counts in the rollup
//!   schema, so there is no cardinality to suppress on.

use std::collections::{BTreeMap, BTreeSet};

use copylocker_server_core::analytics::{
    metric_by_id, metrics as metric_catalog, source_for, suppress_buckets, Bucket as KanonBucket,
    CubeKey, HllSketch, QueryMeta, Source, K_ANONYMITY_MIN,
};
use copylocker_suite::HashScheme;
use copylocker_suite_std::Sha256Scheme;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use worker::{Env, Method, Request, Response, Result};

use super::*;
use crate::admin::hex_encode;
use crate::events::{AnalyticsDetailEvent, ANALYTICS_KIND_CHECK_IN};

/// Metric ids backed by `analytics_rollup` sums.
const ROLLUP_METRICS: &[&str] = &["act.new", "act.by_path"];
/// Metric ids backed by `telemetry_rollup` sums (untrusted T1 self-reports).
const TELEMETRY_METRICS: &[&str] = &[
    "use.session_count",
    "use.days_active",
    "use.session_duration",
    "use.feature_hits",
];
/// The only unique-count metric the rollup pipeline produces today.
const UNIQUE_METRICS: &[&str] = &["dev.checked_in"];

const MAX_QUERY_IDS: usize = 8;
const MAX_WINDOW_DAYS: i64 = 366;
const MAX_HLL_ROWS: usize = 50_000;
const MAX_COUNT_ROWS: usize = 50_000;
/// Bound on raw detail records read by the exact distinct-count path.
const MAX_EXACT_RECORDS: usize = 20_000;
/// Bound on one raw detail record, matching the rollup pipeline.
const MAX_DETAIL_BYTES: u64 = 16 * 1024;
/// Bound on export rows; beyond this the caller must page `metrics`.
const MAX_EXPORT_ROWS: usize = 10_000;
const MAX_DIMS_JSON: usize = 4 * 1024;
const MAX_SUBSCRIPTIONS: usize = 100;
const MAX_SUBSCRIPTION_BYTES: u64 = 16 * 1024;
const DAY_SECONDS: i64 = 86_400;
const DAY_GRANULARITY_LIMIT_SECONDS: i64 = DAY_SECONDS;

/// Domain separation for subscription ids: `sub_<hex>` derives from the vendor and the
/// Idempotency-Key, so a replayed create regenerates the identical record.
const SUBSCRIPTION_ID_DOMAIN: &[u8] = b"copylocker/analytics-subscription/v1";
const SUBSCRIPTION_PREFIX: &str = "analytics/subscriptions/";

pub(super) async fn route(request: &mut Request, env: &Env, segments: &[&str]) -> Result<Response> {
    match segments {
        ["analytics", "definitions"] => definitions(request, env).await,
        ["analytics", "metrics"] => metrics_endpoint(request, env).await,
        ["analytics", "export"] => export(request, env).await,
        ["analytics", "subscriptions"] => subscriptions(request, env).await,
        _ => not_found("analytics route not found"),
    }
}

// ---------------------------------------------------------------------------
// definitions
// ---------------------------------------------------------------------------

async fn definitions(request: &mut Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Get {
        return method_not_allowed();
    }
    match authorize(request, env, "analytics:r").await? {
        Ok(_principal) => {}
        Err(rejection) => return Ok(rejection),
    }
    response::json_no_store(
        200,
        &json!({
            "ok": true,
            "items": metric_catalog(),
        }),
    )
}

// ---------------------------------------------------------------------------
// metrics + export
// ---------------------------------------------------------------------------

async fn metrics_endpoint(request: &mut Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Get {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "analytics:r").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let query = match MetricsQuery::parse(request, false)? {
        Ok(query) => query,
        Err(rejection) => return Ok(rejection),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &query.product, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let report = match compute_report(env, &database, &query).await? {
        Ok(report) => report,
        Err(rejection) => return Ok(rejection),
    };
    response::json_no_store(200, &report.body)
}

async fn export(request: &mut Request, env: &Env) -> Result<Response> {
    if request.method() != Method::Get {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "analytics:r").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    let query = match MetricsQuery::parse(request, true)? {
        Ok(query) => query,
        Err(rejection) => return Ok(rejection),
    };
    let format = match query.format {
        Some(format) => format,
        None => return invalid_request("export requires format=csv or format=ndjson"),
    };
    let database = env.d1("DB")?;
    if !product_owned(&database, &query.product, &principal.vendor_id).await? {
        return not_found("product not found");
    }
    let report = match compute_report(env, &database, &query).await? {
        Ok(report) => report,
        Err(rejection) => return Ok(rejection),
    };
    if report.rows.len() > MAX_EXPORT_ROWS {
        return response::api_error_no_store(
            413,
            "result_too_large",
            "export exceeds the inline row cap; page the metrics endpoint instead",
        );
    }
    let (content_type, filename, body) = match format {
        ExportFormat::Csv => (
            "text/csv; charset=utf-8",
            "copylocker-analytics.csv",
            render_csv(&report.rows),
        ),
        ExportFormat::Ndjson => (
            "application/x-ndjson; charset=utf-8",
            "copylocker-analytics.ndjson",
            render_ndjson(&report.rows)?,
        ),
    };
    let headers = worker::Headers::new();
    headers.set("Content-Type", content_type)?;
    headers.set("Cache-Control", "no-store")?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    headers.set(
        "Content-Disposition",
        &format!("attachment; filename=\"{filename}\""),
    )?;
    Ok(Response::from_bytes(body)?
        .with_status(200)
        .with_headers(headers))
}

struct Report {
    /// The `metrics` JSON body.
    body: Value,
    /// Flattened rows for exports: `(metric_id, bucket, dims_json, value)`.
    rows: Vec<ExportRow>,
}

struct ExportRow {
    metric_id: String,
    bucket: String,
    dims_json: String,
    value: u64,
}

/// Run the shared query semantics behind `metrics` and `export`.
async fn compute_report(
    env: &Env,
    database: &D1Database,
    query: &MetricsQuery,
) -> Result<std::result::Result<Report, Response>> {
    let mut series = Vec::with_capacity(query.ids.len());
    let mut rows = Vec::new();
    let mut unique_source = None;
    let mut suppressed_buckets = 0_u64;
    for id in &query.ids {
        let points = if UNIQUE_METRICS.contains(&id.as_str()) {
            let (source, unique) = unique_series(env, database, query).await?;
            unique_source = Some(source);
            let buckets = unique
                .into_iter()
                .map(|bucket| KanonBucket {
                    key: format!("{}|{}", bucket.point.bucket, bucket.point.dims_key()),
                    distinct_machines: bucket.distinct,
                    value: bucket.point,
                })
                .collect::<Vec<_>>();
            let suppression = suppress_buckets(buckets, K_ANONYMITY_MIN);
            suppressed_buckets = suppressed_buckets.saturating_add(suppression.suppressed_count());
            suppression
                .surviving
                .into_iter()
                .map(|bucket| bucket.value)
                .collect()
        } else {
            count_series(database, query, id).await?
        };
        for point in &points {
            rows.push(ExportRow {
                metric_id: id.clone(),
                bucket: point.bucket.clone(),
                dims_json: point.dims_key(),
                value: point.value,
            });
        }
        series.push(json!({
            "metric_id": id,
            "points": points.iter().map(Point::to_json).collect::<Vec<_>>(),
        }));
    }

    let source = unique_source.unwrap_or(Source::Exact);
    let meta = QueryMeta::new(source, suppressed_buckets);
    let mut meta_json = serde_json::to_value(meta)?;
    if let Some(warning) = resolution_warning(database, &query.product, query.granularity).await? {
        let object = meta_json.as_object_mut().ok_or_else(|| {
            worker::Error::RustError("analytics query meta is not an object".to_owned())
        })?;
        object.insert("warning".to_owned(), Value::String(warning));
    }
    Ok(Ok(Report {
        body: json!({
            "ok": true,
            "product_id": query.product,
            "from": date_string(query.from_days),
            "to": date_string(query.to_days),
            "granularity": query.granularity.as_str(),
            "series": series,
            "meta": meta_json,
        }),
        rows,
    }))
}

/// One series point: the bucket start date, its group-by dimensions, and the value.
#[derive(Clone)]
struct Point {
    bucket: String,
    dims: BTreeMap<String, Value>,
    value: u64,
}

impl Point {
    fn dims_key(&self) -> String {
        serde_json::to_string(&self.dims).unwrap_or_else(|_| "{}".to_owned())
    }

    fn to_json(&self) -> Value {
        json!({
            "bucket": self.bucket,
            "dims": self.dims,
            "value": self.value,
        })
    }
}

struct UniqueBucket {
    point: Point,
    distinct: u64,
}

/// Unique-count series (`dev.checked_in`): exact from bounded R2 raw detail, or HLL
/// merge over `analytics_hll`, per the design's machine-count rule (§4.3).
async fn unique_series(
    env: &Env,
    database: &D1Database,
    query: &MetricsQuery,
) -> Result<(Source, Vec<UniqueBucket>)> {
    let source = match query.source {
        SourceSelection::Auto => source_for(machine_count(database, &query.product).await?),
        SourceSelection::Exact => Source::Exact,
        SourceSelection::Hll => Source::Hll,
    };
    match source {
        Source::Exact => Ok((source, exact_unique_series(env, query).await?)),
        Source::Hll => Ok((source, hll_unique_series(database, query).await?)),
    }
}

async fn machine_count(database: &D1Database, product: &str) -> Result<u64> {
    let row = database
        .prepare(
            "SELECT COUNT(*) AS value FROM machines m \
             JOIN licenses l ON l.id = m.license_id WHERE l.product_id = ?",
        )
        .bind(&[text(product)])?
        .first::<IntegerRow>(None)
        .await?
        .ok_or_else(|| {
            worker::Error::RustError("analytics machine count returned no row".to_owned())
        })?;
    u64::try_from(row.value)
        .map_err(|_| worker::Error::RustError("analytics machine count is invalid".to_owned()))
}

/// Merge per-day, per-cube sketches into granularity buckets (`90-analytics-telemetry.md
/// §4.2`): merge is register-wise max, so merging daily sketches equals sketching the
/// whole window.
async fn hll_unique_series(
    database: &D1Database,
    query: &MetricsQuery,
) -> Result<Vec<UniqueBucket>> {
    let cube = query.group_by.unwrap_or(0);
    let prefix = format!("cube_{cube}|{}", query.product);
    let (condition, mut bindings) = if cube == 0 {
        ("cube_key = ?".to_owned(), vec![text(&prefix)])
    } else {
        let range_start = format!("{prefix}|");
        // Lexicographic range over the `|` (0x7C) separator: the exclusive end is its
        // byte successor `}` (0x7D); no LIKE wildcards involved.
        let range_end = format!("{prefix}}}");
        (
            "cube_key >= ? AND cube_key < ?".to_owned(),
            vec![text(&range_start), text(&range_end)],
        )
    };
    let mut all_bindings = vec![text(&query.product)];
    all_bindings.append(&mut bindings);
    all_bindings.push(text(&date_string(query.from_days)));
    all_bindings.push(text(&date_string(query.to_days)));
    all_bindings.push(integer(
        i64::try_from(MAX_HLL_ROWS)
            .unwrap_or(i64::MAX)
            .saturating_add(1),
    )?);
    let rows = database
        .prepare(format!(
            "SELECT date, cube_key, sketch FROM analytics_hll \
             WHERE product_id = ? AND {condition} AND date >= ? AND date <= ? \
             ORDER BY date, cube_key LIMIT ?"
        ))
        .bind(&all_bindings)?
        .all()
        .await?
        .results::<HllDbRow>()?;
    if rows.len() > MAX_HLL_ROWS {
        return Err(worker::Error::RustError(
            "analytics HLL query exceeded its row cap".to_owned(),
        ));
    }

    let mut merged: BTreeMap<(i64, String), HllSketch> = BTreeMap::new();
    for row in rows {
        let Ok(key) = CubeKey::parse(&row.cube_key) else {
            continue; // A poisoned row is skipped, never fatal.
        };
        let Some(days) = parse_date(&row.date) else {
            continue;
        };
        let Ok(sketch) = HllSketch::from_bytes(&row.sketch) else {
            continue;
        };
        let bucket = bucket_start(days, query.granularity);
        merged
            .entry((bucket, key.encode()))
            .or_default()
            .merge(&sketch);
    }
    let mut buckets = Vec::with_capacity(merged.len());
    for ((bucket_days, encoded), sketch) in merged {
        let distinct = sketch.cardinality();
        let dims = match CubeKey::parse(&encoded) {
            Ok(key) => cube_dims(&key),
            Err(_) => continue,
        };
        buckets.push(UniqueBucket {
            point: Point {
                bucket: date_string(bucket_days),
                dims,
                value: distinct,
            },
            distinct,
        });
    }
    Ok(buckets)
}

/// Exact distinct counts from the bounded R2 raw detail (`90-analytics-telemetry.md §4.3`).
async fn exact_unique_series(env: &Env, query: &MetricsQuery) -> Result<Vec<UniqueBucket>> {
    let cube = query.group_by.unwrap_or(0);
    let bucket = env.bucket("ARCHIVE")?;
    let mut sets: BTreeMap<(i64, String), BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut scanned = 0_usize;
    let mut days = query.from_days;
    while days <= query.to_days {
        let date = date_string(days);
        let prefix = format!("{}{}/{date}/", crate::analytics::RAW_PREFIX, query.product);
        let mut cursor: Option<String> = None;
        loop {
            let mut listing = bucket.list().prefix(&prefix);
            if let Some(cursor) = cursor.take() {
                listing = listing.cursor(cursor);
            }
            let page = listing.execute().await?;
            for object in page.objects() {
                scanned = scanned.saturating_add(1);
                if scanned > MAX_EXACT_RECORDS {
                    return Err(worker::Error::RustError(
                        "exact analytics query exceeded its raw record cap".to_owned(),
                    ));
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
                if !record.is_valid()
                    || record.kind != ANALYTICS_KIND_CHECK_IN
                    || record.product_id != query.product
                {
                    continue;
                }
                let Some(cube_key) = record_cube_key(&record, cube) else {
                    continue;
                };
                let bucket_days = bucket_start(days, query.granularity);
                sets.entry((bucket_days, cube_key))
                    .or_default()
                    .insert(record.machine_key.clone());
            }
            if !page.truncated() {
                break;
            }
            let Some(next) = page.cursor() else {
                break;
            };
            cursor = Some(next);
        }
        days = days.saturating_add(1);
    }

    let mut buckets = Vec::with_capacity(sets.len());
    for ((bucket_days, encoded), machines) in sets {
        let distinct = u64::try_from(machines.len()).unwrap_or(u64::MAX);
        let dims = match CubeKey::parse(&encoded) {
            Ok(key) => cube_dims(&key),
            Err(_) => continue,
        };
        buckets.push(UniqueBucket {
            point: Point {
                bucket: date_string(bucket_days),
                dims,
                value: distinct,
            },
            distinct,
        });
    }
    Ok(buckets)
}

/// The encoded cube key for one check-in record under the selected cube, mirroring the
/// rollup pipeline's fixed cube set (`90-analytics-telemetry.md §4.2`).
fn record_cube_key(record: &AnalyticsDetailEvent, cube: u8) -> Option<String> {
    let product = record.product_id.clone();
    let dims = match cube {
        0 => vec![product],
        1 => vec![product, record.app_version.clone()],
        2 => vec![product, record.os.clone(), record.arch.clone()],
        3 => vec![product, record.country.clone()?],
        4 => vec![product, record.activation_path.clone()],
        5 => vec![product, record.mode.clone()],
        6 => vec![product, record.release_id.clone()],
        7 => vec![product, record.policy_id.clone()],
        8 => vec![product, record.sdk_version.clone()],
        _ => return None,
    };
    CubeKey::new(cube, dims).ok().map(|key| key.encode())
}

/// The point dimensions of a cube key: every dimension except `product`, which is already
/// a query parameter. Keys sort because `BTreeMap` sorts.
fn cube_dims(key: &CubeKey) -> BTreeMap<String, Value> {
    key.dimension_names()
        .iter()
        .zip(key.dimensions().iter())
        .skip(1)
        .map(|(name, value)| ((*name).to_owned(), Value::String(value.clone())))
        .collect()
}

/// Sum `analytics_rollup` / `telemetry_rollup` rows into granularity buckets, keeping the
/// stored `dims_json` as the series grouping.
async fn count_series(
    database: &D1Database,
    query: &MetricsQuery,
    metric_id: &str,
) -> Result<Vec<Point>> {
    let table = if ROLLUP_METRICS.contains(&metric_id) {
        "analytics_rollup"
    } else {
        "telemetry_rollup"
    };
    let rows = database
        .prepare(format!(
            "SELECT date, dims_json, SUM(value) AS value FROM {table} \
             WHERE product_id = ? AND metric_id = ? AND date >= ? AND date <= ? \
             GROUP BY date, dims_json ORDER BY date, dims_json LIMIT ?"
        ))
        .bind(&[
            text(&query.product),
            text(metric_id),
            text(&date_string(query.from_days)),
            text(&date_string(query.to_days)),
            integer(
                i64::try_from(MAX_COUNT_ROWS)
                    .unwrap_or(i64::MAX)
                    .saturating_add(1),
            )?,
        ])?
        .all()
        .await?
        .results::<CountDbRow>()?;
    if rows.len() > MAX_COUNT_ROWS {
        return Err(worker::Error::RustError(
            "analytics count query exceeded its row cap".to_owned(),
        ));
    }

    let mut sums: BTreeMap<(i64, String), (BTreeMap<String, Value>, u64)> = BTreeMap::new();
    for row in rows {
        let Some(days) = parse_date(&row.date) else {
            continue;
        };
        if row.value < 0 || row.dims_json.len() > MAX_DIMS_JSON {
            continue;
        }
        let Ok(Value::Object(dims)) = serde_json::from_str::<Value>(&row.dims_json) else {
            continue;
        };
        let value = u64::try_from(row.value)
            .map_err(|_| worker::Error::RustError("analytics count is invalid".to_owned()))?;
        let bucket = bucket_start(days, query.granularity);
        let entry = sums
            .entry((bucket, row.dims_json.clone()))
            .or_insert_with(|| (BTreeMap::new(), 0));
        entry.0 = dims.into_iter().collect();
        entry.1 = entry.1.saturating_add(value);
    }
    Ok(sums
        .into_iter()
        .map(|((bucket_days, _), (dims, value))| Point {
            bucket: date_string(bucket_days),
            dims,
            value,
        })
        .collect())
}

/// The design's resolution constraint (`90-analytics-telemetry.md §3`): activity metrics
/// are only as fine-grained as `min(refresh_after, heartbeat_sec)`. At day granularity a
/// product whose effective refresh interval exceeds one day gets the §3 warning.
async fn resolution_warning(
    database: &D1Database,
    product: &str,
    granularity: Granularity,
) -> Result<Option<String>> {
    if granularity != Granularity::Day {
        return Ok(None);
    }
    let rows = database
        .prepare(
            "SELECT refresh_after_sec, heartbeat_sec FROM policies \
             WHERE product_id = ? LIMIT 101",
        )
        .bind(&[text(product)])?
        .all()
        .await?
        .results::<PolicyResolutionRow>()?;
    if rows.len() > 100 {
        return Err(worker::Error::RustError(
            "analytics resolution query exceeded its row cap".to_owned(),
        ));
    }
    let mut resolution: Option<i64> = None;
    for row in rows {
        if row.refresh_after_sec <= 0 || row.heartbeat_sec.is_some_and(|value| value <= 0) {
            return Err(worker::Error::RustError(
                "policy refresh intervals are invalid".to_owned(),
            ));
        }
        let effective = row
            .heartbeat_sec
            .map_or(row.refresh_after_sec, |heartbeat| {
                heartbeat.min(row.refresh_after_sec)
            });
        resolution = Some(resolution.map_or(effective, |current| current.min(effective)));
    }
    let Some(resolution) = resolution else {
        return Ok(None);
    };
    if resolution <= DAY_GRANULARITY_LIMIT_SECONDS {
        return Ok(None);
    }
    let days = resolution / DAY_SECONDS;
    Ok(Some(format!(
        "the product's effective refresh interval is {days} days; day-granularity activity \
         data is unreliable (90-analytics-telemetry.md §3) — use week or month granularity, \
         shorten refresh_after, enable heartbeat, or enable T1 telemetry"
    )))
}

// ---------------------------------------------------------------------------
// subscriptions
// ---------------------------------------------------------------------------

async fn subscriptions(request: &mut Request, env: &Env) -> Result<Response> {
    if !matches!(request.method(), Method::Get | Method::Post) {
        return method_not_allowed();
    }
    let principal = match authorize(request, env, "analytics:r").await? {
        Ok(principal) => principal,
        Err(rejection) => return Ok(rejection),
    };
    if request.method() == Method::Get {
        return list_subscriptions(request, env, &principal).await;
    }
    create_subscription(request, env, &principal).await
}

async fn create_subscription(
    request: &mut Request,
    env: &Env,
    principal: &AdminPrincipal,
) -> Result<Response> {
    let body = match read_json::<SubscriptionBody>(request).await? {
        Ok(body) => body,
        Err(rejection) => return Ok(rejection),
    };
    if let Err(message) = validate_subscription(&body) {
        return invalid_request(message);
    }
    let request_id = match require_idempotency_key(request)? {
        Ok(value) => value,
        Err(rejection) => return Ok(rejection),
    };
    let action = "analytics:subscription:create";
    let id = subscription_id(&principal.vendor_id, &request_id);
    let target = format!("{}/analytics-subscriptions/{id}", body.product_id);
    let request_value = serde_json::to_value(&body)?;
    if crate::events::admin_snapshot_canonical(&request_value).is_none() {
        return invalid_request("subscription request contains unsupported JSON data");
    }
    let request_hash = admin_operations::request_hash(action, &target, &request_value)?;
    let database = env.d1("DB")?;
    if let Some(response) = replay_operation(
        env,
        &database,
        principal,
        &request_id,
        &request_hash,
        "analytics:r",
    )
    .await?
    {
        return Ok(response);
    }
    if !product_owned(&database, &body.product_id, &principal.vendor_id).await? {
        return not_found("product not found");
    }

    let record = SubscriptionRecord {
        schema_version: 1,
        id: id.clone(),
        product_id: body.product_id.clone(),
        metric_ids: body.metric_ids.clone(),
        window_days: body.window_days,
        granularity: body.granularity.clone(),
        webhook_url: body.webhook_url.clone(),
        created_by: principal.actor.clone(),
        created_at: now_seconds(),
        delivery: "pending".to_owned(),
    };
    let record_json = serde_json::to_value(&record)?;
    let record_bytes = serde_json::to_vec(&record)?;
    // The R2 write precedes the journal batch: the key and bytes are deterministic
    // functions of the Idempotency-Key, so a retried create rewrites identical bytes.
    env.bucket("ARCHIVE")?
        .put(subscription_r2_key(&principal.vendor_id, &id), record_bytes)
        .execute()
        .await?;
    let operation = NewOperation {
        vendor_id: principal.vendor_id.clone(),
        request_id: request_id.clone(),
        actor: principal.actor.clone(),
        required_scope: "analytics:r".to_owned(),
        action: action.to_owned(),
        target,
        source_kind: "analytics".to_owned(),
        source_id: id,
        request_hash: request_hash.clone(),
        before: Value::Null,
        after: record_json.clone(),
        result: json!({"ok": true, "subscription": record_json}),
        response_status: 201,
        side_effect: None,
        created_at: now_seconds(),
    };
    let statements = vec![admin_operations::insert_statement(&database, &operation)?];
    if let Err(error) = database.batch(statements).await {
        if let Some(response) = replay_operation(
            env,
            &database,
            principal,
            &request_id,
            &request_hash,
            "analytics:r",
        )
        .await?
        {
            return Ok(response);
        }
        return Err(error);
    }
    finish_new_operation(env, &database, principal, &request_id).await
}

async fn list_subscriptions(
    request: &Request,
    env: &Env,
    principal: &AdminPrincipal,
) -> Result<Response> {
    let mut product_filter = None;
    for (name, value) in request.url()?.query_pairs() {
        if name != "product_id" || product_filter.is_some() || !valid_identifier(&value) {
            return invalid_request("at most one valid product_id query parameter is allowed");
        }
        product_filter = Some(value.into_owned());
    }
    let prefix = format!("{SUBSCRIPTION_PREFIX}{}/", principal.vendor_id);
    let bucket = env.bucket("ARCHIVE")?;
    let mut keys = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut listing = bucket.list().prefix(&prefix);
        if let Some(cursor) = cursor.take() {
            listing = listing.cursor(cursor);
        }
        let page = listing.execute().await?;
        keys.extend(page.objects().into_iter().map(|object| object.key()));
        if keys.len() > MAX_SUBSCRIPTIONS {
            return response::api_error_no_store(
                413,
                "result_too_large",
                "subscription list exceeds 100 items",
            );
        }
        if !page.truncated() {
            break;
        }
        let Some(next) = page.cursor() else {
            break;
        };
        cursor = Some(next);
    }
    keys.sort();
    let mut items = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(object) = bucket.get(&key).execute().await? else {
            continue; // Deleted between listing and read.
        };
        if object.size() > MAX_SUBSCRIPTION_BYTES {
            return Err(worker::Error::RustError(
                "analytics subscription record is oversized".to_owned(),
            ));
        }
        let Some(body) = object.body() else {
            continue;
        };
        let record =
            serde_json::from_slice::<SubscriptionRecord>(&body.bytes().await?).map_err(|_| {
                worker::Error::RustError("analytics subscription record is corrupt".to_owned())
            })?;
        if !record.is_valid() {
            return Err(worker::Error::RustError(
                "analytics subscription record is invalid".to_owned(),
            ));
        }
        if product_filter
            .as_ref()
            .is_some_and(|filter| *filter != record.product_id)
        {
            continue;
        }
        items.push(serde_json::to_value(&record)?);
    }
    response::json_no_store(200, &json!({"ok": true, "items": items}))
}

fn subscription_id(vendor_id: &str, request_id: &str) -> String {
    let digest = Sha256Scheme::hash_parts(&[
        SUBSCRIPTION_ID_DOMAIN,
        vendor_id.as_bytes(),
        request_id.as_bytes(),
    ]);
    let short = digest.as_bytes().get(..16).unwrap_or(&[]);
    format!("sub_{}", hex_encode(short))
}

fn subscription_r2_key(vendor_id: &str, id: &str) -> String {
    format!("{SUBSCRIPTION_PREFIX}{vendor_id}/{id}.json")
}

fn validate_subscription(body: &SubscriptionBody) -> std::result::Result<(), &'static str> {
    if !valid_identifier(&body.product_id) {
        return Err("subscription product id is invalid");
    }
    if body.metric_ids.is_empty() || body.metric_ids.len() > MAX_QUERY_IDS {
        return Err("subscription must reference 1-8 metric ids");
    }
    let mut seen = BTreeSet::new();
    for id in &body.metric_ids {
        if metric_by_id(id).is_none() {
            return Err("subscription references an unknown metric id");
        }
        if !seen.insert(id) {
            return Err("subscription metric ids must be unique");
        }
    }
    if !(1..=90).contains(&body.window_days) {
        return Err("subscription window_days must be between 1 and 90");
    }
    if Granularity::parse(&body.granularity).is_none() {
        return Err("subscription granularity must be day, week, or month");
    }
    if !valid_webhook_url(&body.webhook_url) {
        return Err("subscription webhook url must be an https URL without credentials");
    }
    Ok(())
}

/// Webhook URLs are https-only (design §8); credentials in the authority are rejected so
/// a stored config can never smuggle a basic-auth secret into the report delivery path.
fn valid_webhook_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    !authority.is_empty()
        && !authority.contains('@')
        && authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':'))
        && value.len() <= 512
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionBody {
    product_id: String,
    metric_ids: Vec<String>,
    window_days: u32,
    granularity: String,
    webhook_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubscriptionRecord {
    schema_version: u8,
    id: String,
    product_id: String,
    metric_ids: Vec<String>,
    window_days: u32,
    granularity: String,
    webhook_url: String,
    created_by: String,
    created_at: i64,
    delivery: String,
}

impl SubscriptionRecord {
    fn is_valid(&self) -> bool {
        self.schema_version == 1
            && self.id.starts_with("sub_")
            && self.id.len() == 36
            && self.delivery == "pending"
            && valid_identifier(&self.product_id)
            && !self.metric_ids.is_empty()
            && self.metric_ids.len() <= MAX_QUERY_IDS
            && self.metric_ids.iter().all(|id| metric_by_id(id).is_some())
            && (1..=90).contains(&self.window_days)
            && Granularity::parse(&self.granularity).is_some()
            && valid_webhook_url(&self.webhook_url)
            && !self.created_by.is_empty()
            && self.created_by.len() <= 128
            && self.created_at >= 0
    }
}

// ---------------------------------------------------------------------------
// query parsing, dates, rendering
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Granularity {
    Day,
    Week,
    Month,
}

impl Granularity {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "day" => Some(Self::Day),
            "week" => Some(Self::Week),
            "month" => Some(Self::Month),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SourceSelection {
    Auto,
    Exact,
    Hll,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExportFormat {
    Csv,
    Ndjson,
}

struct MetricsQuery {
    product: String,
    ids: Vec<String>,
    from_days: i64,
    to_days: i64,
    granularity: Granularity,
    group_by: Option<u8>,
    source: SourceSelection,
    format: Option<ExportFormat>,
}

impl MetricsQuery {
    fn parse(request: &Request, allow_format: bool) -> Result<std::result::Result<Self, Response>> {
        let invalid = || {
            response::api_error_no_store(
                400,
                "invalid_query",
                "analytics queries take product, ids, from, to, and optional granularity, \
                 group_by, source, and format parameters",
            )
        };
        let mut product = None;
        let mut ids = None;
        let mut from = None;
        let mut to = None;
        let mut granularity = None;
        let mut group_by = None;
        let mut source = None;
        let mut format = None;
        for (name, value) in request.url()?.query_pairs() {
            match name.as_ref() {
                "product" if product.is_none() && valid_identifier(&value) => {
                    product = Some(value.into_owned());
                }
                "ids" if ids.is_none() => {
                    let parsed = value
                        .split(',')
                        .map(str::trim)
                        .filter(|id| !id.is_empty())
                        .map(str::to_owned)
                        .collect::<Vec<_>>();
                    if parsed.is_empty() || parsed.len() > MAX_QUERY_IDS {
                        return Ok(Err(invalid()?));
                    }
                    ids = Some(parsed);
                }
                "from" if from.is_none() => {
                    let Some(days) = parse_date(&value) else {
                        return Ok(Err(invalid()?));
                    };
                    from = Some(days);
                }
                "to" if to.is_none() => {
                    let Some(days) = parse_date(&value) else {
                        return Ok(Err(invalid()?));
                    };
                    to = Some(days);
                }
                "granularity" if granularity.is_none() => {
                    let Some(parsed) = Granularity::parse(&value) else {
                        return Ok(Err(invalid()?));
                    };
                    granularity = Some(parsed);
                }
                "group_by" if group_by.is_none() => {
                    let Some(cube) = parse_group_by(&value) else {
                        return Ok(Err(invalid()?));
                    };
                    group_by = Some(cube);
                }
                "source" if source.is_none() => {
                    source = Some(match value.as_ref() {
                        "auto" => SourceSelection::Auto,
                        "exact" => SourceSelection::Exact,
                        "hll" => SourceSelection::Hll,
                        _ => return Ok(Err(invalid()?)),
                    });
                }
                "format" if allow_format && format.is_none() => {
                    format = Some(match value.as_ref() {
                        "csv" => ExportFormat::Csv,
                        "ndjson" => ExportFormat::Ndjson,
                        _ => return Ok(Err(invalid()?)),
                    });
                }
                _ => return Ok(Err(invalid()?)),
            }
        }
        let (Some(product), Some(ids), Some(from_days), Some(to_days)) = (product, ids, from, to)
        else {
            return Ok(Err(invalid()?));
        };
        if from_days > to_days || to_days.saturating_sub(from_days) > MAX_WINDOW_DAYS {
            return Ok(Err(response::api_error_no_store(
                400,
                "invalid_query",
                "analytics windows are at most 366 days and from must not exceed to",
            )?));
        }
        for id in &ids {
            let served = UNIQUE_METRICS.contains(&id.as_str())
                || ROLLUP_METRICS.contains(&id.as_str())
                || TELEMETRY_METRICS.contains(&id.as_str());
            if metric_by_id(id).is_none() {
                return Ok(Err(response::api_error_no_store(
                    400,
                    "invalid_metric",
                    "analytics queries reference an unknown metric id",
                )?));
            }
            if !served {
                return Ok(Err(response::api_error_no_store(
                    400,
                    "metric_not_served",
                    "the metric is catalogued but not served by the rollup pipeline yet",
                )?));
            }
        }
        Ok(Ok(Self {
            product,
            ids,
            from_days,
            to_days,
            granularity: granularity.unwrap_or(Granularity::Day),
            group_by,
            source: source.unwrap_or(SourceSelection::Auto),
            format,
        }))
    }
}

/// `group_by` values map onto the fixed cube set (§4.2); arbitrary dimension combinations
/// do not exist as cubes and are rejected here, just like in [`CubeKey`].
fn parse_group_by(value: &str) -> Option<u8> {
    match value {
        "app_version" => Some(1),
        "os_arch" => Some(2),
        "country" => Some(3),
        "activation_path" => Some(4),
        "mode" => Some(5),
        "release_id" => Some(6),
        "policy_id" => Some(7),
        "sdk_version" => Some(8),
        _ => None,
    }
}

/// Strict `YYYY-MM-DD` → days since the Unix epoch. Never panics on adversarial input.
pub(super) fn parse_date(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 {
        return None;
    }
    let dashes = bytes.get(4) == Some(&b'-') && bytes.get(7) == Some(&b'-');
    if !dashes {
        return None;
    }
    let year = parse_digits(bytes.get(0..4)?)?;
    let month = parse_digits(bytes.get(5..7)?)?;
    let day = parse_digits(bytes.get(8..10)?)?;
    if !(1970..=2100).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > i64::from(days_in_month(year, month))
    {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

fn parse_digits(bytes: &[u8]) -> Option<i64> {
    let mut value = 0_i64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?;
        value = value.checked_add(i64::from(byte.wrapping_sub(b'0')))?;
    }
    Some(value)
}

fn days_in_month(year: i64, month: i64) -> u8 {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if leap => 29,
        _ => 28,
    }
}

/// Days since the Unix epoch for a valid civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

pub(super) fn date_string(days: i64) -> String {
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The start day of the granularity bucket containing `days`: the day itself, the ISO
/// week Monday (1970-01-01 was a Thursday), or the first of the month.
fn bucket_start(days: i64, granularity: Granularity) -> i64 {
    match granularity {
        Granularity::Day => days,
        Granularity::Week => days - (days + 3).rem_euclid(7),
        Granularity::Month => {
            let (year, month, _) = civil_from_days(days);
            days_from_civil(year, month, 1)
        }
    }
}

fn render_csv(rows: &[ExportRow]) -> Vec<u8> {
    let mut out = String::from("metric_id,bucket,dims_json,value\n");
    for row in rows {
        out.push_str(&csv_field(&row.metric_id));
        out.push(',');
        out.push_str(&csv_field(&row.bucket));
        out.push(',');
        out.push_str(&csv_field(&row.dims_json));
        out.push(',');
        out.push_str(&row.value.to_string());
        out.push('\n');
    }
    out.into_bytes()
}

fn csv_field(value: &str) -> String {
    if value
        .bytes()
        .any(|byte| matches!(byte, b',' | b'"' | b'\n' | b'\r'))
    {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn render_ndjson(rows: &[ExportRow]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for row in rows {
        let dims: Value = serde_json::from_str(&row.dims_json)?;
        out.extend_from_slice(&serde_json::to_vec(&json!({
            "metric_id": row.metric_id,
            "bucket": row.bucket,
            "dims": dims,
            "value": row.value,
        }))?);
        out.push(b'\n');
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct HllDbRow {
    date: String,
    cube_key: String,
    #[serde(with = "serde_bytes")]
    sketch: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct CountDbRow {
    date: String,
    dims_json: String,
    value: i64,
}

#[derive(Debug, Deserialize)]
struct PolicyResolutionRow {
    refresh_after_sec: i64,
    heartbeat_sec: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct IntegerRow {
    value: i64,
}
