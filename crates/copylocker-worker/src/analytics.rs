//! The worker-side analytics pipeline (`90-analytics-telemetry.md §5, §6`).
//!
//! Three legs live here:
//!
//! 1. **Telemetry consumption** on the validate path: after the device proof has been
//!    verified (authorization is unchanged), a reported `TelemetryBlock` passes the
//!    policy tier gate, the consent gate, and `clip::clip_telemetry` before it may ride
//!    the detail stream. Every drop and clip becomes an operational `t1.*` counter.
//! 2. **Detail stream**: the request path enqueues one [`AnalyticsDetailEvent`] per
//!    successful activation or check-in; the queue consumer archives it to R2 raw.
//! 3. **Daily rollup**: the `15 0 * * *` cron aggregates one UTC day of R2 records into
//!    `analytics_rollup` (exact counts), `analytics_hll` (per-cube sketches), and
//!    `telemetry_rollup` (T1 aggregates), all idempotently.
//!
//! Deviation from §5: the Analytics Engine near-realtime leg is **pending** — no
//! Analytics Engine binding exists in `wrangler.jsonc` yet. When the binding lands,
//! `writeDataPoint()` hooks in beside [`enqueue_detail`]; the D1 rollup implemented
//! here stays the exact path.

use std::collections::{BTreeMap, BTreeSet};

use copylocker_proto::{ActivationRequest, TelemetryBlock, ValidateRequest};
use copylocker_server_core::analytics::{
    clip_telemetry, consent_allows, ClipEvent, CubeKey, HllSketch, TelemetryValues,
};
use copylocker_types::{MachineId, Mode};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use worker::wasm_bindgen::JsValue;
use worker::{Bucket, Conditional, D1Database, D1Type, Date, Env, Error, Response, Result};

use crate::bindings::authorization::{self, AuthorizationContext};
use crate::bindings::rng::WorkerRng;
use crate::events::{
    analytics_r2_key, is_product_id, utc_day_string, AnalyticsDetailEvent, ANALYTICS_DETAIL_EVENT,
    ANALYTICS_DETAIL_SCHEMA_VERSION, ANALYTICS_KIND_ACTIVATION, ANALYTICS_KIND_CHECK_IN,
    TELEMETRY_DROPPED_NO_CONSENT, TELEMETRY_DROPPED_TIER_GATE,
};

/// The cron expression that runs the daily rollup (UTC 00:15, `90-analytics-telemetry.md
/// §4.2`). The every-minute dev trigger never runs it; the scheduled handler dispatches
/// on `event.cron()`.
pub(crate) const ROLLUP_CRON: &str = "15 0 * * *";

/// Domain separation for the analytics pseudonym: the analytics key is
/// `HMAC(SERVER_PEPPER, label)`, so machine-key hashes cannot be correlated with the
/// license-key HMACs derived from the same pepper.
const ANALYTICS_PEPPER_LABEL: &[u8] = b"copylocker/analytics-pepper";
/// R2 prefix of the raw detail stream (`90-analytics-telemetry.md §5`; 90-day retention
/// via bucket lifecycle, `data-model.md §14`).
pub(crate) const RAW_PREFIX: &str = "analytics/raw/";
/// Hard bound on one detail record; oversized objects are skipped, never truncated.
const MAX_DETAIL_BYTES: u64 = 16 * 1024;
/// Bound on records aggregated per product-day. Listing is lexicographic and keys are
/// re-sorted, so the cap truncates deterministically and a re-run aggregates the same
/// records.
const MAX_ROLLUP_RECORDS: usize = 10_000;
/// Bound on product prefixes listed per rollup run.
const MAX_ROLLUP_PRODUCTS: usize = 1_000;
/// Statements per D1 batch in the rollup writer.
const D1_WRITE_BATCH: usize = 100;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

// Rollup metric ids. `dev.checked_in`, `act.new`, `act.by_path`, and the `use.*` ids are
// from the design catalog (`90-analytics-telemetry.md §2`); the `t1.*` ids are
// operational counters measuring the telemetry pipeline itself (dropped/clipped
// reports) and deliberately live outside the catalog, always with `dims_json = "{}"`.
const METRIC_CHECKED_IN: &str = "dev.checked_in";
const METRIC_ACT_NEW: &str = "act.new";
const METRIC_ACT_BY_PATH: &str = "act.by_path";
const METRIC_USE_SESSION_COUNT: &str = "use.session_count";
const METRIC_USE_DAYS_ACTIVE: &str = "use.days_active";
const METRIC_USE_SESSION_DURATION: &str = "use.session_duration";
const METRIC_USE_FEATURE_HITS: &str = "use.feature_hits";
const METRIC_T1_DROPPED_NO_CONSENT: &str = "t1.dropped_no_consent";
const METRIC_T1_DROPPED_TIER_GATE: &str = "t1.dropped_tier_gate";

/// Map a clip-event kind (recorded on the detail event) to its anomaly counter id.
fn clip_counter_metric(kind: &str) -> Option<&'static str> {
    match kind {
        "session_count_clipped" => Some("t1.clipped_session_count"),
        "days_active_clipped" => Some("t1.clipped_days_active"),
        "histogram_bucket_clipped" => Some("t1.clipped_histogram_bucket"),
        "feature_hits_clipped" => Some("t1.clipped_feature_hits"),
        "feature_key_dropped" => Some("t1.dropped_feature_key"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Pseudonymous machine key
// ---------------------------------------------------------------------------

/// The pseudonymous machine key (`90-analytics-telemetry.md §4.2`):
/// `HMAC(HMAC(SERVER_PEPPER, "copylocker/analytics-pepper"), machine_id)`. Raw machine
/// ids never enter the analytics stream, and the derived key cannot be reversed or
/// correlated with license-key lookups without the pepper.
pub(crate) async fn machine_key(env: &Env, machine_id: &[u8]) -> Result<Vec<u8>> {
    let pepper = authorization::server_pepper(env)
        .await
        .map_err(|error| match error {
            authorization::AuthorizationError::Server(error) => error,
            _ => Error::RustError("server pepper is unavailable".to_owned()),
        })?;
    let mut derive = <Hmac<Sha256>>::new_from_slice(pepper.expose())
        .map_err(|_| Error::RustError("server pepper is invalid".to_owned()))?;
    derive.update(ANALYTICS_PEPPER_LABEL);
    let analytics_key = derive.finalize().into_bytes();
    let mut mac = <Hmac<Sha256>>::new_from_slice(&analytics_key)
        .map_err(|_| Error::RustError("analytics machine key derivation failed".to_owned()))?;
    mac.update(machine_id);
    Ok(mac.finalize().into_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Telemetry consumption (validate path)
// ---------------------------------------------------------------------------

/// What the validate path decided to do with a reported telemetry block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TelemetryOutcome {
    /// Nothing usable: no block was reported, or the gate lookup failed (best effort —
    /// the block is silently forfeited and the validate response is unaffected).
    Absent,
    /// The block passed every gate: clipped values plus the kinds of every applied clip.
    Accepted {
        values: TelemetryValues,
        clip_kinds: Vec<String>,
    },
    /// The block was dropped; the reason becomes a rollup counter.
    Dropped(&'static str),
}

/// Apply the T1 gates in design order (`90-analytics-telemetry.md §6`):
///
/// 1. **Tier gate**: only a policy with `telemetry_tier = 'T1'` accepts telemetry; every
///    other value drops the block (`t1.dropped_tier_gate`).
/// 2. **Consent gate**: `consent_version = 0` drops the block (`t1.dropped_no_consent`),
///    the SDK-integration-error signal.
/// 3. **Clipping**: fixed caps plus the feature allow-list; every clip is recorded so it
///    is both stored clipped *and* counted as an anomaly.
pub(crate) fn evaluate_telemetry(
    telemetry_tier: &str,
    block: &TelemetryBlock,
    feature_allowlist: &[&str],
) -> TelemetryOutcome {
    if telemetry_tier != "T1" {
        return TelemetryOutcome::Dropped(TELEMETRY_DROPPED_TIER_GATE);
    }
    if !consent_allows(block.consent_version) {
        return TelemetryOutcome::Dropped(TELEMETRY_DROPPED_NO_CONSENT);
    }
    let clipped = clip_telemetry(values_of(block), feature_allowlist);
    TelemetryOutcome::Accepted {
        values: clipped.values,
        clip_kinds: clipped.events.iter().map(clip_event_kind).collect(),
    }
}

fn values_of(block: &TelemetryBlock) -> TelemetryValues {
    TelemetryValues {
        consent_version: block.consent_version,
        window_start: block.window_start,
        session_count: block.session_count,
        session_duration_histogram: block.session_duration_histogram,
        feature_hits: block.feature_hits.clone(),
        days_active: block.days_active,
    }
}

fn clip_event_kind(event: &ClipEvent) -> String {
    match event {
        ClipEvent::SessionCountClipped { .. } => "session_count_clipped",
        ClipEvent::DaysActiveClipped { .. } => "days_active_clipped",
        ClipEvent::HistogramBucketClipped { .. } => "histogram_bucket_clipped",
        ClipEvent::FeatureHitsClipped { .. } => "feature_hits_clipped",
        ClipEvent::FeatureKeyDropped { .. } => "feature_key_dropped",
    }
    .to_owned()
}

/// The telemetry gate inputs: the policy's `telemetry_tier` and the feature allow-list.
/// The schema has no per-product telemetry whitelist column, so the allow-list is the
/// product's feature catalog (every non-deprecated feature id in `features`).
///
/// These D1 reads serve telemetry processing only; they never feed an authorization
/// decision (`data-model.md §15`), and any failure forfeits just the telemetry block.
async fn load_telemetry_policy(
    database: &D1Database,
    policy_id: &str,
    product_id: &str,
) -> Result<(String, Vec<String>)> {
    let tier = database
        .prepare("SELECT telemetry_tier FROM policies WHERE id = ? AND product_id = ?")
        .bind(&[text(policy_id), text(product_id)])?
        .first::<TelemetryTierRow>(None)
        .await?
        .ok_or_else(|| Error::RustError("license policy is missing".to_owned()))?
        .telemetry_tier;
    let allowlist = database
        .prepare("SELECT id FROM features WHERE product_id = ? AND deprecated_at IS NULL")
        .bind(&[text(product_id)])?
        .all()
        .await?
        .results::<FeatureIdRow>()?
        .into_iter()
        .map(|row| row.id)
        .collect();
    Ok((tier, allowlist))
}

// ---------------------------------------------------------------------------
// Detail event emission (request path, best effort)
// ---------------------------------------------------------------------------

/// Emit the check-in detail event for a successful validate (`ticket` outcome).
/// Telemetry consumption and the enqueue are best effort: a failure is logged, never
/// propagated, so analytics can never break validation.
pub(crate) async fn emit_check_in_detail(
    env: &Env,
    authorization: &AuthorizationContext,
    validation: &ValidateRequest,
    activation_path: Option<&str>,
    country: Option<String>,
    now: i64,
) {
    match build_check_in_event(
        env,
        authorization,
        validation,
        activation_path,
        country,
        now,
    )
    .await
    {
        Ok(event) => enqueue_detail(env, event, ANALYTICS_KIND_CHECK_IN).await,
        Err(error) => log_emit_error(ANALYTICS_KIND_CHECK_IN, &error),
    }
}

/// Emit the activation detail event for a freshly completed activation. Idempotent
/// replays (which return the stored envelope) never reach this path, so `act.new` is
/// not double counted. Same best-effort contract as [`emit_check_in_detail`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn emit_activation_detail(
    env: &Env,
    authorization: &AuthorizationContext,
    activation: &ActivationRequest,
    machine_id: MachineId,
    activation_path: &str,
    reused: bool,
    country: Option<String>,
    now: i64,
) {
    match build_activation_event(
        env,
        authorization,
        activation,
        machine_id,
        activation_path,
        reused,
        country,
        now,
    )
    .await
    {
        Ok(event) => enqueue_detail(env, event, ANALYTICS_KIND_ACTIVATION).await,
        Err(error) => log_emit_error(ANALYTICS_KIND_ACTIVATION, &error),
    }
}

async fn build_check_in_event(
    env: &Env,
    authorization: &AuthorizationContext,
    validation: &ValidateRequest,
    activation_path: Option<&str>,
    country: Option<String>,
    now: i64,
) -> Result<AnalyticsDetailEvent> {
    let Some(activation_path) = activation_path else {
        return Err(Error::RustError(
            "validation state omitted the activation path".to_owned(),
        ));
    };
    let outcome = match validation.telemetry.as_ref() {
        None => TelemetryOutcome::Absent,
        Some(block) => match load_telemetry_policy(
            &env.d1("DB")?,
            &authorization.policy.id,
            &authorization.product_id,
        )
        .await
        {
            Ok((tier, allowlist)) => {
                let refs: Vec<&str> = allowlist.iter().map(String::as_str).collect();
                evaluate_telemetry(&tier, block, &refs)
            }
            Err(error) => {
                worker::console_error!(
                    "{}",
                    serde_json::json!({
                        "level": "error",
                        "message": "telemetry gate lookup failed; forfeiting telemetry block",
                        "product_id": authorization.product_id,
                        "error": error.to_string()
                    })
                );
                TelemetryOutcome::Absent
            }
        },
    };
    let key = machine_key(env, validation.machine_id.as_bytes()).await?;
    let (telemetry, telemetry_dropped, clip_events) = split_outcome(outcome);
    let event = AnalyticsDetailEvent {
        event: ANALYTICS_DETAIL_EVENT.to_owned(),
        schema_version: ANALYTICS_DETAIL_SCHEMA_VERSION,
        record_id: random_record_id()?,
        occurred_at: now,
        kind: ANALYTICS_KIND_CHECK_IN.to_owned(),
        product_id: authorization.product_id.clone(),
        machine_key: key,
        app_version: validation.client_info.app_version.clone(),
        os: validation.client_info.os.clone(),
        arch: validation.client_info.arch.clone(),
        country,
        activation_path: activation_path.to_owned(),
        mode: mode_dimension(authorization.policy.mode).to_owned(),
        release_id: validation.client_info.release_id.clone(),
        policy_id: authorization.policy.id.clone(),
        sdk_version: validation.client_info.sdk_version.clone(),
        reused: None,
        telemetry,
        telemetry_dropped,
        clip_events,
    };
    if event.is_valid() {
        Ok(event)
    } else {
        Err(Error::RustError(
            "check-in detail event failed validation".to_owned(),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn build_activation_event(
    env: &Env,
    authorization: &AuthorizationContext,
    activation: &ActivationRequest,
    machine_id: MachineId,
    activation_path: &str,
    reused: bool,
    country: Option<String>,
    now: i64,
) -> Result<AnalyticsDetailEvent> {
    let key = machine_key(env, machine_id.as_bytes()).await?;
    let event = AnalyticsDetailEvent {
        event: ANALYTICS_DETAIL_EVENT.to_owned(),
        schema_version: ANALYTICS_DETAIL_SCHEMA_VERSION,
        record_id: random_record_id()?,
        occurred_at: now,
        kind: ANALYTICS_KIND_ACTIVATION.to_owned(),
        product_id: authorization.product_id.clone(),
        machine_key: key,
        app_version: activation.client_info.app_version.clone(),
        os: activation.client_info.os.clone(),
        arch: activation.client_info.arch.clone(),
        country,
        activation_path: activation_path.to_owned(),
        mode: mode_dimension(authorization.policy.mode).to_owned(),
        release_id: activation.client_info.release_id.clone(),
        policy_id: authorization.policy.id.clone(),
        sdk_version: activation.client_info.sdk_version.clone(),
        reused: Some(reused),
        telemetry: None,
        telemetry_dropped: None,
        clip_events: Vec::new(),
    };
    if event.is_valid() {
        Ok(event)
    } else {
        Err(Error::RustError(
            "activation detail event failed validation".to_owned(),
        ))
    }
}

fn split_outcome(
    outcome: TelemetryOutcome,
) -> (Option<TelemetryValues>, Option<String>, Vec<String>) {
    match outcome {
        TelemetryOutcome::Absent => (None, None, Vec::new()),
        TelemetryOutcome::Accepted { values, clip_kinds } => (Some(values), None, clip_kinds),
        TelemetryOutcome::Dropped(reason) => (None, Some(reason.to_owned()), Vec::new()),
    }
}

async fn enqueue_detail(env: &Env, event: AnalyticsDetailEvent, kind: &str) {
    let result = match env.queue("EVENTS") {
        Ok(queue) => queue.send(event).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        log_emit_error(kind, &error);
    }
}

fn log_emit_error(kind: &str, error: &Error) {
    worker::console_error!(
        "{}",
        serde_json::json!({
            "level": "error",
            "message": "analytics detail event could not be enqueued",
            "kind": kind,
            "error": error.to_string()
        })
    );
}

/// Test-only hook (`ENVIRONMENT == "test"`, routed from `router.rs`): serialize a sample
/// detail event exactly the way the queue producer transports it — worker-rs
/// `Queue::send` serializes the event with `serde_wasm_bindgen::to_value` under the
/// default `QueueContentType::Json`, and the platform then JSON-stringifies that
/// `JsValue` for delivery — and return the resulting JSON text. The vitest suite parses
/// this payload (exactly what the platform would hand the consumer as `message.body`)
/// and feeds it to the queue consumer, covering the real producer → platform → consumer
/// round-trip that direct `dispatchEvents` tests bypass: those hand the consumer
/// in-memory `JsValue`s, where a `serde_bytes` `Uint8Array` survives intact even though
/// the platform would mangle it into `{"0":…,"1":…}`.
pub(crate) fn test_detail_event_queue_body(env: &Env) -> Result<Response> {
    if !crate::admin::is_test_environment(env) {
        return crate::response::api_error(404, "not_found", "Not found");
    }
    let event = AnalyticsDetailEvent {
        event: ANALYTICS_DETAIL_EVENT.to_owned(),
        schema_version: ANALYTICS_DETAIL_SCHEMA_VERSION,
        record_id: "0f".repeat(16),
        occurred_at: 1_700_000_000,
        kind: ANALYTICS_KIND_CHECK_IN.to_owned(),
        product_id: "product_1".to_owned(),
        machine_key: vec![5; 32],
        app_version: "1.2.3".to_owned(),
        os: "macos".to_owned(),
        arch: "arm64".to_owned(),
        country: Some("DE".to_owned()),
        activation_path: "online".to_owned(),
        mode: "O".to_owned(),
        release_id: "rel_1".to_owned(),
        policy_id: "policy_1".to_owned(),
        sdk_version: "0.1.0".to_owned(),
        reused: None,
        telemetry: None,
        telemetry_dropped: None,
        clip_events: Vec::new(),
    };
    let value = worker::serde_wasm_bindgen::to_value(&event)?;
    let body = worker::js_sys::JSON::stringify(&value)?;
    Response::ok(String::from(body))
}

fn mode_dimension(mode: Mode) -> &'static str {
    match mode {
        Mode::OfflineHybrid => "O",
        Mode::EnforcedOnline => "E",
    }
}

fn random_record_id() -> Result<String> {
    let mut rng = WorkerRng::new()?;
    Ok(hex_encode(&rng.random_array::<16>()?))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let low = HEX.get(usize::from(byte & 0x0f)).copied().unwrap_or(b'0');
        encoded.push(char::from(high));
        encoded.push(char::from(low));
    }
    encoded
}

// ---------------------------------------------------------------------------
// R2 raw archive (queue consumer leg)
// ---------------------------------------------------------------------------

/// Archive one detail record to the raw R2 stream (`90-analytics-telemetry.md §5`). The
/// conditional write plus byte comparison makes queue redelivery idempotent, like
/// `audit::archive`: a replayed message rewrites identical bytes.
pub(crate) async fn archive_detail(env: &Env, event: &AnalyticsDetailEvent) -> Result<()> {
    let key = analytics_r2_key(&event.product_id, event.occurred_at, &event.record_id)
        .ok_or_else(|| Error::RustError("analytics detail event has no valid R2 key".to_owned()))?;
    let body = serde_json::to_vec(event).map_err(|_| {
        Error::RustError("analytics detail event could not be serialized".to_owned())
    })?;
    let bucket = env.bucket("ARCHIVE")?;
    let inserted = bucket
        .put(&key, body.clone())
        .only_if(Conditional {
            etag_does_not_match: Some("*".to_owned()),
            ..Conditional::default()
        })
        .execute()
        .await?;
    if inserted.is_some() {
        return Ok(());
    }

    let existing = bucket.get(&key).execute().await?.ok_or_else(|| {
        Error::RustError("analytics detail object disappeared after conditional write".to_owned())
    })?;
    let body_matches = match existing.body() {
        Some(existing_body) => existing_body.bytes().await? == body,
        None => false,
    };
    if body_matches {
        Ok(())
    } else {
        Err(Error::RustError(
            "analytics detail key already contains different bytes".to_owned(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Daily rollup (cron leg)
// ---------------------------------------------------------------------------

/// Roll up "yesterday UTC" (`90-analytics-telemetry.md §4.2`): read the day's R2 detail
/// records per product, then write exact-count `analytics_rollup` rows, per-cube
/// `analytics_hll` sketches, and `telemetry_rollup` T1 aggregates.
///
/// Idempotent (§12): aggregation is a pure function of the day's listed records and
/// every write is an `INSERT OR REPLACE` keyed by the table's PRIMARY KEY — never
/// `COUNT(*)` accumulation — so re-running a day's rollup yields byte-identical rows.
/// Rows are never retroactively deleted: aggregates hold no personal data
/// (`data-model.md §14`).
pub(crate) async fn rollup_previous_day(env: &Env) -> Result<()> {
    let now = now_seconds();
    let day_start = (now / 86_400)
        .checked_sub(1)
        .and_then(|day| day.checked_mul(86_400))
        .ok_or_else(|| Error::RustError("rollup day is out of range".to_owned()))?;
    let date = utc_day_string(day_start)
        .ok_or_else(|| Error::RustError("rollup date is out of range".to_owned()))?;
    let bucket = env.bucket("ARCHIVE")?;
    let database = env.d1("DB")?;
    let products = list_products(&bucket).await?;
    let mut failed = 0_u32;
    for product in &products {
        if let Err(error) = rollup_product_day(&bucket, &database, product, &date, day_start).await
        {
            failed = failed.saturating_add(1);
            worker::console_error!(
                "{}",
                serde_json::json!({
                    "level": "error",
                    "message": "analytics rollup failed for one product",
                    "product_id": product,
                    "date": date,
                    "error": error.to_string()
                })
            );
        }
    }
    worker::console_log!(
        "{}",
        serde_json::json!({
            "level": "info",
            "message": "analytics rollup completed",
            "date": date,
            "products": products.len(),
            "failed": failed
        })
    );
    Ok(())
}

async fn rollup_product_day(
    bucket: &Bucket,
    database: &D1Database,
    product: &str,
    date: &str,
    day_start: i64,
) -> Result<()> {
    let records = read_day_records(bucket, product, date, day_start).await?;
    if records.is_empty() {
        return Ok(());
    }
    let aggregates = aggregate_day(&records);
    write_rollup(database, product, date, &aggregates).await
}

/// Product ids with raw records, from the delimited prefixes under `analytics/raw/`.
async fn list_products(bucket: &Bucket) -> Result<Vec<String>> {
    let mut products = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut listing = bucket.list().prefix(RAW_PREFIX).delimiter("/");
        if let Some(cursor) = cursor.take() {
            listing = listing.cursor(cursor);
        }
        let page = listing.execute().await?;
        for prefix in page.delimited_prefixes() {
            let Some(product) = prefix
                .strip_prefix(RAW_PREFIX)
                .and_then(|rest| rest.strip_suffix('/'))
            else {
                continue;
            };
            if is_product_id(product) {
                products.push(product.to_owned());
            }
        }
        if products.len() >= MAX_ROLLUP_PRODUCTS {
            products.truncate(MAX_ROLLUP_PRODUCTS);
            break;
        }
        if !page.truncated() {
            break;
        }
        let Some(next) = page.cursor() else {
            break;
        };
        cursor = Some(next);
    }
    products.sort();
    products.dedup();
    Ok(products)
}

/// Read and validate one product-day of detail records. Records that fail validation,
/// belong to another day or product, or sit under a mismatched key are skipped (logged),
/// never fatal: the rollup must survive a poisoned object.
async fn read_day_records(
    bucket: &Bucket,
    product: &str,
    date: &str,
    day_start: i64,
) -> Result<Vec<AnalyticsDetailEvent>> {
    let prefix = format!("{RAW_PREFIX}{product}/{date}/");
    let mut keys = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut listing = bucket.list().prefix(&prefix);
        if let Some(cursor) = cursor.take() {
            listing = listing.cursor(cursor);
        }
        let page = listing.execute().await?;
        keys.extend(page.objects().into_iter().map(|object| object.key()));
        if keys.len() >= MAX_ROLLUP_RECORDS {
            keys.truncate(MAX_ROLLUP_RECORDS);
            worker::console_error!(
                "{}",
                serde_json::json!({
                    "level": "error",
                    "message": "analytics rollup record cap reached",
                    "product_id": product,
                    "date": date,
                    "cap": MAX_ROLLUP_RECORDS
                })
            );
            break;
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

    let mut records = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(object) = bucket.get(&key).execute().await? else {
            continue; // Deleted between listing and read.
        };
        if object.size() > MAX_DETAIL_BYTES {
            log_skipped_record(product, &key, "oversized object");
            continue;
        }
        let Some(body) = object.body() else {
            continue;
        };
        let bytes = body.bytes().await?;
        if bytes.len() as u64 > MAX_DETAIL_BYTES {
            log_skipped_record(product, &key, "oversized body");
            continue;
        }
        let Ok(event) = serde_json::from_slice::<AnalyticsDetailEvent>(&bytes) else {
            log_skipped_record(product, &key, "malformed record");
            continue;
        };
        let misplaced = !event.is_valid()
            || event.product_id != product
            || event.occurred_at < day_start
            || event.occurred_at >= day_start.saturating_add(86_400)
            || analytics_r2_key(&event.product_id, event.occurred_at, &event.record_id).as_deref()
                != Some(key.as_str());
        if misplaced {
            log_skipped_record(product, &key, "invalid or misplaced record");
            continue;
        }
        records.push(event);
    }
    Ok(records)
}

fn log_skipped_record(product: &str, key: &str, reason: &str) {
    worker::console_error!(
        "{}",
        serde_json::json!({
            "level": "error",
            "message": "analytics rollup skipped a record",
            "product_id": product,
            "r2_key": key,
            "reason": reason
        })
    );
}

/// One product-day of aggregates over the detail records.
#[derive(Default)]
struct DayAggregates {
    /// Per encoded cube key: the exact machine set plus the mergeable sketch.
    cubes: BTreeMap<String, CubeAggregate>,
    /// Activations that created a new machine (`reused = false` only; fingerprint-tolerance
    /// reuses are deliberately excluded, `90-analytics-telemetry.md §2.1`).
    activations_new: u64,
    activations_by_path: BTreeMap<String, u64>,
    /// Telemetry blocks seen (accepted or dropped) and accepted.
    telemetry_seen: u64,
    telemetry_accepted: u64,
    session_count_sum: u64,
    days_active_sum: u64,
    session_duration_sum: [u64; 4],
    feature_hits_sum: BTreeMap<String, u64>,
    /// Operational counters keyed by `t1.*` metric id.
    counters: BTreeMap<&'static str, u64>,
}

struct CubeAggregate {
    key: CubeKey,
    machines: BTreeSet<Vec<u8>>,
    sketch: HllSketch,
}

fn aggregate_day(records: &[AnalyticsDetailEvent]) -> DayAggregates {
    let mut aggregates = DayAggregates::default();
    for record in records {
        match record.kind.as_str() {
            ANALYTICS_KIND_CHECK_IN => {
                for (encoded, cube) in cube_keys(record) {
                    let entry = aggregates
                        .cubes
                        .entry(encoded)
                        .or_insert_with(|| CubeAggregate {
                            key: cube,
                            machines: BTreeSet::new(),
                            sketch: HllSketch::new(),
                        });
                    entry.machines.insert(record.machine_key.clone());
                    entry.sketch.add(&record.machine_key);
                }
            }
            ANALYTICS_KIND_ACTIVATION if record.reused == Some(false) => {
                aggregates.activations_new = aggregates.activations_new.saturating_add(1);
                let count = aggregates
                    .activations_by_path
                    .entry(record.activation_path.clone())
                    .or_insert(0);
                *count = count.saturating_add(1);
            }
            _ => {}
        }
        accumulate_telemetry(&mut aggregates, record);
    }
    aggregates
}

/// The nine fixed cubes over one check-in record (`90-analytics-telemetry.md §4.2`).
/// Absent dimensions (e.g. no `cf.country`) form no bucket in their cube. Valid events
/// always produce valid keys: `is_valid` rejects empty, overlong, or `|`-carrying
/// dimension values, so construction cannot fail here.
fn cube_keys(record: &AnalyticsDetailEvent) -> Vec<(String, CubeKey)> {
    let product = record.product_id.clone();
    let candidates: [Option<Vec<String>>; 9] = [
        Some(vec![product.clone()]),
        Some(vec![product.clone(), record.app_version.clone()]),
        Some(vec![
            product.clone(),
            record.os.clone(),
            record.arch.clone(),
        ]),
        record
            .country
            .clone()
            .map(|country| vec![product.clone(), country]),
        Some(vec![product.clone(), record.activation_path.clone()]),
        Some(vec![product.clone(), record.mode.clone()]),
        Some(vec![product.clone(), record.release_id.clone()]),
        Some(vec![product.clone(), record.policy_id.clone()]),
        Some(vec![product.clone(), record.sdk_version.clone()]),
    ];
    let mut keys = Vec::with_capacity(9);
    for (cube, dims) in candidates.into_iter().enumerate() {
        let Some(dims) = dims else {
            continue;
        };
        let Ok(cube_key) = CubeKey::new(cube as u8, dims) else {
            continue;
        };
        keys.push((cube_key.encode(), cube_key));
    }
    keys
}

fn accumulate_telemetry(aggregates: &mut DayAggregates, record: &AnalyticsDetailEvent) {
    if record.telemetry.is_none() && record.telemetry_dropped.is_none() {
        return;
    }
    aggregates.telemetry_seen = aggregates.telemetry_seen.saturating_add(1);
    if let Some(reason) = record.telemetry_dropped.as_deref() {
        let metric = match reason {
            TELEMETRY_DROPPED_NO_CONSENT => Some(METRIC_T1_DROPPED_NO_CONSENT),
            TELEMETRY_DROPPED_TIER_GATE => Some(METRIC_T1_DROPPED_TIER_GATE),
            _ => None,
        };
        if let Some(metric) = metric {
            bump_counter(aggregates, metric);
        }
        return;
    }
    let Some(values) = record.telemetry.as_ref() else {
        return;
    };
    aggregates.telemetry_accepted = aggregates.telemetry_accepted.saturating_add(1);
    aggregates.session_count_sum = aggregates
        .session_count_sum
        .saturating_add(values.session_count);
    aggregates.days_active_sum = aggregates
        .days_active_sum
        .saturating_add(values.days_active);
    for (bucket, count) in values.session_duration_histogram.iter().enumerate() {
        if let Some(sum) = aggregates.session_duration_sum.get_mut(bucket) {
            *sum = sum.saturating_add(*count);
        }
    }
    for (feature, hits) in &values.feature_hits {
        let sum = aggregates
            .feature_hits_sum
            .entry(feature.clone())
            .or_insert(0);
        *sum = sum.saturating_add(*hits);
    }
    for kind in &record.clip_events {
        if let Some(metric) = clip_counter_metric(kind) {
            bump_counter(aggregates, metric);
        }
    }
}

fn bump_counter(aggregates: &mut DayAggregates, metric: &'static str) {
    let count = aggregates.counters.entry(metric).or_insert(0);
    *count = count.saturating_add(1);
}

const ROLLUP_INSERT: &str =
    "INSERT OR REPLACE INTO analytics_rollup(product_id, date, metric_id, dims_json, value) \
     VALUES (?, ?, ?, ?, ?)";
const HLL_INSERT: &str =
    "INSERT OR REPLACE INTO analytics_hll(product_id, date, cube_key, sketch) \
     VALUES (?, ?, ?, ?)";
const TELEMETRY_INSERT: &str = "INSERT OR REPLACE INTO telemetry_rollup(\
       product_id, date, metric_id, dims_json, value, sample_n\
     ) VALUES (?, ?, ?, ?, ?, ?)";

fn push_rollup_statement(
    statements: &mut Vec<worker::D1PreparedStatement>,
    database: &D1Database,
    product: &str,
    date: &str,
    metric: &str,
    dims: &str,
    value: i64,
) -> Result<()> {
    statements.push(database.prepare(ROLLUP_INSERT).bind(&[
        text(product),
        text(date),
        text(metric),
        text(dims),
        integer(value)?,
    ])?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_telemetry_statement(
    statements: &mut Vec<worker::D1PreparedStatement>,
    database: &D1Database,
    product: &str,
    date: &str,
    metric: &str,
    dims: &str,
    value: u64,
    sample_n: i64,
) -> Result<()> {
    statements.push(database.prepare(TELEMETRY_INSERT).bind(&[
        text(product),
        text(date),
        text(metric),
        text(dims),
        integer(to_i64(value)?)?,
        integer(sample_n)?,
    ])?);
    Ok(())
}

/// Write one product-day of aggregates. Statement order is deterministic (every map is
/// a `BTreeMap`), and each statement is an `INSERT OR REPLACE` on the table's PRIMARY
/// KEY, which is what makes a re-run byte-identical.
async fn write_rollup(
    database: &D1Database,
    product: &str,
    date: &str,
    aggregates: &DayAggregates,
) -> Result<()> {
    let mut statements = Vec::new();
    for (encoded, aggregate) in &aggregates.cubes {
        push_rollup_statement(
            &mut statements,
            database,
            product,
            date,
            METRIC_CHECKED_IN,
            &dims_json(&aggregate.key),
            aggregates_len(aggregate)?,
        )?;
        statements.push(database.prepare(HLL_INSERT).bind(&[
            text(product),
            text(date),
            text(encoded),
            blob(&aggregate.sketch.to_bytes()),
        ])?);
    }
    if aggregates.activations_new > 0 {
        push_rollup_statement(
            &mut statements,
            database,
            product,
            date,
            METRIC_ACT_NEW,
            "{}",
            to_i64(aggregates.activations_new)?,
        )?;
        for (path, count) in &aggregates.activations_by_path {
            let dims = serde_json::to_string(&BTreeMap::from([("activation_path", path)]))
                .map_err(|_| Error::RustError("activation dims could not serialize".to_owned()))?;
            push_rollup_statement(
                &mut statements,
                database,
                product,
                date,
                METRIC_ACT_BY_PATH,
                &dims,
                to_i64(*count)?,
            )?;
        }
    }

    let accepted = to_i64(aggregates.telemetry_accepted)?;
    let seen = to_i64(aggregates.telemetry_seen)?;
    if aggregates.telemetry_accepted > 0 {
        push_telemetry_statement(
            &mut statements,
            database,
            product,
            date,
            METRIC_USE_SESSION_COUNT,
            "{}",
            aggregates.session_count_sum,
            accepted,
        )?;
        push_telemetry_statement(
            &mut statements,
            database,
            product,
            date,
            METRIC_USE_DAYS_ACTIVE,
            "{}",
            aggregates.days_active_sum,
            accepted,
        )?;
        for (bucket, sum) in aggregates.session_duration_sum.iter().enumerate() {
            push_telemetry_statement(
                &mut statements,
                database,
                product,
                date,
                METRIC_USE_SESSION_DURATION,
                &format!("{{\"bucket\":{bucket}}}"),
                *sum,
                accepted,
            )?;
        }
        for (feature, sum) in &aggregates.feature_hits_sum {
            let dims = serde_json::to_string(&BTreeMap::from([("feature_id", feature)]))
                .map_err(|_| Error::RustError("feature dims could not serialize".to_owned()))?;
            push_telemetry_statement(
                &mut statements,
                database,
                product,
                date,
                METRIC_USE_FEATURE_HITS,
                &dims,
                *sum,
                accepted,
            )?;
        }
    }
    for (metric, count) in &aggregates.counters {
        push_telemetry_statement(
            &mut statements,
            database,
            product,
            date,
            metric,
            "{}",
            *count,
            seen,
        )?;
    }

    while !statements.is_empty() {
        let take = statements
            .drain(..statements.len().min(D1_WRITE_BATCH))
            .collect();
        database.batch(take).await?;
    }
    Ok(())
}

fn aggregates_len(aggregate: &CubeAggregate) -> Result<i64> {
    to_i64(u64::try_from(aggregate.machines.len()).unwrap_or(u64::MAX))
}

/// The `dims_json` of a cube row: every dimension except `product`, which already has
/// its own column. Keys serialize in sorted order, so the JSON is deterministic.
fn dims_json(key: &CubeKey) -> String {
    let dims: BTreeMap<&str, &str> = key
        .dimension_names()
        .iter()
        .zip(key.dimensions().iter())
        .skip(1)
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    serde_json::to_string(&dims).unwrap_or_else(|_| "{}".to_owned())
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::RustError("rollup value is out of range".to_owned()))
}

fn now_seconds() -> i64 {
    i64::try_from(Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
}

fn integer(value: i64) -> Result<JsValue> {
    if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
        return Err(Error::RustError(
            "analytics integer exceeds JavaScript safe range".to_owned(),
        ));
    }
    Ok(JsValue::from_f64(value as f64))
}

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn blob(value: &[u8]) -> JsValue {
    JsValue::from(&D1Type::Blob(value))
}

#[derive(Debug, Deserialize)]
struct TelemetryTierRow {
    telemetry_tier: String,
}

#[derive(Debug, Deserialize)]
struct FeatureIdRow {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap as Map;

    fn block(consent: u64, sessions: u64) -> TelemetryBlock {
        TelemetryBlock {
            consent_version: consent,
            window_start: 1_800_000_000,
            session_count: sessions,
            session_duration_histogram: [10, 5, 2, 0],
            feature_hits: Map::from([(String::from("export"), 4)]),
            days_active: 9,
        }
    }

    fn detail_record(kind: &str) -> AnalyticsDetailEvent {
        AnalyticsDetailEvent {
            event: ANALYTICS_DETAIL_EVENT.to_owned(),
            schema_version: ANALYTICS_DETAIL_SCHEMA_VERSION,
            record_id: "ab".repeat(16),
            occurred_at: 1_800_000_000,
            kind: kind.to_owned(),
            product_id: "product_1".to_owned(),
            machine_key: vec![7; 32],
            app_version: "1.2.3".to_owned(),
            os: "macos".to_owned(),
            arch: "arm64".to_owned(),
            country: Some("DE".to_owned()),
            activation_path: "online".to_owned(),
            mode: "O".to_owned(),
            release_id: "rel_1".to_owned(),
            policy_id: "policy_1".to_owned(),
            sdk_version: "0.1.0".to_owned(),
            reused: (kind == ANALYTICS_KIND_ACTIVATION).then_some(false),
            telemetry: None,
            telemetry_dropped: None,
            clip_events: Vec::new(),
        }
    }

    #[test]
    fn a_non_t1_policy_drops_telemetry_as_a_tier_gate() {
        assert_eq!(
            evaluate_telemetry("T0", &block(3, 12), &["export"]),
            TelemetryOutcome::Dropped(TELEMETRY_DROPPED_TIER_GATE)
        );
        assert_eq!(
            evaluate_telemetry("Off", &block(3, 12), &["export"]),
            TelemetryOutcome::Dropped(TELEMETRY_DROPPED_TIER_GATE)
        );
    }

    #[test]
    fn missing_consent_drops_telemetry_and_is_counted() {
        assert_eq!(
            evaluate_telemetry("T1", &block(0, 12), &["export"]),
            TelemetryOutcome::Dropped(TELEMETRY_DROPPED_NO_CONSENT)
        );
    }

    #[test]
    fn poisoned_values_arrive_clipped_and_flagged() -> std::result::Result<(), String> {
        let outcome = evaluate_telemetry("T1", &block(3, 1_000_000_000), &["export"]);
        let TelemetryOutcome::Accepted { values, clip_kinds } = outcome else {
            return Err("poisoned block must be accepted after clipping".to_owned());
        };
        assert_eq!(values.session_count, 10_000);
        assert_eq!(clip_kinds, ["session_count_clipped"]);
        Ok(())
    }

    #[test]
    fn undeclared_features_are_dropped_from_the_allow_list() -> std::result::Result<(), String> {
        let mut poisoned = block(3, 12);
        poisoned.feature_hits.insert(String::from("spy"), 1);
        let TelemetryOutcome::Accepted { values, clip_kinds } =
            evaluate_telemetry("T1", &poisoned, &["export"])
        else {
            return Err(
                "block with an undeclared feature must be accepted minus the key".to_owned(),
            );
        };
        assert_eq!(
            values.feature_hits,
            Map::from([(String::from("export"), 4)])
        );
        assert_eq!(clip_kinds, ["feature_key_dropped"]);
        Ok(())
    }

    #[test]
    fn cube_keys_cover_the_nine_fixed_cubes() {
        let keys = cube_keys(&detail_record(ANALYTICS_KIND_CHECK_IN));
        assert_eq!(keys.len(), 9);
        assert_eq!(
            keys.first().map(|(encoded, _)| encoded.as_str()),
            Some("cube_0|product_1")
        );
        assert_eq!(
            keys.get(2).map(|(encoded, _)| encoded.as_str()),
            Some("cube_2|product_1|macos|arm64")
        );
        let mut without_country = detail_record(ANALYTICS_KIND_CHECK_IN);
        without_country.country = None;
        assert_eq!(cube_keys(&without_country).len(), 8);
    }

    #[test]
    fn aggregation_counts_drops_clips_and_poisoned_sums() {
        let mut dropped = detail_record(ANALYTICS_KIND_CHECK_IN);
        dropped.telemetry_dropped = Some(TELEMETRY_DROPPED_NO_CONSENT.to_owned());
        let mut accepted = detail_record(ANALYTICS_KIND_CHECK_IN);
        accepted.machine_key = vec![9; 32];
        accepted.telemetry = Some(TelemetryValues {
            consent_version: 3,
            window_start: 1_800_000_000,
            session_count: 10_000,
            session_duration_histogram: [10, 5, 2, 0],
            feature_hits: Map::from([(String::from("export"), 4)]),
            days_active: 9,
        });
        accepted.clip_events = vec!["session_count_clipped".to_owned()];
        let activation = detail_record(ANALYTICS_KIND_ACTIVATION);

        let aggregates = aggregate_day(&[dropped, accepted, activation]);
        assert_eq!(aggregates.telemetry_seen, 2);
        assert_eq!(aggregates.telemetry_accepted, 1);
        assert_eq!(aggregates.session_count_sum, 10_000);
        assert_eq!(
            aggregates.counters.get(METRIC_T1_DROPPED_NO_CONSENT),
            Some(&1)
        );
        assert_eq!(
            aggregates.counters.get("t1.clipped_session_count"),
            Some(&1)
        );
        assert_eq!(aggregates.activations_new, 1);
        assert_eq!(aggregates.activations_by_path.get("online"), Some(&1));
        // Two distinct machines checked in.
        let cube_zero = aggregates.cubes.get("cube_0|product_1");
        assert_eq!(cube_zero.map(|cube| cube.machines.len()), Some(2));
        assert_eq!(cube_zero.map(|cube| cube.sketch.cardinality()), Some(2));
    }

    #[test]
    fn dims_json_omits_the_product_column_and_is_deterministic() {
        let record = detail_record(ANALYTICS_KIND_CHECK_IN);
        let keys = cube_keys(&record);
        let os_arch = keys.get(2).map(|(_, key)| dims_json(key));
        assert_eq!(
            os_arch.as_deref(),
            Some("{\"arch\":\"arm64\",\"os\":\"macos\"}")
        );
        let product_only = keys.first().map(|(_, key)| dims_json(key));
        assert_eq!(product_only.as_deref(), Some("{}"));
    }
}
