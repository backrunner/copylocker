use std::time::Duration;

use copylocker_proto::{Envelope, MachineCredential};
use copylocker_server_core::deactivate::plan as plan_deactivation;
use copylocker_server_core::heartbeat::{plan as plan_heartbeat, zombie_cutoff};
use copylocker_server_core::revoke::{
    plan_license as plan_license_revocation, plan_machine as plan_machine_revocation, RevokeError,
};
use copylocker_server_core::store::{ActivationStatus, LicenseStatus};
use copylocker_suite::cbor::decode_canonical;
use copylocker_suite::{DomainCtx, HashScheme, Signature, SignatureScheme};
use copylocker_suite_std::{FastSig, Sha256Scheme};
use copylocker_types::{ArtifactKind, LicenseId, MachineId, SuiteId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use worker::{
    durable_object, wasm_bindgen, Date, DurableObject, Env, Method, Request, Response, Result,
    SqlStorage, SqlStorageValue, State,
};

use super::{ready, unavailable};
use crate::events::{
    MachineProjection, ProjectionEvent, LICENSE_PROJECTION_EVENT, PROJECTION_SCHEMA_VERSION,
};
use crate::middleware::body::{self, BodyError};
use crate::response;

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS _sql_schema_migrations (
  id INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v BLOB
);
CREATE TABLE IF NOT EXISTS activations (
  machine_id BLOB PRIMARY KEY,
  fingerprint BLOB NOT NULL,
  attrs BLOB,
  device_kem_ek BLOB NOT NULL,
  device_sig_vk BLOB NOT NULL,
  status INTEGER NOT NULL,
  activation_path TEXT NOT NULL,
  release_id TEXT,
  variant_id INTEGER,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  last_hb_at INTEGER,
  refresh_after INTEGER,
  not_after INTEGER,
  build_fp TEXT,
  app_version TEXT,
  geo TEXT,
  transfer_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_act_fpr ON activations(fingerprint);
CREATE INDEX IF NOT EXISTS idx_act_status ON activations(status);
CREATE INDEX IF NOT EXISTS idx_act_hb ON activations(last_hb_at);
CREATE TABLE IF NOT EXISTS nonces (
  nonce BLOB PRIMARY KEY,
  seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonce_ts ON nonces(seen_at);
CREATE TABLE IF NOT EXISTS transfers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  machine_id BLOB NOT NULL,
  action INTEGER NOT NULL,
  at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  payload BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  sent_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(sent_at) WHERE sent_at IS NULL;
CREATE TABLE IF NOT EXISTS idem (
  key TEXT PRIMARY KEY,
  resp BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
INSERT OR IGNORE INTO _sql_schema_migrations(id) VALUES (1);
"#;

const SCHEMA_V2: &str = r#"
ALTER TABLE activations ADD COLUMN os TEXT;
ALTER TABLE activations ADD COLUMN arch TEXT;
ALTER TABLE activations ADD COLUMN sdk_version TEXT;
ALTER TABLE activations ADD COLUMN suspicion INTEGER NOT NULL DEFAULT 0;
INSERT INTO _sql_schema_migrations(id) VALUES (2);
"#;

const SCHEMA_V3: &str = r#"
ALTER TABLE idem ADD COLUMN kind TEXT;
ALTER TABLE idem ADD COLUMN request_hash BLOB;
INSERT INTO _sql_schema_migrations(id) VALUES (3);
"#;

const SCHEMA_V4: &str = r#"
ALTER TABLE activations ADD COLUMN credential_state BLOB;
INSERT INTO _sql_schema_migrations(id) VALUES (4);
"#;

const STATUS_ACTIVE: i64 = 0;
const STATUS_RELEASED: i64 = 1;
const STATUS_REVOKED: i64 = 2;
const STATUS_PENDING: i64 = 3;
const PENDING_TTL_SECS: i64 = 60;
const DEFAULT_NONCE_TTL_SECS: i64 = 48 * 60 * 60;
const IDEMPOTENCY_TTL_SECS: i64 = 24 * 60 * 60;
const RELEASED_RETENTION_SECS: i64 = 90 * 24 * 60 * 60;
const MAX_INTERNAL_BODY: usize = 64 * 1024;
const LICENSE_SCHEMA_VERSION: i32 = 4;
const MAX_CREDENTIAL_STATE: usize = 256;
const OUTBOX_BATCH_SIZE: i64 = 100;
const OPERATION_HASH_LABEL: &[u8] = b"copylocker/license-operation/v1";

#[durable_object]
#[derive(Debug)]
pub struct LicenseDO {
    state: State,
    env: Env,
    initialization_error: Option<String>,
}

impl DurableObject for LicenseDO {
    fn new(state: State, env: Env) -> Self {
        let initialization_error = initialize(&state.storage().sql())
            .err()
            .map(|error| error.to_string());
        Self {
            state,
            env,
            initialization_error,
        }
    }

    async fn fetch(&self, mut request: Request) -> Result<Response> {
        if let Some(error) = self.initialization_error.as_deref() {
            return unavailable("LicenseDO", error);
        }

        let method = request.method();
        let path = request.path();
        match (method, path.as_str()) {
            (Method::Get, "/health") => ready("LicenseDO", LICENSE_SCHEMA_VERSION),
            (Method::Post, "/init") => self.init(&mut request).await,
            (Method::Post, "/reserve") => self.reserve(&mut request).await,
            (Method::Post, "/complete") => self.complete(&mut request).await,
            (Method::Post, "/commit") => self.commit(&mut request).await,
            (Method::Post, "/deactivate") => self.deactivate(&mut request).await,
            (Method::Post, "/heartbeat") => self.heartbeat(&mut request).await,
            (Method::Post, "/revoke") => self.revoke(&mut request).await,
            (Method::Post, "/admin-update") => self.admin_update(&mut request).await,
            (Method::Post, "/validate") => self.validate(&mut request).await,
            (Method::Get, _) => internal_error(404, "not_found"),
            _ => internal_error(405, "method_not_allowed"),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        if let Some(error) = self.initialization_error.as_deref() {
            return unavailable("LicenseDO", error);
        }
        let now = now_seconds();
        self.reclaim(now)?;
        self.flush_outbox(now).await?;
        self.schedule_next_alarm(now).await?;
        Response::empty()
    }
}

impl LicenseDO {
    async fn init(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<InitRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        let heartbeat_sec = match input.heartbeat_sec.map(i64::try_from).transpose() {
            Ok(value) => value,
            Err(_) => return internal_error(400, "invalid_request"),
        };
        if input.license_id.len() != 16
            || !is_product_id(&input.product_id)
            || SuiteId::from_slice(&input.suite_id).is_none()
            || input.seats == 0
            || input.seats > 100_000
            || heartbeat_sec == Some(0)
            || input.nonce_ttl_sec.is_some_and(|value| value <= 0)
        {
            return internal_error(400, "invalid_request");
        }
        if !self.owns_license(&input.license_id)? {
            return internal_error(409, "identity_conflict");
        }

        let sql = self.state.storage().sql();
        if let Some(existing) = meta_blob(&sql, "license_id")? {
            if existing != input.license_id {
                return internal_error(409, "identity_conflict");
            }
        }
        if let Some(existing) = meta_text(&sql, "product_id")? {
            if existing != input.product_id {
                return internal_error(409, "identity_conflict");
            }
        }
        if let Some(existing) = meta_blob(&sql, "suite_id")? {
            if existing != input.suite_id {
                return internal_error(409, "identity_conflict");
            }
        }

        upsert_meta(&sql, "license_id", input.license_id.into())?;
        upsert_meta(&sql, "product_id", input.product_id.into())?;
        upsert_meta(&sql, "suite_id", input.suite_id.into())?;
        upsert_meta(&sql, "seats", i64::from(input.seats).into())?;
        upsert_optional_i64(&sql, "heartbeat_sec", heartbeat_sec)?;
        upsert_optional_i64(&sql, "expires_at", input.expires_at)?;
        upsert_meta(
            &sql,
            "nonce_ttl_sec",
            input.nonce_ttl_sec.unwrap_or(DEFAULT_NONCE_TTL_SECS).into(),
        )?;
        sql.exec(
            "INSERT OR IGNORE INTO meta(k, v) VALUES ('status', 'active')",
            None,
        )?;
        apply_pending_admin_update(&sql)?;
        sql.exec(
            "INSERT OR IGNORE INTO meta(k, v) VALUES ('proj_version', 0)",
            None,
        )?;
        sql.exec(
            "INSERT OR IGNORE INTO meta(k, v) VALUES ('revocation_epoch', 0)",
            None,
        )?;
        sql.exec(
            "INSERT OR IGNORE INTO meta(k, v) VALUES ('security_floor', 0)",
            None,
        )?;

        self.schedule_next_alarm(now_seconds()).await?;
        response::json(200, &OkResponse { ok: true })
    }

    async fn admin_update(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<AdminUpdateRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        let heartbeat_sec = match input.heartbeat_sec.map(i64::try_from).transpose() {
            Ok(value) => value,
            Err(_) => return internal_error(400, "invalid_request"),
        };
        if input.license_id.len() != LicenseId::LEN
            || input.operation_id.is_empty()
            || input.operation_id.len() > 512
            || input
                .operation_id
                .bytes()
                .any(|byte| !byte.is_ascii_graphic())
            || input.version <= 0
            || input.seats == 0
            || input.seats > 100_000
            || heartbeat_sec == Some(0)
            || input.expires_at.is_some_and(|value| value < 0)
            || !matches!(input.status.as_str(), "active" | "suspended" | "expired")
        {
            return internal_error(400, "invalid_request");
        }
        if !self.owns_license(&input.license_id)? {
            return internal_error(409, "identity_conflict");
        }

        let encoded = serde_json::to_vec(&input)?;
        let request_hash =
            Sha256Scheme::hash_parts(&[OPERATION_HASH_LABEL, b"admin-update", &encoded]);
        let cache_key = format!("admin:{}", input.operation_id);
        let sql = self.state.storage().sql();
        match load_operation_response(&sql, &cache_key, "admin-update", request_hash.as_bytes())? {
            OperationReplay::Completed => {
                return response::json(
                    200,
                    &AdminUpdateResponse {
                        ok: true,
                        initialized: meta_blob(&sql, "license_id")?.is_some(),
                    },
                );
            }
            OperationReplay::Conflict => return internal_error(409, "idempotency_conflict"),
            OperationReplay::Missing => {}
        }

        let initialized = meta_blob(&sql, "license_id")?.is_some();
        let current_version = meta_i64(&sql, "admin_version")?.unwrap_or(0);
        if current_version >= input.version {
            store_operation_response(
                &sql,
                &cache_key,
                "admin-update",
                request_hash.as_bytes(),
                now_seconds(),
            )?;
            return response::json(
                200,
                &AdminUpdateResponse {
                    ok: true,
                    initialized,
                },
            );
        }

        let Some(stored_license_id) = meta_blob(&sql, "license_id")? else {
            upsert_meta(&sql, "pending_admin_status", input.status.into())?;
            upsert_meta(&sql, "pending_admin_seats", i64::from(input.seats).into())?;
            upsert_optional_i64(&sql, "pending_admin_heartbeat_sec", heartbeat_sec)?;
            upsert_optional_i64(&sql, "pending_admin_expires_at", input.expires_at)?;
            upsert_meta(&sql, "pending_admin_update", 1_i64.into())?;
            upsert_meta(&sql, "admin_version", input.version.into())?;
            store_operation_response(
                &sql,
                &cache_key,
                "admin-update",
                request_hash.as_bytes(),
                now_seconds(),
            )?;
            return response::json(
                200,
                &AdminUpdateResponse {
                    ok: true,
                    initialized: false,
                },
            );
        };
        if stored_license_id != input.license_id {
            return internal_error(409, "identity_conflict");
        }
        if meta_text(&sql, "status")?.as_deref() == Some("revoked") {
            return internal_error(409, "license_revoked");
        }

        upsert_meta(&sql, "status", input.status.into())?;
        upsert_meta(&sql, "seats", i64::from(input.seats).into())?;
        upsert_optional_i64(&sql, "heartbeat_sec", heartbeat_sec)?;
        upsert_optional_i64(&sql, "expires_at", input.expires_at)?;
        let now = now_seconds();
        append_projection(&sql, None, now)?;
        upsert_meta(&sql, "admin_version", input.version.into())?;
        store_operation_response(
            &sql,
            &cache_key,
            "admin-update",
            request_hash.as_bytes(),
            now,
        )?;
        self.schedule_next_alarm(now).await?;
        response::json(
            200,
            &AdminUpdateResponse {
                ok: true,
                initialized: true,
            },
        )
    }

    async fn reserve(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<ReserveRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        let Some(variant_id) = validate_reservation(&input) else {
            return internal_error(400, "invalid_request");
        };

        let now = now_seconds();
        let sql = self.state.storage().sql();
        let Some(seats) = meta_i64(&sql, "seats")? else {
            return internal_error(409, "not_initialized");
        };
        if meta_text(&sql, "status")?.as_deref() != Some("active")
            || meta_i64(&sql, "expires_at")?.is_some_and(|expiry| now >= expiry)
        {
            return internal_error(401, "invalid_credential");
        }
        let revocation_epoch = meta_i64(&sql, "revocation_epoch")?.unwrap_or(0);
        let security_floor = meta_i64(&sql, "security_floor")?.unwrap_or(0);

        let cache_key = format!("reserve:{}", input.idempotency_key);
        let request_hash = reserve_request_hash(&input)?;
        match load_operation_response(&sql, &cache_key, "reserve", request_hash.as_bytes())? {
            OperationReplay::Completed => {
                let cached = load_idempotent_response(&sql, &cache_key)?.ok_or_else(|| {
                    worker::Error::RustError("reservation idempotency row is corrupt".to_owned())
                })?;
                let current_status = activation_status(&sql, &cached.machine_id)?;
                let replayable = cached.activation_envelope.is_some()
                    || matches!(current_status, Some(STATUS_ACTIVE | STATUS_PENDING));
                if replayable {
                    let status = if cached.reused_existing { 200 } else { 201 };
                    return response::json(status, &cached);
                }
                sql.exec(
                    "DELETE FROM idem WHERE key = ?",
                    Some(vec![cache_key.clone().into()]),
                )?;
            }
            OperationReplay::Conflict => return internal_error(409, "idempotency_conflict"),
            OperationReplay::Missing => {}
        }

        let existing = sql
            .exec(
                "SELECT machine_id, status FROM activations \
                 WHERE fingerprint = ? AND status IN (0, 3) \
                 ORDER BY status, created_at LIMIT 1",
                Some(vec![input.fingerprint.clone().into()]),
            )?
            .to_array::<ActivationIdentity>()?
            .into_iter()
            .next();

        let (reservation, status) = if let Some(existing) = existing {
            if existing.status == STATUS_PENDING {
                return internal_error(409, "activation_pending");
            }
            let state = activation_status_name(existing.status).to_owned();
            (
                ReserveResponse {
                    ok: true,
                    machine_id: existing.machine_id,
                    reused_existing: true,
                    status: state,
                    revocation_epoch,
                    security_floor,
                    variant_id,
                    refresh_after: input.refresh_after,
                    not_after: input.not_after,
                    build_fp: input.build_fp.clone(),
                    fingerprint: input.fingerprint.clone(),
                    credential_state: input.credential_state.clone(),
                    activation_envelope: None,
                    material: Some(ReserveMaterial::from(&input)),
                },
                200,
            )
        } else {
            let occupied = sql
                .exec(
                    "SELECT COUNT(*) AS count FROM activations WHERE status IN (0, 3)",
                    None,
                )?
                .one::<CountRow>()?
                .count;
            if occupied >= seats {
                return internal_error(409, "seat_exhausted");
            }

            sql.exec(
                "INSERT INTO activations( \
                   machine_id, fingerprint, attrs, device_kem_ek, device_sig_vk, status, \
                   activation_path, release_id, variant_id, created_at, last_seen_at, \
                   refresh_after, not_after, build_fp, app_version, os, arch, sdk_version, geo, \
                   credential_state \
                 ) VALUES (?, ?, ?, ?, ?, 3, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                Some(vec![
                    input.machine_id.clone().into(),
                    input.fingerprint.clone().into(),
                    input.attrs.clone().into(),
                    input.device_kem_ek.clone().into(),
                    input.device_sig_vk.clone().into(),
                    input.activation_path.clone().into(),
                    input.release_id.clone().into(),
                    variant_id.into(),
                    now.into(),
                    now.into(),
                    input.refresh_after.into(),
                    input.not_after.into(),
                    input.build_fp.clone().into(),
                    input.app_version.clone().into(),
                    input.os.clone().into(),
                    input.arch.clone().into(),
                    input.sdk_version.clone().into(),
                    input.geo.clone().into(),
                    input.credential_state.clone().into(),
                ]),
            )?;
            append_projection(&sql, Some(&input.machine_id), now)?;
            (
                ReserveResponse {
                    ok: true,
                    machine_id: input.machine_id.clone(),
                    reused_existing: false,
                    status: "pending".to_owned(),
                    revocation_epoch,
                    security_floor,
                    variant_id,
                    refresh_after: input.refresh_after,
                    not_after: input.not_after,
                    build_fp: input.build_fp.clone(),
                    fingerprint: input.fingerprint.clone(),
                    credential_state: input.credential_state.clone(),
                    activation_envelope: None,
                    material: Some(ReserveMaterial::from(&input)),
                },
                201,
            )
        };

        store_idempotent_response(&sql, &cache_key, &reservation, request_hash.as_bytes(), now)?;
        self.schedule_next_alarm(now).await?;
        response::json(status, &reservation)
    }

    async fn complete(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<CompleteRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        if input.idempotency_key.is_empty()
            || input.idempotency_key.len() > 128
            || input.request_hash.len() != copylocker_types::Digest::LEN
            || input.machine_id.len() != MachineId::LEN
            || input.activation_envelope.is_empty()
            || input.activation_envelope.len() > MAX_INTERNAL_BODY
        {
            return internal_error(400, "invalid_request");
        }

        let now = now_seconds();
        let sql = self.state.storage().sql();
        let cache_key = format!("reserve:{}", input.idempotency_key);
        match load_operation_response(&sql, &cache_key, "reserve", &input.request_hash)? {
            OperationReplay::Completed => {}
            OperationReplay::Conflict => return internal_error(409, "idempotency_conflict"),
            OperationReplay::Missing => return internal_error(409, "reservation_missing"),
        }
        let mut reservation = load_idempotent_response(&sql, &cache_key)?.ok_or_else(|| {
            worker::Error::RustError("reservation idempotency row is corrupt".to_owned())
        })?;
        if reservation.machine_id != input.machine_id {
            return internal_error(409, "idempotency_conflict");
        }
        if let Some(envelope) = reservation.activation_envelope {
            self.schedule_next_alarm(now).await?;
            return response::json(200, &CompleteResponse { ok: true, envelope });
        }
        let Some(material) = reservation.material.as_ref() else {
            return internal_error(409, "reservation_incompatible");
        };
        let Some(credential_state) = reservation.credential_state.as_ref() else {
            return internal_error(409, "reservation_incompatible");
        };
        if !completion_matches(&sql, &input.activation_envelope, &reservation, material)? {
            return internal_error(400, "invalid_artifact");
        }
        let Some(status) = activation_status(&sql, &input.machine_id)? else {
            return internal_error(409, "reservation_missing");
        };
        if !matches!(status, STATUS_ACTIVE | STATUS_PENDING) {
            return internal_error(401, "invalid_credential");
        }

        sql.exec(
            "UPDATE activations SET fingerprint = ?, attrs = ?, device_kem_ek = ?, \
             device_sig_vk = ?, status = 0, activation_path = ?, release_id = ?, \
             variant_id = ?, last_seen_at = ?, refresh_after = ?, not_after = ?, \
             build_fp = ?, app_version = ?, os = ?, arch = ?, sdk_version = ?, geo = ?, \
             credential_state = ? WHERE machine_id = ? AND status IN (0, 3)",
            Some(vec![
                reservation.fingerprint.clone().into(),
                material.attrs.clone().into(),
                material.device_kem_ek.clone().into(),
                material.device_sig_vk.clone().into(),
                material.activation_path.clone().into(),
                material.release_id.clone().into(),
                material.variant_id.into(),
                now.into(),
                material.refresh_after.into(),
                material.not_after.into(),
                material.build_fp.clone().into(),
                material.app_version.clone().into(),
                material.os.clone().into(),
                material.arch.clone().into(),
                material.sdk_version.clone().into(),
                material.geo.clone().into(),
                credential_state.clone().into(),
                input.machine_id.clone().into(),
            ]),
        )?;
        append_projection(&sql, Some(&input.machine_id), now)?;
        reservation.status = "active".to_owned();
        reservation.activation_envelope = Some(input.activation_envelope.clone());
        update_idempotent_response(&sql, &cache_key, &reservation, &input.request_hash)?;

        self.schedule_next_alarm(now).await?;
        response::json(
            200,
            &CompleteResponse {
                ok: true,
                envelope: input.activation_envelope,
            },
        )
    }

    async fn commit(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<MachineRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        if input.machine_id.len() != 16 {
            return internal_error(400, "invalid_request");
        }

        let now = now_seconds();
        let sql = self.state.storage().sql();
        let Some(status) = activation_status(&sql, &input.machine_id)? else {
            return internal_error(401, "invalid_credential");
        };
        match status {
            STATUS_PENDING => {
                sql.exec(
                    "UPDATE activations SET status = 0, last_seen_at = ? \
                     WHERE machine_id = ? AND status = 3",
                    Some(vec![now.into(), input.machine_id.clone().into()]),
                )?;
                append_projection(&sql, Some(&input.machine_id), now)?;
            }
            STATUS_ACTIVE => {}
            STATUS_RELEASED | STATUS_REVOKED => {
                return internal_error(401, "invalid_credential");
            }
            _ => return internal_error(500, "storage_corrupt"),
        }

        self.schedule_next_alarm(now).await?;
        response::json(200, &OkResponse { ok: true })
    }

    async fn deactivate(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<AuthenticatedMachineRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        if input.idempotency_key.is_empty() || input.idempotency_key.len() > 117 {
            return internal_error(400, "invalid_request");
        }

        let now = now_seconds();
        let sql = self.state.storage().sql();
        let cache_key = format!("deactivate:{}", input.idempotency_key);
        let request_hash = authenticated_request_hash(ArtifactKind::DeactivateRequest, &input);
        match load_operation_response(&sql, &cache_key, "deactivate", request_hash.as_bytes())? {
            OperationReplay::Completed => {
                self.schedule_next_alarm(now).await?;
                return response::json(200, &OkResponse { ok: true });
            }
            OperationReplay::Conflict => return internal_error(409, "idempotency_conflict"),
            OperationReplay::Missing => {}
        }

        let Some(activation) =
            self.authenticate_device(&sql, &input, ArtifactKind::DeactivateRequest)?
        else {
            return internal_error(401, "invalid_credential");
        };
        if !record_nonce(&sql, &input.nonce, now)? {
            return internal_error(409, "replayed_nonce");
        }
        let Some(status) = activation_status_from_storage(activation.status) else {
            return internal_error(500, "storage_corrupt");
        };
        let plan = match plan_deactivation(status) {
            Ok(plan) => plan,
            Err(_) => return internal_error(401, "invalid_credential"),
        };
        if plan.changed {
            let written = sql
                .exec(
                    "UPDATE activations SET status = 1, last_seen_at = ?, \
                     transfer_count = transfer_count + 1 \
                     WHERE machine_id = ? AND status IN (0, 3)",
                    Some(vec![now.into(), input.machine_id.clone().into()]),
                )?
                .rows_written();
            if written == 0 {
                return internal_error(500, "storage_corrupt");
            }
            if plan.record_transfer {
                sql.exec(
                    "INSERT INTO transfers(machine_id, action, at) VALUES (?, 1, ?)",
                    Some(vec![input.machine_id.clone().into(), now.into()]),
                )?;
            }
            append_projection(&sql, Some(&input.machine_id), now)?;
        }
        store_operation_response(&sql, &cache_key, "deactivate", request_hash.as_bytes(), now)?;

        self.schedule_next_alarm(now).await?;
        response::json(200, &OkResponse { ok: true })
    }

    async fn heartbeat(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<AuthenticatedMachineRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };

        let now = now_seconds();
        let sql = self.state.storage().sql();
        let Some(activation) =
            self.authenticate_device(&sql, &input, ArtifactKind::HeartbeatRequest)?
        else {
            return internal_error(401, "invalid_credential");
        };
        let Some(activation_status) = activation_status_from_storage(activation.status) else {
            return internal_error(500, "storage_corrupt");
        };
        let Some(license_status) = meta_text(&sql, "status")? else {
            return internal_error(409, "not_initialized");
        };
        let Some(license_status) = license_status_from_storage(&license_status) else {
            return internal_error(500, "storage_corrupt");
        };
        let heartbeat_secs = meta_i64(&sql, "heartbeat_sec")?;
        if heartbeat_secs.is_some_and(|value| value <= 0) {
            return internal_error(500, "storage_corrupt");
        }
        let heartbeat = match plan_heartbeat(
            license_status,
            meta_i64(&sql, "expires_at")?,
            activation_status,
            heartbeat_secs,
            now,
        ) {
            Ok(plan) => plan,
            Err(_) => return internal_error(401, "invalid_credential"),
        };
        if !record_nonce(&sql, &input.nonce, now)? {
            return internal_error(409, "replayed_nonce");
        }
        let written = sql
            .exec(
                "UPDATE activations SET last_hb_at = ?, last_seen_at = ? \
                 WHERE machine_id = ? AND status = 0",
                Some(vec![
                    now.into(),
                    now.into(),
                    input.machine_id.clone().into(),
                ]),
            )?
            .rows_written();
        if written == 0 {
            return internal_error(401, "invalid_credential");
        }
        append_projection(&sql, Some(&input.machine_id), now)?;

        self.schedule_next_alarm(now).await?;
        response::json(
            200,
            &HeartbeatResponse {
                ok: true,
                next_after: heartbeat.next_after,
            },
        )
    }

    async fn revoke(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<RevokeRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        let subject = match (input.kind, input.machine_id.as_deref()) {
            (RevokeKind::License, None) => RevokeSubject::License,
            (RevokeKind::Machine, Some(id)) if id.len() == MachineId::LEN => {
                RevokeSubject::Machine(id)
            }
            _ => return internal_error(400, "invalid_request"),
        };
        if input.license_id.len() != LicenseId::LEN
            || input.revocation_epoch == 0
            || i64::try_from(input.revocation_epoch).is_err()
        {
            return internal_error(400, "invalid_request");
        }
        if !self.owns_license(&input.license_id)? {
            return internal_error(409, "identity_conflict");
        }

        let now = now_seconds();
        let sql = self.state.storage().sql();
        if meta_blob(&sql, "license_id")?.as_deref() != Some(input.license_id.as_slice()) {
            return internal_error(409, "not_initialized");
        }
        let current_epoch = meta_i64(&sql, "revocation_epoch")?.unwrap_or(0);
        let Ok(current_epoch) = u64::try_from(current_epoch) else {
            return internal_error(500, "storage_corrupt");
        };

        let mut previous_license_status = None;
        let plan = match subject {
            RevokeSubject::License => {
                let Some(status) = meta_text(&sql, "status")? else {
                    return internal_error(409, "not_initialized");
                };
                let Some(core_status) = license_status_from_storage(&status) else {
                    return internal_error(500, "storage_corrupt");
                };
                previous_license_status = Some(status);
                plan_license_revocation(core_status, current_epoch, input.revocation_epoch)
            }
            RevokeSubject::Machine(machine_id) => {
                let status = activation_status(&sql, machine_id)?;
                let status = match status {
                    Some(status) => {
                        let Some(status) = activation_status_from_storage(status) else {
                            return internal_error(500, "storage_corrupt");
                        };
                        Some(status)
                    }
                    None => None,
                };
                plan_machine_revocation(status, current_epoch, input.revocation_epoch)
            }
        };
        let plan = match plan {
            Ok(plan) => plan,
            Err(RevokeError::UnknownMachine) => return internal_error(404, "not_found"),
            Err(RevokeError::StaleEpoch) => return internal_error(409, "stale_revocation_epoch"),
        };

        if plan.state_changed {
            let written = match subject {
                RevokeSubject::License => {
                    let Some(previous_status) = previous_license_status.as_deref() else {
                        return Err(worker::Error::RustError(
                            "license revocation plan omitted its prior status".to_owned(),
                        ));
                    };
                    sql.exec(
                        "UPDATE meta SET v = 'revoked' \
                         WHERE k = 'status' AND CAST(v AS TEXT) = ?",
                        Some(vec![previous_status.into()]),
                    )?
                    .rows_written()
                }
                RevokeSubject::Machine(machine_id) => sql
                    .exec(
                        "UPDATE activations SET status = 2, last_seen_at = ? \
                         WHERE machine_id = ? AND status != 2",
                        Some(vec![now.into(), machine_id.to_vec().into()]),
                    )?
                    .rows_written(),
            };
            if written == 0 {
                return internal_error(500, "storage_corrupt");
            }
        }
        if plan.epoch_changed {
            let epoch = i64::try_from(plan.revocation_epoch)
                .map_err(|_| worker::Error::RustError("revocation epoch overflow".to_owned()))?;
            upsert_meta(&sql, "revocation_epoch", epoch.into())?;
        }
        if plan.state_changed {
            let machine_id = match subject {
                RevokeSubject::License => None,
                RevokeSubject::Machine(machine_id) => Some(machine_id),
            };
            append_projection(&sql, machine_id, now)?;
        }

        self.schedule_next_alarm(now).await?;
        response::json(
            200,
            &RevokeResponse {
                ok: true,
                changed: plan.state_changed || plan.epoch_changed,
                revocation_epoch: plan.revocation_epoch,
            },
        )
    }

    async fn validate(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<ValidateMachineRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        if input.next_refresh_after <= 0
            || input.not_after < 0
            || input.variant_id.is_some_and(|value| value < 0)
        {
            return internal_error(400, "invalid_request");
        }

        let now = now_seconds();
        let sql = self.state.storage().sql();
        let Ok(known_revocation_epoch) = i64::try_from(input.known_revocation_epoch) else {
            return internal_error(401, "invalid_credential");
        };
        let Ok(authoritative_revocation_epoch) =
            i64::try_from(input.authoritative_revocation_epoch)
        else {
            return internal_error(400, "invalid_request");
        };
        let Ok(known_security_floor) = i64::try_from(input.known_security_floor) else {
            return internal_error(401, "invalid_credential");
        };
        let Some(activation) =
            self.authenticate_device(&sql, &input.auth, ArtifactKind::ValidateRequest)?
        else {
            return internal_error(401, "invalid_credential");
        };
        let local_revocation_epoch = meta_i64(&sql, "revocation_epoch")?.unwrap_or(0);
        let revocation_epoch = local_revocation_epoch.max(authoritative_revocation_epoch);
        let security_floor = meta_i64(&sql, "security_floor")?.unwrap_or(0);
        if known_revocation_epoch > revocation_epoch || known_security_floor > security_floor {
            return internal_error(401, "invalid_credential");
        }
        if revocation_epoch != local_revocation_epoch {
            upsert_meta(&sql, "revocation_epoch", revocation_epoch.into())?;
        }
        if !record_nonce(&sql, &input.auth.nonce, now)? {
            return internal_error(409, "replayed_nonce");
        }

        let license_status = meta_text(&sql, "status")?;
        let kill_reason = if license_status.as_deref() == Some("revoked") {
            Some(1_u8)
        } else {
            match activation.status {
                STATUS_REVOKED => Some(2),
                STATUS_RELEASED => Some(3),
                STATUS_ACTIVE | STATUS_PENDING => None,
                _ => return internal_error(500, "storage_corrupt"),
            }
        };

        let outcome = if let Some(reason) = kill_reason {
            ValidateStateResponse {
                ok: true,
                outcome: "kill",
                kill_reason: Some(reason),
                revocation_epoch,
                security_floor,
                suspicion: activation.suspicion,
                fingerprint: None,
                credential_state: None,
            }
        } else {
            if license_status.as_deref() != Some("active")
                || meta_i64(&sql, "expires_at")?.is_some_and(|expiry| now >= expiry)
            {
                return internal_error(401, "invalid_credential");
            }
            sql.exec(
                "UPDATE activations SET last_seen_at = ?, refresh_after = ?, not_after = ?, \
                 variant_id = COALESCE(?, variant_id) WHERE machine_id = ? AND status IN (0, 3)",
                Some(vec![
                    now.into(),
                    input.next_refresh_after.into(),
                    input.not_after.into(),
                    input.variant_id.into(),
                    input.auth.machine_id.clone().into(),
                ]),
            )?;
            append_projection(&sql, Some(&input.auth.machine_id), now)?;
            ValidateStateResponse {
                ok: true,
                outcome: "ticket",
                kill_reason: None,
                revocation_epoch,
                security_floor,
                suspicion: activation.suspicion,
                fingerprint: Some(activation.fingerprint),
                credential_state: activation.credential_state,
            }
        };

        self.schedule_next_alarm(now).await?;
        response::json(200, &outcome)
    }

    fn authenticate_device(
        &self,
        sql: &SqlStorage,
        input: &AuthenticatedMachineRequest,
        kind: ArtifactKind,
    ) -> Result<Option<AuthenticatedActivation>> {
        if input.license_id.len() != 16
            || input.machine_id.len() != 16
            || input.suite_id.len() != SuiteId::LEN
            || input.nonce.len() != 32
            || input.proof_input.is_empty()
            || input.proof_input.len() > copylocker_types::MAX_BODY_BYTES
            || input.proof.len() != FastSig::SIG_MAX_LEN
            || !proof_input_matches(kind, input)
            || !self.owns_license(&input.license_id)?
        {
            return Ok(None);
        }
        if meta_blob(sql, "license_id")?.as_deref() != Some(input.license_id.as_slice())
            || meta_blob(sql, "suite_id")?.as_deref() != Some(input.suite_id.as_slice())
        {
            return Ok(None);
        }
        let Some(product_id) = meta_text(sql, "product_id")? else {
            return Ok(None);
        };
        let Some(suite_id) = SuiteId::from_slice(&input.suite_id) else {
            return Ok(None);
        };
        let activation = sql
            .exec(
                "SELECT device_sig_vk, status, suspicion, fingerprint, credential_state \
                 FROM activations WHERE machine_id = ?",
                Some(vec![input.machine_id.clone().into()]),
            )?
            .to_array::<AuthenticatedActivation>()?
            .into_iter()
            .next();
        let Some(activation) = activation else {
            return Ok(None);
        };
        let Ok(verifying_key) = FastSig::decode_vk(&activation.device_sig_vk) else {
            return Ok(None);
        };
        let signature = Signature(input.proof.clone());
        let context = DomainCtx::new(kind, suite_id, &product_id);
        if FastSig::verify(&verifying_key, context, &input.proof_input, &signature).is_err() {
            return Ok(None);
        }
        Ok(Some(activation))
    }

    fn owns_license(&self, license_id: &[u8]) -> Result<bool> {
        let Some(license_id) = LicenseId::from_slice(license_id) else {
            return Ok(false);
        };
        let namespace = self.env.durable_object("LICENSE")?;
        let expected = namespace.id_from_name(&license_id.to_hex())?;
        Ok(self.state.id().to_string() == expected.to_string())
    }

    fn reclaim(&self, now: i64) -> Result<()> {
        let sql = self.state.storage().sql();

        let pending = sql
            .exec(
                "UPDATE activations SET status = 1, last_seen_at = ? \
                 WHERE status = 3 AND created_at <= ? RETURNING machine_id",
                Some(vec![
                    now.into(),
                    now.saturating_sub(PENDING_TTL_SECS).into(),
                ]),
            )?
            .to_array::<MachineRow>()?;
        for row in pending {
            append_projection(&sql, Some(&row.machine_id), now)?;
        }

        if let Some(heartbeat) = meta_i64(&sql, "heartbeat_sec")? {
            let Some(stale_before) = zombie_cutoff(heartbeat, now) else {
                return Err(worker::Error::RustError(
                    "heartbeat interval is invalid".to_owned(),
                ));
            };
            let zombies = sql
                .exec(
                    "UPDATE activations SET status = 1, last_seen_at = ? \
                     WHERE status = 0 \
                       AND COALESCE(last_hb_at, last_seen_at, created_at) < ? \
                     RETURNING machine_id",
                    Some(vec![now.into(), stale_before.into()]),
                )?
                .to_array::<MachineRow>()?;
            for row in zombies {
                append_projection(&sql, Some(&row.machine_id), now)?;
            }
        }

        if meta_text(&sql, "status")?.as_deref() == Some("active")
            && meta_i64(&sql, "expires_at")?.is_some_and(|expiry| now >= expiry)
        {
            upsert_meta(&sql, "status", "expired".into())?;
            let expired = sql
                .exec(
                    "UPDATE activations SET status = 1, last_seen_at = ? \
                     WHERE status IN (0, 3) RETURNING machine_id",
                    Some(vec![now.into()]),
                )?
                .to_array::<MachineRow>()?;
            for row in expired {
                append_projection(&sql, Some(&row.machine_id), now)?;
            }
            append_projection(&sql, None, now)?;
        }

        let nonce_ttl = meta_i64(&sql, "nonce_ttl_sec")?.unwrap_or(DEFAULT_NONCE_TTL_SECS);
        sql.exec(
            "DELETE FROM nonces WHERE seen_at <= ?",
            Some(vec![now.saturating_sub(nonce_ttl).into()]),
        )?;
        sql.exec(
            "DELETE FROM idem WHERE created_at <= ?",
            Some(vec![now.saturating_sub(IDEMPOTENCY_TTL_SECS).into()]),
        )?;
        sql.exec(
            "DELETE FROM activations WHERE status = 1 \
             AND COALESCE(last_seen_at, created_at) <= ?",
            Some(vec![now.saturating_sub(RELEASED_RETENTION_SECS).into()]),
        )?;
        Ok(())
    }

    async fn flush_outbox(&self, now: i64) -> Result<()> {
        let sql = self.state.storage().sql();
        let rows = sql
            .exec(
                "SELECT id, payload FROM outbox \
                 WHERE sent_at IS NULL ORDER BY id LIMIT ?",
                Some(vec![OUTBOX_BATCH_SIZE.into()]),
            )?
            .to_array::<OutboxRow>()?;
        if rows.is_empty() {
            return Ok(());
        }

        let queue = self.env.queue("EVENTS")?;
        for row in rows {
            let event = serde_json::from_slice::<ProjectionEvent>(&row.payload)
                .map_err(|error| worker::Error::RustError(error.to_string()))?;
            if !event.is_valid() {
                return Err(worker::Error::RustError(
                    "invalid projection event in durable outbox".to_owned(),
                ));
            }
            queue.send(event).await?;
            sql.exec(
                "UPDATE outbox SET sent_at = ? WHERE id = ? AND sent_at IS NULL",
                Some(vec![now.into(), row.id.into()]),
            )?;
        }
        Ok(())
    }

    async fn schedule_next_alarm(&self, now: i64) -> Result<()> {
        let sql = self.state.storage().sql();
        let mut candidates = vec![
            minimum_time(
                &sql,
                "SELECT MIN(?) AS at FROM outbox WHERE sent_at IS NULL",
                Some(vec![now.into()]),
            )?,
            minimum_time(
                &sql,
                "SELECT MIN(created_at + 60) AS at FROM activations WHERE status = 3",
                None,
            )?,
            minimum_time(
                &sql,
                "SELECT MIN(seen_at + CAST((SELECT v FROM meta WHERE k = 'nonce_ttl_sec') AS INTEGER)) AS at FROM nonces",
                None,
            )?,
            minimum_time(
                &sql,
                "SELECT MIN(created_at + 86400) AS at FROM idem",
                None,
            )?,
            minimum_time(
                &sql,
                "SELECT MIN(COALESCE(last_seen_at, created_at) + 7776000) AS at \
                 FROM activations WHERE status = 1",
                None,
            )?,
        ];
        if let Some(heartbeat) = meta_i64(&sql, "heartbeat_sec")? {
            candidates.push(minimum_time(
                &sql,
                "SELECT MIN(COALESCE(last_hb_at, last_seen_at, created_at) + ?) AS at \
                 FROM activations WHERE status = 0",
                Some(vec![heartbeat.saturating_mul(3).into()]),
            )?);
        }
        if meta_text(&sql, "status")?.as_deref() == Some("active") {
            candidates.push(meta_i64(&sql, "expires_at")?);
        }

        let storage = self.state.storage();
        if let Some(next) = candidates.into_iter().flatten().min() {
            let delay = u64::try_from(next.saturating_sub(now)).unwrap_or_default();
            storage.set_alarm(Duration::from_secs(delay)).await
        } else {
            storage.delete_alarm().await
        }
    }
}

#[derive(Debug, Deserialize)]
struct InitRequest {
    license_id: Vec<u8>,
    product_id: String,
    suite_id: Vec<u8>,
    seats: u32,
    #[serde(default)]
    heartbeat_sec: Option<u64>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    nonce_ttl_sec: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AdminUpdateRequest {
    license_id: Vec<u8>,
    operation_id: String,
    version: i64,
    status: String,
    seats: u32,
    heartbeat_sec: Option<u64>,
    expires_at: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReserveRequest {
    idempotency_key: String,
    #[serde(default)]
    request_hash: Option<Vec<u8>>,
    machine_id: Vec<u8>,
    fingerprint: Vec<u8>,
    #[serde(default)]
    attrs: Option<Vec<u8>>,
    device_kem_ek: Vec<u8>,
    device_sig_vk: Vec<u8>,
    activation_path: String,
    release_id: String,
    variant_id: u64,
    refresh_after: i64,
    not_after: i64,
    #[serde(default)]
    build_fp: Option<String>,
    #[serde(default)]
    app_version: Option<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    arch: Option<String>,
    #[serde(default)]
    sdk_version: Option<String>,
    #[serde(default)]
    geo: Option<String>,
    #[serde(default)]
    credential_state: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct CompleteRequest {
    idempotency_key: String,
    request_hash: Vec<u8>,
    machine_id: Vec<u8>,
    activation_envelope: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct MachineRequest {
    machine_id: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct AuthenticatedMachineRequest {
    license_id: Vec<u8>,
    machine_id: Vec<u8>,
    suite_id: Vec<u8>,
    nonce: Vec<u8>,
    proof_input: Vec<u8>,
    proof: Vec<u8>,
    #[serde(default)]
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
struct ValidateMachineRequest {
    auth: AuthenticatedMachineRequest,
    known_revocation_epoch: u64,
    authoritative_revocation_epoch: u64,
    known_security_floor: u64,
    next_refresh_after: i64,
    not_after: i64,
    #[serde(default)]
    variant_id: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RevokeKind {
    License,
    Machine,
}

#[derive(Clone, Copy, Debug)]
enum RevokeSubject<'a> {
    License,
    Machine(&'a [u8]),
}

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    license_id: Vec<u8>,
    kind: RevokeKind,
    #[serde(default)]
    machine_id: Option<Vec<u8>>,
    revocation_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ReserveResponse {
    ok: bool,
    machine_id: Vec<u8>,
    reused_existing: bool,
    status: String,
    #[serde(default)]
    revocation_epoch: i64,
    #[serde(default)]
    security_floor: i64,
    #[serde(default)]
    variant_id: i64,
    #[serde(default)]
    refresh_after: i64,
    #[serde(default)]
    not_after: i64,
    #[serde(default)]
    build_fp: Option<String>,
    #[serde(default)]
    fingerprint: Vec<u8>,
    #[serde(default)]
    credential_state: Option<Vec<u8>>,
    #[serde(default)]
    activation_envelope: Option<Vec<u8>>,
    #[serde(default)]
    material: Option<ReserveMaterial>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ReserveMaterial {
    attrs: Option<Vec<u8>>,
    device_kem_ek: Vec<u8>,
    device_sig_vk: Vec<u8>,
    activation_path: String,
    release_id: String,
    variant_id: i64,
    refresh_after: i64,
    not_after: i64,
    build_fp: Option<String>,
    app_version: Option<String>,
    os: Option<String>,
    arch: Option<String>,
    sdk_version: Option<String>,
    geo: Option<String>,
}

impl From<&ReserveRequest> for ReserveMaterial {
    fn from(input: &ReserveRequest) -> Self {
        Self {
            attrs: input.attrs.clone(),
            device_kem_ek: input.device_kem_ek.clone(),
            device_sig_vk: input.device_sig_vk.clone(),
            activation_path: input.activation_path.clone(),
            release_id: input.release_id.clone(),
            variant_id: i64::try_from(input.variant_id).unwrap_or(i64::MAX),
            refresh_after: input.refresh_after,
            not_after: input.not_after,
            build_fp: input.build_fp.clone(),
            app_version: input.app_version.clone(),
            os: input.os.clone(),
            arch: input.arch.clone(),
            sdk_version: input.sdk_version.clone(),
            geo: input.geo.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CompleteResponse {
    ok: bool,
    envelope: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct OkResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct AdminUpdateResponse {
    ok: bool,
    initialized: bool,
}

#[derive(Debug, Serialize)]
struct HeartbeatResponse {
    ok: bool,
    next_after: i64,
}

#[derive(Debug, Serialize)]
struct RevokeResponse {
    ok: bool,
    changed: bool,
    revocation_epoch: u64,
}

#[derive(Debug, Serialize)]
struct ValidateStateResponse {
    ok: bool,
    outcome: &'static str,
    kill_reason: Option<u8>,
    revocation_epoch: i64,
    security_floor: i64,
    suspicion: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<Vec<u8>>,
    credential_state: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
struct InternalError<'a> {
    ok: bool,
    error: &'a str,
}

#[derive(Debug, Deserialize)]
struct ActivationIdentity {
    #[serde(with = "serde_bytes")]
    machine_id: Vec<u8>,
    status: i64,
}

#[derive(Debug, Deserialize)]
struct MachineRow {
    #[serde(with = "serde_bytes")]
    machine_id: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct CountRow {
    count: i64,
}

#[derive(Debug, Deserialize)]
struct IntRow {
    value: i64,
}

#[derive(Debug, Deserialize)]
struct OptionalIntRow {
    value: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TextRow {
    value: String,
}

#[derive(Debug, Deserialize)]
struct BlobRow {
    #[serde(with = "serde_bytes")]
    resp: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct OperationIdempotencyRow {
    kind: Option<String>,
    #[serde(with = "serde_bytes")]
    request_hash: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct AuthenticatedActivation {
    #[serde(with = "serde_bytes")]
    device_sig_vk: Vec<u8>,
    status: i64,
    suspicion: i64,
    #[serde(with = "serde_bytes")]
    fingerprint: Vec<u8>,
    #[serde(default, with = "serde_bytes")]
    credential_state: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationReplay {
    Completed,
    Conflict,
    Missing,
}

#[derive(Debug, Deserialize)]
struct MetaBlobRow {
    #[serde(with = "serde_bytes")]
    value: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct OutboxRow {
    id: i64,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct MachineProjectionRow {
    #[serde(with = "serde_bytes")]
    machine_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    fingerprint: Vec<u8>,
    status: i64,
    activation_path: String,
    created_at: i64,
    last_seen_at: Option<i64>,
    os: Option<String>,
    arch: Option<String>,
    app_version: Option<String>,
    sdk_version: Option<String>,
    release_id: Option<String>,
    variant_id: Option<i64>,
    build_fp: Option<String>,
    geo: Option<String>,
    suspicion: i64,
}

async fn parse_json<T: DeserializeOwned>(request: &mut Request) -> Result<Option<T>> {
    let bytes = match body::read_raw(request, MAX_INTERNAL_BODY).await {
        Ok(bytes) => bytes,
        Err(BodyError::Read(error)) => return Err(error),
        Err(_) => return Ok(None),
    };
    Ok(serde_json::from_slice(&bytes).ok())
}

fn validate_reservation(input: &ReserveRequest) -> Option<i64> {
    let valid = !input.idempotency_key.is_empty()
        && input.idempotency_key.len() <= 128
        && input.machine_id.len() == 16
        && input
            .request_hash
            .as_ref()
            .is_none_or(|hash| hash.len() == copylocker_types::Digest::LEN)
        && !input.fingerprint.is_empty()
        && input.fingerprint.len() <= 128
        && input.attrs.as_ref().is_none_or(|attrs| attrs.len() <= 4096)
        && !input.device_kem_ek.is_empty()
        && input.device_kem_ek.len() <= 16 * 1024
        && !input.device_sig_vk.is_empty()
        && input.device_sig_vk.len() <= 1024
        && matches!(
            input.activation_path.as_str(),
            "online" | "offline_ar" | "olk" | "account"
        )
        && !input.release_id.is_empty()
        && input.release_id.len() <= 128
        && optional_string_is_bounded(&input.build_fp, 256)
        && optional_string_is_bounded(&input.app_version, 128)
        && optional_string_is_bounded(&input.os, 128)
        && optional_string_is_bounded(&input.arch, 128)
        && optional_string_is_bounded(&input.sdk_version, 128)
        && optional_string_is_bounded(&input.geo, 16)
        && input
            .credential_state
            .as_ref()
            .is_none_or(|state| !state.is_empty() && state.len() <= MAX_CREDENTIAL_STATE);
    if valid {
        i64::try_from(input.variant_id).ok()
    } else {
        None
    }
}

fn initialize(sql: &SqlStorage) -> Result<()> {
    sql.exec(SCHEMA_V1, None)?;
    let version = sql
        .exec(
            "SELECT COALESCE(MAX(id), 0) AS value FROM _sql_schema_migrations",
            None,
        )?
        .one::<IntRow>()?
        .value;
    if version < 2 {
        sql.exec(SCHEMA_V2, None)?;
    }
    if version < 3 {
        sql.exec(SCHEMA_V3, None)?;
    }
    if version < 4 {
        sql.exec(SCHEMA_V4, None)?;
    }
    Ok(())
}

fn now_seconds() -> i64 {
    i64::try_from(Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
}

fn internal_error(status: u16, code: &str) -> Result<Response> {
    response::json(
        status,
        &InternalError {
            ok: false,
            error: code,
        },
    )
}

fn upsert_meta(sql: &SqlStorage, key: &str, value: SqlStorageValue) -> Result<()> {
    sql.exec(
        "INSERT INTO meta(k, v) VALUES (?, ?) \
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        Some(vec![key.into(), value]),
    )?;
    Ok(())
}

fn upsert_optional_i64(sql: &SqlStorage, key: &str, value: Option<i64>) -> Result<()> {
    if let Some(value) = value {
        upsert_meta(sql, key, value.into())
    } else {
        sql.exec("DELETE FROM meta WHERE k = ?", Some(vec![key.into()]))?;
        Ok(())
    }
}

fn apply_pending_admin_update(sql: &SqlStorage) -> Result<()> {
    if meta_i64(sql, "pending_admin_update")? != Some(1) {
        return Ok(());
    }
    let status = meta_text(sql, "pending_admin_status")?
        .ok_or_else(|| worker::Error::RustError("pending Admin status is missing".to_owned()))?;
    let seats = meta_i64(sql, "pending_admin_seats")?
        .ok_or_else(|| worker::Error::RustError("pending Admin seats are missing".to_owned()))?;
    if !matches!(status.as_str(), "active" | "suspended" | "expired")
        || !(1..=100_000).contains(&seats)
    {
        return Err(worker::Error::RustError(
            "pending Admin update is corrupt".to_owned(),
        ));
    }
    upsert_meta(sql, "status", status.into())?;
    upsert_meta(sql, "seats", seats.into())?;
    upsert_optional_i64(
        sql,
        "heartbeat_sec",
        meta_i64(sql, "pending_admin_heartbeat_sec")?,
    )?;
    upsert_optional_i64(
        sql,
        "expires_at",
        meta_i64(sql, "pending_admin_expires_at")?,
    )?;
    sql.exec(
        "DELETE FROM meta WHERE k IN (\
           'pending_admin_update', 'pending_admin_status', 'pending_admin_seats', \
           'pending_admin_heartbeat_sec', 'pending_admin_expires_at'\
         )",
        None,
    )?;
    Ok(())
}

fn meta_i64(sql: &SqlStorage, key: &str) -> Result<Option<i64>> {
    Ok(sql
        .exec(
            "SELECT CAST(v AS INTEGER) AS value FROM meta WHERE k = ?",
            Some(vec![key.into()]),
        )?
        .to_array::<IntRow>()?
        .into_iter()
        .next()
        .map(|row| row.value))
}

fn meta_text(sql: &SqlStorage, key: &str) -> Result<Option<String>> {
    Ok(sql
        .exec(
            "SELECT CAST(v AS TEXT) AS value FROM meta WHERE k = ?",
            Some(vec![key.into()]),
        )?
        .to_array::<TextRow>()?
        .into_iter()
        .next()
        .map(|row| row.value))
}

fn meta_blob(sql: &SqlStorage, key: &str) -> Result<Option<Vec<u8>>> {
    Ok(sql
        .exec(
            "SELECT v AS value FROM meta WHERE k = ?",
            Some(vec![key.into()]),
        )?
        .to_array::<MetaBlobRow>()?
        .into_iter()
        .next()
        .map(|row| row.value))
}

fn activation_status(sql: &SqlStorage, machine_id: &[u8]) -> Result<Option<i64>> {
    Ok(sql
        .exec(
            "SELECT status AS value FROM activations WHERE machine_id = ?",
            Some(vec![machine_id.to_vec().into()]),
        )?
        .to_array::<IntRow>()?
        .into_iter()
        .next()
        .map(|row| row.value))
}

fn activation_status_name(status: i64) -> &'static str {
    match status {
        STATUS_ACTIVE => "active",
        STATUS_PENDING => "pending",
        STATUS_RELEASED => "released",
        STATUS_REVOKED => "revoked",
        _ => "unknown",
    }
}

fn activation_status_from_storage(status: i64) -> Option<ActivationStatus> {
    match status {
        STATUS_ACTIVE => Some(ActivationStatus::Active),
        STATUS_RELEASED => Some(ActivationStatus::Released),
        STATUS_REVOKED => Some(ActivationStatus::Revoked),
        STATUS_PENDING => Some(ActivationStatus::Pending),
        _ => None,
    }
}

fn license_status_from_storage(status: &str) -> Option<LicenseStatus> {
    match status {
        "active" => Some(LicenseStatus::Active),
        "suspended" => Some(LicenseStatus::Suspended),
        "expired" => Some(LicenseStatus::Expired),
        "revoked" => Some(LicenseStatus::Revoked),
        _ => None,
    }
}

fn load_idempotent_response(sql: &SqlStorage, key: &str) -> Result<Option<ReserveResponse>> {
    let row = sql
        .exec(
            "SELECT resp FROM idem WHERE key = ?",
            Some(vec![key.into()]),
        )?
        .to_array::<BlobRow>()?
        .into_iter()
        .next();
    row.map_or(Ok(None), |row| {
        serde_json::from_slice(&row.resp)
            .map(Some)
            .map_err(|error| worker::Error::RustError(error.to_string()))
    })
}

fn store_idempotent_response(
    sql: &SqlStorage,
    key: &str,
    value: &ReserveResponse,
    request_hash: &[u8],
    now: i64,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    sql.exec(
        "INSERT INTO idem(key, resp, created_at, kind, request_hash) \
         VALUES (?, ?, ?, 'reserve', ?)",
        Some(vec![
            key.into(),
            bytes.into(),
            now.into(),
            request_hash.to_vec().into(),
        ]),
    )?;
    Ok(())
}

fn reserve_request_hash(input: &ReserveRequest) -> Result<copylocker_types::Digest> {
    if let Some(request_hash) = input.request_hash.as_deref() {
        return copylocker_types::Digest::from_slice(request_hash).ok_or_else(|| {
            worker::Error::RustError("reservation request hash is invalid".to_owned())
        });
    }
    let encoded = serde_json::to_vec(input)?;
    Ok(Sha256Scheme::hash_parts(&[
        OPERATION_HASH_LABEL,
        b"reserve",
        &encoded,
    ]))
}

fn update_idempotent_response(
    sql: &SqlStorage,
    key: &str,
    value: &ReserveResponse,
    request_hash: &[u8],
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    let written = sql
        .exec(
            "UPDATE idem SET resp = ? WHERE key = ? AND kind = 'reserve' AND request_hash = ?",
            Some(vec![bytes.into(), key.into(), request_hash.to_vec().into()]),
        )?
        .rows_written();
    if written != 1 {
        return Err(worker::Error::RustError(
            "reservation idempotency update failed".to_owned(),
        ));
    }
    Ok(())
}

fn completion_matches(
    sql: &SqlStorage,
    envelope: &[u8],
    reservation: &ReserveResponse,
    material: &ReserveMaterial,
) -> Result<bool> {
    let Ok(envelope) = Envelope::decode(envelope) else {
        return Ok(false);
    };
    let Ok(credential) = envelope.peek_unverified::<MachineCredential>() else {
        return Ok(false);
    };
    let Some(license_id) = meta_blob(sql, "license_id")? else {
        return Ok(false);
    };
    let Some(product_id) = meta_text(sql, "product_id")? else {
        return Ok(false);
    };
    let Some(suite_id) = meta_blob(sql, "suite_id")? else {
        return Ok(false);
    };
    Ok(credential.license_id.as_bytes() == license_id.as_slice()
        && credential.product_id == product_id
        && credential.suite_id.as_bytes() == suite_id.as_slice()
        && credential.machine_id.as_bytes() == reservation.machine_id.as_slice()
        && credential.fingerprint.as_bytes() == reservation.fingerprint.as_slice()
        && credential.variant_id == u64::try_from(material.variant_id).unwrap_or(u64::MAX)
        && credential.refresh_after == material.refresh_after
        && credential.not_after == material.not_after
        && credential.build_fingerprint.as_deref() == material.build_fp.as_deref())
}

fn authenticated_request_hash(
    kind: ArtifactKind,
    input: &AuthenticatedMachineRequest,
) -> copylocker_types::Digest {
    Sha256Scheme::hash_parts(&[
        OPERATION_HASH_LABEL,
        &[kind as u8],
        &input.license_id,
        &input.machine_id,
        &input.suite_id,
        &input.nonce,
        &input.proof_input,
        &input.proof,
    ])
}

fn load_operation_response(
    sql: &SqlStorage,
    key: &str,
    kind: &str,
    request_hash: &[u8],
) -> Result<OperationReplay> {
    let row = sql
        .exec(
            "SELECT kind, COALESCE(request_hash, X'') AS request_hash FROM idem WHERE key = ?",
            Some(vec![key.into()]),
        )?
        .to_array::<OperationIdempotencyRow>()?
        .into_iter()
        .next();
    let Some(row) = row else {
        return Ok(OperationReplay::Missing);
    };
    if row.kind.as_deref() == Some(kind) && row.request_hash == request_hash {
        Ok(OperationReplay::Completed)
    } else {
        Ok(OperationReplay::Conflict)
    }
}

fn store_operation_response(
    sql: &SqlStorage,
    key: &str,
    kind: &str,
    request_hash: &[u8],
    now: i64,
) -> Result<()> {
    let encoded_response = serde_json::to_vec(&OkResponse { ok: true })?;
    sql.exec(
        "INSERT INTO idem(key, resp, created_at, kind, request_hash) VALUES (?, ?, ?, ?, ?)",
        Some(vec![
            key.into(),
            encoded_response.into(),
            now.into(),
            kind.into(),
            request_hash.to_vec().into(),
        ]),
    )?;
    Ok(())
}

fn record_nonce(sql: &SqlStorage, nonce: &[u8], now: i64) -> Result<bool> {
    let written = sql
        .exec(
            "INSERT OR IGNORE INTO nonces(nonce, seen_at) VALUES (?, ?)",
            Some(vec![nonce.to_vec().into(), now.into()]),
        )?
        .rows_written();
    Ok(written != 0)
}

fn proof_input_matches(kind: ArtifactKind, input: &AuthenticatedMachineRequest) -> bool {
    let Ok(value) = decode_canonical(&input.proof_input, copylocker_proto::CLIENT_LIMITS) else {
        return false;
    };
    let (license_key, machine_key, proof_key) = match kind {
        ArtifactKind::ValidateRequest => (12, 2, 8),
        ArtifactKind::HeartbeatRequest | ArtifactKind::DeactivateRequest => (2, 3, 6),
        _ => return false,
    };
    value.as_map().is_some()
        && value.get(proof_key).is_none()
        && value
            .get(0)
            .and_then(copylocker_suite::cbor::CborValue::as_uint)
            == Some(u64::from(copylocker_types::PROTO_VER))
        && value
            .get(1)
            .and_then(copylocker_suite::cbor::CborValue::as_bytes)
            == Some(input.suite_id.as_slice())
        && value
            .get(license_key)
            .and_then(copylocker_suite::cbor::CborValue::as_bytes)
            == Some(input.license_id.as_slice())
        && value
            .get(machine_key)
            .and_then(copylocker_suite::cbor::CborValue::as_bytes)
            == Some(input.machine_id.as_slice())
        && value
            .get(4)
            .and_then(copylocker_suite::cbor::CborValue::as_bytes)
            == Some(input.nonce.as_slice())
}

fn is_product_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn append_projection(sql: &SqlStorage, machine_id: Option<&[u8]>, now: i64) -> Result<()> {
    let version = sql
        .exec(
            "INSERT INTO meta(k, v) VALUES ('proj_version', 1) \
             ON CONFLICT(k) DO UPDATE SET v = CAST(meta.v AS INTEGER) + 1 \
             RETURNING CAST(v AS INTEGER) AS value",
            None,
        )?
        .one::<IntRow>()?
        .value;
    let license_id = meta_blob(sql, "license_id")?.ok_or_else(|| {
        worker::Error::RustError("license metadata is not initialized".to_owned())
    })?;
    let license_status = meta_text(sql, "status")?.ok_or_else(|| {
        worker::Error::RustError("license status metadata is not initialized".to_owned())
    })?;
    let seats_used = sql
        .exec(
            "SELECT COUNT(*) AS count FROM activations WHERE status IN (0, 3)",
            None,
        )?
        .one::<CountRow>()?
        .count;
    let last_seen_at = minimum_time(
        sql,
        "SELECT MAX(COALESCE(last_seen_at, created_at)) AS at FROM activations",
        None,
    )?;
    let machine = machine_id
        .map(|machine_id| {
            sql.exec(
                "SELECT machine_id, fingerprint, status, activation_path, created_at, \
                   last_seen_at, os, arch, app_version, sdk_version, release_id, variant_id, \
                   build_fp, geo, suspicion \
                 FROM activations WHERE machine_id = ?",
                Some(vec![machine_id.to_vec().into()]),
            )?
            .one::<MachineProjectionRow>()
        })
        .transpose()?
        .map(|row| MachineProjection {
            machine_id: row.machine_id,
            fingerprint: row.fingerprint,
            status: activation_status_name(row.status).to_owned(),
            activation_path: row.activation_path,
            first_seen_at: row.created_at,
            last_seen_at: row.last_seen_at,
            os: row.os,
            arch: row.arch,
            app_version: row.app_version,
            sdk_version: row.sdk_version,
            release_id: row.release_id,
            variant_id: row.variant_id,
            build_fp: row.build_fp,
            geo_country: row.geo,
            suspicion: row.suspicion,
        });
    let event = ProjectionEvent {
        event: LICENSE_PROJECTION_EVENT.to_owned(),
        schema_version: PROJECTION_SCHEMA_VERSION,
        license_id,
        license_status,
        seats_used,
        last_seen_at,
        machine,
        proj_version: version,
        occurred_at: now,
    };
    let payload = serde_json::to_vec(&event)?;
    sql.exec(
        "INSERT INTO outbox(kind, payload, created_at) VALUES ('projection', ?, ?)",
        Some(vec![payload.into(), now.into()]),
    )?;
    Ok(())
}

fn optional_string_is_bounded(value: &Option<String>, max_len: usize) -> bool {
    value.as_ref().is_none_or(|value| value.len() <= max_len)
}

fn minimum_time(
    sql: &SqlStorage,
    query: &str,
    bindings: Option<Vec<SqlStorageValue>>,
) -> Result<Option<i64>> {
    Ok(sql.exec(query, bindings)?.one::<OptionalIntRow>()?.value)
}
