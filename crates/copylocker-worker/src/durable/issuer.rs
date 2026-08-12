use std::time::Duration;

use copylocker_proto::{
    ActivationResponse, Envelope, KillOrder, MachineCredential, OfflineLicenseKey, RevocationBatch,
    ValidationTicket,
};
use copylocker_suite::{Artifact, DomainCtx, HashScheme, SignatureScheme};
use copylocker_suite_std::sig::HybridSigningKey;
use copylocker_suite_std::{HybridSig, Sha256Scheme};
use copylocker_types::{ArtifactKind, EpochId, SuiteId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use worker::{
    durable_object, wasm_bindgen, Date, DurableObject, Env, Method, Request, Response, Result,
    SqlStorage, State,
};
use zeroize::Zeroize;

use super::{ready, unavailable};
use crate::events::{
    audit_r2_key, is_issuable_kind, issuance_hash, issuer_object_name, issuer_shard,
    AuditArchiveEvent, IssuanceHashInput, AUDIT_ARCHIVE_EVENT, AUDIT_SCHEMA_VERSION,
};
use crate::middleware::body::{self, BodyError};
use crate::response;

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS _sql_schema_migrations (
  id INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS issuance_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  kind INTEGER NOT NULL,
  subject BLOB NOT NULL,
  epoch_id BLOB NOT NULL,
  digest BLOB NOT NULL,
  prev_hash BLOB NOT NULL,
  hash BLOB NOT NULL
);
INSERT OR IGNORE INTO _sql_schema_migrations(id) VALUES (1);
"#;

const SCHEMA_V2: &str = r#"
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
  request_hash BLOB NOT NULL,
  resp BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_idem_created ON idem(created_at);
INSERT INTO _sql_schema_migrations(id) VALUES (2);
"#;

const ISSUER_SCHEMA_VERSION: i32 = 2;
const MAX_INTERNAL_BODY: usize = 6 * 1024 * 1024;
const MAX_TBS_SIZE: usize = 1024 * 1024;
const OUTBOX_BATCH_SIZE: i64 = 100;
const IDEMPOTENCY_TTL_SECS: i64 = 24 * 60 * 60;
const SENT_OUTBOX_TTL_SECS: i64 = 7 * 24 * 60 * 60;
const EPOCH_SIGNING_KEY_BINDING: &str = "EPOCH_SIGNING_KEY";
const EPOCH_SECRET_SCHEMA_VERSION: u8 = 1;
const REQUEST_HASH_LABEL: &[u8] = b"copylocker/issuer-request/v1";
const ZERO_HASH: [u8; 32] = [0; 32];

#[durable_object]
#[derive(Debug)]
pub struct IssuerDO {
    state: State,
    env: Env,
    initialization_error: Option<String>,
}

impl DurableObject for IssuerDO {
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
            return unavailable("IssuerDO", error);
        }

        match (request.method(), request.path().as_str()) {
            (Method::Get, "/health") => ready("IssuerDO", ISSUER_SCHEMA_VERSION),
            (Method::Post, "/sign") => self.sign(&mut request).await,
            (Method::Get, _) => internal_error(404, "not_found"),
            _ => internal_error(405, "method_not_allowed"),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        if let Some(error) = self.initialization_error.as_deref() {
            return unavailable("IssuerDO", error);
        }

        let now = now_seconds();
        self.reclaim(now)?;
        self.flush_outbox(now).await?;
        self.schedule_next_alarm(now).await?;
        Response::empty()
    }
}

impl IssuerDO {
    async fn sign(&self, request: &mut Request) -> Result<Response> {
        let Some(input) = parse_json::<IssueRequest>(request).await? else {
            return internal_error(400, "invalid_request");
        };
        let Some(kind) = validate_issue_request(&input) else {
            return internal_error(400, "invalid_request");
        };
        if !self.owns_shard(input.shard)? {
            return internal_error(409, "wrong_issuer_shard");
        }

        let request_hash = issue_request_hash(&input);
        match load_idempotent_response(
            &self.state.storage().sql(),
            &input.idempotency_key,
            request_hash.as_bytes(),
        )? {
            IdempotencyResult::Replay(cached) => {
                self.schedule_next_alarm(now_seconds()).await?;
                return response::json(200, &cached);
            }
            IdempotencyResult::Conflict => {
                return internal_error(409, "idempotency_conflict");
            }
            IdempotencyResult::Missing => {}
        }

        let epoch_key = match self.load_epoch_key().await {
            Ok(key) => key,
            Err(error) => {
                worker::console_error!(
                    "{}",
                    serde_json::json!({
                        "level": "error",
                        "message": "issuer signing key unavailable",
                        "error": error.to_string()
                    })
                );
                return internal_error(503, "issuer_unavailable");
            }
        };

        let test_environment = crate::suites::is_test_environment(&self.env);
        let Some(artifact_suite) = validate_tbs(&input, kind, &epoch_key, test_environment) else {
            return internal_error(400, "invalid_artifact");
        };
        let envelope = match sign_envelope(&input, kind, &epoch_key, artifact_suite) {
            Ok(envelope) => envelope,
            Err(error) => {
                worker::console_error!(
                    "{}",
                    serde_json::json!({
                        "level": "error",
                        "message": "artifact signing failed",
                        "error": error.to_string()
                    })
                );
                return internal_error(503, "issuer_unavailable");
            }
        };

        // Another request may have completed while this one awaited Secrets Store.
        let sql = self.state.storage().sql();
        match load_idempotent_response(&sql, &input.idempotency_key, request_hash.as_bytes())? {
            IdempotencyResult::Replay(cached) => {
                self.schedule_next_alarm(now_seconds()).await?;
                return response::json(200, &cached);
            }
            IdempotencyResult::Conflict => {
                return internal_error(409, "idempotency_conflict");
            }
            IdempotencyResult::Missing => {}
        }

        let now = now_seconds();
        let issued = append_issuance(
            &sql,
            &input,
            kind,
            &epoch_key,
            &envelope,
            request_hash.as_bytes(),
            now,
        )?;
        self.schedule_next_alarm(now).await?;
        response::json(201, &issued)
    }

    async fn load_epoch_key(&self) -> Result<EpochKey> {
        let test_environment = self
            .env
            .var("ENVIRONMENT")
            .ok()
            .is_some_and(|value| value.to_string() == "test");
        if test_environment {
            let value = self.env.var("TEST_EPOCH_SIGNING_KEY")?.to_string();
            return parse_epoch_secret(value).map_err(|()| {
                worker::Error::RustError("test epoch signing key is invalid".to_owned())
            });
        }

        let binding = self.env.secret_store(EPOCH_SIGNING_KEY_BINDING)?;
        let value = binding.get().await?.ok_or_else(|| {
            worker::Error::RustError("epoch signing key is not configured".to_owned())
        })?;
        parse_epoch_secret(value)
            .map_err(|()| worker::Error::RustError("epoch signing key is invalid".to_owned()))
    }

    fn owns_shard(&self, shard: u8) -> Result<bool> {
        let namespace = self.env.durable_object("ISSUER")?;
        let expected = namespace.id_from_name(&issuer_object_name(shard))?;
        Ok(self.state.id().to_string() == expected.to_string())
    }

    fn reclaim(&self, now: i64) -> Result<()> {
        let sql = self.state.storage().sql();
        sql.exec(
            "DELETE FROM idem WHERE created_at <= ?",
            Some(vec![now.saturating_sub(IDEMPOTENCY_TTL_SECS).into()]),
        )?;
        sql.exec(
            "DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at <= ?",
            Some(vec![now.saturating_sub(SENT_OUTBOX_TTL_SECS).into()]),
        )?;
        Ok(())
    }

    async fn flush_outbox(&self, now: i64) -> Result<()> {
        let sql = self.state.storage().sql();
        let rows = sql
            .exec(
                "SELECT id, payload FROM outbox WHERE sent_at IS NULL ORDER BY id LIMIT ?",
                Some(vec![OUTBOX_BATCH_SIZE.into()]),
            )?
            .to_array::<OutboxRow>()?;
        if rows.is_empty() {
            return Ok(());
        }

        let queue = self.env.queue("EVENTS")?;
        for row in rows {
            let event =
                serde_json::from_slice::<AuditArchiveEvent>(&row.payload).map_err(|_| {
                    worker::Error::RustError("issuer outbox payload is corrupt".to_owned())
                })?;
            if !event.is_valid() {
                return Err(worker::Error::RustError(
                    "issuer outbox event is invalid".to_owned(),
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
        let pending = sql
            .exec(
                "SELECT COUNT(*) AS value FROM outbox WHERE sent_at IS NULL",
                None,
            )?
            .one::<IntRow>()?
            .value;
        let storage = self.state.storage();
        if pending > 0 {
            return storage.set_alarm(Duration::from_secs(0)).await;
        }

        let next = sql
            .exec(
                "SELECT MIN(at) AS value FROM (\
                   SELECT MIN(created_at + 86400) AS at FROM idem \
                   UNION ALL \
                   SELECT MIN(sent_at + 604800) AS at FROM outbox WHERE sent_at IS NOT NULL\
                 )",
                None,
            )?
            .one::<OptionalIntRow>()?
            .value;
        if let Some(next) = next {
            let delay = u64::try_from(next.saturating_sub(now)).unwrap_or_default();
            storage.set_alarm(Duration::from_secs(delay)).await
        } else {
            storage.delete_alarm().await
        }
    }
}

#[derive(Debug, Deserialize)]
struct IssueRequest {
    idempotency_key: String,
    shard: u8,
    routing_key: Vec<u8>,
    kind: u8,
    product_id: String,
    subject: Vec<u8>,
    tbs: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct IssueResponse {
    ok: bool,
    seq: i64,
    epoch_id: Vec<u8>,
    envelope: Vec<u8>,
    digest: Vec<u8>,
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct EpochSecretPayload {
    schema_version: u8,
    epoch_id: Vec<u8>,
    suite_id: Vec<u8>,
    signing_key: Vec<u8>,
}

#[derive(Debug)]
struct EpochKey {
    epoch_id: EpochId,
    suite_id: SuiteId,
    signing_key: HybridSigningKey,
}

#[derive(Debug, Serialize)]
struct InternalError<'a> {
    ok: bool,
    error: &'a str,
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
struct ChainHeadRow {
    seq: i64,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct IdempotencyRow {
    #[serde(with = "serde_bytes")]
    request_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    resp: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct OutboxRow {
    id: i64,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
}

enum IdempotencyResult {
    Missing,
    Replay(IssueResponse),
    Conflict,
}

async fn parse_json<T: DeserializeOwned>(request: &mut Request) -> Result<Option<T>> {
    let bytes = match body::read_raw(request, MAX_INTERNAL_BODY).await {
        Ok(bytes) => bytes,
        Err(BodyError::Read(error)) => return Err(error),
        Err(_) => return Ok(None),
    };
    Ok(serde_json::from_slice(&bytes).ok())
}

fn validate_issue_request(input: &IssueRequest) -> Option<ArtifactKind> {
    let kind = ArtifactKind::from_u8(input.kind)?;
    let valid = !input.idempotency_key.is_empty()
        && input.idempotency_key.len() <= 128
        && input
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
        && input.routing_key.len() == 16
        && issuer_shard(&input.routing_key) == input.shard
        && is_issuable_kind(kind)
        && is_product_id(&input.product_id)
        && !input.subject.is_empty()
        && input.subject.len() <= 64
        && !input.tbs.is_empty()
        && input.tbs.len() <= MAX_TBS_SIZE;
    valid.then_some(kind)
}

/// Validate the to-be-signed artifact and return the suite it must be signed under.
///
/// Production accepts only the epoch key's own suite (CL-STD-1), which keeps the historical
/// behavior byte-identical. Under `ENVIRONMENT == "test"` the synthetic `CL-TST-1` suite is
/// also accepted so the multi-suite request path is exercised end to end; the envelope and the
/// signature domain then carry the artifact's suite, never the key's.
fn validate_tbs(
    input: &IssueRequest,
    kind: ArtifactKind,
    key: &EpochKey,
    test_environment: bool,
) -> Option<SuiteId> {
    let supported = |suite_id: SuiteId| -> Option<SuiteId> {
        if suite_id == key.suite_id
            || (test_environment && suite_id == crate::suites::TEST_SUITE_ID)
        {
            Some(suite_id)
        } else {
            None
        }
    };
    match kind {
        ArtifactKind::MachineCred => MachineCredential::from_canonical(&input.tbs)
            .ok()
            .filter(|a| {
                a.epoch_id == key.epoch_id
                    && a.product_id == input.product_id
                    && a.license_id.as_bytes() == input.routing_key.as_slice()
                    && a.license_id.as_bytes() == input.subject.as_slice()
            })
            .and_then(|a| supported(a.suite_id)),
        ArtifactKind::ValidationTicket => ValidationTicket::from_canonical(&input.tbs)
            .ok()
            .filter(|a| {
                a.epoch_id == key.epoch_id && a.machine_id.as_bytes() == input.subject.as_slice()
            })
            .and_then(|a| supported(a.suite_id)),
        ArtifactKind::KillOrder => KillOrder::from_canonical(&input.tbs)
            .ok()
            .filter(|a| a.machine_id.as_bytes() == input.subject.as_slice())
            .and_then(|a| supported(a.suite_id)),
        ArtifactKind::RevocationBatch => RevocationBatch::from_canonical(&input.tbs)
            .ok()
            .filter(|batch| {
                let subject = input.subject.as_slice();
                let subject_is_revoked = batch
                    .revoked_license_ids
                    .iter()
                    .any(|id| id.as_bytes() == subject)
                    || batch
                        .revoked_machine_ids
                        .iter()
                        .any(|id| id.as_bytes() == subject)
                    || batch
                        .revoked_epoch_ids
                        .iter()
                        .any(|id| id.as_bytes() == subject);
                batch.proto_ver == copylocker_types::PROTO_VER
                    && batch.from_epoch > 0
                    && batch.from_epoch <= batch.to_epoch
                    && subject_is_revoked
            })
            .and_then(|batch| supported(batch.suite_id)),
        ArtifactKind::OfflineLicenseKey => OfflineLicenseKey::from_canonical(&input.tbs)
            .ok()
            .filter(|a| {
                a.epoch_id == key.epoch_id
                    && a.product_id == input.product_id
                    && a.license_id.as_bytes() == input.routing_key.as_slice()
                    && a.license_id.as_bytes() == input.subject.as_slice()
            })
            .and_then(|a| supported(a.suite_id)),
        ArtifactKind::ActivationResponse => ActivationResponse::from_canonical(&input.tbs)
            .ok()
            .and_then(|response| {
                let suite = supported(response.suite_id)?;
                Envelope::decode(&response.credential)
                    .and_then(|envelope| envelope.peek_unverified::<MachineCredential>())
                    .ok()
                    .filter(|credential| {
                        credential.suite_id == suite
                            && credential.epoch_id == key.epoch_id
                            && credential.product_id == input.product_id
                            && credential.license_id.as_bytes() == input.routing_key.as_slice()
                            && credential.license_id.as_bytes() == input.subject.as_slice()
                    })?;
                Some(suite)
            }),
        _ => None,
    }
}

fn sign_envelope(
    input: &IssueRequest,
    kind: ArtifactKind,
    key: &EpochKey,
    suite_id: SuiteId,
) -> std::result::Result<Vec<u8>, copylocker_proto::ProtoError> {
    let context = DomainCtx::new(kind, suite_id, &input.product_id);
    let signature = HybridSig::sign(&key.signing_key, context, &input.tbs)?;
    Ok(Envelope {
        proto_ver: copylocker_types::PROTO_VER,
        suite_id,
        kind,
        tbs: input.tbs.clone(),
        sig: signature.0,
        epoch_ref: Some(key.epoch_id),
    }
    .encode())
}

fn append_issuance(
    sql: &SqlStorage,
    input: &IssueRequest,
    kind: ArtifactKind,
    key: &EpochKey,
    envelope: &[u8],
    request_hash: &[u8],
    now: i64,
) -> Result<IssueResponse> {
    let kind_code = kind as u8;
    let head = sql
        .exec(
            "SELECT seq, hash FROM issuance_log ORDER BY seq DESC LIMIT 1",
            None,
        )?
        .to_array::<ChainHeadRow>()?
        .into_iter()
        .next();
    let seq = head
        .as_ref()
        .map_or(Some(1), |row| row.seq.checked_add(1))
        .ok_or_else(|| worker::Error::RustError("issuer sequence exhausted".to_owned()))?;
    let prev_hash = match head {
        Some(row) if row.hash.len() == ZERO_HASH.len() => row.hash,
        Some(_) => {
            return Err(worker::Error::RustError(
                "issuer chain head is corrupt".to_owned(),
            ));
        }
        None => ZERO_HASH.to_vec(),
    };
    let digest = Sha256Scheme::hash(envelope);
    let hash = issuance_hash(&IssuanceHashInput {
        shard: input.shard,
        seq,
        occurred_at: now,
        kind: kind_code,
        product_id: &input.product_id,
        subject: &input.subject,
        epoch_id: key.epoch_id.as_bytes(),
        digest: digest.as_bytes(),
        prev_hash: &prev_hash,
    });
    let r2_key = audit_r2_key(now, input.shard, seq)
        .ok_or_else(|| worker::Error::RustError("issuer timestamp is out of range".to_owned()))?;
    let event = AuditArchiveEvent {
        event: AUDIT_ARCHIVE_EVENT.to_owned(),
        schema_version: AUDIT_SCHEMA_VERSION,
        shard: input.shard,
        seq,
        occurred_at: now,
        kind: kind_code,
        product_id: input.product_id.clone(),
        subject: input.subject.clone(),
        epoch_id: key.epoch_id.as_bytes().to_vec(),
        digest: digest.as_bytes().to_vec(),
        prev_hash: prev_hash.clone(),
        hash: hash.as_bytes().to_vec(),
        envelope: envelope.to_vec(),
        r2_key,
    };
    if !event.is_valid() {
        return Err(worker::Error::RustError(
            "issuer generated an invalid audit event".to_owned(),
        ));
    }
    let payload = serde_json::to_vec(&event)?;
    let issued = IssueResponse {
        ok: true,
        seq,
        epoch_id: key.epoch_id.as_bytes().to_vec(),
        envelope: envelope.to_vec(),
        digest: digest.as_bytes().to_vec(),
        prev_hash: prev_hash.clone(),
        hash: hash.as_bytes().to_vec(),
    };
    let encoded_response = serde_json::to_vec(&issued)?;

    // These synchronous writes are coalesced atomically by Durable Object storage.
    sql.exec(
        "INSERT INTO issuance_log(\
           seq, ts, kind, subject, epoch_id, digest, prev_hash, hash\
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        Some(vec![
            seq.into(),
            now.into(),
            i64::from(kind_code).into(),
            input.subject.clone().into(),
            key.epoch_id.as_bytes().to_vec().into(),
            digest.as_bytes().to_vec().into(),
            prev_hash.into(),
            hash.as_bytes().to_vec().into(),
        ]),
    )?;
    sql.exec(
        "INSERT INTO outbox(kind, payload, created_at) VALUES ('audit', ?, ?)",
        Some(vec![payload.into(), now.into()]),
    )?;
    sql.exec(
        "INSERT INTO idem(key, request_hash, resp, created_at) VALUES (?, ?, ?, ?)",
        Some(vec![
            input.idempotency_key.clone().into(),
            request_hash.to_vec().into(),
            encoded_response.into(),
            now.into(),
        ]),
    )?;
    Ok(issued)
}

fn issue_request_hash(input: &IssueRequest) -> copylocker_types::Digest {
    Sha256Scheme::hash_parts(&[
        REQUEST_HASH_LABEL,
        &[input.shard],
        &input.routing_key,
        &[input.kind],
        input.product_id.as_bytes(),
        &input.subject,
        &input.tbs,
    ])
}

fn load_idempotent_response(
    sql: &SqlStorage,
    key: &str,
    request_hash: &[u8],
) -> Result<IdempotencyResult> {
    let row = sql
        .exec(
            "SELECT request_hash, resp FROM idem WHERE key = ?",
            Some(vec![key.into()]),
        )?
        .to_array::<IdempotencyRow>()?
        .into_iter()
        .next();
    let Some(row) = row else {
        return Ok(IdempotencyResult::Missing);
    };
    if row.request_hash != request_hash {
        return Ok(IdempotencyResult::Conflict);
    }
    let response = serde_json::from_slice(&row.resp).map_err(|_| {
        worker::Error::RustError("issuer idempotency response is corrupt".to_owned())
    })?;
    Ok(IdempotencyResult::Replay(response))
}

fn parse_epoch_secret(mut value: String) -> std::result::Result<EpochKey, ()> {
    let parsed = serde_json::from_str::<EpochSecretPayload>(&value);
    value.zeroize();
    let mut parsed = parsed.map_err(|_| ())?;
    if parsed.schema_version != EPOCH_SECRET_SCHEMA_VERSION {
        parsed.signing_key.zeroize();
        return Err(());
    }
    let epoch_id = EpochId::from_slice(&parsed.epoch_id);
    let suite_id = SuiteId::from_slice(&parsed.suite_id);
    let signing_key = HybridSig::decode_sk(&parsed.signing_key);
    parsed.signing_key.zeroize();
    if suite_id != Some(copylocker_suite_std::CL_STD_1_SUITE_ID) {
        return Err(());
    }
    Ok(EpochKey {
        epoch_id: epoch_id.ok_or(())?,
        suite_id: suite_id.ok_or(())?,
        signing_key: signing_key.map_err(|_| ())?,
    })
}

fn is_product_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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
    if version < i64::from(ISSUER_SCHEMA_VERSION) {
        sql.exec(SCHEMA_V2, None)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_types::{KillReason, MachineId};

    fn key() -> std::result::Result<EpochKey, String> {
        HybridSig::decode_sk(&[7; 64])
            .map(|signing_key| EpochKey {
                epoch_id: EpochId([3; 8]),
                suite_id: copylocker_suite_std::CL_STD_1_SUITE_ID,
                signing_key,
            })
            .map_err(|error| format!("{error:?}"))
    }

    fn request(tbs: Vec<u8>) -> IssueRequest {
        let routing_key = vec![9; 16];
        IssueRequest {
            idempotency_key: "issue-1".to_owned(),
            shard: issuer_shard(&routing_key),
            routing_key,
            kind: ArtifactKind::KillOrder as u8,
            product_id: "product_1".to_owned(),
            subject: vec![4; 16],
            tbs,
        }
    }

    #[test]
    fn signs_a_validated_artifact_with_the_epoch_key() -> std::result::Result<(), String> {
        let key = key()?;
        let artifact = KillOrder {
            proto_ver: copylocker_types::PROTO_VER,
            suite_id: key.suite_id,
            machine_id: MachineId([4; 16]),
            nonce_c_echo: [5; 32],
            server_time: 1_700_000_000,
            reason: KillReason::RevokedLicense,
            user_message: None,
            revocation_epoch: 7,
        };
        let input = request(
            artifact
                .to_canonical()
                .map_err(|error| format!("{error:?}"))?,
        );
        assert_eq!(
            validate_tbs(&input, ArtifactKind::KillOrder, &key, false),
            Some(key.suite_id)
        );

        let encoded = sign_envelope(&input, ArtifactKind::KillOrder, &key, key.suite_id)
            .map_err(|error| error.to_string())?;
        let envelope = Envelope::decode(&encoded).map_err(|error| error.to_string())?;
        let verifying_key = HybridSig::verifying_key(&key.signing_key);
        let opened = envelope
            .open::<HybridSig, KillOrder>(&input.product_id, &verifying_key)
            .map_err(|error| error.to_string())?;
        assert_eq!(opened, artifact);
        Ok(())
    }

    #[test]
    fn rejects_artifacts_whose_subject_does_not_match() -> std::result::Result<(), String> {
        let key = key()?;
        let artifact = KillOrder {
            proto_ver: copylocker_types::PROTO_VER,
            suite_id: key.suite_id,
            machine_id: MachineId([8; 16]),
            nonce_c_echo: [5; 32],
            server_time: 1_700_000_000,
            reason: KillReason::RevokedLicense,
            user_message: None,
            revocation_epoch: 7,
        };
        let input = request(
            artifact
                .to_canonical()
                .map_err(|error| format!("{error:?}"))?,
        );
        assert_eq!(
            validate_tbs(&input, ArtifactKind::KillOrder, &key, false),
            None
        );
        Ok(())
    }

    #[test]
    fn the_test_suite_is_accepted_only_in_the_test_environment() -> std::result::Result<(), String>
    {
        let key = key()?;
        let artifact = KillOrder {
            proto_ver: copylocker_types::PROTO_VER,
            suite_id: crate::suites::TEST_SUITE_ID,
            machine_id: MachineId([4; 16]),
            nonce_c_echo: [5; 32],
            server_time: 1_700_000_000,
            reason: KillReason::RevokedLicense,
            user_message: None,
            revocation_epoch: 7,
        };
        let input = request(
            artifact
                .to_canonical()
                .map_err(|error| format!("{error:?}"))?,
        );
        assert_eq!(
            validate_tbs(&input, ArtifactKind::KillOrder, &key, false),
            None
        );
        assert_eq!(
            validate_tbs(&input, ArtifactKind::KillOrder, &key, true),
            Some(crate::suites::TEST_SUITE_ID)
        );
        let encoded = sign_envelope(
            &input,
            ArtifactKind::KillOrder,
            &key,
            crate::suites::TEST_SUITE_ID,
        )
        .map_err(|error| error.to_string())?;
        let envelope = Envelope::decode(&encoded).map_err(|error| error.to_string())?;
        assert_eq!(envelope.suite_id, crate::suites::TEST_SUITE_ID);
        let verifying_key = HybridSig::verifying_key(&key.signing_key);
        let opened = envelope
            .open::<HybridSig, KillOrder>(&input.product_id, &verifying_key)
            .map_err(|error| error.to_string())?;
        assert_eq!(opened, artifact);
        Ok(())
    }

    #[test]
    fn rejects_epoch_secret_for_a_different_suite() {
        let value = serde_json::json!({
            "schema_version": EPOCH_SECRET_SCHEMA_VERSION,
            "epoch_id": [3, 3, 3, 3, 3, 3, 3, 3],
            "suite_id": [0, 0, 0, 0],
            "signing_key": vec![7_u8; 64],
        })
        .to_string();

        assert!(parse_epoch_secret(value).is_err());
    }
}
