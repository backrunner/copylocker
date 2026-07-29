use copylocker_suite::HashScheme;
use copylocker_suite_std::Sha256Scheme;
use copylocker_types::ArtifactKind;
use serde::Deserialize;
use worker::wasm_bindgen::JsValue;
use worker::{Conditional, D1Database, D1SessionConstraint, D1Type, Date, Env, Result};

use crate::durable::verify_admin_audit;
use crate::events::{admin_audit_index_seq, audit_index_seq, AdminAuditEvent, AuditArchiveEvent};

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

pub(crate) async fn archive(env: &Env, event: &AuditArchiveEvent) -> Result<()> {
    let archive = event.to_canonical().ok_or_else(|| {
        worker::Error::RustError("audit archive event failed validation".to_owned())
    })?;
    archive_r2(env, &event.r2_key, &archive).await?;
    index_d1(env, event).await
}

pub(crate) async fn archive_admin(env: &Env, event: &AdminAuditEvent) -> Result<()> {
    let archive = event.to_canonical().ok_or_else(|| {
        worker::Error::RustError("Admin audit archive event failed validation".to_owned())
    })?;
    verify_admin_source(env, event).await?;
    archive_r2(env, &event.r2_key, &archive).await?;
    index_admin_d1(env, event).await?;
    mark_admin_archived(env, event).await
}

async fn archive_r2(env: &Env, r2_key: &str, archive: &[u8]) -> Result<()> {
    let bucket = env.bucket("ARCHIVE")?;
    let checksum = Sha256Scheme::hash(archive);
    let inserted = bucket
        .put(r2_key, archive.to_vec())
        .sha256(checksum.as_bytes().to_vec())
        .only_if(Conditional {
            etag_does_not_match: Some("*".to_owned()),
            ..Conditional::default()
        })
        .execute()
        .await?;
    if inserted.is_some() {
        return Ok(());
    }

    let existing = bucket.get(r2_key).execute().await?.ok_or_else(|| {
        worker::Error::RustError("audit archive disappeared after conditional write".to_owned())
    })?;
    let body = existing
        .body()
        .ok_or_else(|| worker::Error::RustError("audit archive object has no body".to_owned()))?;
    if body.bytes().await? == archive {
        Ok(())
    } else {
        Err(worker::Error::RustError(
            "audit archive key already contains different bytes".to_owned(),
        ))
    }
}

async fn verify_admin_source(env: &Env, event: &AdminAuditEvent) -> Result<()> {
    let row = env
        .d1("DB")?
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT event_json, prev_hash, hash, r2_key \
             FROM admin_audit_events WHERE seq = ?",
        )
        .bind(&[integer(event.seq)?])?
        .first::<AdminAuditSourceRow>(None)
        .await?
        .ok_or_else(|| {
            worker::Error::RustError("Admin audit source record is missing".to_owned())
        })?;
    let stored = serde_json::from_str::<AdminAuditEvent>(&row.event_json)
        .map_err(|_| worker::Error::RustError("Admin audit source JSON is corrupt".to_owned()))?;
    if stored == *event
        && row.prev_hash == event.prev_hash
        && row.hash == event.hash
        && row.r2_key == event.r2_key
    {
        if event.schema_version == 1 {
            Ok(())
        } else {
            verify_admin_audit(env, event).await
        }
    } else {
        Err(worker::Error::RustError(
            "Admin audit event conflicts with its source record".to_owned(),
        ))
    }
}

async fn index_admin_d1(env: &Env, event: &AdminAuditEvent) -> Result<()> {
    let database = env.d1("DB")?;
    let seq = admin_audit_index_seq(event.seq).ok_or_else(|| {
        worker::Error::RustError("Admin audit index sequence is out of range".to_owned())
    })?;
    let result = database
        .prepare(
            "INSERT INTO audit_index(\
               seq, ts, actor, action, target, prev_hash, hash, r2_key\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(seq) DO NOTHING",
        )
        .bind(&[
            integer(seq)?,
            integer(event.occurred_at)?,
            JsValue::from_str(&event.actor),
            JsValue::from_str(&event.action),
            JsValue::from_str(&event.target),
            blob(&event.prev_hash),
            blob(&event.hash),
            JsValue::from_str(&event.r2_key),
        ])?
        .run()
        .await?;
    let inserted = result
        .meta()?
        .and_then(|meta| meta.changes)
        .is_some_and(|changes| changes > 0);
    if inserted {
        return Ok(());
    }

    verify_admin_index(&database, seq, event).await
}

async fn verify_admin_index(
    database: &D1Database,
    seq: i64,
    event: &AdminAuditEvent,
) -> Result<()> {
    let existing = database
        .prepare(
            "SELECT ts, actor, action, target, prev_hash, hash, r2_key \
             FROM audit_index WHERE seq = ?",
        )
        .bind(&[integer(seq)?])?
        .first::<AuditIndexRow>(None)
        .await?;
    let matches = existing.is_some_and(|row| {
        row.ts == event.occurred_at
            && row.actor == event.actor
            && row.action == event.action
            && row.target.as_deref() == Some(event.target.as_str())
            && row.prev_hash == event.prev_hash
            && row.hash == event.hash
            && row.r2_key == event.r2_key
    });
    if matches {
        Ok(())
    } else {
        Err(worker::Error::RustError(
            "Admin audit index sequence conflicts with an existing record".to_owned(),
        ))
    }
}

async fn mark_admin_archived(env: &Env, event: &AdminAuditEvent) -> Result<()> {
    let result = env
        .d1("DB")?
        .prepare(
            "UPDATE admin_audit_events SET archived_at = COALESCE(archived_at, ?) \
             WHERE seq = ? AND event_json = ?",
        )
        .bind(&[
            integer(now_seconds())?,
            integer(event.seq)?,
            JsValue::from_str(&serde_json::to_string(event)?),
        ])?
        .run()
        .await?;
    if result.meta()?.and_then(|meta| meta.changes) == Some(1) {
        Ok(())
    } else {
        Err(worker::Error::RustError(
            "Admin audit source disappeared before archive checkpoint".to_owned(),
        ))
    }
}

fn now_seconds() -> i64 {
    i64::try_from(Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
}

async fn index_d1(env: &Env, event: &AuditArchiveEvent) -> Result<()> {
    let database = env.d1("DB")?;
    let seq = audit_index_seq(event.shard, event.seq).ok_or_else(|| {
        worker::Error::RustError("audit index sequence is out of range".to_owned())
    })?;
    let kind = ArtifactKind::from_u8(event.kind)
        .ok_or_else(|| worker::Error::RustError("audit artifact kind is invalid".to_owned()))?;
    let actor = format!("issuer:{}", event.shard);
    let action = format!("issue:{}", kind.ctx_name());
    let target = hex_encode(&event.subject);

    let result = database
        .prepare(
            "INSERT INTO audit_index(\
               seq, ts, actor, action, target, prev_hash, hash, r2_key\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(seq) DO NOTHING",
        )
        .bind(&[
            integer(seq)?,
            integer(event.occurred_at)?,
            JsValue::from_str(&actor),
            JsValue::from_str(&action),
            JsValue::from_str(&target),
            blob(&event.prev_hash),
            blob(&event.hash),
            JsValue::from_str(&event.r2_key),
        ])?
        .run()
        .await?;
    let inserted = result
        .meta()?
        .and_then(|meta| meta.changes)
        .is_some_and(|changes| changes > 0);
    if inserted {
        return Ok(());
    }

    verify_existing_index(&database, seq, event, &actor, &action, &target).await
}

async fn verify_existing_index(
    database: &D1Database,
    seq: i64,
    event: &AuditArchiveEvent,
    actor: &str,
    action: &str,
    target: &str,
) -> Result<()> {
    let existing = database
        .prepare(
            "SELECT ts, actor, action, target, prev_hash, hash, r2_key \
             FROM audit_index WHERE seq = ?",
        )
        .bind(&[integer(seq)?])?
        .first::<AuditIndexRow>(None)
        .await?;
    let matches = existing.is_some_and(|row| {
        row.ts == event.occurred_at
            && row.actor == actor
            && row.action == action
            && row.target.as_deref() == Some(target)
            && row.prev_hash == event.prev_hash
            && row.hash == event.hash
            && row.r2_key == event.r2_key
    });
    if matches {
        Ok(())
    } else {
        Err(worker::Error::RustError(
            "audit index sequence conflicts with an existing record".to_owned(),
        ))
    }
}

#[derive(Debug, Deserialize)]
struct AuditIndexRow {
    ts: i64,
    actor: String,
    action: String,
    target: Option<String>,
    #[serde(with = "serde_bytes")]
    prev_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
    r2_key: String,
}

#[derive(Debug, Deserialize)]
struct AdminAuditSourceRow {
    event_json: String,
    #[serde(with = "serde_bytes")]
    prev_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
    r2_key: String,
}

fn blob(value: &[u8]) -> JsValue {
    JsValue::from(&D1Type::Blob(value))
}

fn integer(value: i64) -> Result<JsValue> {
    if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
        return Err(worker::Error::RustError(
            "audit integer exceeds JavaScript safe range".to_owned(),
        ));
    }
    Ok(JsValue::from_f64(value as f64))
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
