use worker::wasm_bindgen::JsValue;
use worker::{D1Database, D1Type, Result};

use crate::events::{MachineProjection, ProjectionEvent};

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

pub(crate) async fn apply(database: &D1Database, event: &ProjectionEvent) -> Result<()> {
    let mut statements = Vec::with_capacity(2);
    if let Some(machine) = &event.machine {
        statements.push(machine_statement(database, event, machine)?);
    }
    statements.push(license_statement(database, event)?);
    database.batch(statements).await?;
    Ok(())
}

fn machine_statement(
    database: &D1Database,
    event: &ProjectionEvent,
    machine: &MachineProjection,
) -> Result<worker::D1PreparedStatement> {
    database
        .prepare(
            "INSERT INTO machines(\
               id, license_id, fingerprint, status, activation_path, first_seen_at, \
               last_seen_at, os, arch, app_version, sdk_version, release_id, variant_id, \
               build_fp, geo_country, suspicion, proj_version\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
               license_id = excluded.license_id, \
               fingerprint = excluded.fingerprint, \
               status = excluded.status, \
               activation_path = excluded.activation_path, \
               first_seen_at = excluded.first_seen_at, \
               last_seen_at = excluded.last_seen_at, \
               os = excluded.os, \
               arch = excluded.arch, \
               app_version = excluded.app_version, \
               sdk_version = excluded.sdk_version, \
               release_id = excluded.release_id, \
               variant_id = excluded.variant_id, \
               build_fp = excluded.build_fp, \
               geo_country = excluded.geo_country, \
               suspicion = excluded.suspicion, \
               proj_version = excluded.proj_version \
             WHERE machines.proj_version < excluded.proj_version",
        )
        .bind(&[
            blob(&machine.machine_id),
            blob(&event.license_id),
            blob(&machine.fingerprint),
            text(&machine.status),
            text(&machine.activation_path),
            integer(machine.first_seen_at)?,
            optional_integer(machine.last_seen_at)?,
            optional_text(machine.os.as_deref()),
            optional_text(machine.arch.as_deref()),
            optional_text(machine.app_version.as_deref()),
            optional_text(machine.sdk_version.as_deref()),
            optional_text(machine.release_id.as_deref()),
            optional_integer(machine.variant_id)?,
            optional_text(machine.build_fp.as_deref()),
            optional_text(machine.geo_country.as_deref()),
            integer(machine.suspicion)?,
            integer(event.proj_version)?,
        ])
}

fn license_statement(
    database: &D1Database,
    event: &ProjectionEvent,
) -> Result<worker::D1PreparedStatement> {
    database
        .prepare(
            "UPDATE licenses SET \
               status = ?1, seats_used = ?2, last_seen_at = ?3, updated_at = ?4, \
               proj_version = ?5 \
             WHERE id = ?6 AND proj_version < ?5",
        )
        .bind(&[
            text(&event.license_status),
            integer(event.seats_used)?,
            optional_integer(event.last_seen_at)?,
            integer(event.occurred_at)?,
            integer(event.proj_version)?,
            blob(&event.license_id),
        ])
}

fn blob(value: &[u8]) -> JsValue {
    JsValue::from(&D1Type::Blob(value))
}

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn optional_text(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, JsValue::from_str)
}

fn integer(value: i64) -> Result<JsValue> {
    if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
        return Err(worker::Error::RustError(
            "projection integer exceeds JavaScript safe range".to_owned(),
        ));
    }
    Ok(JsValue::from_f64(value as f64))
}

fn optional_integer(value: Option<i64>) -> Result<JsValue> {
    value.map_or(Ok(JsValue::NULL), integer)
}
