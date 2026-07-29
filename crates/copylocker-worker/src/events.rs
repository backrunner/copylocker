use copylocker_suite::cbor::{decode_canonical, CborValue, Limits, MapBuilder};
use copylocker_suite::HashScheme;
use copylocker_suite_std::Sha256Scheme;
use copylocker_types::{ArtifactKind, Digest, KillReason};
use serde::{Deserialize, Serialize};

pub(crate) const LICENSE_PROJECTION_EVENT: &str = "license_projection";
pub(crate) const PROJECTION_SCHEMA_VERSION: u8 = 1;
pub(crate) const AUDIT_ARCHIVE_EVENT: &str = "audit_archive";
pub(crate) const AUDIT_SCHEMA_VERSION: u8 = 1;
pub(crate) const ADMIN_AUDIT_ARCHIVE_EVENT: &str = "admin_audit_archive";
pub(crate) const ADMIN_AUDIT_SCHEMA_VERSION: u8 = 2;
pub(crate) const ISSUER_SHARDS: u8 = 8;

const AUDIT_CHAIN_LABEL: &[u8] = b"copylocker/issuer-audit/v1";
const ADMIN_AUDIT_V1_CHAIN_LABEL: &[u8] = b"copylocker/admin-audit/v1";
const ADMIN_AUDIT_V2_CHAIN_LABEL: &[u8] = b"copylocker/admin-audit/v2";
const ADMIN_APPEND_REQUEST_LABEL: &[u8] = b"copylocker/admin-audit-append/v1";
const MAX_AUDIT_ENVELOPE: usize = 2 * 1024 * 1024;
const MAX_ADMIN_SNAPSHOT: usize = 64 * 1024;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProjectionEvent {
    pub(crate) event: String,
    pub(crate) schema_version: u8,
    pub(crate) license_id: Vec<u8>,
    pub(crate) license_status: String,
    pub(crate) seats_used: i64,
    pub(crate) last_seen_at: Option<i64>,
    pub(crate) machine: Option<MachineProjection>,
    pub(crate) proj_version: i64,
    pub(crate) occurred_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct MachineProjection {
    pub(crate) machine_id: Vec<u8>,
    pub(crate) fingerprint: Vec<u8>,
    pub(crate) status: String,
    pub(crate) activation_path: String,
    pub(crate) first_seen_at: i64,
    pub(crate) last_seen_at: Option<i64>,
    pub(crate) os: Option<String>,
    pub(crate) arch: Option<String>,
    pub(crate) app_version: Option<String>,
    pub(crate) sdk_version: Option<String>,
    pub(crate) release_id: Option<String>,
    pub(crate) variant_id: Option<i64>,
    pub(crate) build_fp: Option<String>,
    pub(crate) geo_country: Option<String>,
    pub(crate) suspicion: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AuditArchiveEvent {
    pub(crate) event: String,
    pub(crate) schema_version: u8,
    pub(crate) shard: u8,
    pub(crate) seq: i64,
    pub(crate) occurred_at: i64,
    pub(crate) kind: u8,
    pub(crate) product_id: String,
    pub(crate) subject: Vec<u8>,
    pub(crate) epoch_id: Vec<u8>,
    pub(crate) digest: Vec<u8>,
    pub(crate) prev_hash: Vec<u8>,
    pub(crate) hash: Vec<u8>,
    pub(crate) envelope: Vec<u8>,
    pub(crate) r2_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct AdminAuditEvent {
    pub(crate) event: String,
    pub(crate) schema_version: u8,
    pub(crate) seq: i64,
    pub(crate) occurred_at: i64,
    pub(crate) vendor_id: String,
    pub(crate) actor: String,
    pub(crate) action: String,
    pub(crate) target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<u8>,
    pub(crate) request_id: String,
    pub(crate) before: serde_json::Value,
    pub(crate) after: serde_json::Value,
    pub(crate) prev_hash: Vec<u8>,
    pub(crate) hash: Vec<u8>,
    pub(crate) r2_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct AdminRevocationSnapshot {
    pub(crate) kind: String,
    pub(crate) target: String,
    pub(crate) license_id: String,
    pub(crate) product_id: String,
    pub(crate) status: String,
    pub(crate) seats: u32,
    pub(crate) heartbeat_sec: Option<u64>,
    pub(crate) expires_at: Option<i64>,
    pub(crate) affected_machines: u64,
    pub(crate) revocation_epoch: u64,
}

pub(crate) struct IssuanceHashInput<'a> {
    pub(crate) shard: u8,
    pub(crate) seq: i64,
    pub(crate) occurred_at: i64,
    pub(crate) kind: u8,
    pub(crate) product_id: &'a str,
    pub(crate) subject: &'a [u8],
    pub(crate) epoch_id: &'a [u8],
    pub(crate) digest: &'a [u8],
    pub(crate) prev_hash: &'a [u8],
}

pub(crate) struct AdminAuditHashInput<'a> {
    pub(crate) seq: i64,
    pub(crate) occurred_at: i64,
    pub(crate) vendor_id: &'a str,
    pub(crate) actor: &'a str,
    pub(crate) action: &'a str,
    pub(crate) target: &'a str,
    pub(crate) reason: u8,
    pub(crate) request_id: &'a str,
    pub(crate) before: &'a [u8],
    pub(crate) after: &'a [u8],
    pub(crate) prev_hash: &'a [u8],
}

pub(crate) struct AdminAuditV2HashInput<'a> {
    pub(crate) seq: i64,
    pub(crate) occurred_at: i64,
    pub(crate) vendor_id: &'a str,
    pub(crate) actor: &'a str,
    pub(crate) action: &'a str,
    pub(crate) target: &'a str,
    pub(crate) reason: Option<u8>,
    pub(crate) request_id: &'a str,
    pub(crate) before: &'a [u8],
    pub(crate) after: &'a [u8],
    pub(crate) prev_hash: &'a [u8],
}

impl ProjectionEvent {
    pub(crate) fn is_valid(&self) -> bool {
        self.event == LICENSE_PROJECTION_EVENT
            && self.schema_version == PROJECTION_SCHEMA_VERSION
            && self.license_id.len() == 16
            && matches!(
                self.license_status.as_str(),
                "active" | "suspended" | "expired" | "revoked"
            )
            && self.seats_used >= 0
            && self.proj_version > 0
            && self.occurred_at >= 0
            && self.last_seen_at.is_none_or(|value| value >= 0)
            && self
                .machine
                .as_ref()
                .is_none_or(MachineProjection::is_valid)
    }
}

impl MachineProjection {
    fn is_valid(&self) -> bool {
        self.machine_id.len() == 16
            && !self.fingerprint.is_empty()
            && self.fingerprint.len() <= 128
            && matches!(
                self.status.as_str(),
                "active" | "pending" | "released" | "revoked"
            )
            && matches!(
                self.activation_path.as_str(),
                "online" | "offline_ar" | "olk" | "account"
            )
            && self.first_seen_at >= 0
            && self.last_seen_at.is_none_or(|value| value >= 0)
            && self.variant_id.is_none_or(|value| value >= 0)
            && self.suspicion >= 0
            && optional_string_is_bounded(&self.os, 128)
            && optional_string_is_bounded(&self.arch, 128)
            && optional_string_is_bounded(&self.app_version, 128)
            && optional_string_is_bounded(&self.sdk_version, 128)
            && optional_string_is_bounded(&self.release_id, 128)
            && optional_string_is_bounded(&self.build_fp, 256)
            && optional_string_is_bounded(&self.geo_country, 16)
    }
}

impl AuditArchiveEvent {
    pub(crate) fn is_valid(&self) -> bool {
        self.event == AUDIT_ARCHIVE_EVENT
            && self.schema_version == AUDIT_SCHEMA_VERSION
            && self.shard < ISSUER_SHARDS
            && (1..=MAX_SAFE_INTEGER).contains(&self.seq)
            && (0..=MAX_SAFE_INTEGER).contains(&self.occurred_at)
            && ArtifactKind::from_u8(self.kind).is_some_and(is_issuable_kind)
            && is_product_id(&self.product_id)
            && !self.subject.is_empty()
            && self.subject.len() <= 64
            && self.epoch_id.len() == 8
            && self.digest.len() == Digest::LEN
            && self.prev_hash.len() == Digest::LEN
            && self.hash.len() == Digest::LEN
            && !self.envelope.is_empty()
            && self.envelope.len() <= MAX_AUDIT_ENVELOPE
            && audit_r2_key(self.occurred_at, self.shard, self.seq).as_deref()
                == Some(self.r2_key.as_str())
            && Sha256Scheme::hash(&self.envelope).as_bytes() == self.digest.as_slice()
            && issuance_hash(&IssuanceHashInput {
                shard: self.shard,
                seq: self.seq,
                occurred_at: self.occurred_at,
                kind: self.kind,
                product_id: &self.product_id,
                subject: &self.subject,
                epoch_id: &self.epoch_id,
                digest: &self.digest,
                prev_hash: &self.prev_hash,
            })
            .as_bytes()
                == self.hash.as_slice()
            && audit_index_seq(self.shard, self.seq).is_some()
    }

    pub(crate) fn to_canonical(&self) -> Option<Vec<u8>> {
        if !self.is_valid() {
            return None;
        }
        let seq = u64::try_from(self.seq).ok()?;
        let occurred_at = u64::try_from(self.occurred_at).ok()?;
        let mut map = MapBuilder::new();
        map.put(0, CborValue::Uint(u64::from(self.schema_version)));
        map.put(1, CborValue::Uint(u64::from(self.shard)));
        map.put(2, CborValue::Uint(seq));
        map.put(3, CborValue::Uint(occurred_at));
        map.put(4, CborValue::Uint(u64::from(self.kind)));
        map.put(5, CborValue::Text(self.product_id.clone()));
        map.put(6, CborValue::Bytes(self.subject.clone()));
        map.put(7, CborValue::Bytes(self.epoch_id.clone()));
        map.put(8, CborValue::Bytes(self.digest.clone()));
        map.put(9, CborValue::Bytes(self.prev_hash.clone()));
        map.put(10, CborValue::Bytes(self.hash.clone()));
        map.put(11, CborValue::Bytes(self.envelope.clone()));
        Some(map.finish())
    }
}

impl AdminAuditEvent {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        seq: i64,
        occurred_at: i64,
        vendor_id: String,
        actor: String,
        reason: u8,
        request_id: String,
        before: AdminRevocationSnapshot,
        after: AdminRevocationSnapshot,
        prev_hash: Vec<u8>,
    ) -> Option<Self> {
        let action = format!("revoke:{}", before.kind);
        let target = before.target.clone();
        let before_bytes = before.to_canonical()?;
        let after_bytes = after.to_canonical()?;
        let hash = admin_audit_hash(&AdminAuditHashInput {
            seq,
            occurred_at,
            vendor_id: &vendor_id,
            actor: &actor,
            action: &action,
            target: &target,
            reason,
            request_id: &request_id,
            before: &before_bytes,
            after: &after_bytes,
            prev_hash: &prev_hash,
        });
        let event = Self {
            event: ADMIN_AUDIT_ARCHIVE_EVENT.to_owned(),
            schema_version: 1,
            seq,
            occurred_at,
            vendor_id,
            actor,
            action,
            target,
            reason: Some(reason),
            request_id,
            before: serde_json::to_value(before).ok()?,
            after: serde_json::to_value(after).ok()?,
            prev_hash,
            hash: hash.as_bytes().to_vec(),
            r2_key: admin_audit_r2_key(occurred_at, seq)?,
        };
        event.is_valid().then_some(event)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_v2(
        seq: i64,
        occurred_at: i64,
        vendor_id: String,
        actor: String,
        action: String,
        target: String,
        reason: Option<u8>,
        request_id: String,
        before: serde_json::Value,
        after: serde_json::Value,
        prev_hash: Vec<u8>,
    ) -> Option<Self> {
        let before_bytes = admin_snapshot_canonical(&before)?;
        let after_bytes = admin_snapshot_canonical(&after)?;
        let hash = admin_audit_v2_hash(&AdminAuditV2HashInput {
            seq,
            occurred_at,
            vendor_id: &vendor_id,
            actor: &actor,
            action: &action,
            target: &target,
            reason,
            request_id: &request_id,
            before: &before_bytes,
            after: &after_bytes,
            prev_hash: &prev_hash,
        });
        let event = Self {
            event: ADMIN_AUDIT_ARCHIVE_EVENT.to_owned(),
            schema_version: ADMIN_AUDIT_SCHEMA_VERSION,
            seq,
            occurred_at,
            vendor_id,
            actor,
            action,
            target,
            reason,
            request_id,
            before,
            after,
            prev_hash,
            hash: hash.as_bytes().to_vec(),
            r2_key: admin_audit_r2_key(occurred_at, seq)?,
        };
        event.is_valid().then_some(event)
    }

    pub(crate) fn is_valid(&self) -> bool {
        let common = self.event == ADMIN_AUDIT_ARCHIVE_EVENT
            && (1..=MAX_SAFE_INTEGER).contains(&self.seq)
            && (0..=MAX_SAFE_INTEGER).contains(&self.occurred_at)
            && is_identifier(&self.vendor_id)
            && !self.actor.is_empty()
            && self.actor.len() <= 128
            && valid_admin_action(&self.action)
            && valid_admin_target(&self.target)
            && valid_idempotency_key(&self.request_id)
            && self.prev_hash.len() == Digest::LEN
            && self.hash.len() == Digest::LEN
            && admin_audit_r2_key(self.occurred_at, self.seq).as_deref()
                == Some(self.r2_key.as_str())
            && admin_audit_index_seq(self.seq).is_some();
        common
            && match self.schema_version {
                1 => self.is_valid_v1(),
                ADMIN_AUDIT_SCHEMA_VERSION => self.is_valid_v2(),
                _ => false,
            }
    }

    pub(crate) fn to_canonical(&self) -> Option<Vec<u8>> {
        if !self.is_valid() {
            return None;
        }
        let (before, after) = self.snapshot_values()?;
        let mut map = MapBuilder::new();
        map.put(0, CborValue::Uint(u64::from(self.schema_version)));
        map.put(1, CborValue::Uint(u64::try_from(self.seq).ok()?));
        map.put(2, CborValue::Uint(u64::try_from(self.occurred_at).ok()?));
        map.put(3, CborValue::Text(self.vendor_id.clone()));
        map.put(4, CborValue::Text(self.actor.clone()));
        map.put(5, CborValue::Text(self.action.clone()));
        map.put(6, CborValue::Text(self.target.clone()));
        map.put_opt(
            7,
            self.reason.map(|value| CborValue::Uint(u64::from(value))),
        );
        map.put(8, CborValue::Text(self.request_id.clone()));
        map.put(9, before);
        map.put(10, after);
        map.put(11, CborValue::Bytes(self.prev_hash.clone()));
        map.put(12, CborValue::Bytes(self.hash.clone()));
        Some(map.finish())
    }

    fn is_valid_v1(&self) -> bool {
        let Some(reason) = self.reason else {
            return false;
        };
        let Some((before, after)) = self.revocation_snapshots() else {
            return false;
        };
        let Some(before_bytes) = before.to_canonical() else {
            return false;
        };
        let Some(after_bytes) = after.to_canonical() else {
            return false;
        };
        self.action == format!("revoke:{}", before.kind)
            && self.target == before.target
            && KillReason::from_u8(reason).is_some()
            && before.same_entity(&after)
            && before.status != "revoked"
            && before.revocation_epoch.checked_add(1) == Some(after.revocation_epoch)
            && after.revocation_epoch == self.seq as u64
            && after.status == "revoked"
            && after.affected_machines == 0
            && admin_audit_hash(&AdminAuditHashInput {
                seq: self.seq,
                occurred_at: self.occurred_at,
                vendor_id: &self.vendor_id,
                actor: &self.actor,
                action: &self.action,
                target: &self.target,
                reason,
                request_id: &self.request_id,
                before: &before_bytes,
                after: &after_bytes,
                prev_hash: &self.prev_hash,
            })
            .as_bytes()
                == self.hash.as_slice()
    }

    fn is_valid_v2(&self) -> bool {
        if self
            .reason
            .is_some_and(|reason| KillReason::from_u8(reason).is_none())
            || self.before == self.after
        {
            return false;
        }
        let Some(before) = admin_snapshot_canonical(&self.before) else {
            return false;
        };
        let Some(after) = admin_snapshot_canonical(&self.after) else {
            return false;
        };
        admin_audit_v2_hash(&AdminAuditV2HashInput {
            seq: self.seq,
            occurred_at: self.occurred_at,
            vendor_id: &self.vendor_id,
            actor: &self.actor,
            action: &self.action,
            target: &self.target,
            reason: self.reason,
            request_id: &self.request_id,
            before: &before,
            after: &after,
            prev_hash: &self.prev_hash,
        })
        .as_bytes()
            == self.hash.as_slice()
    }

    fn snapshot_values(&self) -> Option<(CborValue, CborValue)> {
        if self.schema_version == 1 {
            let (before, after) = self.revocation_snapshots()?;
            return Some((before.to_value(), after.to_value()));
        }
        Some((
            admin_snapshot_value(&self.before, 0)?,
            admin_snapshot_value(&self.after, 0)?,
        ))
    }

    pub(crate) fn revocation_snapshots(
        &self,
    ) -> Option<(AdminRevocationSnapshot, AdminRevocationSnapshot)> {
        Some((
            serde_json::from_value(self.before.clone()).ok()?,
            serde_json::from_value(self.after.clone()).ok()?,
        ))
    }
}

impl AdminRevocationSnapshot {
    pub(crate) fn is_valid(&self) -> bool {
        let valid_status = match self.kind.as_str() {
            "license" => matches!(
                self.status.as_str(),
                "active" | "suspended" | "expired" | "revoked"
            ),
            "machine" => matches!(
                self.status.as_str(),
                "active" | "pending" | "released" | "revoked"
            ),
            _ => false,
        };
        is_lower_hex(&self.target, 32)
            && is_lower_hex(&self.license_id, 32)
            && is_identifier(&self.product_id)
            && valid_status
            && (1..=100_000).contains(&self.seats)
            && self
                .heartbeat_sec
                .is_none_or(|value| value > 0 && value <= MAX_SAFE_INTEGER as u64)
            && self
                .expires_at
                .is_none_or(|value| (0..=MAX_SAFE_INTEGER).contains(&value))
            && self.affected_machines <= MAX_SAFE_INTEGER as u64
            && self.revocation_epoch <= MAX_SAFE_INTEGER as u64
    }

    fn same_entity(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.target == other.target
            && self.license_id == other.license_id
            && self.product_id == other.product_id
            && self.seats == other.seats
            && self.heartbeat_sec == other.heartbeat_sec
            && self.expires_at == other.expires_at
    }

    pub(crate) fn to_canonical(&self) -> Option<Vec<u8>> {
        self.is_valid().then(|| self.to_value().to_canonical())
    }

    fn to_value(&self) -> CborValue {
        let mut map = MapBuilder::new();
        map.put(0, CborValue::Text(self.kind.clone()));
        map.put(1, CborValue::Text(self.target.clone()));
        map.put(2, CborValue::Text(self.license_id.clone()));
        map.put(3, CborValue::Text(self.product_id.clone()));
        map.put(4, CborValue::Text(self.status.clone()));
        map.put(5, CborValue::Uint(u64::from(self.seats)));
        map.put_opt(6, self.heartbeat_sec.map(CborValue::Uint));
        map.put_opt(7, self.expires_at.map(CborValue::int));
        map.put(8, CborValue::Uint(self.affected_machines));
        map.put(9, CborValue::Uint(self.revocation_epoch));
        map.build()
    }
}

pub(crate) fn admin_snapshot_canonical(value: &serde_json::Value) -> Option<Vec<u8>> {
    let encoded = admin_snapshot_value(value, 0)?.to_canonical();
    if encoded.len() > MAX_ADMIN_SNAPSHOT {
        return None;
    }
    decode_canonical(
        &encoded,
        Limits {
            max_string: MAX_ADMIN_SNAPSHOT,
            ..Limits::default()
        },
    )
    .ok()?;
    Some(encoded)
}

fn admin_snapshot_value(value: &serde_json::Value, depth: u8) -> Option<CborValue> {
    if depth > Limits::default().max_depth {
        return None;
    }
    match value {
        serde_json::Value::Null => Some(CborValue::Null),
        serde_json::Value::Bool(value) => Some(CborValue::Bool(*value)),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                (value <= MAX_SAFE_INTEGER as u64).then_some(CborValue::Uint(value))
            } else {
                value
                    .as_i64()
                    .filter(|value| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value))
                    .map(CborValue::int)
            }
        }
        serde_json::Value::String(value) => {
            (value.len() <= MAX_ADMIN_SNAPSHOT).then(|| CborValue::Text(value.clone()))
        }
        serde_json::Value::Array(values) => {
            if values.len() > Limits::default().max_items {
                return None;
            }
            values
                .iter()
                .map(|value| admin_snapshot_value(value, depth.saturating_add(1)))
                .collect::<Option<Vec<_>>>()
                .map(CborValue::Array)
        }
        serde_json::Value::Object(values) => {
            if values.len() > Limits::default().max_items {
                return None;
            }
            values
                .iter()
                .map(|(key, value)| {
                    (key.len() <= MAX_ADMIN_SNAPSHOT).then(|| {
                        Some((
                            CborValue::Text(key.clone()),
                            admin_snapshot_value(value, depth.saturating_add(1))?,
                        ))
                    })?
                })
                .collect::<Option<Vec<_>>>()
                .map(CborValue::Map)
        }
    }
}

pub(crate) fn is_issuable_kind(kind: ArtifactKind) -> bool {
    matches!(
        kind,
        ArtifactKind::MachineCred
            | ArtifactKind::ValidationTicket
            | ArtifactKind::KillOrder
            | ArtifactKind::RevocationBatch
            | ArtifactKind::OfflineLicenseKey
            | ArtifactKind::ActivationResponse
    )
}

pub(crate) fn issuance_hash(input: &IssuanceHashInput<'_>) -> Digest {
    Sha256Scheme::hash_parts(&[
        AUDIT_CHAIN_LABEL,
        &[input.shard],
        &input.seq.to_be_bytes(),
        &input.occurred_at.to_be_bytes(),
        &[input.kind],
        input.product_id.as_bytes(),
        input.subject,
        input.epoch_id,
        input.digest,
        input.prev_hash,
    ])
}

pub(crate) fn admin_audit_hash(input: &AdminAuditHashInput<'_>) -> Digest {
    Sha256Scheme::hash_parts(&[
        ADMIN_AUDIT_V1_CHAIN_LABEL,
        &input.seq.to_be_bytes(),
        &input.occurred_at.to_be_bytes(),
        input.vendor_id.as_bytes(),
        input.actor.as_bytes(),
        input.action.as_bytes(),
        input.target.as_bytes(),
        &[input.reason],
        input.request_id.as_bytes(),
        input.before,
        input.after,
        input.prev_hash,
    ])
}

pub(crate) fn admin_audit_v2_hash(input: &AdminAuditV2HashInput<'_>) -> Digest {
    let reason = input.reason.map(|value| [value]);
    let reason = reason.as_ref().map_or(&[][..], |value| &value[..]);
    Sha256Scheme::hash_parts(&[
        ADMIN_AUDIT_V2_CHAIN_LABEL,
        &input.seq.to_be_bytes(),
        &input.occurred_at.to_be_bytes(),
        input.vendor_id.as_bytes(),
        input.actor.as_bytes(),
        input.action.as_bytes(),
        input.target.as_bytes(),
        reason,
        input.request_id.as_bytes(),
        input.before,
        input.after,
        input.prev_hash,
    ])
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn admin_append_request_hash(
    occurred_at: i64,
    vendor_id: &str,
    actor: &str,
    action: &str,
    target: &str,
    reason: Option<u8>,
    request_id: &str,
    before: &[u8],
    after: &[u8],
) -> Digest {
    let reason = reason.map(|value| [value]);
    let reason = reason.as_ref().map_or(&[][..], |value| &value[..]);
    Sha256Scheme::hash_parts(&[
        ADMIN_APPEND_REQUEST_LABEL,
        &occurred_at.to_be_bytes(),
        vendor_id.as_bytes(),
        actor.as_bytes(),
        action.as_bytes(),
        target.as_bytes(),
        reason,
        request_id.as_bytes(),
        before,
        after,
    ])
}

pub(crate) fn issuer_shard(routing_key: &[u8]) -> u8 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let hash = routing_key.iter().fold(FNV_OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    });
    (hash % u64::from(ISSUER_SHARDS)) as u8
}

pub(crate) fn issuer_object_name(shard: u8) -> String {
    format!("issuer-{shard}")
}

pub(crate) fn audit_index_seq(shard: u8, local_seq: i64) -> Option<i64> {
    if shard >= ISSUER_SHARDS || local_seq <= 0 {
        return None;
    }
    local_seq
        .checked_sub(1)?
        .checked_mul(i64::from(ISSUER_SHARDS))?
        .checked_add(i64::from(shard))?
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
}

pub(crate) fn admin_audit_index_seq(seq: i64) -> Option<i64> {
    (1..=MAX_SAFE_INTEGER)
        .contains(&seq)
        .then(|| seq.checked_neg())
        .flatten()
}

pub(crate) fn audit_r2_key(occurred_at: i64, shard: u8, seq: i64) -> Option<String> {
    if occurred_at < 0 || shard >= ISSUER_SHARDS || seq <= 0 {
        return None;
    }
    let days = occurred_at / 86_400;
    let (year, month, day) = civil_from_days(days)?;
    Some(format!(
        "audit/{year:04}/{month:02}/{day:02}/{shard}/{seq}.cbor"
    ))
}

pub(crate) fn admin_audit_r2_key(occurred_at: i64, seq: i64) -> Option<String> {
    if occurred_at < 0 || seq <= 0 {
        return None;
    }
    let days = occurred_at / 86_400;
    let (year, month, day) = civil_from_days(days)?;
    Some(format!(
        "audit-admin/{year:04}/{month:02}/{day:02}/{seq}.cbor"
    ))
}

fn civil_from_days(days_since_epoch: i64) -> Option<(i64, i64, i64)> {
    let days = days_since_epoch.checked_add(719_468)?;
    let era = if days >= 0 {
        days / 146_097
    } else {
        days.checked_sub(146_096)? / 146_097
    };
    let day_of_era = days.checked_sub(era.checked_mul(146_097)?)?;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era.checked_add(era.checked_mul(400)?)?;
    let day_of_year =
        day_of_era.checked_sub(365 * year_of_era + year_of_era / 4 - year_of_era / 100)?;
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (1970..=9999).contains(&year).then_some((year, month, day))
}

fn is_product_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_identifier(value: &str) -> bool {
    is_product_id(value)
}

fn valid_admin_action(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.'))
}

fn valid_admin_target(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn optional_string_is_bounded(value: &Option<String>, max_len: usize) -> bool {
    value.as_ref().is_none_or(|value| value.len() <= max_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_suite::cbor::{decode_canonical, Limits};

    #[test]
    fn audit_paths_use_utc_calendar_days() {
        assert_eq!(
            audit_r2_key(0, 0, 1).as_deref(),
            Some("audit/1970/01/01/0/1.cbor")
        );
        assert_eq!(
            audit_r2_key(1_700_000_000, 7, 42).as_deref(),
            Some("audit/2023/11/14/7/42.cbor")
        );
    }

    #[test]
    fn sharded_audit_sequences_do_not_overlap() {
        assert_eq!(audit_index_seq(0, 1), Some(1));
        assert_eq!(audit_index_seq(7, 1), Some(8));
        assert_eq!(audit_index_seq(0, 2), Some(9));

        let mut values = std::collections::BTreeSet::new();
        for seq in 1..=100 {
            for shard in 0..ISSUER_SHARDS {
                assert!(values.insert(audit_index_seq(shard, seq)));
            }
        }
    }

    #[test]
    fn admin_audit_uses_negative_index_space_and_canonical_snapshots(
    ) -> std::result::Result<(), String> {
        let before = AdminRevocationSnapshot {
            kind: "license".to_owned(),
            target: "01".repeat(16),
            license_id: "01".repeat(16),
            product_id: "product_1".to_owned(),
            status: "active".to_owned(),
            seats: 3,
            heartbeat_sec: Some(3_600),
            expires_at: None,
            affected_machines: 2,
            revocation_epoch: 0,
        };
        let mut after = before.clone();
        after.status = "revoked".to_owned();
        after.affected_machines = 0;
        after.revocation_epoch = 1;
        let event = AdminAuditEvent::new(
            1,
            1_700_000_000,
            "vendor_1".to_owned(),
            "admin@example.test".to_owned(),
            KillReason::RevokedLicense as u8,
            "request-1".to_owned(),
            before,
            after,
            vec![0; Digest::LEN],
        )
        .ok_or_else(|| "valid Admin audit event was rejected".to_owned())?;

        assert_eq!(admin_audit_index_seq(1), Some(-1));
        assert_eq!(
            admin_audit_index_seq(MAX_SAFE_INTEGER),
            Some(-MAX_SAFE_INTEGER)
        );
        assert_eq!(admin_audit_index_seq(0), None);
        assert_eq!(event.r2_key, "audit-admin/2023/11/14/1.cbor".to_owned());
        let archive = event
            .to_canonical()
            .ok_or_else(|| "Admin audit event did not encode".to_owned())?;
        let decoded =
            decode_canonical(&archive, Limits::default()).map_err(|error| format!("{error:?}"))?;
        assert_eq!(decoded.as_map().map(<[_]>::len), Some(13));
        assert_eq!(decoded.get(1).and_then(CborValue::as_uint), Some(1));
        assert_eq!(
            decoded.get(5).and_then(CborValue::as_text),
            Some("revoke:license")
        );
        assert_eq!(
            decoded
                .get(9)
                .and_then(|snapshot| snapshot.get(4))
                .and_then(CborValue::as_text),
            Some("active")
        );
        assert_eq!(
            decoded
                .get(10)
                .and_then(|snapshot| snapshot.get(4))
                .and_then(CborValue::as_text),
            Some("revoked")
        );

        let mut tampered = event;
        tampered.actor = "other@example.test".to_owned();
        assert!(!tampered.is_valid());
        Ok(())
    }

    #[test]
    fn audit_archive_cbor_uses_the_version_one_field_map() -> std::result::Result<(), String> {
        let envelope = vec![0xa0];
        let digest = Sha256Scheme::hash(&envelope);
        let prev_hash = [0_u8; Digest::LEN];
        let hash = issuance_hash(&IssuanceHashInput {
            shard: 0,
            seq: 1,
            occurred_at: 0,
            kind: ArtifactKind::KillOrder as u8,
            product_id: "p",
            subject: &[1],
            epoch_id: &[2; 8],
            digest: digest.as_bytes(),
            prev_hash: &prev_hash,
        });
        let event = AuditArchiveEvent {
            event: AUDIT_ARCHIVE_EVENT.to_owned(),
            schema_version: AUDIT_SCHEMA_VERSION,
            shard: 0,
            seq: 1,
            occurred_at: 0,
            kind: ArtifactKind::KillOrder as u8,
            product_id: "p".to_owned(),
            subject: vec![1],
            epoch_id: vec![2; 8],
            digest: digest.as_bytes().to_vec(),
            prev_hash: prev_hash.to_vec(),
            hash: hash.as_bytes().to_vec(),
            envelope: envelope.clone(),
            r2_key: "audit/1970/01/01/0/1.cbor".to_owned(),
        };

        let archive = event
            .to_canonical()
            .ok_or_else(|| "valid audit event was rejected".to_owned())?;
        let decoded =
            decode_canonical(&archive, Limits::default()).map_err(|error| format!("{error:?}"))?;
        assert_eq!(decoded.as_map().map(<[_]>::len), Some(12));
        assert_eq!(decoded.get(0).and_then(CborValue::as_uint), Some(1));
        assert_eq!(decoded.get(1).and_then(CborValue::as_uint), Some(0));
        assert_eq!(decoded.get(2).and_then(CborValue::as_uint), Some(1));
        assert_eq!(decoded.get(3).and_then(CborValue::as_uint), Some(0));
        assert_eq!(
            decoded.get(4).and_then(CborValue::as_uint),
            Some(u64::from(ArtifactKind::KillOrder as u8))
        );
        assert_eq!(decoded.get(5).and_then(CborValue::as_text), Some("p"));
        assert_eq!(decoded.get(6).and_then(CborValue::as_bytes), Some(&[1][..]));
        assert_eq!(
            decoded.get(7).and_then(CborValue::as_bytes),
            Some(&[2; 8][..])
        );
        assert_eq!(
            decoded.get(8).and_then(CborValue::as_bytes),
            Some(digest.as_bytes().as_slice())
        );
        assert_eq!(
            decoded.get(9).and_then(CborValue::as_bytes),
            Some(prev_hash.as_slice())
        );
        assert_eq!(
            decoded.get(10).and_then(CborValue::as_bytes),
            Some(hash.as_bytes().as_slice())
        );
        assert_eq!(
            decoded.get(11).and_then(CborValue::as_bytes),
            Some(envelope.as_slice())
        );
        Ok(())
    }
}
