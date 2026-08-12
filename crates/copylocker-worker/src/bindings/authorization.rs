use std::collections::BTreeMap;

use copylocker_server_core::catalog::{Catalog, Feature, FeatureGroup, GroupMembers, Tier};
use copylocker_server_core::entitlement::{resolve, with_context, EntitlementSpec};
use copylocker_server_core::policy::{
    OfflineUpgradePolicy, Policy, RuntimeSpec, SeatSpec, Validity, VtSignature,
};
use copylocker_server_core::version::{
    decide, CompromisedAction, Release, ReleaseRegistry, ReleaseStatus, VersionDecision,
};
use copylocker_suite::cbor::{decode_canonical, CborValue, Limits, MapBuilder};
use copylocker_suite::{AeadScheme, CryptoRng, CryptoSuite, Secret};
use copylocker_types::{
    Digest, Entitlements, EpochId, Fingerprint, KillReason, LicenseId, Mode, SuiteId, Verdict,
    VersionScope,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use worker::wasm_bindgen::JsValue;
use worker::{D1Database, D1Type, Env, Error, Result};
use zeroize::Zeroize;

use crate::suites::{suite_dispatch, RequestSuite};

const SERVER_PEPPER_BINDING: &str = "SERVER_PEPPER";
const VARIANT_PARAMS_KEY_BINDING: &str = "VARIANT_PARAMS_KEY";
const ASSET_KEK_KEY_BINDING: &str = "ASSET_KEK_KEY";
const TEST_SERVER_PEPPER_BINDING: &str = "TEST_SERVER_PEPPER";
const TEST_VARIANT_PARAMS_KEY_BINDING: &str = "TEST_VARIANT_PARAMS_KEY";
const TEST_ASSET_KEK_KEY_BINDING: &str = "TEST_ASSET_KEK_KEY";
const SECRET_SCHEMA_VERSION: u8 = 1;
const VARIANT_PARAMS_SCHEMA_VERSION: u64 = 1;
const SECRET_LEN: usize = 32;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const CONFIG_LIMITS: Limits = Limits {
    max_depth: 8,
    max_items: 256,
    max_string: 64 * 1024,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LoadPurpose {
    Activate,
    Validate,
}

#[derive(Debug)]
pub(crate) enum AuthorizationError {
    InvalidCredential,
    ReleaseNotRegistered,
    VersionOutOfScope,
    ReleaseCompromised,
    Server(Error),
}

impl From<Error> for AuthorizationError {
    fn from(error: Error) -> Self {
        Self::Server(error)
    }
}

pub(crate) struct AuthorizationContext {
    pub(crate) license_id: LicenseId,
    pub(crate) product_id: String,
    pub(crate) license_status: String,
    pub(crate) seats: u32,
    pub(crate) heartbeat_secs: Option<i64>,
    pub(crate) expires_at: Option<i64>,
    pub(crate) policy: Policy,
    pub(crate) entitlements: Entitlements,
    pub(crate) release: Option<ReleaseMaterial>,
    pub(crate) verdict: Verdict,
    pub(crate) release_status: Option<u8>,
    pub(crate) kill_reason: Option<KillReason>,
}

impl AuthorizationContext {
    pub(crate) fn next_refresh_after(&self, now: i64) -> i64 {
        now.saturating_add(self.policy.runtime.refresh_after_secs)
    }

    pub(crate) fn not_after(&self, now: i64) -> i64 {
        match (self.policy.expires_at(now), self.expires_at) {
            (Some(policy), Some(license)) => policy.min(license),
            (Some(policy), None) => policy,
            (None, Some(license)) => license,
            (None, None) => copylocker_types::TimeWindow::UNLIMITED,
        }
    }
}

pub(crate) struct ReleaseMaterial {
    pub(crate) release_id: String,
    pub(crate) build_fingerprint: String,
    pub(crate) variant_id: u64,
    pub(crate) variant_const: [u8; 32],
    pub(crate) module_digest: Digest,
    pub(crate) binder_extra: Vec<Vec<u8>>,
    pub(crate) asset_keks: Vec<RegisteredAssetKek>,
    /// The release's registered suite, resolved from the persisted release row. At-rest
    /// protection for this release's material dispatches on it.
    pub(crate) suite: RequestSuite,
    state_key: Secret<[u8; SECRET_LEN]>,
}

impl ReleaseMaterial {
    pub(crate) fn seal_credential_state(
        &self,
        license_id: LicenseId,
        fingerprint: &Fingerprint,
        credential_secret: &Secret<[u8; SECRET_LEN]>,
        rng: &mut dyn CryptoRng,
    ) -> Result<Vec<u8>> {
        let aad = credential_state_aad(license_id, fingerprint);
        suite_dispatch!(
            self.suite,
            S,
            <S as CryptoSuite>::Aead::seal_with_nonce(
                self.state_key.expose(),
                &aad,
                credential_secret.as_slice(),
                rng,
            )
        )
        .map_err(|_| Error::RustError("credential state encryption failed".to_owned()))
    }

    pub(crate) fn open_credential_state(
        &self,
        license_id: LicenseId,
        fingerprint: &Fingerprint,
        encrypted: &[u8],
    ) -> Result<Secret<[u8; SECRET_LEN]>> {
        let aad = credential_state_aad(license_id, fingerprint);
        let mut plaintext = suite_dispatch!(
            self.suite,
            S,
            <S as CryptoSuite>::Aead::open_with_nonce(self.state_key.expose(), &aad, encrypted)
        )
        .map_err(|_| Error::RustError("credential state decryption failed".to_owned()))?;
        let value = plaintext.as_slice().try_into().map_err(|_| {
            Error::RustError("credential state has an invalid plaintext length".to_owned())
        })?;
        plaintext.zeroize();
        Ok(Secret::new(value))
    }
}

pub(crate) struct RegisteredAssetKek {
    pub(crate) feature_id: String,
    pub(crate) key: Secret<[u8; SECRET_LEN]>,
}

pub(crate) struct SigningEpoch {
    pub(crate) epoch_id: EpochId,
    pub(crate) fast_verifying_key: Vec<u8>,
}

pub(crate) async fn load_signing_epoch(
    env: &Env,
    product_id: &str,
    now: i64,
) -> std::result::Result<SigningEpoch, AuthorizationError> {
    let row = env
        .d1("DB")?
        .prepare(
            "SELECT id, suite_id, vk_fast FROM epochs \
             WHERE revoked_at IS NULL AND not_before <= ? AND not_after > ? \
               AND (product_scope IS NULL OR product_scope = ?) \
             ORDER BY CASE WHEN product_scope = ? THEN 0 ELSE 1 END, not_before DESC \
             LIMIT 1",
        )
        .bind(&[
            number(now)?,
            number(now)?,
            text(product_id),
            text(product_id),
        ])?
        .first::<EpochRow>(None)
        .await?
        .ok_or_else(|| server_error("no active signing epoch is configured"))?;
    let epoch_id =
        EpochId::from_slice(&row.id).ok_or_else(|| server_error("signing epoch id is invalid"))?;
    let suite_id = SuiteId::from_slice(&row.suite_id)
        .ok_or_else(|| server_error("signing epoch suite is invalid"))?;
    if suite_id != copylocker_suite_std::CL_STD_1_SUITE_ID || row.fast_verifying_key.is_empty() {
        return Err(server_error("signing epoch key material is invalid"));
    }
    Ok(SigningEpoch {
        epoch_id,
        fast_verifying_key: row.fast_verifying_key,
    })
}

pub(crate) async fn load_by_license_id(
    env: &Env,
    license_id: LicenseId,
    release_id: &str,
    purpose: LoadPurpose,
    now: i64,
) -> std::result::Result<AuthorizationContext, AuthorizationError> {
    let database = env.d1("DB")?;
    let license = database
        .prepare(
            "SELECT id, product_id, policy_id, status, seats_override, \
                    entitlement_override_json, version_scope_override_json, expires_at, \
                    catalog_version \
             FROM licenses WHERE id = ?",
        )
        .bind(&[blob(license_id.as_bytes())])?
        .first::<LicenseRow>(None)
        .await?
        .ok_or(AuthorizationError::InvalidCredential)?;
    load_context(env, &database, license, release_id, purpose, now).await
}

pub(crate) async fn load_by_license_key(
    env: &Env,
    license_key: &copylocker_proto::LicenseKey,
    release_id: &str,
    purpose: LoadPurpose,
    now: i64,
) -> std::result::Result<AuthorizationContext, AuthorizationError> {
    let key_hmac = license_key_hmac(env, license_key).await?;

    let database = env.d1("DB")?;
    let license = database
        .prepare(
            "SELECT id, product_id, policy_id, status, seats_override, \
                    entitlement_override_json, version_scope_override_json, expires_at, \
                    catalog_version \
             FROM licenses WHERE key_hmac = ?",
        )
        .bind(&[blob(&key_hmac)])?
        .first::<LicenseRow>(None)
        .await?
        .ok_or(AuthorizationError::InvalidCredential)?;
    load_context(env, &database, license, release_id, purpose, now).await
}

/// Load the license bound to a Mode E account. When several licenses name the same account,
/// the most recently created one wins; the caller still enforces `status = active`.
pub(crate) async fn load_by_account(
    env: &Env,
    account_id: &str,
    release_id: &str,
    purpose: LoadPurpose,
    now: i64,
) -> std::result::Result<AuthorizationContext, AuthorizationError> {
    let database = env.d1("DB")?;
    let license = database
        .prepare(
            "SELECT id, product_id, policy_id, status, seats_override, \
                    entitlement_override_json, version_scope_override_json, expires_at, \
                    catalog_version \
             FROM licenses WHERE account_id = ? ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(&[text(account_id)])?
        .first::<LicenseRow>(None)
        .await?
        .ok_or(AuthorizationError::InvalidCredential)?;
    load_context(env, &database, license, release_id, purpose, now).await
}

/// The raw server pepper, exposed for the analytics pseudonymous machine key
/// (`90-analytics-telemetry.md §4.2`). Callers must domain-separate any derived key.
pub(crate) async fn server_pepper(
    env: &Env,
) -> std::result::Result<Secret<[u8; SECRET_LEN]>, AuthorizationError> {
    load_secret_key(env, SERVER_PEPPER_BINDING, TEST_SERVER_PEPPER_BINDING).await
}

pub(crate) async fn license_key_hmac(
    env: &Env,
    license_key: &copylocker_proto::LicenseKey,
) -> std::result::Result<Vec<u8>, AuthorizationError> {
    let pepper = load_secret_key(env, SERVER_PEPPER_BINDING, TEST_SERVER_PEPPER_BINDING).await?;
    let mut mac = <Hmac<Sha256>>::new_from_slice(pepper.expose())
        .map_err(|_| server_error("server pepper is invalid"))?;
    mac.update(&license_key.to_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(crate) async fn derive_license_issue_batch(
    env: &Env,
    operation_id: &str,
    product_short: u8,
    count: u32,
) -> std::result::Result<Vec<(LicenseId, copylocker_proto::LicenseKey, Vec<u8>)>, AuthorizationError>
{
    if operation_id.is_empty() || operation_id.len() > 512 || !(1..=100).contains(&count) {
        return Err(server_error("license issue operation id is invalid"));
    }
    let pepper = load_secret_key(env, SERVER_PEPPER_BINDING, TEST_SERVER_PEPPER_BINDING).await?;
    let derive = |label: &[u8], index: u32| -> std::result::Result<Vec<u8>, AuthorizationError> {
        let mut mac = <Hmac<Sha256>>::new_from_slice(pepper.expose())
            .map_err(|_| server_error("server pepper is invalid"))?;
        mac.update(b"copylocker/license-issue/v1");
        mac.update(label);
        mac.update(operation_id.as_bytes());
        mac.update(&index.to_be_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    };
    let mut issued = Vec::with_capacity(count as usize);
    for index in 0..count {
        let id_bytes = derive(b"license-id", index)?;
        let random_bytes = derive(b"license-key", index)?;
        let license_id = LicenseId(
            id_bytes
                .get(..16)
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| server_error("license id derivation failed"))?,
        );
        let key_random = random_bytes
            .get(..10)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| server_error("license key derivation failed"))?;
        let license_key = copylocker_proto::LicenseKey::new(product_short, key_random);
        let mut mac = <Hmac<Sha256>>::new_from_slice(pepper.expose())
            .map_err(|_| server_error("server pepper is invalid"))?;
        mac.update(&license_key.to_bytes());
        issued.push((
            license_id,
            license_key,
            mac.finalize().into_bytes().to_vec(),
        ));
    }
    Ok(issued)
}

async fn load_context(
    env: &Env,
    database: &D1Database,
    license: LicenseRow,
    release_id: &str,
    purpose: LoadPurpose,
    now: i64,
) -> std::result::Result<AuthorizationContext, AuthorizationError> {
    let license_id = LicenseId::from_slice(&license.id)
        .ok_or_else(|| server_error("license row has an invalid id"))?;
    if !is_identifier(&license.product_id) || !is_identifier(&license.policy_id) {
        return Err(server_error("license row has an invalid identifier"));
    }
    if !matches!(
        license.status.as_str(),
        "active" | "suspended" | "expired" | "revoked"
    ) {
        return Err(server_error("license row has an invalid status"));
    }
    let catalog_version = u32_from_i64(license.catalog_version, "catalog version")?;
    let seats_override = license
        .seats_override
        .map(|value| u32_from_i64(value, "license seat override"))
        .transpose()?;
    if license.expires_at.is_some_and(|value| value < 0) {
        return Err(server_error("license expiry is invalid"));
    }

    let mut policy = load_policy(database, &license.policy_id, &license.product_id).await?;
    if let Some(override_json) = license.entitlement_override_json.as_deref() {
        policy.entitlement = parse_json(override_json, "license entitlement override")?;
    }
    if let Some(override_json) = license.version_scope_override_json.as_deref() {
        policy.version_scope = parse_json(override_json, "license version scope override")?;
    }
    policy
        .validate()
        .map_err(|_| server_error("policy failed semantic validation"))?;

    let catalog = load_catalog(database, &license.product_id, catalog_version).await?;
    let entitlements = with_context(
        resolve(&catalog, &policy.entitlement, now)
            .map_err(|_| server_error("entitlement resolution failed"))?,
        Some(policy.version_scope.clone()),
        None,
    );
    let releases = load_release_rows(database, &license.product_id).await?;
    let registry = ReleaseRegistry {
        releases: releases
            .iter()
            .map(ReleaseRow::registry_release)
            .collect::<std::result::Result<Vec<_>, _>>()?,
    };

    let (selected, verdict, release_status, kill_reason) =
        match decide(&registry, &policy.version_scope, release_id) {
            VersionDecision::InScope { variant_id } => {
                let selected = selected_release(&releases, release_id, variant_id)?;
                let status = selected.release_status()? as u8;
                (Some(selected), Verdict::Ok, Some(status), None)
            }
            VersionDecision::NotRegistered => {
                return Err(AuthorizationError::ReleaseNotRegistered);
            }
            VersionDecision::OutOfScope { .. } if purpose == LoadPurpose::Activate => {
                return Err(AuthorizationError::VersionOutOfScope);
            }
            VersionDecision::OutOfScope { .. } => (None, Verdict::VersionOutOfScope, Some(0), None),
            VersionDecision::Compromised {
                action: CompromisedAction::Warn,
            } => {
                let selected = releases
                    .iter()
                    .find(|release| release.id == release_id)
                    .ok_or_else(|| server_error("release registry lost its selected release"))?;
                (Some(selected), Verdict::Ok, Some(2), None)
            }
            VersionDecision::Compromised {
                action: CompromisedAction::ForceUpgrade,
            } if purpose == LoadPurpose::Validate => {
                (None, Verdict::NeedsReactivation, Some(2), None)
            }
            VersionDecision::Compromised {
                action: CompromisedAction::Revoke,
            } if purpose == LoadPurpose::Validate => (
                None,
                Verdict::NeedsReactivation,
                Some(2),
                Some(KillReason::Fraud),
            ),
            VersionDecision::Compromised { .. } => {
                return Err(AuthorizationError::ReleaseCompromised);
            }
        };

    let release = match selected {
        Some(row) => Some(load_release_material(env, database, row).await?),
        None => None,
    };
    let seats = seats_override.unwrap_or(policy.seats.seats);
    if seats == 0 {
        return Err(server_error("effective seat count is zero"));
    }

    Ok(AuthorizationContext {
        license_id,
        product_id: license.product_id,
        license_status: license.status,
        seats,
        heartbeat_secs: policy.seats.heartbeat_secs,
        expires_at: license.expires_at,
        policy,
        entitlements,
        release,
        verdict,
        release_status,
        kill_reason,
    })
}

pub(crate) async fn load_policy(
    database: &D1Database,
    policy_id: &str,
    product_id: &str,
) -> std::result::Result<Policy, AuthorizationError> {
    let row = database
        .prepare(
            "SELECT id, product_id, name, preset, entitlement_json, validity_json, \
                    version_scope_json, seats, max_transfers, transfer_window_s, heartbeat_sec, \
                    mode, refresh_after_sec, grace_seconds, fpr_tolerance, allow_vm, allow_olk, \
                    allow_unbound_olk, vt_signature, offline_upgrade_policy, preload_variants_n, \
                    report_attrs \
             FROM policies WHERE id = ? AND product_id = ?",
        )
        .bind(&[text(policy_id), text(product_id)])?
        .first::<PolicyRow>(None)
        .await?
        .ok_or_else(|| server_error("license policy is missing"))?;

    let mode = u8_from_i64(row.mode, "policy mode")?;
    let fpr_tolerance = u8_from_i64(row.fpr_tolerance, "fingerprint tolerance")?;
    let max_transfers = row
        .max_transfers
        .map(|value| u32_from_i64(value, "maximum transfers"))
        .transpose()?;
    let preload_variants_n = u32_from_i64(row.preload_variants_n, "preload variants")?;
    let grace_secs = u32_from_i64(row.grace_seconds, "grace seconds")?;
    let heartbeat_secs = positive_optional(row.heartbeat_sec, "heartbeat seconds")?;
    let transfer_window_secs = positive_optional(row.transfer_window_s, "transfer window")?;
    if row.refresh_after_sec <= 0 {
        return Err(server_error("policy refresh interval is invalid"));
    }

    Ok(Policy {
        id: row.id,
        product_id: row.product_id,
        name: row.name,
        preset: row.preset,
        entitlement: parse_json(&row.entitlement_json, "policy entitlement")?,
        validity: parse_json::<Validity>(&row.validity_json, "policy validity")?,
        version_scope: parse_json::<VersionScope>(&row.version_scope_json, "policy version scope")?,
        seats: SeatSpec {
            seats: u32_from_i64(row.seats, "policy seats")?,
            max_transfers,
            transfer_window_secs,
            heartbeat_secs,
        },
        mode: Mode::from_u8(mode).ok_or_else(|| server_error("policy mode is invalid"))?,
        runtime: RuntimeSpec {
            refresh_after_secs: row.refresh_after_sec,
            grace_secs,
            fpr_tolerance,
            allow_vm: bool_from_i64(row.allow_vm, "allow_vm")?,
            allow_olk: bool_from_i64(row.allow_olk, "allow_olk")?,
            allow_unbound_olk: bool_from_i64(row.allow_unbound_olk, "allow_unbound_olk")?,
            vt_signature: match row.vt_signature.as_str() {
                "fast" => VtSignature::Fast,
                "pq" => VtSignature::Pq,
                _ => return Err(server_error("policy VT signature mode is invalid")),
            },
            offline_upgrade_policy: match row.offline_upgrade_policy.as_str() {
                "require_online" => OfflineUpgradePolicy::RequireOnline,
                "preload_n" => OfflineUpgradePolicy::PreloadN,
                "variant_stable" => OfflineUpgradePolicy::VariantStable,
                _ => return Err(server_error("policy offline upgrade mode is invalid")),
            },
            preload_variants_n,
            report_attrs: bool_from_i64(row.report_attrs, "report_attrs")?,
        },
    })
}

pub(crate) async fn load_catalog(
    database: &D1Database,
    product_id: &str,
    version: u32,
) -> std::result::Result<Catalog, AuthorizationError> {
    if let Some(row) = database
        .prepare("SELECT snapshot FROM catalog_versions WHERE product_id = ? AND version = ?")
        .bind(&[text(product_id), number(i64::from(version))?])?
        .first::<CatalogSnapshotRow>(None)
        .await?
    {
        let catalog = crate::json_cbor::decode::<Catalog>(&row.snapshot)
            .map_err(AuthorizationError::Server)?;
        if catalog.product_id != product_id || catalog.version != version {
            return Err(server_error("catalog snapshot identity is invalid"));
        }
        catalog
            .validate()
            .map_err(|_| server_error("catalog snapshot failed semantic validation"))?;
        return Ok(catalog);
    }

    let features = database
        .prepare("SELECT id, label, description, deprecated_at FROM features WHERE product_id = ?")
        .bind(&[text(product_id)])?
        .all()
        .await?
        .results::<FeatureRow>()?
        .into_iter()
        .map(|row| Feature {
            id: row.id,
            label: row.label,
            description: row.description,
            deprecated_at: row.deprecated_at,
        })
        .collect();
    let groups = database
        .prepare("SELECT id, label, members_json FROM feature_groups WHERE product_id = ?")
        .bind(&[text(product_id)])?
        .all()
        .await?
        .results::<GroupRow>()?
        .into_iter()
        .map(|row| {
            Ok(FeatureGroup {
                id: row.id,
                label: row.label,
                members: parse_json::<GroupMembers>(&row.members_json, "feature group")?,
            })
        })
        .collect::<std::result::Result<Vec<_>, AuthorizationError>>()?;
    let tiers = database
        .prepare(
            "SELECT id, label, rank, groups_json, features_json, limits_json, archived_at \
             FROM tiers WHERE product_id = ?",
        )
        .bind(&[text(product_id)])?
        .all()
        .await?
        .results::<TierRow>()?
        .into_iter()
        .map(|row| {
            Ok(Tier {
                id: row.id,
                label: row.label,
                rank: i32::try_from(row.rank)
                    .map_err(|_| server_error("tier rank is out of range"))?,
                groups: parse_json(&row.groups_json, "tier groups")?,
                features: row
                    .features_json
                    .as_deref()
                    .map(|json| parse_json(json, "tier features"))
                    .transpose()?
                    .unwrap_or_default(),
                limits: parse_json(&row.limits_json, "tier limits")?,
                archived_at: row.archived_at,
            })
        })
        .collect::<std::result::Result<Vec<_>, AuthorizationError>>()?;
    let catalog = Catalog {
        product_id: product_id.to_owned(),
        version,
        features,
        groups,
        tiers,
    };
    catalog
        .validate()
        .map_err(|_| server_error("catalog failed semantic validation"))?;
    Ok(catalog)
}

async fn load_release_rows(
    database: &D1Database,
    product_id: &str,
) -> std::result::Result<Vec<ReleaseRow>, AuthorizationError> {
    let rows = database
        .prepare(
            "SELECT id, product_id, app_version, variant_id, variant_params, build_fingerprint, \
                    channel, status, compromised_action, min_sdk_version, proto_ver, suite_id, \
                    published_at \
             FROM releases WHERE product_id = ?",
        )
        .bind(&[text(product_id)])?
        .all()
        .await?
        .results::<ReleaseRow>()?;
    for row in &rows {
        row.validate()?;
    }
    Ok(rows)
}

fn selected_release<'a>(
    releases: &'a [ReleaseRow],
    release_id: &str,
    variant_id: u64,
) -> std::result::Result<&'a ReleaseRow, AuthorizationError> {
    let row = releases
        .iter()
        .find(|release| release.id == release_id)
        .ok_or_else(|| server_error("release registry lost its selected release"))?;
    if row.variant_id_u64()? != variant_id {
        return Err(server_error("release registry variant mismatch"));
    }
    Ok(row)
}

async fn load_release_material(
    env: &Env,
    database: &D1Database,
    release: &ReleaseRow,
) -> std::result::Result<ReleaseMaterial, AuthorizationError> {
    let variant_key = load_secret_key(
        env,
        VARIANT_PARAMS_KEY_BINDING,
        TEST_VARIANT_PARAMS_KEY_BINDING,
    )
    .await?;
    let variant_id = release.variant_id_u64()?;
    let suite_id = release.suite_id()?;
    let suite = RequestSuite::resolve_persisted(suite_id)
        .ok_or_else(|| server_error("release suite is unsupported"))?;
    let parsed = open_variant_params_with(
        &variant_key,
        &release.id,
        &release.product_id,
        variant_id,
        &release.build_fingerprint,
        suite_id,
        &release.variant_params,
    )?;
    if parsed.variant_id != variant_id {
        return Err(server_error("release variant parameter id mismatch"));
    }

    let asset_key = load_secret_key(env, ASSET_KEK_KEY_BINDING, TEST_ASSET_KEK_KEY_BINDING).await?;
    let rows = database
        .prepare(
            "SELECT feature_id, key_version, encrypted_kek FROM release_feature_keks \
             WHERE release_id = ? AND product_id = ? ORDER BY feature_id",
        )
        .bind(&[text(&release.id), text(&release.product_id)])?
        .all()
        .await?
        .results::<AssetKekRow>()?;
    let mut asset_keks = Vec::with_capacity(rows.len());
    for row in rows {
        if !is_feature_id(&row.feature_id) || row.key_version <= 0 {
            return Err(server_error("asset KEK row is invalid"));
        }
        let key_version = u64::try_from(row.key_version)
            .map_err(|_| server_error("asset KEK version is invalid"))?;
        let key = open_asset_kek_with(
            &asset_key,
            &release.id,
            &release.product_id,
            &row.feature_id,
            key_version,
            suite_id,
            &row.encrypted_kek,
        )?;
        asset_keks.push(RegisteredAssetKek {
            feature_id: row.feature_id,
            key,
        });
    }

    Ok(ReleaseMaterial {
        release_id: release.id.clone(),
        build_fingerprint: release.build_fingerprint.clone(),
        variant_id,
        variant_const: parsed.variant_const,
        module_digest: Digest(parsed.module_digest),
        binder_extra: parsed.binder_extra,
        asset_keks,
        suite,
        state_key: variant_key,
    })
}

pub(crate) struct VariantParams {
    pub(crate) variant_id: u64,
    pub(crate) variant_const: [u8; 32],
    pub(crate) module_digest: [u8; 32],
    pub(crate) binder_extra: Vec<Vec<u8>>,
}

impl VariantParams {
    /// Canonical CBOR plaintext (`ADR-0013` `variant_params_v1`). CL-STD-1 omits
    /// the suite-private slot 5.
    fn encode(&self) -> Vec<u8> {
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(VARIANT_PARAMS_SCHEMA_VERSION));
        builder.put(1, CborValue::Uint(self.variant_id));
        builder.put(2, CborValue::Bytes(self.variant_const.to_vec()));
        builder.put(3, CborValue::Bytes(self.module_digest.to_vec()));
        builder.put(
            4,
            CborValue::Array(
                self.binder_extra
                    .iter()
                    .map(|item| CborValue::Bytes(item.clone()))
                    .collect(),
            ),
        );
        builder.finish()
    }
}

/// Encrypt freshly derived variant parameters for D1 storage (the write half of
/// `load_release_material`; plaintext never touches D1). The suite selects the AEAD through
/// the supported-suite registry and is bound into the at-rest AAD.
pub(crate) async fn seal_variant_params_at_rest(
    env: &Env,
    release_id: &str,
    product_id: &str,
    build_fingerprint: &str,
    suite_id: SuiteId,
    params: &VariantParams,
    rng: &mut dyn CryptoRng,
) -> std::result::Result<Vec<u8>, AuthorizationError> {
    let variant_key = load_secret_key(
        env,
        VARIANT_PARAMS_KEY_BINDING,
        TEST_VARIANT_PARAMS_KEY_BINDING,
    )
    .await?;
    let suite = RequestSuite::resolve_persisted(suite_id)
        .ok_or_else(|| server_error("release suite is unsupported"))?;
    let aad = variant_at_rest_aad(
        release_id,
        product_id,
        params.variant_id,
        build_fingerprint,
        suite_id,
    );
    suite_dispatch!(
        suite,
        S,
        <S as CryptoSuite>::Aead::seal_with_nonce(
            variant_key.expose(),
            &aad,
            &params.encode(),
            rng
        )
    )
    .map_err(|_| server_error("variant parameters at-rest encryption failed"))
}

/// Decrypt one release's variant parameters (used to reuse a stable variant on
/// a later release of the same product).
pub(crate) async fn open_variant_params_at_rest(
    env: &Env,
    release_id: &str,
    product_id: &str,
    variant_id: u64,
    build_fingerprint: &str,
    suite_id: SuiteId,
    encrypted: &[u8],
) -> std::result::Result<VariantParams, AuthorizationError> {
    let variant_key = load_secret_key(
        env,
        VARIANT_PARAMS_KEY_BINDING,
        TEST_VARIANT_PARAMS_KEY_BINDING,
    )
    .await?;
    open_variant_params_with(
        &variant_key,
        release_id,
        product_id,
        variant_id,
        build_fingerprint,
        suite_id,
        encrypted,
    )
}

fn open_variant_params_with(
    variant_key: &Secret<[u8; SECRET_LEN]>,
    release_id: &str,
    product_id: &str,
    variant_id: u64,
    build_fingerprint: &str,
    suite_id: SuiteId,
    encrypted: &[u8],
) -> std::result::Result<VariantParams, AuthorizationError> {
    let suite = RequestSuite::resolve_persisted(suite_id)
        .ok_or_else(|| server_error("release suite is unsupported"))?;
    let aad = variant_at_rest_aad(
        release_id,
        product_id,
        variant_id,
        build_fingerprint,
        suite_id,
    );
    let mut plaintext = suite_dispatch!(
        suite,
        S,
        <S as CryptoSuite>::Aead::open_with_nonce(variant_key.expose(), &aad, encrypted)
    )
    .map_err(|_| server_error("release variant parameters could not be decrypted"))?;
    let parsed = parse_variant_params(&plaintext);
    plaintext.zeroize();
    parsed
}

/// Load the full signing material of one release, for preloading offline KEKs
/// of sibling releases (`preload_n`).
pub(crate) async fn load_release_material_by_id(
    env: &Env,
    database: &D1Database,
    release_id: &str,
    product_id: &str,
) -> std::result::Result<Option<ReleaseMaterial>, AuthorizationError> {
    let row = database
        .prepare(
            "SELECT id, product_id, app_version, variant_id, variant_params, build_fingerprint, \
                    channel, status, compromised_action, min_sdk_version, proto_ver, suite_id, \
                    published_at \
             FROM releases WHERE id = ? AND product_id = ?",
        )
        .bind(&[text(release_id), text(product_id)])?
        .first::<ReleaseRow>(None)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    row.validate()?;
    load_release_material(env, database, &row).await.map(Some)
}

/// The newest registered sibling releases eligible for offline-KEK preloading,
/// newest first. Compromised and deprecated releases are excluded: a build that
/// is on its way out must not receive freshly wrapped keys.
pub(crate) async fn preload_release_ids(
    database: &D1Database,
    product_id: &str,
    current_release_id: &str,
    limit: u32,
) -> std::result::Result<Vec<String>, AuthorizationError> {
    let limit = i64::from(limit.clamp(1, 16));
    let rows = database
        .prepare(
            "SELECT id FROM releases \
             WHERE product_id = ? AND status = 'active' AND id != ? \
             ORDER BY published_at DESC, id DESC LIMIT ?",
        )
        .bind(&[text(product_id), text(current_release_id), number(limit)?])?
        .all()
        .await?
        .results::<ReleaseIdRow>()?;
    Ok(rows.into_iter().map(|row| row.id).collect())
}

/// The global monotonic security baseline (`security_floor_log`).
pub(crate) async fn current_security_floor(
    env: &Env,
) -> std::result::Result<u64, AuthorizationError> {
    let row = env
        .d1("DB")?
        .prepare("SELECT COALESCE(MAX(floor), 0) AS value FROM security_floor_log")
        .first::<FloorRow>(None)
        .await?
        .ok_or_else(|| server_error("security floor query returned no row"))?;
    u64::try_from(row.value).map_err(|_| server_error("security floor is invalid"))
}

fn parse_variant_params(bytes: &[u8]) -> std::result::Result<VariantParams, AuthorizationError> {
    let value = decode_canonical(bytes, CONFIG_LIMITS)
        .map_err(|_| server_error("release variant parameters are not canonical CBOR"))?;
    let entries = value
        .as_map()
        .ok_or_else(|| server_error("release variant parameters are not a map"))?;
    if entries.len() != 5 || value.get(5).is_some() {
        return Err(server_error("release variant parameter schema is invalid"));
    }
    if value.get(0).and_then(CborValue::as_uint) != Some(VARIANT_PARAMS_SCHEMA_VERSION) {
        return Err(server_error(
            "release variant parameter version is unsupported",
        ));
    }
    let variant_id = value
        .get(1)
        .and_then(CborValue::as_uint)
        .ok_or_else(|| server_error("release variant id is missing"))?;
    let variant_const = fixed_bytes::<32>(&value, 2, "variant constant")?;
    let module_digest = fixed_bytes::<32>(&value, 3, "module digest")?;
    let binder_extra = value
        .get(4)
        .and_then(CborValue::as_array)
        .ok_or_else(|| server_error("variant binder extras are invalid"))?
        .iter()
        .map(|item| {
            item.as_bytes()
                .map(<[u8]>::to_vec)
                .ok_or_else(|| server_error("variant binder extra is not bytes"))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(VariantParams {
        variant_id,
        variant_const,
        module_digest,
        binder_extra,
    })
}

fn fixed_bytes<const N: usize>(
    value: &CborValue,
    key: u64,
    name: &str,
) -> std::result::Result<[u8; N], AuthorizationError> {
    value
        .get(key)
        .and_then(CborValue::as_bytes)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| server_error(&format!("release {name} has an invalid length")))
}

fn variant_at_rest_aad(
    release_id: &str,
    product_id: &str,
    variant_id: u64,
    build_fingerprint: &str,
    suite_id: SuiteId,
) -> Vec<u8> {
    let mut builder = MapBuilder::new();
    builder.put(
        0,
        CborValue::Text("copylocker/variant-at-rest/v1".to_owned()),
    );
    builder.put(1, CborValue::Text(release_id.to_owned()));
    builder.put(2, CborValue::Text(product_id.to_owned()));
    builder.put(3, CborValue::Uint(variant_id));
    builder.put(4, CborValue::Text(build_fingerprint.to_owned()));
    builder.put(5, CborValue::Bytes(suite_id.as_bytes().to_vec()));
    builder.finish()
}

fn asset_kek_at_rest_aad(
    release_id: &str,
    product_id: &str,
    feature_id: &str,
    key_version: u64,
) -> Vec<u8> {
    let mut builder = MapBuilder::new();
    builder.put(
        0,
        CborValue::Text("copylocker/asset-kek-at-rest/v1".to_owned()),
    );
    builder.put(1, CborValue::Text(release_id.to_owned()));
    builder.put(2, CborValue::Text(product_id.to_owned()));
    builder.put(3, CborValue::Text(feature_id.to_owned()));
    builder.put(4, CborValue::Uint(key_version));
    builder.finish()
}

/// Encrypt a registered asset KEK for D1 storage.
///
/// This is the write half of the at-rest protection in `load_release_material`:
/// the KEK only ever exists in plaintext inside a request handler, never in D1.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn seal_asset_kek_at_rest(
    env: &Env,
    release_id: &str,
    product_id: &str,
    feature_id: &str,
    key_version: u64,
    suite_id: SuiteId,
    kek: &Secret<[u8; SECRET_LEN]>,
    rng: &mut dyn CryptoRng,
) -> std::result::Result<Vec<u8>, AuthorizationError> {
    let asset_key = load_secret_key(env, ASSET_KEK_KEY_BINDING, TEST_ASSET_KEK_KEY_BINDING).await?;
    let suite = RequestSuite::resolve_persisted(suite_id)
        .ok_or_else(|| server_error("release suite is unsupported"))?;
    let aad = asset_kek_at_rest_aad(release_id, product_id, feature_id, key_version);
    suite_dispatch!(
        suite,
        S,
        <S as CryptoSuite>::Aead::seal_with_nonce(asset_key.expose(), &aad, kek.as_slice(), rng)
    )
    .map_err(|_| server_error("asset KEK at-rest encryption failed"))
}

/// Decrypt a stored asset KEK row, enforcing the 32-byte plaintext contract.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn open_asset_kek_at_rest(
    env: &Env,
    release_id: &str,
    product_id: &str,
    feature_id: &str,
    key_version: u64,
    suite_id: SuiteId,
    encrypted: &[u8],
) -> std::result::Result<Secret<[u8; SECRET_LEN]>, AuthorizationError> {
    let asset_key = load_secret_key(env, ASSET_KEK_KEY_BINDING, TEST_ASSET_KEK_KEY_BINDING).await?;
    open_asset_kek_with(
        &asset_key,
        release_id,
        product_id,
        feature_id,
        key_version,
        suite_id,
        encrypted,
    )
}

#[allow(clippy::too_many_arguments)]
fn open_asset_kek_with(
    asset_key: &Secret<[u8; SECRET_LEN]>,
    release_id: &str,
    product_id: &str,
    feature_id: &str,
    key_version: u64,
    suite_id: SuiteId,
    encrypted: &[u8],
) -> std::result::Result<Secret<[u8; SECRET_LEN]>, AuthorizationError> {
    let suite = RequestSuite::resolve_persisted(suite_id)
        .ok_or_else(|| server_error("release suite is unsupported"))?;
    let aad = asset_kek_at_rest_aad(release_id, product_id, feature_id, key_version);
    let mut plaintext = suite_dispatch!(
        suite,
        S,
        <S as CryptoSuite>::Aead::open_with_nonce(asset_key.expose(), &aad, encrypted)
    )
    .map_err(|_| server_error("registered asset KEK could not be decrypted"))?;
    let key = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| server_error("registered asset KEK has an invalid length"))?;
    plaintext.zeroize();
    Ok(Secret::new(key))
}

fn credential_state_aad(license_id: LicenseId, fingerprint: &Fingerprint) -> Vec<u8> {
    let mut builder = MapBuilder::new();
    builder.put(
        0,
        CborValue::Text("copylocker/activation-state/v1".to_owned()),
    );
    builder.put(1, CborValue::Bytes(license_id.as_bytes().to_vec()));
    builder.put(2, CborValue::Bytes(fingerprint.as_bytes().to_vec()));
    builder.finish()
}

async fn load_secret_key(
    env: &Env,
    binding: &str,
    test_binding: &str,
) -> std::result::Result<Secret<[u8; SECRET_LEN]>, AuthorizationError> {
    let mut value = if is_test_environment(env) {
        env.var(test_binding)
            .map_err(|_| server_error("test secret binding is missing"))?
            .to_string()
    } else {
        env.secret_store(binding)?
            .get()
            .await?
            .ok_or_else(|| server_error("Secrets Store value is missing"))?
    };
    let parsed = parse_secret_value(&value);
    value.zeroize();
    parsed.map(Secret::new)
}

fn is_test_environment(env: &Env) -> bool {
    env.var("ENVIRONMENT")
        .ok()
        .is_some_and(|value| value.to_string() == "test")
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SecretWire {
    Payload { schema_version: u8, key: Vec<u8> },
    Bytes(Vec<u8>),
    Hex(String),
}

fn parse_secret_value(value: &str) -> std::result::Result<[u8; SECRET_LEN], AuthorizationError> {
    let mut bytes = match serde_json::from_str::<SecretWire>(value) {
        Ok(SecretWire::Payload {
            schema_version,
            key,
        }) if schema_version == SECRET_SCHEMA_VERSION => key,
        Ok(SecretWire::Bytes(bytes)) => bytes,
        Ok(SecretWire::Hex(value)) => decode_hex(&value)?,
        _ => return Err(server_error("secret payload is invalid")),
    };
    let key = bytes
        .as_slice()
        .try_into()
        .map_err(|_| server_error("secret key must contain exactly 32 bytes"))?;
    bytes.zeroize();
    Ok(key)
}

fn decode_hex(value: &str) -> std::result::Result<Vec<u8>, AuthorizationError> {
    if value.len() != SECRET_LEN * 2 {
        return Err(server_error("hex secret has an invalid length"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair.first().copied())?;
            let low = hex_nibble(pair.get(1).copied())?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: Option<u8>) -> std::result::Result<u8, AuthorizationError> {
    match value {
        Some(b'0'..=b'9') => Ok(value.unwrap_or_default() - b'0'),
        Some(b'a'..=b'f') => Ok(value.unwrap_or_default() - b'a' + 10),
        Some(b'A'..=b'F') => Ok(value.unwrap_or_default() - b'A' + 10),
        _ => Err(server_error("hex secret contains a non-hex character")),
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(
    value: &str,
    name: &str,
) -> std::result::Result<T, AuthorizationError> {
    serde_json::from_str(value).map_err(|_| server_error(&format!("{name} JSON is invalid")))
}

fn positive_optional(
    value: Option<i64>,
    name: &str,
) -> std::result::Result<Option<i64>, AuthorizationError> {
    if value.is_some_and(|value| value <= 0) {
        return Err(server_error(&format!("{name} must be positive")));
    }
    Ok(value)
}

fn bool_from_i64(value: i64, name: &str) -> std::result::Result<bool, AuthorizationError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(server_error(&format!("{name} is not a boolean"))),
    }
}

fn u8_from_i64(value: i64, name: &str) -> std::result::Result<u8, AuthorizationError> {
    u8::try_from(value).map_err(|_| server_error(&format!("{name} is out of range")))
}

fn u32_from_i64(value: i64, name: &str) -> std::result::Result<u32, AuthorizationError> {
    u32::try_from(value).map_err(|_| server_error(&format!("{name} is out of range")))
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_feature_id(value: &str) -> bool {
    is_identifier(value)
}

fn server_error(message: &str) -> AuthorizationError {
    AuthorizationError::Server(Error::RustError(message.to_owned()))
}

fn blob(value: &[u8]) -> JsValue {
    JsValue::from(&D1Type::Blob(value))
}

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn number(value: i64) -> std::result::Result<JsValue, AuthorizationError> {
    if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
        return Err(server_error("D1 integer binding is outside the safe range"));
    }
    Ok(JsValue::from_f64(value as f64))
}

#[derive(Debug, Deserialize)]
struct LicenseRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    product_id: String,
    policy_id: String,
    status: String,
    seats_override: Option<i64>,
    entitlement_override_json: Option<String>,
    version_scope_override_json: Option<String>,
    expires_at: Option<i64>,
    catalog_version: i64,
}

#[derive(Debug, Deserialize)]
struct PolicyRow {
    id: String,
    product_id: String,
    name: String,
    preset: Option<String>,
    entitlement_json: String,
    validity_json: String,
    version_scope_json: String,
    seats: i64,
    max_transfers: Option<i64>,
    transfer_window_s: Option<i64>,
    heartbeat_sec: Option<i64>,
    mode: i64,
    refresh_after_sec: i64,
    grace_seconds: i64,
    fpr_tolerance: i64,
    allow_vm: i64,
    allow_olk: i64,
    allow_unbound_olk: i64,
    vt_signature: String,
    offline_upgrade_policy: String,
    preload_variants_n: i64,
    report_attrs: i64,
}

#[derive(Debug, Deserialize)]
struct FeatureRow {
    id: String,
    label: String,
    description: Option<String>,
    deprecated_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct GroupRow {
    id: String,
    label: String,
    members_json: String,
}

#[derive(Debug, Deserialize)]
struct TierRow {
    id: String,
    label: String,
    rank: i64,
    groups_json: String,
    features_json: Option<String>,
    limits_json: String,
    archived_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CatalogSnapshotRow {
    #[serde(with = "serde_bytes")]
    snapshot: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ReleaseRow {
    id: String,
    product_id: String,
    app_version: String,
    variant_id: i64,
    #[serde(with = "serde_bytes")]
    variant_params: Vec<u8>,
    build_fingerprint: String,
    channel: String,
    status: String,
    compromised_action: Option<String>,
    min_sdk_version: String,
    proto_ver: i64,
    #[serde(with = "serde_bytes")]
    suite_id: Vec<u8>,
    published_at: i64,
}

impl ReleaseRow {
    fn validate(&self) -> std::result::Result<(), AuthorizationError> {
        if !is_identifier(&self.id)
            || self.product_id.is_empty()
            || self.app_version.is_empty()
            || self.build_fingerprint.is_empty()
            || self.channel.is_empty()
            || self.min_sdk_version.is_empty()
            || self.proto_ver != i64::from(copylocker_types::PROTO_VER)
            || RequestSuite::resolve_persisted(self.suite_id()?).is_none()
            || self.variant_params.is_empty()
            || !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&self.published_at)
        {
            return Err(server_error("release row is invalid"));
        }
        let _ = self.variant_id_u64()?;
        let _ = self.release_status()?;
        let _ = self.compromised_action()?;
        Ok(())
    }

    fn variant_id_u64(&self) -> std::result::Result<u64, AuthorizationError> {
        u64::try_from(self.variant_id)
            .map_err(|_| server_error("release variant id is out of range"))
    }

    fn suite_id(&self) -> std::result::Result<SuiteId, AuthorizationError> {
        SuiteId::from_slice(&self.suite_id)
            .ok_or_else(|| server_error("release suite id is invalid"))
    }

    fn release_status(&self) -> std::result::Result<ReleaseStatus, AuthorizationError> {
        match self.status.as_str() {
            "active" => Ok(ReleaseStatus::Active),
            "deprecated" => Ok(ReleaseStatus::Deprecated),
            "compromised" => Ok(ReleaseStatus::Compromised),
            _ => Err(server_error("release status is invalid")),
        }
    }

    fn compromised_action(
        &self,
    ) -> std::result::Result<Option<CompromisedAction>, AuthorizationError> {
        match self.compromised_action.as_deref() {
            None => Ok(None),
            Some("warn") => Ok(Some(CompromisedAction::Warn)),
            Some("force_upgrade") => Ok(Some(CompromisedAction::ForceUpgrade)),
            Some("revoke") => Ok(Some(CompromisedAction::Revoke)),
            Some(_) => Err(server_error("release compromised action is invalid")),
        }
    }

    fn registry_release(&self) -> std::result::Result<Release, AuthorizationError> {
        Ok(Release {
            id: self.id.clone(),
            product_id: self.product_id.clone(),
            app_version: self.app_version.clone(),
            variant_id: self.variant_id_u64()?,
            build_fingerprint: self.build_fingerprint.clone(),
            channel: self.channel.clone(),
            status: self.release_status()?,
            compromised_action: self.compromised_action()?,
            published_at: self.published_at,
        })
    }
}

#[derive(Debug, Deserialize)]
struct AssetKekRow {
    feature_id: String,
    key_version: i64,
    #[serde(with = "serde_bytes")]
    encrypted_kek: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ReleaseIdRow {
    id: String,
}

#[derive(Debug, Deserialize)]
struct FloorRow {
    value: i64,
}

#[derive(Debug, Deserialize)]
struct EpochRow {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    suite_id: Vec<u8>,
    #[serde(rename = "vk_fast", with = "serde_bytes")]
    fast_verifying_key: Vec<u8>,
}

#[allow(dead_code)]
fn _type_assertions(
    _fingerprint: Fingerprint,
    _map: BTreeMap<String, i64>,
    _entitlement: EntitlementSpec,
) {
}
