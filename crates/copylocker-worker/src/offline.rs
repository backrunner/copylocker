//! Air-gapped activation relay (`POST /v1/offline/request`, FR-SRV-016, ADR-0005 §5.3).
//!
//! A device that can never reach the network generates an activation request offline and a
//! relay carries it here. The response is a *signed* `ActivationResponse` wrapping the machine
//! credential plus the epoch certificate chain, so the offline device can verify the whole
//! exchange against its pinned root without trusting the relay. The seat reservation, credential
//! sealing, and signing pipeline is the same one `/v1/activate` uses; only the wrapping differs.

use copylocker_proto::{ActivationResponse, Credential};
use copylocker_suite::{Artifact, HashScheme};
use copylocker_suite_std::Sha256Scheme;
use copylocker_types::{ArtifactKind, LicenseId};
use serde::Deserialize;
use worker::{Conditional, Env, Error, Request, Response, Result};

use crate::admin::hex_encode;
use crate::response;
use crate::router;

/// How long a signed activation response stays importable (`data-model.md §13` archives the
/// response file for the same seven days).
const ACTIVATION_RESPONSE_TTL_SECS: i64 = 7 * 24 * 60 * 60;
/// Maximum epoch certificates attached to one response.
const MAX_EPOCH_CHAIN: i64 = 8;

const NEEDS_LOGIN: u64 = 1003;

pub(crate) async fn request(mut request: Request, env: &Env) -> Result<Response> {
    let parsed = match router::parse_activation_request(&mut request, env).await? {
        Ok(parsed) => parsed,
        Err(response) => return Ok(response),
    };
    // Mode E first activation must happen online (`prd.md` §5.2); an account token cannot
    // ride the offline relay.
    if matches!(parsed.activation.credential, Credential::AccountToken(_)) {
        return response::protocol_error(401, NEEDS_LOGIN, None, None);
    }
    let credential = match router::resolve_activation_credential(env, &parsed.activation).await? {
        Ok(credential) => credential,
        Err(response) => return Ok(response),
    };
    let now = router_now();
    let authorization =
        match router::authorize_activation(env, &parsed.activation, &credential, now).await? {
            Ok(authorization) => authorization,
            Err(response) => return Ok(response),
        };
    // The relay's country would masquerade as the offline device's, so the detail event
    // carries no geo (`90-analytics-telemetry.md §7`: offline devices are a known blind spot).
    let issued =
        match router::issue_activation(env, &parsed, &authorization, "offline_ar", None, now)
            .await?
        {
            Ok(issued) => issued,
            Err(response) => return Ok(response),
        };

    let chain = epoch_cert_chain(env, &issued.product_id, now).await?;
    let activation_response = ActivationResponse {
        proto_ver: copylocker_types::PROTO_VER,
        suite_id: parsed.activation.suite_id,
        nonce_c_echo: parsed.activation.nonce_c,
        credential: issued.envelope,
        chain,
        server_time: now,
        valid_until: now.saturating_add(ACTIVATION_RESPONSE_TTL_SECS),
    };
    let tbs = activation_response
        .to_canonical()
        .map_err(|_| Error::RustError("activation response encoding failed".to_owned()))?;
    let envelope = router::issue_artifact(
        env,
        issued.license_id,
        &issued.product_id,
        issued.license_id.as_bytes().to_vec(),
        ArtifactKind::ActivationResponse,
        tbs,
    )
    .await?;
    if let Some(archived) = archive_activation_response(
        env,
        issued.license_id,
        &parsed.activation.nonce_c,
        &envelope,
    )
    .await?
    {
        // Cross-second replay of an already-answered request: return the archived
        // original response byte-identically instead of the freshly re-signed envelope.
        return response::cbor(200, archived, "no-store");
    }
    response::cbor(200, envelope, "no-store")
}

/// Archive one signed activation response (`data-model.md §13`,
/// `offline/<license_id>/<nonce>.aresp`, seven days via the bucket lifecycle rule).
///
/// The key is deterministic per (license, request nonce) and the write conditional. When the
/// key already holds bytes, those bytes are the response this exact request produced earlier —
/// the outer `ActivationResponse` embeds `server_time`, so a cross-second replay rebuilds a
/// differently-signed envelope around the identical journaled credential. Returning the
/// archived original is the idempotent replay: the nonce is a 32-byte client random, the
/// credential inside stays sealed to the original device's KEM key, and no response ever
/// reaches a relay unarchived. A transient archive failure still fails the request, so the
/// relay can safely retry (issuance is idempotent).
async fn archive_activation_response(
    env: &Env,
    license_id: LicenseId,
    nonce_c: &[u8; 32],
    envelope: &[u8],
) -> Result<Option<Vec<u8>>> {
    let key = format!(
        "offline/{}/{}.aresp",
        license_id.to_hex(),
        hex_encode(nonce_c)
    );
    let bucket = env.bucket("ARCHIVE")?;
    let checksum = Sha256Scheme::hash(envelope);
    let inserted = bucket
        .put(&key, envelope.to_vec())
        .sha256(checksum.as_bytes().to_vec())
        .only_if(Conditional {
            etag_does_not_match: Some("*".to_owned()),
            ..Conditional::default()
        })
        .execute()
        .await?;
    if inserted.is_some() {
        return Ok(None);
    }
    let existing = bucket.get(&key).execute().await?.ok_or_else(|| {
        Error::RustError(
            "offline activation archive disappeared after conditional write".to_owned(),
        )
    })?;
    let body = existing.body().ok_or_else(|| {
        Error::RustError("offline activation archive object has no body".to_owned())
    })?;
    let archived = body.bytes().await?;
    if archived == envelope {
        Ok(None)
    } else {
        Ok(Some(archived))
    }
}

/// Every currently valid epoch certificate for the product, newest first. The client verifies
/// each against its pinned root, so serving them here does not extend trust; the set mirrors
/// what `/v1/keys` publishes.
pub(crate) async fn epoch_cert_chain(
    env: &Env,
    product_id: &str,
    now: i64,
) -> Result<Vec<Vec<u8>>> {
    let rows = env
        .d1("DB")?
        .prepare(
            "SELECT cert FROM epochs \
             WHERE revoked_at IS NULL AND not_before <= ? AND not_after > ? \
               AND (product_scope IS NULL OR product_scope = ?) \
             ORDER BY not_before DESC LIMIT ?",
        )
        .bind(&[
            worker::wasm_bindgen::JsValue::from_f64(now as f64),
            worker::wasm_bindgen::JsValue::from_f64(now as f64),
            worker::wasm_bindgen::JsValue::from_str(product_id),
            worker::wasm_bindgen::JsValue::from_f64(MAX_EPOCH_CHAIN as f64),
        ])?
        .all()
        .await?
        .results::<EpochCertRow>()?;
    if rows.is_empty() {
        return Err(Error::RustError(
            "no epoch certificate is available for the offline chain".to_owned(),
        ));
    }
    Ok(rows.into_iter().map(|row| row.cert).collect())
}

#[derive(Debug, Deserialize)]
struct EpochCertRow {
    #[serde(with = "serde_bytes")]
    cert: Vec<u8>,
}

fn router_now() -> i64 {
    i64::try_from(worker::Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
}
