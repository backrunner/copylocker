//! Build-manifest signing key custody (M4-B, `50-unplugin-integrity.md` §2.5).
//!
//! The remote manifest signer uses a dedicated Ed25519 key that is independent of the Epoch
//! chain (`protocol-spec.md` §9 allows a standalone build key). The seed only ever lives in the
//! `BUILD_SIGNING_KEY` secret binding (`TEST_BUILD_SIGNING_KEY` under `ENVIRONMENT=test`); D1
//! stores nothing but the public key fingerprint registered through the Admin API.
//!
//! The signed message is `"copylocker/im-sig/v1" ‖ tbs` — byte-identical to what
//! `@copylocker/guard`'s `verifyManifestSignature` checks and to what `packages/unplugin`'s
//! remote signer contract expects back (a raw 64-byte Ed25519 signature).

use ed25519_dalek::{Signer as _, SigningKey};
use serde::Deserialize;
use worker::{Env, Error, Result};
use zeroize::Zeroize;

use copylocker_suite::Secret;

const BUILD_SIGNING_KEY_BINDING: &str = "BUILD_SIGNING_KEY";
const TEST_BUILD_SIGNING_KEY_BINDING: &str = "TEST_BUILD_SIGNING_KEY";
/// Domain separator shared with `@copylocker/guard` (`MANIFEST_SIGNATURE_DOMAIN`).
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"copylocker/im-sig/v1";
const SEED_LEN: usize = 32;
const HYBRID_SK_LEN: usize = 64;
const SECRET_SCHEMA_VERSION: u8 = 1;

pub(crate) struct BuildSigningKey {
    seed: Secret<[u8; SEED_LEN]>,
}

impl BuildSigningKey {
    pub(crate) async fn load(env: &Env) -> Result<Self> {
        let mut value = if is_test_environment(env) {
            env.var(TEST_BUILD_SIGNING_KEY_BINDING)?.to_string()
        } else {
            env.secret_store(BUILD_SIGNING_KEY_BINDING)?
                .get()
                .await?
                .ok_or_else(|| signing_error("build signing key is not configured"))?
        };
        let parsed = parse_secret(&value);
        value.zeroize();
        parsed
    }

    /// The raw 32-byte Ed25519 verifying key — the value CI pipelines pin as a root pin.
    pub(crate) fn verifying_key(&self) -> [u8; SEED_LEN] {
        SigningKey::from_bytes(self.seed.expose())
            .verifying_key()
            .to_bytes()
    }

    /// Sign a manifest tbs payload, returning the raw 64-byte Ed25519 signature.
    pub(crate) fn sign_manifest(&self, tbs: &[u8]) -> [u8; 64] {
        let mut message = Vec::with_capacity(MANIFEST_SIGNATURE_DOMAIN.len() + tbs.len());
        message.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
        message.extend_from_slice(tbs);
        SigningKey::from_bytes(self.seed.expose())
            .sign(&message)
            .to_bytes()
    }
}

/// Accepted secret shapes:
/// - the `keygen build` secret file (`{"schema_version":1,"kind":"build","signing_key":[64]}`,
///   a hybrid CL-STD-1 key; its last 32 bytes are the Ed25519 seed);
/// - a raw 32-byte seed as a JSON byte array or hex string (the generic secret envelope used by
///   the other Worker secrets).
fn parse_secret(value: &str) -> Result<BuildSigningKey> {
    let mut seed = if let Ok(mut file) = serde_json::from_str::<BuildKeyFile>(value) {
        if file.schema_version != SECRET_SCHEMA_VERSION || file.kind != "build" {
            return Err(signing_error("build signing key metadata is invalid"));
        }
        if file.signing_key.len() != HYBRID_SK_LEN {
            return Err(signing_error("build signing key has an invalid length"));
        }
        let mut seed = [0_u8; SEED_LEN];
        let tail = file
            .signing_key
            .get(SEED_LEN..)
            .ok_or_else(|| signing_error("build signing key has an invalid length"))?;
        seed.copy_from_slice(tail);
        file.signing_key.zeroize();
        seed
    } else {
        match serde_json::from_str::<SecretWire>(value) {
            Ok(SecretWire::Payload {
                schema_version: SECRET_SCHEMA_VERSION,
                key,
            }) => seed_from_vec(key)?,
            Ok(SecretWire::Bytes(bytes)) => seed_from_vec(bytes)?,
            Ok(SecretWire::Hex(hex)) => {
                let mut seed = [0_u8; SEED_LEN];
                let bytes = crate::admin::decode_hex_id(&hex, SEED_LEN)
                    .ok_or_else(|| signing_error("build signing key hex is invalid"))?;
                seed.copy_from_slice(&bytes);
                seed
            }
            _ => return Err(signing_error("build signing key payload is invalid")),
        }
    };
    let secret = Secret::new(seed);
    seed.zeroize();
    Ok(BuildSigningKey { seed: secret })
}

fn seed_from_vec(mut bytes: Vec<u8>) -> Result<[u8; SEED_LEN]> {
    let seed: Result<[u8; SEED_LEN]> = bytes
        .as_slice()
        .try_into()
        .map_err(|_| signing_error("build signing key must contain exactly 32 bytes"));
    bytes.zeroize();
    seed
}

fn is_test_environment(env: &Env) -> bool {
    env.var("ENVIRONMENT")
        .ok()
        .is_some_and(|value| value.to_string() == "test")
}

fn signing_error(message: &str) -> Error {
    Error::RustError(message.to_owned())
}

#[derive(Debug, Deserialize)]
struct BuildKeyFile {
    schema_version: u8,
    kind: String,
    signing_key: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SecretWire {
    Payload { schema_version: u8, key: Vec<u8> },
    Bytes(Vec<u8>),
    Hex(String),
}
