use copylocker_proto::Envelope;
use copylocker_suite::{Artifact, SignatureScheme};
use copylocker_suite_std::sig::FastSigningKey;
use copylocker_suite_std::FastSig;
use copylocker_types::{EpochId, SuiteId};
use serde::Deserialize;
use worker::{Env, Error, Result};
use zeroize::Zeroize;

use super::authorization::SigningEpoch;

const EPOCH_FAST_SIGNING_KEY_BINDING: &str = "EPOCH_FAST_SIGNING_KEY";
const TEST_EPOCH_FAST_SIGNING_KEY_BINDING: &str = "TEST_EPOCH_FAST_SIGNING_KEY";
const FAST_SECRET_SCHEMA_VERSION: u8 = 1;

pub(crate) struct FastEpochSigner {
    epoch_id: EpochId,
    suite_id: SuiteId,
    signing_key: FastSigningKey,
}

impl FastEpochSigner {
    pub(crate) async fn load(env: &Env, epoch: &SigningEpoch) -> Result<Self> {
        let mut value = if is_test_environment(env) {
            env.var(TEST_EPOCH_FAST_SIGNING_KEY_BINDING)?.to_string()
        } else {
            env.secret_store(EPOCH_FAST_SIGNING_KEY_BINDING)?
                .get()
                .await?
                .ok_or_else(|| signing_error("fast epoch signing key is not configured"))?
        };
        let parsed = parse_secret(&value, epoch);
        value.zeroize();
        parsed
    }

    pub(crate) fn seal<A: Artifact>(&self, artifact: &A, product_id: &str) -> Result<Vec<u8>> {
        Envelope::seal::<FastSig, A>(
            artifact,
            self.suite_id,
            product_id,
            Some(self.epoch_id),
            &self.signing_key,
        )
        .map(|envelope| envelope.encode())
        .map_err(|_| signing_error("fast artifact signing failed"))
    }
}

#[derive(Debug, Deserialize)]
struct FastSecretPayload {
    schema_version: u8,
    epoch_id: Vec<u8>,
    suite_id: Vec<u8>,
    signing_key: Vec<u8>,
}

fn parse_secret(value: &str, expected: &SigningEpoch) -> Result<FastEpochSigner> {
    let mut payload = serde_json::from_str::<FastSecretPayload>(value)
        .map_err(|_| signing_error("fast epoch signing key payload is invalid"))?;
    let epoch_id = EpochId::from_slice(&payload.epoch_id);
    let suite_id = SuiteId::from_slice(&payload.suite_id);
    let metadata_valid = payload.schema_version == FAST_SECRET_SCHEMA_VERSION
        && epoch_id == Some(expected.epoch_id)
        && suite_id == Some(copylocker_suite_std::CL_STD_1_SUITE_ID);
    let signing_key = metadata_valid
        .then(|| FastSig::decode_sk(&payload.signing_key))
        .transpose()
        .map_err(|_| signing_error("fast epoch signing key is invalid"))?
        .ok_or_else(|| signing_error("fast epoch signing key metadata does not match D1"));
    payload.signing_key.zeroize();
    let signing_key = signing_key?;
    let verifying_key = FastSig::encode_vk(&FastSig::verifying_key(&signing_key));
    if verifying_key != expected.fast_verifying_key {
        return Err(signing_error(
            "fast epoch signing key does not match the registered public key",
        ));
    }
    Ok(FastEpochSigner {
        epoch_id: expected.epoch_id,
        suite_id: copylocker_suite_std::CL_STD_1_SUITE_ID,
        signing_key,
    })
}

fn is_test_environment(env: &Env) -> bool {
    env.var("ENVIRONMENT")
        .ok()
        .is_some_and(|value| value.to_string() == "test")
}

fn signing_error(message: &str) -> Error {
    Error::RustError(message.to_owned())
}
