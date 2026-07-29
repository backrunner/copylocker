use core::fmt;

use copylocker_proto::responses::{MAX_EPOCH_CERTIFICATE_BYTES, MAX_KEYSET_CERTIFICATES};
use copylocker_store::MAX_RECORD_LEN;
use copylocker_suite::cbor::{decode_canonical, CborValue, Limits, MapBuilder};
use copylocker_suite::{CodecError, Secret};
use copylocker_types::EpochId;
use zeroize::Zeroize;

const SNAPSHOT_SCHEMA: u64 = 1;
const MAX_SECRET_KEY_BYTES: usize = 64 * 1024;
const MAX_ARTIFACT_BYTES: usize = 1024 * 1024;
const SNAPSHOT_LIMITS: Limits = Limits {
    max_depth: copylocker_types::MAX_CBOR_DEPTH,
    max_items: 4_096,
    max_string: MAX_RECORD_LEN,
};

pub(crate) struct ClientSnapshot {
    kem_secret_key: Secret<Vec<u8>>,
    signing_secret_key: Secret<Vec<u8>>,
    credential_envelope: Option<Vec<u8>>,
    epoch_certificates: Vec<Vec<u8>>,
    validation_ticket: Option<Vec<u8>>,
    pending_activation_nonce: Option<[u8; 32]>,
    revoked_epochs: Vec<EpochId>,
}

impl ClientSnapshot {
    pub(crate) fn new(kem_secret_key: Vec<u8>, signing_secret_key: Vec<u8>) -> Self {
        Self {
            kem_secret_key: Secret::new(kem_secret_key),
            signing_secret_key: Secret::new(signing_secret_key),
            credential_envelope: None,
            epoch_certificates: Vec::new(),
            validation_ticket: None,
            pending_activation_nonce: None,
            revoked_epochs: Vec::new(),
        }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, SnapshotError> {
        validate_secret(self.kem_secret_key.expose())?;
        validate_secret(self.signing_secret_key.expose())?;
        validate_optional_artifact(self.credential_envelope.as_deref())?;
        validate_optional_artifact(self.validation_ticket.as_deref())?;
        validate_certificates(&self.epoch_certificates)?;

        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(SNAPSHOT_SCHEMA));
        builder.put(1, CborValue::Bytes(self.kem_secret_key.expose().clone()));
        builder.put(
            2,
            CborValue::Bytes(self.signing_secret_key.expose().clone()),
        );
        builder.put_opt(3, self.credential_envelope.clone().map(CborValue::Bytes));
        builder.put(
            4,
            CborValue::Array(
                self.epoch_certificates
                    .iter()
                    .cloned()
                    .map(CborValue::Bytes)
                    .collect(),
            ),
        );
        builder.put_opt(5, self.validation_ticket.clone().map(CborValue::Bytes));
        builder.put_opt(
            6,
            self.pending_activation_nonce
                .map(|nonce| CborValue::Bytes(nonce.to_vec())),
        );
        builder.put(
            7,
            CborValue::Array(
                self.revoked_epochs
                    .iter()
                    .map(|epoch| CborValue::Bytes(epoch.as_bytes().to_vec()))
                    .collect(),
            ),
        );
        let encoded = builder.finish();
        if encoded.len() > MAX_RECORD_LEN {
            return Err(SnapshotError::TooLarge);
        }
        Ok(encoded)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, SnapshotError> {
        if bytes.len() > MAX_RECORD_LEN {
            return Err(SnapshotError::TooLarge);
        }
        let value = decode_canonical(bytes, SNAPSHOT_LIMITS).map_err(SnapshotError::Codec)?;
        let schema = required(&value, 0)?
            .as_uint()
            .ok_or(SnapshotError::Malformed)?;
        if schema != SNAPSHOT_SCHEMA {
            return Err(SnapshotError::UnsupportedSchema);
        }
        let kem_secret_key = required_bytes(&value, 1)?;
        let signing_secret_key = required_bytes(&value, 2)?;
        validate_secret(&kem_secret_key)?;
        validate_secret(&signing_secret_key)?;
        let credential_envelope = optional_bytes(&value, 3)?;
        let validation_ticket = optional_bytes(&value, 5)?;
        validate_optional_artifact(credential_envelope.as_deref())?;
        validate_optional_artifact(validation_ticket.as_deref())?;
        let epoch_certificates = decode_certificates(&value)?;
        let pending_activation_nonce = optional_bytes(&value, 6)?
            .map(|bytes| bytes.try_into().map_err(|_| SnapshotError::Malformed))
            .transpose()?;
        let revoked_epochs = decode_revoked_epochs(&value)?;

        Ok(Self {
            kem_secret_key: Secret::new(kem_secret_key),
            signing_secret_key: Secret::new(signing_secret_key),
            credential_envelope,
            epoch_certificates,
            validation_ticket,
            pending_activation_nonce,
            revoked_epochs,
        })
    }

    pub(crate) fn kem_secret_key(&self) -> &[u8] {
        self.kem_secret_key.expose()
    }

    pub(crate) fn signing_secret_key(&self) -> &[u8] {
        self.signing_secret_key.expose()
    }

    pub(crate) fn credential_envelope(&self) -> Option<&[u8]> {
        self.credential_envelope.as_deref()
    }

    pub(crate) fn set_credential_envelope(&mut self, value: Option<Vec<u8>>) {
        self.credential_envelope.zeroize();
        self.credential_envelope = value;
    }

    pub(crate) fn epoch_certificates(&self) -> &[Vec<u8>] {
        &self.epoch_certificates
    }

    pub(crate) fn set_epoch_certificates(&mut self, value: Vec<Vec<u8>>) {
        self.epoch_certificates.zeroize();
        self.epoch_certificates = value;
    }

    pub(crate) fn validation_ticket(&self) -> Option<&[u8]> {
        self.validation_ticket.as_deref()
    }

    pub(crate) fn set_validation_ticket(&mut self, value: Option<Vec<u8>>) {
        self.validation_ticket.zeroize();
        self.validation_ticket = value;
    }

    pub(crate) const fn pending_activation_nonce(&self) -> Option<[u8; 32]> {
        self.pending_activation_nonce
    }

    pub(crate) fn set_pending_activation_nonce(&mut self, value: Option<[u8; 32]>) {
        self.pending_activation_nonce = value;
    }

    pub(crate) fn revoked_epochs(&self) -> &[EpochId] {
        &self.revoked_epochs
    }

    pub(crate) fn set_revoked_epochs(&mut self, value: Vec<EpochId>) {
        self.revoked_epochs = value;
    }
}

impl fmt::Debug for ClientSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientSnapshot")
            .field("kem_secret_key", &"<redacted>")
            .field("signing_secret_key", &"<redacted>")
            .field(
                "credential_envelope_len",
                &self.credential_envelope.as_ref().map(Vec::len),
            )
            .field("epoch_certificate_count", &self.epoch_certificates.len())
            .field(
                "validation_ticket_len",
                &self.validation_ticket.as_ref().map(Vec::len),
            )
            .field(
                "has_pending_activation",
                &self.pending_activation_nonce.is_some(),
            )
            .field("revoked_epoch_count", &self.revoked_epochs.len())
            .finish()
    }
}

impl Drop for ClientSnapshot {
    fn drop(&mut self) {
        self.credential_envelope.zeroize();
        self.validation_ticket.zeroize();
        self.epoch_certificates.zeroize();
        self.pending_activation_nonce.zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SnapshotError {
    Codec(CodecError),
    Malformed,
    UnsupportedSchema,
    TooLarge,
}

fn required(value: &CborValue, key: u64) -> Result<&CborValue, SnapshotError> {
    if value.as_map().is_none() {
        return Err(SnapshotError::Malformed);
    }
    value.get(key).ok_or(SnapshotError::Malformed)
}

fn required_bytes(value: &CborValue, key: u64) -> Result<Vec<u8>, SnapshotError> {
    required(value, key)?
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or(SnapshotError::Malformed)
}

fn optional_bytes(value: &CborValue, key: u64) -> Result<Option<Vec<u8>>, SnapshotError> {
    value
        .get(key)
        .map(|item| {
            item.as_bytes()
                .map(<[u8]>::to_vec)
                .ok_or(SnapshotError::Malformed)
        })
        .transpose()
}

fn decode_certificates(value: &CborValue) -> Result<Vec<Vec<u8>>, SnapshotError> {
    let values = required(value, 4)?
        .as_array()
        .ok_or(SnapshotError::Malformed)?;
    if values.len() > MAX_KEYSET_CERTIFICATES {
        return Err(SnapshotError::TooLarge);
    }
    let certificates = values
        .iter()
        .map(|item| {
            let bytes = item.as_bytes().ok_or(SnapshotError::Malformed)?;
            if bytes.is_empty() || bytes.len() > MAX_EPOCH_CERTIFICATE_BYTES {
                return Err(SnapshotError::TooLarge);
            }
            Ok(bytes.to_vec())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certificates)
}

fn decode_revoked_epochs(value: &CborValue) -> Result<Vec<EpochId>, SnapshotError> {
    let Some(values) = value.get(7) else {
        return Ok(Vec::new());
    };
    let values = values.as_array().ok_or(SnapshotError::Malformed)?;
    if values.len() > 65_536 {
        return Err(SnapshotError::TooLarge);
    }
    let mut epochs = Vec::with_capacity(values.len());
    for item in values {
        let bytes: [u8; 8] = item
            .as_bytes()
            .ok_or(SnapshotError::Malformed)?
            .try_into()
            .map_err(|_| SnapshotError::Malformed)?;
        let epoch = EpochId(bytes);
        if !epochs.contains(&epoch) {
            epochs.push(epoch);
        }
    }
    Ok(epochs)
}

fn validate_secret(value: &[u8]) -> Result<(), SnapshotError> {
    if value.is_empty() || value.len() > MAX_SECRET_KEY_BYTES {
        return Err(SnapshotError::Malformed);
    }
    Ok(())
}

fn validate_optional_artifact(value: Option<&[u8]>) -> Result<(), SnapshotError> {
    if value.is_some_and(|bytes| bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES) {
        return Err(SnapshotError::TooLarge);
    }
    Ok(())
}

fn validate_certificates(values: &[Vec<u8>]) -> Result<(), SnapshotError> {
    if values.len() > MAX_KEYSET_CERTIFICATES
        || values
            .iter()
            .any(|bytes| bytes.is_empty() || bytes.len() > MAX_EPOCH_CERTIFICATE_BYTES)
    {
        return Err(SnapshotError::TooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> ClientSnapshot {
        let mut snapshot = ClientSnapshot::new(vec![0x11; 32], vec![0x22; 32]);
        snapshot.set_credential_envelope(Some(vec![1, 2, 3]));
        snapshot.set_epoch_certificates(vec![vec![4, 5]]);
        snapshot.set_validation_ticket(Some(vec![6, 7]));
        snapshot.set_pending_activation_nonce(Some([8; 32]));
        snapshot.set_revoked_epochs(vec![EpochId([9; 8])]);
        snapshot
    }

    #[test]
    fn snapshots_round_trip() {
        let encoded = snapshot().encode().unwrap();
        let decoded = ClientSnapshot::decode(&encoded).unwrap();
        assert_eq!(decoded.kem_secret_key(), [0x11; 32]);
        assert_eq!(decoded.signing_secret_key(), [0x22; 32]);
        assert_eq!(decoded.credential_envelope(), Some([1, 2, 3].as_slice()));
        assert_eq!(decoded.epoch_certificates(), &[vec![4, 5]]);
        assert_eq!(decoded.validation_ticket(), Some([6, 7].as_slice()));
        assert_eq!(decoded.pending_activation_nonce(), Some([8; 32]));
        assert_eq!(decoded.revoked_epochs(), &[EpochId([9; 8])]);
    }

    #[test]
    fn debug_redacts_both_private_keys() {
        let rendered = format!("{:?}", snapshot());
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("17, 17"));
        assert!(!rendered.contains("34, 34"));
    }

    #[test]
    fn malformed_or_unknown_schemas_are_rejected() {
        assert!(ClientSnapshot::decode(&[]).is_err());
        let mut builder = MapBuilder::new();
        builder.put(0, CborValue::Uint(99));
        builder.put(1, CborValue::Bytes(vec![1]));
        builder.put(2, CborValue::Bytes(vec![2]));
        builder.put(4, CborValue::Array(Vec::new()));
        assert!(matches!(
            ClientSnapshot::decode(&builder.finish()),
            Err(SnapshotError::UnsupportedSchema)
        ));
    }

    #[test]
    fn oversized_certificate_is_rejected_before_use() {
        let mut value = snapshot();
        value.set_epoch_certificates(vec![vec![0; MAX_EPOCH_CERTIFICATE_BYTES + 1]]);
        assert_eq!(value.encode(), Err(SnapshotError::TooLarge));
    }
}
