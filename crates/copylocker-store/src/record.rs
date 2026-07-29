use core::fmt;

use zeroize::Zeroize;

use crate::StoreError;

const RECORD_MAGIC: &[u8; 8] = b"CLREC001";
const RECORD_VERSION: u16 = 1;
const RECORD_HEADER_LEN: usize = 58;

/// Maximum plaintext state accepted by the desktop store (16 MiB).
///
/// Credentials are normally measured in KiB. The much larger hard cap leaves room for future
/// suites while bounding allocations when a local file is corrupt or hostile.
pub const MAX_RECORD_LEN: usize = 16 * 1024 * 1024;

/// State that must only move forwards across every local replica.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MonotonicState {
    last_seen_max: i64,
    last_server_time: i64,
    rollback_events: u32,
    max_seen_security_floor: u64,
    max_seen_revocation_epoch: u64,
}

impl MonotonicState {
    /// Construct persisted high-water marks.
    #[must_use]
    pub const fn new(
        last_seen_max: i64,
        last_server_time: i64,
        rollback_events: u32,
        max_seen_security_floor: u64,
        max_seen_revocation_epoch: u64,
    ) -> Self {
        Self {
            last_seen_max,
            last_server_time,
            rollback_events,
            max_seen_security_floor,
            max_seen_revocation_epoch,
        }
    }

    /// Greatest local or authoritative time ever observed.
    #[must_use]
    pub const fn last_seen_max(self) -> i64 {
        self.last_seen_max
    }

    /// Greatest authoritative server time ever observed.
    #[must_use]
    pub const fn last_server_time(self) -> i64 {
        self.last_server_time
    }

    /// Greatest rollback counter ever persisted.
    #[must_use]
    pub const fn rollback_events(self) -> u32 {
        self.rollback_events
    }

    /// Greatest credential security floor ever accepted.
    #[must_use]
    pub const fn max_seen_security_floor(self) -> u64 {
        self.max_seen_security_floor
    }

    /// Greatest revocation epoch ever accepted.
    #[must_use]
    pub const fn max_seen_revocation_epoch(self) -> u64 {
        self.max_seen_revocation_epoch
    }

    /// Merge another replica without allowing any protected value to decrease.
    pub fn merge(&mut self, other: Self) {
        self.last_seen_max = self.last_seen_max.max(other.last_seen_max);
        self.last_server_time = self.last_server_time.max(other.last_server_time);
        self.rollback_events = self.rollback_events.max(other.rollback_events);
        self.max_seen_security_floor = self
            .max_seen_security_floor
            .max(other.max_seen_security_floor);
        self.max_seen_revocation_epoch = self
            .max_seen_revocation_epoch
            .max(other.max_seen_revocation_epoch);
    }

    const fn is_well_formed(self) -> bool {
        self.last_seen_max >= self.last_server_time
    }
}

/// Variant-independent plaintext stored inside the AEAD envelope.
///
/// `payload` is owned by the layer above this crate and normally contains the machine
/// credential, device keys, and client state. Release/variant identifiers may occur inside that
/// payload, but never participate in this record's framing or encryption key.
pub struct StoreRecord {
    generation: u64,
    monotonic: MonotonicState,
    payload: Vec<u8>,
}

impl StoreRecord {
    /// Create a new record. The store assigns its durable generation during `save`.
    #[must_use]
    pub fn new(payload: Vec<u8>, monotonic: MonotonicState) -> Self {
        Self {
            generation: 0,
            monotonic,
            payload,
        }
    }

    /// Monotonic write generation assigned by the store.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Persisted clock, downgrade, and revocation high-water marks.
    #[must_use]
    pub const fn monotonic(&self) -> MonotonicState {
        self.monotonic
    }

    /// Borrow the opaque application state.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consume the record and return the opaque application state.
    #[must_use]
    pub fn into_payload(mut self) -> Vec<u8> {
        core::mem::take(&mut self.payload)
    }

    /// Encode the fixed, variant-independent plaintext format.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        if !self.monotonic.is_well_formed() {
            return Err(StoreError::InvalidRecord);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| StoreError::RecordTooLarge)?;
        let total_len = RECORD_HEADER_LEN
            .checked_add(self.payload.len())
            .ok_or(StoreError::RecordTooLarge)?;
        if total_len > MAX_RECORD_LEN {
            return Err(StoreError::RecordTooLarge);
        }

        let mut output = Vec::with_capacity(total_len);
        output.extend_from_slice(RECORD_MAGIC);
        output.extend_from_slice(&RECORD_VERSION.to_be_bytes());
        output.extend_from_slice(&self.generation.to_be_bytes());
        output.extend_from_slice(&self.monotonic.last_seen_max.to_be_bytes());
        output.extend_from_slice(&self.monotonic.last_server_time.to_be_bytes());
        output.extend_from_slice(&self.monotonic.rollback_events.to_be_bytes());
        output.extend_from_slice(&self.monotonic.max_seen_security_floor.to_be_bytes());
        output.extend_from_slice(&self.monotonic.max_seen_revocation_epoch.to_be_bytes());
        output.extend_from_slice(&payload_len.to_be_bytes());
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    /// Decode and strictly validate the fixed plaintext format.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() < RECORD_HEADER_LEN || bytes.len() > MAX_RECORD_LEN {
            return Err(if bytes.len() > MAX_RECORD_LEN {
                StoreError::RecordTooLarge
            } else {
                StoreError::InvalidRecord
            });
        }

        let mut cursor = Cursor::new(bytes);
        if &cursor.take::<8>()? != RECORD_MAGIC {
            return Err(StoreError::InvalidRecord);
        }
        let version = u16::from_be_bytes(cursor.take()?);
        if version != RECORD_VERSION {
            return Err(StoreError::UnsupportedRecordVersion(version));
        }
        let generation = u64::from_be_bytes(cursor.take()?);
        let monotonic = MonotonicState::new(
            i64::from_be_bytes(cursor.take()?),
            i64::from_be_bytes(cursor.take()?),
            u32::from_be_bytes(cursor.take()?),
            u64::from_be_bytes(cursor.take()?),
            u64::from_be_bytes(cursor.take()?),
        );
        if !monotonic.is_well_formed() {
            return Err(StoreError::InvalidRecord);
        }
        let payload_len = usize::try_from(u32::from_be_bytes(cursor.take()?))
            .map_err(|_| StoreError::InvalidRecord)?;
        if cursor.remaining().len() != payload_len {
            return Err(StoreError::InvalidRecord);
        }

        Ok(Self {
            generation,
            monotonic,
            payload: cursor.remaining().to_vec(),
        })
    }

    pub(crate) fn copy_with_generation(&self, generation: u64, monotonic: MonotonicState) -> Self {
        Self {
            generation,
            monotonic,
            payload: self.payload.clone(),
        }
    }

    pub(crate) fn set_monotonic(&mut self, monotonic: MonotonicState) {
        self.monotonic = monotonic;
    }

    pub(crate) fn same_payload(&self, other: &Self) -> bool {
        self.payload == other.payload
    }
}

impl Drop for StoreRecord {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

impl fmt::Debug for StoreRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreRecord")
            .field("generation", &self.generation)
            .field("monotonic", &self.monotonic)
            .field("payload_len", &self.payload.len())
            .field("payload", &"<redacted>")
            .finish()
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(StoreError::InvalidRecord)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(StoreError::InvalidRecord)?;
        self.position = end;
        bytes.try_into().map_err(|_| StoreError::InvalidRecord)
    }

    fn remaining(&self) -> &'a [u8] {
        self.bytes.get(self.position..).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_and_debug_redacts_the_payload() {
        let record = StoreRecord::new(
            b"device-private-key".to_vec(),
            MonotonicState::new(20, 18, 2, 7, 9),
        );
        let encoded = record.encode().unwrap();
        let decoded = StoreRecord::decode(&encoded).unwrap();
        assert_eq!(decoded.payload(), b"device-private-key");
        assert_eq!(decoded.monotonic(), record.monotonic());

        let debug = format!("{decoded:?}");
        assert!(debug.contains("payload_len"));
        assert!(!debug.contains("device-private-key"));
    }

    #[test]
    fn every_truncation_is_rejected() {
        let encoded = StoreRecord::new(vec![1, 2, 3], MonotonicState::default())
            .encode()
            .unwrap();
        for end in 0..encoded.len() {
            assert!(StoreRecord::decode(&encoded[..end]).is_err(), "end={end}");
        }
    }

    #[test]
    fn monotonic_merge_never_lowers_any_field() {
        let mut state = MonotonicState::new(20, 18, 2, 7, 9);
        state.merge(MonotonicState::new(19, 22, 1, 10, 8));
        assert_eq!(state, MonotonicState::new(20, 22, 2, 10, 9));
    }

    #[test]
    fn server_time_cannot_exceed_the_effective_high_water_mark() {
        let invalid = StoreRecord::new(vec![], MonotonicState::new(10, 11, 0, 0, 0));
        assert!(matches!(invalid.encode(), Err(StoreError::InvalidRecord)));
    }
}
