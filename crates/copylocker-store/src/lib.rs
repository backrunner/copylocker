//! Device-bound desktop storage (`20-client-core.md §2`).
//!
//! The outer envelope is deliberately independent of release variants. Its key is derived from
//! a random OS-protected secret plus device fingerprint material; its AAD binds only the
//! application, store version, and platform. The same sealed bytes are written to two locations,
//! and every load merges clock, revocation, and security-floor high-water marks before repairing
//! either stale copy.

#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

#[cfg(not(any(feature = "keychain", feature = "file-only")))]
compile_error!("enable either the `keychain` or `file-only` feature");

mod error;
mod file;
mod platform;
mod protected;
mod record;

use core::fmt;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use copylocker_suite::{AeadScheme, KeyDerivation, Secret};
use copylocker_suite_std::{HkdfSha512, XChaCha20Poly1305Aead};
use zeroize::Zeroize;

pub use error::StoreError;
pub use platform::PlatformProtectedStorage;
pub use protected::{FileProtectedStorage, ProtectedSlot, ProtectedStorage};
pub use record::{MonotonicState, StoreRecord, MAX_RECORD_LEN};

use file::{read_optional, secure_remove, write_atomic, MAX_SEALED_LEN};

const ROOT_SECRET_LEN: usize = 32;
const OUTER_MAGIC: &[u8; 8] = b"CLSTR001";
const OUTER_VERSION: u16 = 1;
const OUTER_HEADER_LEN: usize = 11;
const MAX_FINGERPRINT_MATERIAL_LEN: usize = 64 * 1024;

/// Desktop platform bound into the store AAD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PlatformTag {
    /// Apple macOS.
    Macos = 1,
    /// Microsoft Windows.
    Windows = 2,
    /// Desktop Linux.
    Linux = 3,
}

impl PlatformTag {
    fn current() -> Result<Self, StoreError> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self::Macos)
        }
        #[cfg(target_os = "windows")]
        {
            Ok(Self::Windows)
        }
        #[cfg(target_os = "linux")]
        {
            Ok(Self::Linux)
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            Err(StoreError::UnsupportedPlatform)
        }
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::Macos => b"macos",
            Self::Windows => b"windows",
            Self::Linux => b"linux",
        }
    }
}

/// Configuration for one application's local store.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StoreConfig {
    app_id: String,
    file_path: PathBuf,
    platform: PlatformTag,
}

impl StoreConfig {
    /// Use the platform's conventional per-user application-data directory.
    pub fn new(app_id: impl Into<String>) -> Result<Self, StoreError> {
        let app_id = app_id.into();
        validate_app_id(&app_id)?;
        let file_path = default_data_root()?.join(&app_id).join("cl.bin");
        Ok(Self {
            app_id,
            file_path,
            platform: PlatformTag::current()?,
        })
    }

    /// Override the encrypted backup path, primarily for portable hosts and tests.
    #[must_use]
    pub fn with_file_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.file_path = path.into();
        self
    }

    /// Stable application identifier used for path and keychain isolation.
    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// Encrypted backup replica path.
    #[must_use]
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Platform bound into the envelope AAD.
    #[must_use]
    pub const fn platform(&self) -> PlatformTag {
        self.platform
    }

    fn directory(&self) -> Result<&Path, StoreError> {
        self.file_path
            .parent()
            .ok_or(StoreError::DataDirectoryUnavailable)
    }
}

/// Raw-byte API consumed by the client facade.
///
/// Bytes passed to `save` and returned by `load` are canonical [`StoreRecord`] encodings, not
/// ciphertext. Encryption and replica repair remain internal to the implementation.
pub trait KeyStore: Send + Sync {
    /// Load and merge the durable state, or `None` before first activation.
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError>;
    /// Validate and save one [`StoreRecord`] encoding.
    fn save(&self, blob: &[u8]) -> Result<(), StoreError>;
    /// Wipe every replica and the OS-protected root secret.
    fn wipe(&self) -> Result<(), StoreError>;
}

/// AEAD store backed by one platform-protected replica and one atomic file replica.
pub struct SecureStore<B = PlatformProtectedStorage> {
    config: StoreConfig,
    backend: B,
    fingerprint_material: Secret<Vec<u8>>,
    operation_lock: Mutex<()>,
}

impl SecureStore<PlatformProtectedStorage> {
    /// Construct the normal desktop store for this platform.
    pub fn new(config: StoreConfig, fingerprint_material: &[u8]) -> Result<Self, StoreError> {
        let backend = PlatformProtectedStorage::new(config.app_id(), config.directory()?)?;
        Self::with_backend(config, fingerprint_material, backend)
    }
}

impl<B: ProtectedStorage> SecureStore<B> {
    /// Construct a store with an explicit protected-storage backend.
    ///
    /// This is the injection point for embedding hosts and deterministic tests.
    pub fn with_backend(
        config: StoreConfig,
        fingerprint_material: &[u8],
        backend: B,
    ) -> Result<Self, StoreError> {
        if fingerprint_material.is_empty()
            || fingerprint_material.len() > MAX_FINGERPRINT_MATERIAL_LEN
        {
            return Err(StoreError::InvalidFingerprintMaterial);
        }
        config.directory()?;
        Ok(Self {
            config,
            backend,
            fingerprint_material: Secret::new(fingerprint_material.to_vec()),
            operation_lock: Mutex::new(()),
        })
    }

    /// Load the typed record, merging and repairing redundant replicas.
    pub fn load_record(&self) -> Result<Option<StoreRecord>, StoreError> {
        let _guard = self.lock()?;
        self.load_record_locked()
    }

    /// Persist a typed record while preserving every previously observed high-water mark.
    pub fn save_record(&self, record: &StoreRecord) -> Result<(), StoreError> {
        // Validate size before touching durable state.
        let mut validation = record.encode()?;
        validation.zeroize();

        let _guard = self.lock()?;
        let root = self.root_for_save()?;
        let existing = self.resolve_replicas(&root, false)?;

        let mut monotonic = record.monotonic();
        let next_generation = match existing {
            Some(ref old) => {
                monotonic.merge(old.monotonic());
                old.generation()
                    .checked_add(1)
                    .ok_or(StoreError::InvalidRecord)?
            }
            None => 1,
        };
        let durable = record.copy_with_generation(next_generation, monotonic);
        let sealed = self.seal_record(&root, &durable)?;

        // Either ordering can be interrupted. Writing the protected copy first ensures a failed
        // backup update still leaves the newest monotonic state in the harder-to-delete place.
        self.backend.store(ProtectedSlot::Replica, &sealed)?;
        write_atomic(self.config.file_path(), &sealed)?;
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, StoreError> {
        self.operation_lock
            .lock()
            .map_err(|_| StoreError::LockPoisoned)
    }

    fn load_record_locked(&self) -> Result<Option<StoreRecord>, StoreError> {
        let Some(root) = self.load_root()? else {
            let protected = self.backend.load(ProtectedSlot::Replica)?;
            let file = read_optional(self.config.file_path())?;
            return if protected.is_none() && file.is_none() {
                Ok(None)
            } else {
                Err(StoreError::MissingProtectedSecret)
            };
        };
        self.resolve_replicas(&root, true)
    }

    fn root_for_save(&self) -> Result<Secret<Vec<u8>>, StoreError> {
        if let Some(root) = self.load_root()? {
            return Ok(root);
        }

        // Never generate a replacement key over ciphertext we can no longer decrypt. That would
        // turn a missing keychain entry into silent credential loss.
        if self.backend.load(ProtectedSlot::Replica)?.is_some()
            || read_optional(self.config.file_path())?.is_some()
        {
            return Err(StoreError::MissingProtectedSecret);
        }

        let mut generated = vec![0u8; ROOT_SECRET_LEN];
        getrandom::fill(&mut generated).map_err(|_| StoreError::EntropyUnavailable)?;
        let store_result = self.backend.store(ProtectedSlot::RootSecret, &generated);
        generated.zeroize();
        store_result?;

        // Read back the winner so two processes racing on first use cannot encrypt under the
        // losing process's transient value.
        self.load_root()?.ok_or(StoreError::MissingProtectedSecret)
    }

    fn load_root(&self) -> Result<Option<Secret<Vec<u8>>>, StoreError> {
        let Some(mut root) = self.backend.load(ProtectedSlot::RootSecret)? else {
            return Ok(None);
        };
        if root.len() != ROOT_SECRET_LEN {
            root.zeroize();
            return Err(StoreError::InvalidProtectedSecret);
        }
        Ok(Some(Secret::new(root)))
    }

    fn resolve_replicas(
        &self,
        root: &Secret<Vec<u8>>,
        repair: bool,
    ) -> Result<Option<StoreRecord>, StoreError> {
        let protected = self.backend.load(ProtectedSlot::Replica);
        let file = read_optional(self.config.file_path());
        let mut valid = Vec::with_capacity(2);
        let mut invalid = false;
        let mut first_error = None;

        self.classify_replica(
            ReplicaSource::Protected,
            protected,
            root,
            &mut valid,
            &mut invalid,
            &mut first_error,
        );
        self.classify_replica(
            ReplicaSource::File,
            file,
            root,
            &mut valid,
            &mut invalid,
            &mut first_error,
        );

        if valid.is_empty() {
            if invalid {
                return Err(StoreError::Integrity);
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            return Ok(None);
        }

        let winner_index = valid
            .iter()
            .enumerate()
            .max_by_key(|(_, replica)| replica.record.generation())
            .map(|(index, _)| index)
            .ok_or(StoreError::Integrity)?;
        let winner_generation = valid
            .get(winner_index)
            .ok_or(StoreError::Integrity)?
            .record
            .generation();

        let same_generation: Vec<&ValidReplica> = valid
            .iter()
            .filter(|replica| replica.record.generation() == winner_generation)
            .collect();
        if let Some(first) = same_generation.first() {
            if same_generation
                .iter()
                .skip(1)
                .any(|replica| !replica.record.same_payload(&first.record))
            {
                return Err(StoreError::ReplicaConflict);
            }
        }

        let mut merged = valid
            .first()
            .ok_or(StoreError::Integrity)?
            .record
            .monotonic();
        for replica in valid.iter().skip(1) {
            merged.merge(replica.record.monotonic());
        }

        let mut winner = valid.swap_remove(winner_index);
        let state_changed = winner.record.monotonic() != merged;
        winner.record.set_monotonic(merged);
        let replicas_identical = !invalid
            && first_error.is_none()
            && valid.len() == 1
            && valid
                .first()
                .is_some_and(|other| other.sealed == winner.sealed);

        if repair && (state_changed || !replicas_identical) {
            let sealed = if state_changed {
                self.seal_record(root, &winner.record)?
            } else {
                winner.sealed.clone()
            };
            // A valid replica is already available to the caller. Repair is best-effort so a
            // temporarily locked Keychain cannot turn recoverable data into an outage.
            let _ = self.backend.store(ProtectedSlot::Replica, &sealed);
            let _ = write_atomic(self.config.file_path(), &sealed);
        }

        Ok(Some(winner.record))
    }

    #[allow(clippy::too_many_arguments)]
    fn classify_replica(
        &self,
        source: ReplicaSource,
        read: Result<Option<Vec<u8>>, StoreError>,
        root: &Secret<Vec<u8>>,
        valid: &mut Vec<ValidReplica>,
        invalid: &mut bool,
        first_error: &mut Option<StoreError>,
    ) {
        match read {
            Ok(Some(sealed)) => match self.open_record(root, &sealed) {
                Ok(record) => valid.push(ValidReplica {
                    source,
                    sealed,
                    record,
                }),
                Err(_) => *invalid = true,
            },
            Ok(None) => {}
            Err(error) => {
                if first_error.is_none() {
                    *first_error = Some(error);
                }
            }
        }
    }

    fn derive_key(&self, root: &Secret<Vec<u8>>) -> Result<Secret<[u8; 32]>, StoreError> {
        let capacity = root
            .expose()
            .len()
            .checked_add(self.fingerprint_material.expose().len())
            .ok_or(StoreError::RecordTooLarge)?;
        let mut input = Secret::new(Vec::with_capacity(capacity));
        input.expose_mut().extend_from_slice(root.expose());
        input
            .expose_mut()
            .extend_from_slice(self.fingerprint_material.expose());
        HkdfSha512::derive_from(
            b"copylocker/store/extract/v1",
            input.expose(),
            &[
                b"cl-store/v1",
                self.config.app_id().as_bytes(),
                self.config.platform().label(),
            ],
        )
        .map_err(|_| StoreError::Integrity)
    }

    fn aad(&self) -> Result<Vec<u8>, StoreError> {
        let app_len =
            u32::try_from(self.config.app_id().len()).map_err(|_| StoreError::InvalidAppId)?;
        let mut aad = Vec::with_capacity(40 + self.config.app_id().len());
        aad.extend_from_slice(b"copylocker/store/aad/v1");
        aad.extend_from_slice(&OUTER_VERSION.to_be_bytes());
        aad.push(self.config.platform() as u8);
        aad.extend_from_slice(&app_len.to_be_bytes());
        aad.extend_from_slice(self.config.app_id().as_bytes());
        Ok(aad)
    }

    fn seal_record(
        &self,
        root: &Secret<Vec<u8>>,
        record: &StoreRecord,
    ) -> Result<Vec<u8>, StoreError> {
        let mut plaintext = record.encode()?;
        let key = self.derive_key(root)?;
        let aad = self.aad()?;
        let mut nonce = [0u8; 24];
        if XChaCha20Poly1305Aead::NONCE_LEN != nonce.len() {
            plaintext.zeroize();
            return Err(StoreError::Integrity);
        }
        getrandom::fill(&mut nonce).map_err(|_| StoreError::EntropyUnavailable)?;
        let ciphertext = XChaCha20Poly1305Aead::seal(key.as_slice(), &nonce, &aad, &plaintext)
            .map_err(|_| StoreError::Integrity);
        plaintext.zeroize();
        let ciphertext = ciphertext?;

        let total_len = OUTER_HEADER_LEN
            .checked_add(nonce.len())
            .and_then(|len| len.checked_add(ciphertext.len()))
            .ok_or(StoreError::RecordTooLarge)?;
        if total_len > MAX_SEALED_LEN {
            return Err(StoreError::RecordTooLarge);
        }
        let mut sealed = Vec::with_capacity(total_len);
        sealed.extend_from_slice(OUTER_MAGIC);
        sealed.extend_from_slice(&OUTER_VERSION.to_be_bytes());
        sealed.push(self.config.platform() as u8);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn open_record(
        &self,
        root: &Secret<Vec<u8>>,
        sealed: &[u8],
    ) -> Result<StoreRecord, StoreError> {
        let minimum = OUTER_HEADER_LEN
            .checked_add(XChaCha20Poly1305Aead::NONCE_LEN)
            .and_then(|len| len.checked_add(XChaCha20Poly1305Aead::TAG_LEN))
            .ok_or(StoreError::Integrity)?;
        if sealed.len() < minimum || sealed.len() > MAX_SEALED_LEN {
            return Err(StoreError::Integrity);
        }
        if sealed.get(..OUTER_MAGIC.len()) != Some(OUTER_MAGIC.as_slice()) {
            return Err(StoreError::Integrity);
        }
        let version_bytes: [u8; 2] = sealed
            .get(8..10)
            .ok_or(StoreError::Integrity)?
            .try_into()
            .map_err(|_| StoreError::Integrity)?;
        if u16::from_be_bytes(version_bytes) != OUTER_VERSION
            || sealed.get(10).copied() != Some(self.config.platform() as u8)
        {
            return Err(StoreError::Integrity);
        }
        let nonce_end = OUTER_HEADER_LEN
            .checked_add(XChaCha20Poly1305Aead::NONCE_LEN)
            .ok_or(StoreError::Integrity)?;
        let nonce = sealed
            .get(OUTER_HEADER_LEN..nonce_end)
            .ok_or(StoreError::Integrity)?;
        let ciphertext = sealed.get(nonce_end..).ok_or(StoreError::Integrity)?;
        let key = self.derive_key(root)?;
        let aad = self.aad()?;
        let mut plaintext = XChaCha20Poly1305Aead::open(key.as_slice(), nonce, &aad, ciphertext)
            .map_err(|_| StoreError::Integrity)?;
        let decoded = StoreRecord::decode(&plaintext).map_err(|_| StoreError::Integrity);
        plaintext.zeroize();
        decoded
    }
}

impl<B: ProtectedStorage> KeyStore for SecureStore<B> {
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.load_record()?
            .map(|record| record.encode())
            .transpose()
    }

    fn save(&self, blob: &[u8]) -> Result<(), StoreError> {
        let record = StoreRecord::decode(blob)?;
        self.save_record(&record)
    }

    fn wipe(&self) -> Result<(), StoreError> {
        let _guard = self.lock()?;
        let protected_replica = self.backend.delete(ProtectedSlot::Replica);
        let file = secure_remove(self.config.file_path());
        let root = self.backend.delete(ProtectedSlot::RootSecret);
        protected_replica.and(file).and(root)
    }
}

impl<B> fmt::Debug for SecureStore<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecureStore")
            .field("config", &self.config)
            .field("fingerprint_material", &"<redacted>")
            .field("backend", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReplicaSource {
    Protected,
    File,
}

struct ValidReplica {
    #[allow(dead_code)]
    source: ReplicaSource,
    sealed: Vec<u8>,
    record: StoreRecord,
}

fn validate_app_id(app_id: &str) -> Result<(), StoreError> {
    if app_id.is_empty()
        || app_id.len() > 128
        || matches!(app_id, "." | "..")
        || !app_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(StoreError::InvalidAppId);
    }
    Ok(())
}

fn default_data_root() -> Result<PathBuf, StoreError> {
    #[cfg(target_os = "macos")]
    {
        env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join("Library").join("Application Support"))
            .ok_or(StoreError::DataDirectoryUnavailable)
    }
    #[cfg(target_os = "windows")]
    {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or(StoreError::DataDirectoryUnavailable)
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(data_home) = env::var_os("XDG_DATA_HOME") {
            let data_home = PathBuf::from(data_home);
            if data_home.is_absolute() {
                return Ok(data_home);
            }
        }
        env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".local").join("share"))
            .ok_or(StoreError::DataDirectoryUnavailable)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Err(StoreError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct MemoryProtectedStorage {
        slots: Arc<Mutex<BTreeMap<u8, Vec<u8>>>>,
    }

    impl MemoryProtectedStorage {
        fn key(slot: ProtectedSlot) -> u8 {
            match slot {
                ProtectedSlot::RootSecret => 0,
                ProtectedSlot::Replica => 1,
            }
        }

        fn get(&self, slot: ProtectedSlot) -> Option<Vec<u8>> {
            self.slots.lock().unwrap().get(&Self::key(slot)).cloned()
        }

        fn put(&self, slot: ProtectedSlot, bytes: Vec<u8>) {
            self.slots.lock().unwrap().insert(Self::key(slot), bytes);
        }

        fn remove(&self, slot: ProtectedSlot) {
            self.slots.lock().unwrap().remove(&Self::key(slot));
        }
    }

    impl ProtectedStorage for MemoryProtectedStorage {
        fn load(&self, slot: ProtectedSlot) -> Result<Option<Vec<u8>>, StoreError> {
            Ok(self.get(slot))
        }

        fn store(&self, slot: ProtectedSlot, bytes: &[u8]) -> Result<(), StoreError> {
            self.put(slot, bytes.to_vec());
            Ok(())
        }

        fn delete(&self, slot: ProtectedSlot) -> Result<(), StoreError> {
            self.remove(slot);
            Ok(())
        }
    }

    fn config(directory: &tempfile::TempDir) -> StoreConfig {
        StoreConfig::new("dev.copylocker.test")
            .unwrap()
            .with_file_path(directory.path().join("cl.bin"))
    }

    fn record(payload: &[u8], time: i64, floor: u64) -> StoreRecord {
        StoreRecord::new(
            payload.to_vec(),
            MonotonicState::new(time, time - 1, 2, floor, floor + 10),
        )
    }

    #[test]
    fn a_record_round_trips_through_two_identical_sealed_replicas() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let store =
            SecureStore::with_backend(config(&directory), b"machine-a", backend.clone()).unwrap();
        store.save_record(&record(b"credential", 100, 3)).unwrap();

        assert_eq!(
            backend.get(ProtectedSlot::Replica).as_deref(),
            fs_read(&directory.path().join("cl.bin")).as_deref()
        );
        let loaded = store.load_record().unwrap().unwrap();
        assert_eq!(loaded.generation(), 1);
        assert_eq!(loaded.payload(), b"credential");
        assert_eq!(loaded.monotonic().last_seen_max(), 100);
    }

    #[test]
    fn a_different_fingerprint_cannot_open_copied_storage() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let first =
            SecureStore::with_backend(config(&directory), b"machine-a", backend.clone()).unwrap();
        first.save_record(&record(b"credential", 100, 3)).unwrap();

        let copied = SecureStore::with_backend(config(&directory), b"machine-b", backend).unwrap();
        assert!(matches!(copied.load_record(), Err(StoreError::Integrity)));
    }

    #[test]
    fn every_single_byte_tamper_fails_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let store =
            SecureStore::with_backend(config(&directory), b"machine-a", backend.clone()).unwrap();
        store.save_record(&record(b"credential", 100, 3)).unwrap();
        let root = Secret::new(backend.get(ProtectedSlot::RootSecret).unwrap());
        let sealed = backend.get(ProtectedSlot::Replica).unwrap();

        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert!(
                store.open_record(&root, &tampered).is_err(),
                "index={index}"
            );
        }
    }

    #[test]
    fn one_corrupt_replica_is_recovered_and_repaired() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let store =
            SecureStore::with_backend(config(&directory), b"machine-a", backend.clone()).unwrap();
        store.save_record(&record(b"credential", 100, 3)).unwrap();

        let mut corrupted = backend.get(ProtectedSlot::Replica).unwrap();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        backend.put(ProtectedSlot::Replica, corrupted);
        assert_eq!(
            store.load_record().unwrap().unwrap().payload(),
            b"credential"
        );
        assert_eq!(
            backend.get(ProtectedSlot::Replica).unwrap(),
            fs_read(&directory.path().join("cl.bin")).unwrap()
        );
    }

    #[test]
    fn deleting_either_replica_cannot_lower_high_water_marks() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let path = directory.path().join("cl.bin");
        let store =
            SecureStore::with_backend(config(&directory), b"machine-a", backend.clone()).unwrap();
        store
            .save_record(&record(b"credential", 9_999, 77))
            .unwrap();

        backend.remove(ProtectedSlot::Replica);
        let from_file = store.load_record().unwrap().unwrap();
        assert_eq!(from_file.monotonic().last_seen_max(), 9_999);
        assert_eq!(from_file.monotonic().max_seen_security_floor(), 77);

        std::fs::remove_file(&path).unwrap();
        let from_protected = store.load_record().unwrap().unwrap();
        assert_eq!(from_protected.monotonic().last_seen_max(), 9_999);
        assert_eq!(from_protected.monotonic().max_seen_security_floor(), 77);
    }

    #[test]
    fn divergent_replicas_merge_monotonic_state_and_repair_the_older_copy() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let path = directory.path().join("cl.bin");
        let store =
            SecureStore::with_backend(config(&directory), b"machine-a", backend.clone()).unwrap();
        store.save_record(&record(b"old", 100, 50)).unwrap();
        let old = backend.get(ProtectedSlot::Replica).unwrap();
        store.save_record(&record(b"new", 200, 40)).unwrap();
        let new = backend.get(ProtectedSlot::Replica).unwrap();

        backend.put(ProtectedSlot::Replica, old);
        write_atomic(&path, &new).unwrap();
        let loaded = store.load_record().unwrap().unwrap();
        assert_eq!(loaded.payload(), b"new");
        assert_eq!(loaded.monotonic().last_seen_max(), 200);
        assert_eq!(loaded.monotonic().max_seen_security_floor(), 50);
        assert_eq!(
            backend.get(ProtectedSlot::Replica).unwrap(),
            fs_read(&path).unwrap()
        );
    }

    #[test]
    fn saving_stale_state_never_rolls_back_monotonic_values() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let store = SecureStore::with_backend(config(&directory), b"machine-a", backend).unwrap();
        store.save_record(&record(b"first", 1_000, 20)).unwrap();
        store.save_record(&record(b"second", 10, 2)).unwrap();

        let loaded = store.load_record().unwrap().unwrap();
        assert_eq!(loaded.generation(), 2);
        assert_eq!(loaded.payload(), b"second");
        assert_eq!(loaded.monotonic().last_seen_max(), 1_000);
        assert_eq!(loaded.monotonic().max_seen_security_floor(), 20);
    }

    #[test]
    fn negative_pre_epoch_times_are_not_silently_raised_to_zero() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let store = SecureStore::with_backend(config(&directory), b"machine-a", backend).unwrap();
        store
            .save_record(&StoreRecord::new(
                b"historical-test-vector".to_vec(),
                MonotonicState::new(-10, -20, 0, 0, 0),
            ))
            .unwrap();
        let loaded = store.load_record().unwrap().unwrap();
        assert_eq!(loaded.monotonic().last_seen_max(), -10);
        assert_eq!(loaded.monotonic().last_server_time(), -20);
    }

    #[test]
    fn wipe_removes_both_replicas_and_the_root_secret() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let path = directory.path().join("cl.bin");
        let store =
            SecureStore::with_backend(config(&directory), b"machine-a", backend.clone()).unwrap();
        store.save_record(&record(b"credential", 100, 3)).unwrap();
        store.wipe().unwrap();

        assert!(backend.get(ProtectedSlot::RootSecret).is_none());
        assert!(backend.get(ProtectedSlot::Replica).is_none());
        assert!(!path.exists());
        assert!(store.load_record().unwrap().is_none());
    }

    #[test]
    fn ciphertext_without_its_protected_secret_is_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let store =
            SecureStore::with_backend(config(&directory), b"machine-a", backend.clone()).unwrap();
        store.save_record(&record(b"credential", 100, 3)).unwrap();
        backend.remove(ProtectedSlot::RootSecret);

        assert!(matches!(
            store.save_record(&record(b"replacement", 200, 4)),
            Err(StoreError::MissingProtectedSecret)
        ));
    }

    #[test]
    fn the_outer_format_is_variant_independent() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let variant_a =
            SecureStore::with_backend(config(&directory), b"machine-a", backend.clone()).unwrap();
        variant_a
            .save_record(&record(b"credential-issued-for-variant-a", 100, 3))
            .unwrap();

        // A replacement client/variant supplies no variant input to the storage envelope and
        // can therefore read the old credential before asking the server to re-wrap feature KEKs.
        let variant_b =
            SecureStore::with_backend(config(&directory), b"machine-a", backend).unwrap();
        assert_eq!(
            variant_b.load_record().unwrap().unwrap().payload(),
            b"credential-issued-for-variant-a"
        );
    }

    #[test]
    fn malformed_raw_records_are_rejected_before_creating_a_secret() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let store =
            SecureStore::with_backend(config(&directory), b"machine-a", backend.clone()).unwrap();
        assert!(matches!(
            store.save(b"not-a-record"),
            Err(StoreError::InvalidRecord)
        ));
        assert!(backend.get(ProtectedSlot::RootSecret).is_none());
    }

    #[test]
    fn debug_never_contains_device_or_payload_material() {
        let directory = tempfile::tempdir().unwrap();
        let backend = MemoryProtectedStorage::default();
        let store = SecureStore::with_backend(
            config(&directory),
            b"highly-identifying-device-material",
            backend,
        )
        .unwrap();
        let rendered = format!("{store:?}");
        assert!(!rendered.contains("highly-identifying"));
        assert!(rendered.contains("<redacted>"));
    }

    fn fs_read(path: &Path) -> Option<Vec<u8>> {
        std::fs::read(path).ok()
    }
}
