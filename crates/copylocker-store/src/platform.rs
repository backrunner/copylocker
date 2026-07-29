use core::fmt;
use std::path::Path;

#[cfg(any(
    not(feature = "keychain"),
    all(feature = "keychain", target_os = "linux")
))]
use crate::FileProtectedStorage;
use crate::{ProtectedSlot, ProtectedStorage, StoreError};

/// Default protected-storage backend selected for the build target.
pub struct PlatformProtectedStorage {
    inner: PlatformInner,
}

enum PlatformInner {
    #[cfg(all(feature = "keychain", target_os = "macos"))]
    Macos(macos::MacosProtectedStorage),
    #[cfg(all(feature = "keychain", target_os = "windows"))]
    Windows(windows::WindowsProtectedStorage),
    #[cfg(all(feature = "keychain", target_os = "linux"))]
    Linux(linux::LinuxProtectedStorage),
    #[cfg(not(feature = "keychain"))]
    File(FileProtectedStorage),
    #[cfg(all(
        feature = "keychain",
        not(any(target_os = "macos", target_os = "windows", target_os = "linux"))
    ))]
    Unsupported,
}

impl PlatformProtectedStorage {
    pub(crate) fn new(app_id: &str, directory: &Path) -> Result<Self, StoreError> {
        #[cfg(all(feature = "keychain", target_os = "macos"))]
        {
            let _ = directory;
            Ok(Self {
                inner: PlatformInner::Macos(macos::MacosProtectedStorage::new(app_id)),
            })
        }
        #[cfg(all(feature = "keychain", target_os = "windows"))]
        {
            Ok(Self {
                inner: PlatformInner::Windows(windows::WindowsProtectedStorage::new(
                    app_id,
                    directory.join("cl.primary"),
                )),
            })
        }
        #[cfg(all(feature = "keychain", target_os = "linux"))]
        {
            Ok(Self {
                inner: PlatformInner::Linux(linux::LinuxProtectedStorage::new(
                    app_id,
                    FileProtectedStorage::new(
                        directory.join("cl.key"),
                        directory.join("cl.primary"),
                    ),
                )),
            })
        }
        #[cfg(not(feature = "keychain"))]
        {
            let _ = app_id;
            Ok(Self {
                inner: PlatformInner::File(FileProtectedStorage::new(
                    directory.join("cl.key"),
                    directory.join("cl.primary"),
                )),
            })
        }
        #[cfg(all(
            feature = "keychain",
            not(any(target_os = "macos", target_os = "windows", target_os = "linux"))
        ))]
        {
            let _ = (app_id, directory);
            Err(StoreError::UnsupportedPlatform)
        }
    }
}

impl ProtectedStorage for PlatformProtectedStorage {
    fn load(&self, slot: ProtectedSlot) -> Result<Option<Vec<u8>>, StoreError> {
        match &self.inner {
            #[cfg(all(feature = "keychain", target_os = "macos"))]
            PlatformInner::Macos(storage) => storage.load(slot),
            #[cfg(all(feature = "keychain", target_os = "windows"))]
            PlatformInner::Windows(storage) => storage.load(slot),
            #[cfg(all(feature = "keychain", target_os = "linux"))]
            PlatformInner::Linux(storage) => storage.load(slot),
            #[cfg(not(feature = "keychain"))]
            PlatformInner::File(storage) => storage.load(slot),
            #[cfg(all(
                feature = "keychain",
                not(any(target_os = "macos", target_os = "windows", target_os = "linux"))
            ))]
            PlatformInner::Unsupported => Err(StoreError::UnsupportedPlatform),
        }
    }

    fn store(&self, slot: ProtectedSlot, bytes: &[u8]) -> Result<(), StoreError> {
        match &self.inner {
            #[cfg(all(feature = "keychain", target_os = "macos"))]
            PlatformInner::Macos(storage) => storage.store(slot, bytes),
            #[cfg(all(feature = "keychain", target_os = "windows"))]
            PlatformInner::Windows(storage) => storage.store(slot, bytes),
            #[cfg(all(feature = "keychain", target_os = "linux"))]
            PlatformInner::Linux(storage) => storage.store(slot, bytes),
            #[cfg(not(feature = "keychain"))]
            PlatformInner::File(storage) => storage.store(slot, bytes),
            #[cfg(all(
                feature = "keychain",
                not(any(target_os = "macos", target_os = "windows", target_os = "linux"))
            ))]
            PlatformInner::Unsupported => Err(StoreError::UnsupportedPlatform),
        }
    }

    fn delete(&self, slot: ProtectedSlot) -> Result<(), StoreError> {
        match &self.inner {
            #[cfg(all(feature = "keychain", target_os = "macos"))]
            PlatformInner::Macos(storage) => storage.delete(slot),
            #[cfg(all(feature = "keychain", target_os = "windows"))]
            PlatformInner::Windows(storage) => storage.delete(slot),
            #[cfg(all(feature = "keychain", target_os = "linux"))]
            PlatformInner::Linux(storage) => storage.delete(slot),
            #[cfg(not(feature = "keychain"))]
            PlatformInner::File(storage) => storage.delete(slot),
            #[cfg(all(
                feature = "keychain",
                not(any(target_os = "macos", target_os = "windows", target_os = "linux"))
            ))]
            PlatformInner::Unsupported => Err(StoreError::UnsupportedPlatform),
        }
    }
}

impl fmt::Debug for PlatformProtectedStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlatformProtectedStorage")
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "keychain", target_os = "macos"))]
mod macos {
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
        AccessControlOptions, PasswordOptions,
    };

    use super::*;

    const ITEM_NOT_FOUND: i32 = -25_300;

    pub(super) struct MacosProtectedStorage {
        service: String,
    }

    impl MacosProtectedStorage {
        pub(super) fn new(app_id: &str) -> Self {
            Self {
                service: format!("dev.copylocker.store.{app_id}"),
            }
        }

        fn account(slot: ProtectedSlot) -> &'static str {
            match slot {
                ProtectedSlot::RootSecret => "store-root-v1",
                ProtectedSlot::Replica => "store-replica-v1",
            }
        }

        fn options(&self, slot: ProtectedSlot) -> PasswordOptions {
            let mut options =
                PasswordOptions::new_generic_password(&self.service, Self::account(slot));
            options.set_access_synchronized(Some(false));
            options
        }

        fn protected_options(&self, slot: ProtectedSlot) -> Result<PasswordOptions, StoreError> {
            let access = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
                AccessControlOptions::empty().bits(),
            )
            .map_err(|_| StoreError::ProtectedStorage)?;
            let mut options = self.options(slot);
            options.set_access_control(access);
            Ok(options)
        }
    }

    impl ProtectedStorage for MacosProtectedStorage {
        fn load(&self, slot: ProtectedSlot) -> Result<Option<Vec<u8>>, StoreError> {
            match generic_password(self.options(slot)) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.code() == ITEM_NOT_FOUND => Ok(None),
                Err(_) => Err(StoreError::ProtectedStorage),
            }
        }

        fn store(&self, slot: ProtectedSlot, bytes: &[u8]) -> Result<(), StoreError> {
            set_generic_password_options(bytes, self.protected_options(slot)?)
                .map_err(|_| StoreError::ProtectedStorage)
        }

        fn delete(&self, slot: ProtectedSlot) -> Result<(), StoreError> {
            match delete_generic_password_options(self.options(slot)) {
                Ok(()) => Ok(()),
                Err(error) if error.code() == ITEM_NOT_FOUND => Ok(()),
                Err(_) => Err(StoreError::ProtectedStorage),
            }
        }
    }
}

#[cfg(all(feature = "keychain", target_os = "windows"))]
mod windows {
    use std::path::PathBuf;

    use keyring::{Entry, Error as KeyringError};

    use super::*;
    use crate::file::{read_optional, secure_remove, write_atomic};

    pub(super) struct WindowsProtectedStorage {
        service: String,
        replica_path: PathBuf,
    }

    impl WindowsProtectedStorage {
        pub(super) fn new(app_id: &str, replica_path: PathBuf) -> Self {
            Self {
                service: format!("dev.copylocker.store.{app_id}"),
                replica_path,
            }
        }

        fn root_entry(&self) -> Result<Entry, StoreError> {
            Entry::new(&self.service, "store-root-v1").map_err(|_| StoreError::ProtectedStorage)
        }
    }

    impl ProtectedStorage for WindowsProtectedStorage {
        fn load(&self, slot: ProtectedSlot) -> Result<Option<Vec<u8>>, StoreError> {
            match slot {
                ProtectedSlot::RootSecret => match self.root_entry()?.get_secret() {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(KeyringError::NoEntry) => Ok(None),
                    Err(_) => Err(StoreError::ProtectedStorage),
                },
                // Credential Manager caps generic credentials at 2.5 KiB, below the size of
                // hybrid-PQ device keys. Keep the sealed primary replica in an atomic file and
                // use Credential Manager only for the wrapping secret.
                ProtectedSlot::Replica => read_optional(&self.replica_path),
            }
        }

        fn store(&self, slot: ProtectedSlot, bytes: &[u8]) -> Result<(), StoreError> {
            match slot {
                ProtectedSlot::RootSecret => self
                    .root_entry()?
                    .set_secret(bytes)
                    .map_err(|_| StoreError::ProtectedStorage),
                ProtectedSlot::Replica => write_atomic(&self.replica_path, bytes),
            }
        }

        fn delete(&self, slot: ProtectedSlot) -> Result<(), StoreError> {
            match slot {
                ProtectedSlot::RootSecret => match self.root_entry()?.delete_credential() {
                    Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
                    Err(_) => Err(StoreError::ProtectedStorage),
                },
                ProtectedSlot::Replica => secure_remove(&self.replica_path),
            }
        }
    }
}

#[cfg(all(feature = "keychain", target_os = "linux"))]
mod linux {
    use std::sync::{Mutex, MutexGuard};

    use keyring::{Entry, Error as KeyringError};

    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum ActiveBackend {
        Keyring,
        File,
    }

    struct KeyringStorage {
        service: String,
    }

    impl KeyringStorage {
        fn new(app_id: &str) -> Self {
            Self {
                service: format!("dev.copylocker.store.{app_id}"),
            }
        }

        fn entry(&self, slot: ProtectedSlot) -> Result<Entry, StoreError> {
            let user = match slot {
                ProtectedSlot::RootSecret => "store-root-v1",
                ProtectedSlot::Replica => "store-replica-v1",
            };
            Entry::new(&self.service, user).map_err(|_| StoreError::ProtectedStorage)
        }
    }

    impl ProtectedStorage for KeyringStorage {
        fn load(&self, slot: ProtectedSlot) -> Result<Option<Vec<u8>>, StoreError> {
            match self.entry(slot)?.get_secret() {
                Ok(bytes) => Ok(Some(bytes)),
                Err(KeyringError::NoEntry) => Ok(None),
                Err(_) => Err(StoreError::ProtectedStorage),
            }
        }

        fn store(&self, slot: ProtectedSlot, bytes: &[u8]) -> Result<(), StoreError> {
            self.entry(slot)?
                .set_secret(bytes)
                .map_err(|_| StoreError::ProtectedStorage)
        }

        fn delete(&self, slot: ProtectedSlot) -> Result<(), StoreError> {
            match self.entry(slot)?.delete_credential() {
                Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
                Err(_) => Err(StoreError::ProtectedStorage),
            }
        }
    }

    pub(super) struct LinuxProtectedStorage {
        keyring: KeyringStorage,
        fallback: FileProtectedStorage,
        active: Mutex<Option<ActiveBackend>>,
    }

    impl LinuxProtectedStorage {
        pub(super) fn new(app_id: &str, fallback: FileProtectedStorage) -> Self {
            Self {
                keyring: KeyringStorage::new(app_id),
                fallback,
                active: Mutex::new(None),
            }
        }

        fn active(&self) -> Result<MutexGuard<'_, Option<ActiveBackend>>, StoreError> {
            self.active.lock().map_err(|_| StoreError::LockPoisoned)
        }

        fn load_root(&self) -> Result<Option<Vec<u8>>, StoreError> {
            let mut active = self.active()?;
            match self.keyring.load(ProtectedSlot::RootSecret) {
                Ok(Some(secret)) => {
                    *active = Some(ActiveBackend::Keyring);
                    Ok(Some(secret))
                }
                Ok(None) => match self.fallback.load(ProtectedSlot::RootSecret)? {
                    Some(secret) => {
                        *active = Some(ActiveBackend::File);
                        Ok(Some(secret))
                    }
                    None => Ok(None),
                },
                Err(keyring_error) => match self.fallback.load(ProtectedSlot::RootSecret)? {
                    Some(secret) => {
                        *active = Some(ActiveBackend::File);
                        Ok(Some(secret))
                    }
                    None => Err(keyring_error),
                },
            }
        }

        fn store_root(&self, bytes: &[u8]) -> Result<(), StoreError> {
            let mut active = self.active()?;
            if matches!(*active, Some(ActiveBackend::File)) {
                return self.fallback.store(ProtectedSlot::RootSecret, bytes);
            }
            match self.keyring.store(ProtectedSlot::RootSecret, bytes) {
                Ok(()) => {
                    *active = Some(ActiveBackend::Keyring);
                    Ok(())
                }
                Err(_) => {
                    self.fallback.store(ProtectedSlot::RootSecret, bytes)?;
                    *active = Some(ActiveBackend::File);
                    Ok(())
                }
            }
        }

        fn load_replica_without_active(&self) -> Result<Option<Vec<u8>>, StoreError> {
            match self.keyring.load(ProtectedSlot::Replica) {
                Ok(Some(bytes)) => Ok(Some(bytes)),
                Ok(None) => self.fallback.load(ProtectedSlot::Replica),
                Err(keyring_error) => self
                    .fallback
                    .load(ProtectedSlot::Replica)?
                    .map_or(Err(keyring_error), |bytes| Ok(Some(bytes))),
            }
        }
    }

    impl ProtectedStorage for LinuxProtectedStorage {
        fn load(&self, slot: ProtectedSlot) -> Result<Option<Vec<u8>>, StoreError> {
            if slot == ProtectedSlot::RootSecret {
                return self.load_root();
            }
            let active = *self.active()?;
            match active {
                Some(ActiveBackend::Keyring) => self.keyring.load(slot),
                Some(ActiveBackend::File) => self.fallback.load(slot),
                None => self.load_replica_without_active(),
            }
        }

        fn store(&self, slot: ProtectedSlot, bytes: &[u8]) -> Result<(), StoreError> {
            if slot == ProtectedSlot::RootSecret {
                return self.store_root(bytes);
            }
            let active = *self.active()?;
            match active {
                Some(ActiveBackend::Keyring) => self.keyring.store(slot, bytes),
                Some(ActiveBackend::File) => self.fallback.store(slot, bytes),
                None => match self.keyring.store(slot, bytes) {
                    Ok(()) => Ok(()),
                    Err(_) => self.fallback.store(slot, bytes),
                },
            }
        }

        fn delete(&self, slot: ProtectedSlot) -> Result<(), StoreError> {
            let keyring_result = self.keyring.delete(slot);
            let fallback_result = self.fallback.delete(slot);
            if slot == ProtectedSlot::RootSecret {
                *self.active()? = None;
            }
            keyring_result.and(fallback_result)
        }
    }
}
