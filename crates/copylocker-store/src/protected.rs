use core::fmt;
use std::path::{Path, PathBuf};

use crate::file::{read_optional, secure_remove, write_atomic};
use crate::StoreError;

/// Independent values kept in platform-protected storage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProtectedSlot {
    /// Random 256-bit root secret used by the store KDF.
    RootSecret,
    /// Primary copy of the sealed application record.
    Replica,
}

/// Minimal abstraction over Keychain, Credential Manager, Secret Service, or a test backend.
///
/// Implementations receive secret bytes directly. They must never route them through command
/// line arguments, environment variables, logs, or textual shell tools.
pub trait ProtectedStorage: Send + Sync {
    /// Read a slot, returning `None` when it has never been written.
    fn load(&self, slot: ProtectedSlot) -> Result<Option<Vec<u8>>, StoreError>;
    /// Replace a slot.
    fn store(&self, slot: ProtectedSlot, bytes: &[u8]) -> Result<(), StoreError>;
    /// Delete a slot. Deleting an absent slot succeeds.
    fn delete(&self, slot: ProtectedSlot) -> Result<(), StoreError>;
}

/// Private-file implementation used by the explicit `file-only` feature and Linux fallback.
///
/// It is weaker than a platform keychain, but the root secret remains mode `0600` and the
/// encrypted record is still device-bound through the fingerprint-derived KDF.
#[derive(Clone)]
pub struct FileProtectedStorage {
    root_secret_path: PathBuf,
    replica_path: PathBuf,
}

impl FileProtectedStorage {
    /// Construct a file backend with explicit paths.
    #[must_use]
    pub fn new(root_secret_path: PathBuf, replica_path: PathBuf) -> Self {
        Self {
            root_secret_path,
            replica_path,
        }
    }

    fn path(&self, slot: ProtectedSlot) -> &Path {
        match slot {
            ProtectedSlot::RootSecret => &self.root_secret_path,
            ProtectedSlot::Replica => &self.replica_path,
        }
    }
}

impl ProtectedStorage for FileProtectedStorage {
    fn load(&self, slot: ProtectedSlot) -> Result<Option<Vec<u8>>, StoreError> {
        read_optional(self.path(slot))
    }

    fn store(&self, slot: ProtectedSlot, bytes: &[u8]) -> Result<(), StoreError> {
        write_atomic(self.path(slot), bytes)
    }

    fn delete(&self, slot: ProtectedSlot) -> Result<(), StoreError> {
        secure_remove(self.path(slot))
    }
}

impl fmt::Debug for FileProtectedStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileProtectedStorage")
            .finish_non_exhaustive()
    }
}
