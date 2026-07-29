use core::fmt;

/// A secure-store failure.
///
/// Errors deliberately do not carry protected values or platform credential details. This
/// keeps a caller's ordinary error logging from disclosing key material.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// The application identifier is empty, too long, or unsafe as a path component.
    InvalidAppId,
    /// Device-binding material is empty or exceeds the local hard bound.
    InvalidFingerprintMaterial,
    /// No conventional per-user data directory is available.
    DataDirectoryUnavailable,
    /// This target has no desktop secure-storage implementation.
    UnsupportedPlatform,
    /// The operating-system random source failed.
    EntropyUnavailable,
    /// The platform credential store could not complete the operation.
    ProtectedStorage,
    /// Encrypted replicas exist but their OS-protected root secret is missing.
    MissingProtectedSecret,
    /// The OS-protected root secret has an unexpected size.
    InvalidProtectedSecret,
    /// A record is malformed or violates the fixed store schema.
    InvalidRecord,
    /// A record uses a newer schema than this SDK understands.
    UnsupportedRecordVersion(u16),
    /// A record or sealed replica exceeds the configured hard bound.
    RecordTooLarge,
    /// AEAD authentication failed, normally because of tampering or a different device.
    Integrity,
    /// Replicas claim the same generation but contain different application payloads.
    ReplicaConflict,
    /// A store path resolves to a symlink or another non-regular file.
    UnsafeFileType,
    /// The per-instance serialization lock was poisoned.
    LockPoisoned,
    /// A local filesystem operation failed.
    Io(std::io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAppId => formatter.write_str("invalid application identifier"),
            Self::InvalidFingerprintMaterial => formatter.write_str("invalid fingerprint material"),
            Self::DataDirectoryUnavailable => {
                formatter.write_str("per-user data directory is unavailable")
            }
            Self::UnsupportedPlatform => formatter.write_str("unsupported storage platform"),
            Self::EntropyUnavailable => formatter.write_str("secure random source is unavailable"),
            Self::ProtectedStorage => formatter.write_str("platform protected storage failed"),
            Self::MissingProtectedSecret => {
                formatter.write_str("protected store secret is missing")
            }
            Self::InvalidProtectedSecret => {
                formatter.write_str("protected store secret is invalid")
            }
            Self::InvalidRecord => formatter.write_str("invalid secure-store record"),
            Self::UnsupportedRecordVersion(version) => {
                write!(
                    formatter,
                    "unsupported secure-store record version {version}"
                )
            }
            Self::RecordTooLarge => formatter.write_str("secure-store record is too large"),
            Self::Integrity => formatter.write_str("secure-store integrity check failed"),
            Self::ReplicaConflict => formatter.write_str("secure-store replicas conflict"),
            Self::UnsafeFileType => formatter.write_str("unsafe secure-store file type"),
            Self::LockPoisoned => formatter.write_str("secure-store lock is unavailable"),
            Self::Io(error) => write!(formatter, "secure-store I/O failed: {error}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
