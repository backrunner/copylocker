use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;

use tempfile::NamedTempFile;
use zeroize::Zeroize;

use crate::record::MAX_RECORD_LEN;
use crate::StoreError;

pub(crate) const MAX_SEALED_LEN: usize = MAX_RECORD_LEN + 128;

pub(crate) fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StoreError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(StoreError::UnsafeFileType);
    }
    if metadata.len() > MAX_SEALED_LEN as u64 {
        return Err(StoreError::RecordTooLarge);
    }

    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_SEALED_LEN as u64 {
        return Err(if opened_metadata.len() > MAX_SEALED_LEN as u64 {
            StoreError::RecordTooLarge
        } else {
            StoreError::UnsafeFileType
        });
    }

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.take((MAX_SEALED_LEN + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SEALED_LEN {
        bytes.zeroize();
        return Err(StoreError::RecordTooLarge);
    }
    Ok(Some(bytes))
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    if bytes.len() > MAX_SEALED_LEN {
        return Err(StoreError::RecordTooLarge);
    }
    let parent = path.parent().ok_or(StoreError::DataDirectoryUnavailable)?;
    ensure_private_dir(parent)?;
    reject_unsafe_existing(path)?;

    let mut temporary = NamedTempFile::new_in(parent)?;
    set_private_file_permissions(temporary.as_file())?;
    temporary.as_file_mut().write_all(bytes)?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    let persisted = temporary
        .persist(path)
        .map_err(|error| StoreError::Io(error.error))?;
    persisted.sync_all()?;
    sync_parent(parent)?;
    Ok(())
}

/// Overwrite a regular file before unlinking it.
///
/// Symlinks are rejected rather than followed: following one during a wipe could destroy an
/// unrelated file selected by another local process.
pub(crate) fn secure_remove(path: &Path) -> Result<(), StoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(StoreError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(StoreError::UnsafeFileType);
    }
    if metadata.len() > MAX_SEALED_LEN as u64 {
        return Err(StoreError::RecordTooLarge);
    }

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_SEALED_LEN as u64 {
        return Err(if opened_metadata.len() > MAX_SEALED_LEN as u64 {
            StoreError::RecordTooLarge
        } else {
            StoreError::UnsafeFileType
        });
    }

    file.seek(SeekFrom::Start(0))?;
    let mut remaining = opened_metadata.len();
    let mut overwrite = [0u8; 4096];
    while remaining != 0 {
        getrandom::fill(&mut overwrite).map_err(|_| StoreError::EntropyUnavailable)?;
        let count = usize::try_from(remaining.min(overwrite.len() as u64))
            .map_err(|_| StoreError::RecordTooLarge)?;
        file.write_all(overwrite.get(..count).ok_or(StoreError::RecordTooLarge)?)?;
        remaining -= count as u64;
    }
    overwrite.zeroize();
    file.flush()?;
    file.sync_all()?;
    file.set_len(0)?;
    file.sync_all()?;
    drop(file);

    fs::remove_file(path)?;
    if let Some(parent) = path.parent() {
        sync_parent(parent)?;
    }
    Ok(())
}

fn reject_unsafe_existing(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(StoreError::UnsafeFileType),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StoreError::Io(error)),
    }
}

fn ensure_private_dir(path: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(StoreError::UnsafeFileType);
    }
    set_private_dir_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(file: &File) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_file: &File) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), StoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_files_are_private_and_secure_remove_unlinks_them() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cl.bin");
        write_atomic(&path, b"secret bytes").unwrap();
        assert_eq!(
            read_optional(&path).unwrap().as_deref(),
            Some(&b"secret bytes"[..])
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        secure_remove(&path).unwrap();
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        let link = directory.path().join("cl.bin");
        File::create(&victim).unwrap().write_all(b"keep").unwrap();
        symlink(&victim, &link).unwrap();

        assert!(matches!(
            read_optional(&link),
            Err(StoreError::UnsafeFileType)
        ));
        assert!(matches!(
            secure_remove(&link),
            Err(StoreError::UnsafeFileType)
        ));
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
    }
}
