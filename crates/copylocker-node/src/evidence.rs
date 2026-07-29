//! Electron native-module and ASAR evidence collection.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use copylocker_suite::EnvEvidence;
use copylocker_types::Digest;

const EVIDENCE_DOMAIN: &[u8] = b"copylocker/electron-evidence/v1";
const MAX_MODULE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ASAR_HEADER_BYTES: usize = 16 * 1024 * 1024;
const BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EvidenceSource {
    Observed,
    EmbeddedFallback,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct EvidenceReport {
    pub(crate) evidence: EnvEvidence,
    pub(crate) source: EvidenceSource,
}

pub(crate) fn collect(
    module_path: &Path,
    asar_path: Option<&Path>,
    expected: [u8; 32],
    build_fingerprint: &str,
) -> EvidenceReport {
    let observed = digest_files(module_path, asar_path).ok();
    let (digest, source) = observed.map_or(
        (Digest(expected), EvidenceSource::EmbeddedFallback),
        |value| (Digest(value), EvidenceSource::Observed),
    );
    EvidenceReport {
        evidence: EnvEvidence {
            module_digest: digest,
            build_fingerprint: build_fingerprint.as_bytes().to_vec(),
            extra: Vec::new(),
        },
        source,
    }
}

fn digest_files(module_path: &Path, asar_path: Option<&Path>) -> io::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EVIDENCE_DOMAIN);
    hash_file(&mut hasher, b"node", module_path, MAX_MODULE_BYTES)?;
    match asar_path {
        Some(path) => {
            let header = read_asar_header(path)?;
            hash_part(&mut hasher, b"asar", &header);
        }
        None => hash_part(&mut hasher, b"asar", &[]),
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_file(
    hasher: &mut blake3::Hasher,
    label: &[u8],
    path: &Path,
    max_bytes: u64,
) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "evidence file is invalid",
        ));
    }
    hasher.update(&(label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(&metadata.len().to_be_bytes());
    let mut file = File::open(path)?;
    let mut buffer = [0u8; BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(buffer.get(..read).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "evidence read exceeded its buffer",
            )
        })?);
    }
    Ok(())
}

fn hash_part(hasher: &mut blake3::Hasher, label: &[u8], bytes: &[u8]) {
    hasher.update(&(label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn read_asar_header(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut prefix = [0u8; 16];
    file.read_exact(&mut prefix)?;
    let length_bytes: [u8; 4] = prefix
        .get(12..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid ASAR prefix"))?;
    let header_len = usize::try_from(u32::from_le_bytes(length_bytes))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ASAR header length"))?;
    if header_len == 0 || header_len > MAX_ASAR_HEADER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ASAR header is outside the permitted bound",
        ));
    }
    let total = prefix
        .len()
        .checked_add(header_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ASAR header overflow"))?;
    let mut header = Vec::with_capacity(total);
    header.extend_from_slice(&prefix);
    let start = header.len();
    header.resize(total, 0);
    file.read_exact(header.get_mut(start..).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "ASAR header allocation failed")
    })?)?;
    Ok(header)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn fake_asar(header: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut prefix = [0u8; 16];
        prefix[12..16].copy_from_slice(&(header.len() as u32).to_le_bytes());
        file.write_all(&prefix).unwrap();
        file.write_all(header).unwrap();
        file
    }

    #[test]
    fn module_and_asar_are_both_deterministic_inputs() {
        let mut module = tempfile::NamedTempFile::new().unwrap();
        module.write_all(b"native module").unwrap();
        let asar = fake_asar(b"asar header");
        let first = digest_files(module.path(), Some(asar.path())).unwrap();
        assert_eq!(
            digest_files(module.path(), Some(asar.path())).unwrap(),
            first
        );
        assert_ne!(digest_files(module.path(), None).unwrap(), first);

        let changed = fake_asar(b"changed header");
        assert_ne!(
            digest_files(module.path(), Some(changed.path())).unwrap(),
            first
        );
    }

    #[test]
    fn collection_failure_uses_the_embedded_digest() {
        let missing = Path::new("definitely-not-a-copylocker-module");
        let report = collect(missing, None, [7; 32], "build-a");
        assert_eq!(report.source, EvidenceSource::EmbeddedFallback);
        assert_eq!(report.evidence.module_digest, Digest([7; 32]));
    }

    #[test]
    fn malformed_or_oversized_asar_headers_are_rejected() {
        let empty = fake_asar(&[]);
        assert!(read_asar_header(empty.path()).is_err());

        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut prefix = [0u8; 16];
        prefix[12..16].copy_from_slice(&((MAX_ASAR_HEADER_BYTES as u32) + 1).to_le_bytes());
        file.write_all(&prefix).unwrap();
        assert!(read_asar_header(file.path()).is_err());
    }
}
