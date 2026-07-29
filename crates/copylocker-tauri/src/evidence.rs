//! Deterministic evidence for the statically linked Tauri host.

use std::borrow::Cow;
use std::fs;

use copylocker_suite::EnvEvidence;
use copylocker_types::Digest;
use object::{Object, ObjectSection};

const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

/// How executable evidence was obtained.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvidenceSource {
    /// The current executable's code section was parsed and hashed.
    ExecutableText,
    /// Collection was unavailable and the embedded expected digest was retained.
    EmbeddedFallback,
}

/// Evidence plus a non-security status for host diagnostics.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EvidenceReport {
    evidence: EnvEvidence,
    source: EvidenceSource,
}

impl EvidenceReport {
    /// Whether collection used the deterministic embedded fallback.
    #[must_use]
    pub const fn degraded(&self) -> bool {
        matches!(self.source, EvidenceSource::EmbeddedFallback)
    }

    /// Evidence source for diagnostics.
    #[must_use]
    pub const fn source(&self) -> EvidenceSource {
        self.source
    }

    /// Consume the report and return key-schedule evidence.
    #[must_use]
    pub fn into_evidence(self) -> EnvEvidence {
        self.evidence
    }
}

/// Collect deterministic evidence without returning a verification boolean.
#[must_use]
pub fn collect(
    expected_module_digest: [u8; 32],
    build_fingerprint: &str,
    extra: Vec<Vec<u8>>,
) -> EvidenceReport {
    let observed = std::env::current_exe()
        .ok()
        .and_then(|path| fs::metadata(&path).ok().map(|metadata| (path, metadata)))
        .filter(|(_, metadata)| metadata.len() <= MAX_EXECUTABLE_BYTES)
        .and_then(|(path, _)| fs::read(path).ok())
        .and_then(|bytes| text_section(&bytes).map(|section| blake3::hash(&section)));

    let (module_digest, source) = observed.map_or(
        (
            Digest(expected_module_digest),
            EvidenceSource::EmbeddedFallback,
        ),
        |digest| (Digest(*digest.as_bytes()), EvidenceSource::ExecutableText),
    );
    EvidenceReport {
        evidence: EnvEvidence {
            module_digest,
            build_fingerprint: build_fingerprint.as_bytes().to_vec(),
            extra,
        },
        source,
    }
}

fn text_section(bytes: &[u8]) -> Option<Cow<'_, [u8]>> {
    let file = object::File::parse(bytes).ok()?;
    [".text", "__text"]
        .into_iter()
        .find_map(|name| file.section_by_name(name))?
        .data()
        .ok()
        .map(Cow::Borrowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_is_stable_across_immediate_reads() {
        let first = collect([7; 32], "build-a", vec![b"extra".to_vec()]);
        for _ in 0..10 {
            assert_eq!(collect([7; 32], "build-a", vec![b"extra".to_vec()]), first);
        }
    }

    #[test]
    fn malformed_objects_use_the_embedded_fallback() {
        assert!(text_section(b"not an executable").is_none());
        let fallback = Digest([9; 32]);
        let report = EvidenceReport {
            evidence: EnvEvidence {
                module_digest: fallback,
                build_fingerprint: b"build-a".to_vec(),
                extra: Vec::new(),
            },
            source: EvidenceSource::EmbeddedFallback,
        };
        assert!(report.degraded());
        assert_eq!(report.into_evidence().module_digest, fallback);
    }
}
