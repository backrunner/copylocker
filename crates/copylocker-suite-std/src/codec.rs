//! Artifact codec: deterministic CBOR.

use alloc::vec::Vec;

use copylocker_suite::{Artifact, ArtifactCodec, CodecError};

/// Deterministic CBOR (RFC 8949 §4.2.1) as the artifact wire format.
///
/// The per-artifact field mapping lives with each artifact's [`Artifact`] implementation in
/// `copylocker-proto`; this type only names the encoding for the suite. A private suite may
/// substitute a wholly private layout here without any caller noticing.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalCborCodec;

impl ArtifactCodec for CanonicalCborCodec {
    fn encode<T: Artifact>(a: &T) -> Result<Vec<u8>, CodecError> {
        a.to_canonical()
    }

    fn decode<T: Artifact>(b: &[u8]) -> Result<T, CodecError> {
        T::from_canonical(b)
    }
}
