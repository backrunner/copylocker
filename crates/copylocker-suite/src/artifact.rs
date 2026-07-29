//! Artifact encoding slot.

use alloc::vec::Vec;

use copylocker_types::ArtifactKind;

use crate::CodecError;

/// A signable protocol artifact.
///
/// Implementations live in `copylocker-proto`. The trait is declared here so that the codec
/// slot can be generic over artifacts without `copylocker-suite` depending on the protocol
/// layer — the dependency arrow must keep pointing upward (`00-crate-layout.md §2`).
pub trait Artifact: Sized {
    /// Which artifact this is. Determines the domain separation context.
    const KIND: ArtifactKind;

    /// Encode to canonical bytes.
    ///
    /// Signatures cover **these bytes**, never the in-memory struct: two encodings of one value
    /// would otherwise be two different signed messages (`crypto-architecture.md §8`).
    fn to_canonical(&self) -> Result<Vec<u8>, CodecError>;

    /// Decode from canonical bytes. Must reject non-canonical input.
    fn from_canonical(bytes: &[u8]) -> Result<Self, CodecError>;
}

/// The artifact wire encoding used by a suite.
///
/// CL-STD-1 fills this with deterministic CBOR (RFC 8949 §4.2.1). A private suite may
/// substitute an entirely private layout; nothing above this trait inspects the bytes.
pub trait ArtifactCodec {
    /// Encode an artifact.
    fn encode<T: Artifact>(a: &T) -> Result<Vec<u8>, CodecError>;

    /// Decode an artifact.
    fn decode<T: Artifact>(b: &[u8]) -> Result<T, CodecError>;
}
