//! Hash slot.

use copylocker_types::Digest;

/// A streaming hash state.
pub trait StreamingHash {
    /// Absorb more input.
    fn update(&mut self, data: &[u8]);
    /// Consume the state and produce the digest.
    fn finalize(self) -> Digest;
}

/// A cryptographic hash function producing a 256-bit digest.
pub trait HashScheme {
    /// Output width in bytes. Fixed at 32 for every currently defined suite.
    const OUT_LEN: usize;

    /// Streaming state type.
    type Hasher: StreamingHash;

    /// One-shot hash.
    fn hash(data: &[u8]) -> Digest;

    /// Start a streaming hash.
    fn hasher() -> Self::Hasher;

    /// Hash a sequence of parts with length prefixes.
    ///
    /// As with KDF info binding, the prefixes keep the encoding injective so that
    /// `["ab","c"]` and `["a","bc"]` hash differently.
    fn hash_parts(parts: &[&[u8]]) -> Digest {
        let mut h = Self::hasher();
        for p in parts {
            h.update(&(p.len() as u64).to_be_bytes());
            h.update(p);
        }
        h.finalize()
    }
}
