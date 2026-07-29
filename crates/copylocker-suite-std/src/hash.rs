//! Hash slots: SHA-256 for the protocol, BLAKE3 for manifests and large files.

use copylocker_suite::{HashScheme, StreamingHash};
use copylocker_types::Digest;
use sha2::Digest as _;

/// SHA-256, used for every protocol-level digest.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256Scheme;

/// Streaming SHA-256 state.
#[derive(Clone, Debug, Default)]
pub struct Sha256Hasher(sha2::Sha256);

impl StreamingHash for Sha256Hasher {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Digest {
        let out = self.0.finalize();
        let mut d = [0u8; 32];
        d.copy_from_slice(&out);
        Digest(d)
    }
}

impl HashScheme for Sha256Scheme {
    const OUT_LEN: usize = 32;
    type Hasher = Sha256Hasher;

    fn hash(data: &[u8]) -> Digest {
        let mut h = Self::hasher();
        h.update(data);
        h.finalize()
    }

    fn hasher() -> Self::Hasher {
        Sha256Hasher::default()
    }
}

/// BLAKE3, used for integrity manifests and asset digests where throughput matters.
///
/// Kept separate from [`Sha256Scheme`] rather than replacing it: SHA-256 is what the protocol
/// artifacts commit to, and swapping the protocol hash would invalidate every existing
/// signature (`crypto-architecture.md §3`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3Scheme;

/// Streaming BLAKE3 state.
#[derive(Clone, Debug, Default)]
pub struct Blake3Hasher(blake3::Hasher);

impl StreamingHash for Blake3Hasher {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Digest {
        Digest(*self.0.finalize().as_bytes())
    }
}

impl HashScheme for Blake3Scheme {
    const OUT_LEN: usize = 32;
    type Hasher = Blake3Hasher;

    fn hash(data: &[u8]) -> Digest {
        Digest(*blake3::hash(data).as_bytes())
    }

    fn hasher() -> Self::Hasher {
        Blake3Hasher::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn sha256_matches_the_published_abc_vector() {
        let d = Sha256Scheme::hash(b"abc");
        assert_eq!(
            d.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn blake3_matches_the_published_abc_vector() {
        let d = Blake3Scheme::hash(b"abc");
        assert_eq!(
            d.to_hex(),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut h = Sha256Scheme::hasher();
        for chunk in data.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), Sha256Scheme::hash(&data));
    }

    #[test]
    fn length_prefixed_parts_are_unambiguous() {
        // Without length prefixes these two would hash identically.
        assert_ne!(
            Sha256Scheme::hash_parts(&[b"ab", b"c"]),
            Sha256Scheme::hash_parts(&[b"a", b"bc"])
        );
    }
}
