//! Size harness that retains the real CL-STD-1 certificate-chain verification path.

#![deny(unsafe_code)]

use copylocker_proto::artifacts::MachineCredential;
use copylocker_proto::chain::{PinnedRoots, VerifiedChain};
use copylocker_proto::envelope::Envelope;
use copylocker_suite::SignatureScheme;
use copylocker_suite_std::{HybridSig, Sha256Scheme};
use copylocker_types::Digest;

const ROOT_VK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/root-vk.bin"));
const ROOT_DIGEST: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/root-digest.bin"));
const EPOCH_ENVELOPE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/epoch-envelope.bin"));
const ARTIFACT_ENVELOPE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/artifact-envelope.bin"));

/// Verify the committed Root -> Epoch -> MachineCredential vector.
///
/// Exporting this function prevents LTO from discarding the parser and hybrid verifier, making
/// the resulting gzip size a stable upper bound for the M0 browser verification path.
// The export marker is the only unsafe attribute in this non-production FFI harness.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn copylocker_verify_embedded_chain() -> u32 {
    verify_embedded_chain().is_ok().into()
}

fn verify_embedded_chain() -> Result<(), ()> {
    let root_vk = HybridSig::decode_vk(ROOT_VK).map_err(|_| ())?;
    let root_digest = Digest::from_slice(ROOT_DIGEST).ok_or(())?;
    let epoch_envelope = Envelope::decode(EPOCH_ENVELOPE).map_err(|_| ())?;
    let artifact_envelope = Envelope::decode(ARTIFACT_ENVELOPE).map_err(|_| ())?;

    let mut chain = VerifiedChain::<HybridSig>::new(PinnedRoots::single(root_digest));
    chain
        .add_epoch::<Sha256Scheme>(&epoch_envelope, "kat-product", &root_vk, 5_000)
        .map_err(|_| ())?;
    chain
        .verify_artifact::<MachineCredential>(&artifact_envelope, "kat-product", 5_000)
        .map(|_| ())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    #[test]
    fn embedded_chain_is_valid() {
        assert_eq!(super::copylocker_verify_embedded_chain(), 1);
    }
}
