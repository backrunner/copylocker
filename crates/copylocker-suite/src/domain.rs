//! Domain separation for signatures and key derivation.
//!
//! Every signature and every KDF call in CopyLocker carries a domain context. Without it, a
//! signature produced for one artifact kind could be replayed as another — e.g. a
//! `ValidationTicket` body reinterpreted as a `KillOrder`. `copylocker-suite-testkit` contains
//! a mandatory "cross-domain replay must fail" test for every suite
//! (`crypto-architecture.md §2`).

use alloc::vec::Vec;

use copylocker_types::{ArtifactKind, SuiteId};

/// Fixed prefix of every domain context. Protocol-visible and frozen.
pub const DOMAIN_PREFIX: &[u8] = b"copylocker/v1/";

/// The context bound into a signature or derivation.
///
/// Serialised form (`crypto-architecture.md §2`):
///
/// ```text
/// "copylocker/v1/" ‖ artifact_kind_name ‖ 0x00 ‖ suite_id(4) ‖ product_id
/// ```
///
/// The `0x00` separator is what makes the encoding injective: without it,
/// (`kind="ar"`, `product="chive"`) and (`kind="arch"`, `product="ive"`) would produce the same
/// bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DomainCtx<'a> {
    kind: ArtifactKind,
    suite_id: SuiteId,
    product_id: &'a str,
}

impl<'a> DomainCtx<'a> {
    /// Build a context.
    #[must_use]
    pub const fn new(kind: ArtifactKind, suite_id: SuiteId, product_id: &'a str) -> Self {
        Self {
            kind,
            suite_id,
            product_id,
        }
    }

    /// The artifact kind this context is for.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// The suite this context is bound to.
    #[must_use]
    pub const fn suite_id(&self) -> SuiteId {
        self.suite_id
    }

    /// The product this context is bound to.
    #[must_use]
    pub const fn product_id(&self) -> &'a str {
        self.product_id
    }

    /// Encoded length in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        DOMAIN_PREFIX.len() + self.kind.ctx_name().len() + 1 + SuiteId::LEN + self.product_id.len()
    }

    /// Serialise to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(DOMAIN_PREFIX);
        out.extend_from_slice(self.kind.ctx_name().as_bytes());
        out.push(0x00);
        out.extend_from_slice(self.suite_id.as_bytes());
        out.extend_from_slice(self.product_id.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const SUITE: SuiteId = SuiteId::from_u32(0x0100_0001);

    #[test]
    fn encoding_matches_the_specified_layout() {
        let ctx = DomainCtx::new(ArtifactKind::MachineCred, SUITE, "acme-editor");
        let mut want = vec![];
        want.extend_from_slice(b"copylocker/v1/machine-cred");
        want.push(0x00);
        want.extend_from_slice(&[0x01, 0x00, 0x00, 0x01]);
        want.extend_from_slice(b"acme-editor");
        assert_eq!(ctx.to_bytes(), want);
        assert_eq!(ctx.encoded_len(), want.len());
    }

    #[test]
    fn different_kinds_produce_different_contexts() {
        for (i, a) in ArtifactKind::ALL.iter().enumerate() {
            for b in ArtifactKind::ALL.iter().skip(i + 1) {
                assert_ne!(
                    DomainCtx::new(*a, SUITE, "p").to_bytes(),
                    DomainCtx::new(*b, SUITE, "p").to_bytes()
                );
            }
        }
    }

    #[test]
    fn different_suites_produce_different_contexts() {
        let a = DomainCtx::new(ArtifactKind::MachineCred, SUITE, "p").to_bytes();
        let b = DomainCtx::new(
            ArtifactKind::MachineCred,
            SuiteId::from_u32(0x0200_0001),
            "p",
        )
        .to_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn separator_makes_kind_and_product_unambiguous() {
        // Without the 0x00 separator these two would collide.
        let a = DomainCtx::new(ArtifactKind::ActivationRequest, SUITE, "chive").to_bytes();
        let b = DomainCtx::new(ArtifactKind::ActivationResponse, SUITE, "ve").to_bytes();
        assert_ne!(a, b);
    }
}
