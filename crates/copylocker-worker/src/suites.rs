//! Supported-suite registry for the request path (ADR-0001, `versioning-and-variants.md` §1).
//!
//! Every protocol envelope is self-describing: it carries the four-byte `suite_id` of the crypto
//! suite its key material belongs to. The server must therefore dispatch its suite-generic
//! operations on the *request's* suite instead of a hardcoded constant, and fail closed on any
//! suite outside the supported set.
//!
//! Production accepts exactly CL-STD-1. A synthetic second suite, `CL-TST-1`, exists so the
//! multi-suite dispatch is exercised end to end by the worker test suite: it shares every
//! CL-STD-1 algorithm slot under a distinct identifier and is accepted only when
//! `ENVIRONMENT == "test"`, so a production deployment can never resolve it. Note that the
//! epoch signing keys (and therefore the envelope signature chain) remain CL-STD-1; per-suite
//! epoch issuance is an admin-side axis and out of scope for the request path.

use copylocker_suite::{CryptoSuite, VendorParams};
use copylocker_suite_std::ClStd1;
use copylocker_types::SuiteId;
use worker::Env;

/// The synthetic test-only suite identifier (`0x0200_0001`).
pub(crate) const TEST_SUITE_ID: SuiteId = SuiteId::from_u32(0x0200_0001);

/// A suite the request path is willing to serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestSuite {
    ClStd1,
    ClTest1,
}

impl RequestSuite {
    /// Resolve a request's suite id against the supported-suite set, failing closed.
    ///
    /// The synthetic test suite resolves only under `ENVIRONMENT == "test"`; production traffic
    /// for it fails closed exactly like any unknown suite.
    pub(crate) fn resolve(env: &Env, suite_id: SuiteId) -> Option<Self> {
        Self::resolve_for(is_test_environment(env), suite_id)
    }

    /// Resolve a persisted suite id (release rows, at-rest material). Persisted data never
    /// names the test suite: registration writes CL-STD-1 rows only, so this set is the
    /// production registry without the test extension.
    pub(crate) fn resolve_persisted(suite_id: SuiteId) -> Option<Self> {
        if suite_id == copylocker_suite_std::CL_STD_1_SUITE_ID {
            Some(Self::ClStd1)
        } else {
            None
        }
    }

    fn resolve_for(test_environment: bool, suite_id: SuiteId) -> Option<Self> {
        if suite_id == copylocker_suite_std::CL_STD_1_SUITE_ID {
            return Some(Self::ClStd1);
        }
        if test_environment && suite_id == TEST_SUITE_ID {
            return Some(Self::ClTest1);
        }
        None
    }

    /// The suite identifier written into artifacts and AEAD contexts.
    pub(crate) const fn suite_id(self) -> SuiteId {
        match self {
            Self::ClStd1 => copylocker_suite_std::CL_STD_1_SUITE_ID,
            Self::ClTest1 => TEST_SUITE_ID,
        }
    }
}

/// Dispatch a suite-generic expression over a resolved [`RequestSuite`], binding the concrete
/// suite type to `$S` inside the expression.
macro_rules! suite_dispatch {
    ($suite:expr, $S:ident, $body:expr) => {
        match $suite {
            $crate::suites::RequestSuite::ClStd1 => {
                type $S = copylocker_suite_std::ClStd1;
                $body
            }
            $crate::suites::RequestSuite::ClTest1 => {
                type $S = $crate::suites::ClTest1;
                $body
            }
        }
    };
}

pub(crate) use suite_dispatch;

/// The synthetic second suite (`CL-TST-1`): every algorithm slot aliases CL-STD-1, only the
/// identifier differs. It exists to prove the server no longer hardcodes one suite; it carries
/// no independent security posture and is never accepted outside the test environment.
pub(crate) struct ClTest1 {
    params: VendorParams,
}

impl CryptoSuite for ClTest1 {
    const SUITE_ID: SuiteId = TEST_SUITE_ID;
    const PROTO_VER: u8 = copylocker_types::PROTO_VER;
    const NAME: &'static str = "CL-TST-1";

    type Sig = <ClStd1 as CryptoSuite>::Sig;
    type Kem = <ClStd1 as CryptoSuite>::Kem;
    type Aead = <ClStd1 as CryptoSuite>::Aead;
    type Kdf = <ClStd1 as CryptoSuite>::Kdf;
    type Hash = <ClStd1 as CryptoSuite>::Hash;
    type Fpr = <ClStd1 as CryptoSuite>::Fpr;
    type Codec = <ClStd1 as CryptoSuite>::Codec;
    type Binder = <ClStd1 as CryptoSuite>::Binder;

    fn with_vendor_params(p: &VendorParams) -> Self {
        Self { params: p.clone() }
    }

    fn vendor_params(&self) -> &VendorParams {
        &self.params
    }
}

pub(crate) fn is_test_environment(env: &Env) -> bool {
    env.var("ENVIRONMENT")
        .ok()
        .is_some_and(|value| value.to_string() == "test")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_resolves_only_cl_std_1() {
        assert_eq!(
            RequestSuite::resolve_for(false, copylocker_suite_std::CL_STD_1_SUITE_ID),
            Some(RequestSuite::ClStd1)
        );
        assert_eq!(RequestSuite::resolve_for(false, TEST_SUITE_ID), None);
        assert_eq!(
            RequestSuite::resolve_for(false, SuiteId::from_u32(0x7F00_0001)),
            None
        );
    }

    #[test]
    fn the_test_environment_also_resolves_the_synthetic_suite() {
        assert_eq!(
            RequestSuite::resolve_for(true, TEST_SUITE_ID),
            Some(RequestSuite::ClTest1)
        );
        assert_eq!(
            RequestSuite::resolve_for(true, SuiteId::from_u32(0x7F00_0001)),
            None
        );
    }

    #[test]
    fn persisted_data_never_resolves_the_test_suite() {
        assert_eq!(
            RequestSuite::resolve_persisted(copylocker_suite_std::CL_STD_1_SUITE_ID),
            Some(RequestSuite::ClStd1)
        );
        assert_eq!(RequestSuite::resolve_persisted(TEST_SUITE_ID), None);
    }

    #[test]
    fn dispatch_selects_the_matching_suite_type() {
        let selected = suite_dispatch!(RequestSuite::ClStd1, S, S::SUITE_ID);
        assert_eq!(selected, copylocker_suite_std::CL_STD_1_SUITE_ID);
        let selected = suite_dispatch!(RequestSuite::ClTest1, S, S::SUITE_ID);
        assert_eq!(selected, TEST_SUITE_ID);
    }
}
