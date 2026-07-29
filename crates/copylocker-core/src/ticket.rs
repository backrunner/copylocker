//! The mandatory validation-ticket checklist (`protocol-spec.md §5`).
//!
//! Eight checks, every one required, every time. The spec calls for a "checklist test" proving
//! that omitting any single check is caught — that test lives at the bottom of this file. The
//! checks are structured as data ([`TicketChecks`]) rather than a bare function so the test can
//! enumerate them.

use copylocker_proto::artifacts::ValidationTicket;
use copylocker_types::{EpochId, MachineId, PROTO_VER};

use crate::clock::ClockState;
use crate::error::FatalError;

/// Maximum tolerated divergence between server time and the local estimate.
///
/// Beyond it the divergence is *recorded* but the ticket still accepted — the local clock is the
/// one more likely to be wrong (`protocol-spec.md §5`, check 6).
pub const MAX_SKEW_SECS: i64 = 24 * 3_600;

/// The context a ticket must be checked against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TicketChecks<'a> {
    /// Suites this build can verify.
    pub supported_suites: &'a [copylocker_types::SuiteId],
    /// The epoch the ticket's envelope referenced, already verified against the chain.
    pub verified_epoch: EpochId,
    /// The nonce this client sent in the request being answered.
    pub sent_nonce: [u8; 32],
    /// This device's machine identifier from its credential.
    pub machine_id: MachineId,
    /// The highest revocation epoch this client has already seen.
    pub known_revocation_epoch: u64,
    /// The highest security floor this client has already seen.
    pub known_security_floor: u64,
}

/// What checking a ticket concluded beyond pass/fail.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TicketObservations {
    /// Server time diverged from the local estimate beyond [`MAX_SKEW_SECS`].
    ///
    /// Logged, not fatal: the local clock is the less trustworthy party.
    pub clock_divergence: Option<i64>,
}

/// Run the full checklist against a **signature-verified** ticket body.
///
/// The envelope signature and chain checks happen before this function; these are the
/// *semantic* checks that a validly signed ticket must still pass. The order matches the spec's
/// numbering.
pub fn check_ticket(
    vt: &ValidationTicket,
    ctx: &TicketChecks<'_>,
    clock: &mut ClockState,
    local_now: i64,
) -> Result<TicketObservations, FatalError> {
    // 1. Protocol version and suite are supported.
    if vt.proto_ver != PROTO_VER {
        return Err(FatalError::CredentialCorrupt);
    }
    if !ctx.supported_suites.contains(&vt.suite_id) {
        return Err(FatalError::CredentialCorrupt);
    }

    // 2. The epoch the envelope referenced is the one whose key verified the signature.
    //    A mismatch means the body claims a different epoch than the one that signed it.
    if vt.epoch_id != ctx.verified_epoch {
        return Err(FatalError::ChainInvalid);
    }

    // (3 is the signature itself, performed by the caller through the chain.)

    // 4. The nonce echo matches what we sent. This is the anti-replay check: a captured
    //    response cannot answer a different request.
    if vt.nonce_c_echo != ctx.sent_nonce {
        return Err(FatalError::NonceMismatch);
    }

    // 5. The ticket is for this machine.
    if vt.machine_id != ctx.machine_id {
        return Err(FatalError::MachineMismatch);
    }

    // 6. Server time within skew of the local estimate — recorded, not fatal.
    let divergence = vt.server_time.saturating_sub(local_now).abs();
    let observations = TicketObservations {
        clock_divergence: (divergence > MAX_SKEW_SECS).then_some(divergence),
    };

    // 7. The revocation epoch never moves backwards. Accepting an older value would roll the
    //    client back to before a revocation it has already seen.
    if vt.revocation_epoch < ctx.known_revocation_epoch {
        return Err(FatalError::RevocationRollback);
    }
    // Same monotonicity for the security floor.
    if vt.security_floor < ctx.known_security_floor {
        return Err(FatalError::SecurityFloorRegression);
    }

    // 8. The next refresh deadline lies in the server's future; a stale or replayed ticket
    //    fails here even if everything else lines up.
    if vt.next_refresh_after <= vt.server_time {
        return Err(FatalError::CredentialCorrupt);
    }

    // All checks passed: the server's word is authoritative for time.
    clock.observe_server_time(vt.server_time);
    Ok(observations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::string::ToString;
    use copylocker_types::{Entitlements, SuiteId, Verdict};

    const SUITE: SuiteId = SuiteId::from_u32(0x0100_0001);
    const NOW: i64 = 1_800_000_000;

    fn ticket() -> ValidationTicket {
        let mut features = BTreeSet::new();
        features.insert("export.pdf".to_string());
        ValidationTicket {
            proto_ver: 1,
            suite_id: SUITE,
            machine_id: MachineId([3; 16]),
            nonce_c_echo: [9; 32],
            server_nonce: [10; 32],
            server_time: NOW,
            next_refresh_after: NOW + 7 * 86_400,
            not_after: NOW + 365 * 86_400,
            revocation_epoch: 42,
            verdict: Verdict::Ok,
            entitlements: Some(Entitlements {
                features,
                limits: BTreeMap::new(),
                tier_id: "pro".to_string(),
                tier_label: "Pro".to_string(),
                catalog_version: 1,
                version_scope: None,
                subscription_hint: None,
            }),
            epoch_id: EpochId([1; 8]),
            suspicion_score: None,
            security_floor: 3,
            release_status: Some(0),
            wrapped_keks: None,
            refresh_now: None,
        }
    }

    fn ctx() -> TicketChecks<'static> {
        TicketChecks {
            supported_suites: &[SUITE],
            verified_epoch: EpochId([1; 8]),
            sent_nonce: [9; 32],
            machine_id: MachineId([3; 16]),
            known_revocation_epoch: 42,
            known_security_floor: 3,
        }
    }

    #[test]
    fn a_correct_ticket_passes_and_advances_the_clock() {
        let mut clock = ClockState::new(NOW - 100);
        let obs = check_ticket(&ticket(), &ctx(), &mut clock, NOW).unwrap();
        assert_eq!(obs.clock_divergence, None);
        assert_eq!(clock.last_server_time(), NOW);
        assert_eq!(clock.last_seen_max(), NOW);
    }

    /// The spec-mandated checklist test: for every semantic check, a ticket violating exactly
    /// that check must fail with the matching error.
    #[test]
    fn each_check_catches_its_own_violation() {
        type Mutation = fn(&mut ValidationTicket);
        let cases: &[(&str, Mutation, FatalError)] = &[
            (
                "proto_ver",
                |vt| vt.proto_ver = 2,
                FatalError::CredentialCorrupt,
            ),
            (
                "suite_id",
                |vt| vt.suite_id = SuiteId::from_u32(0xDEAD),
                FatalError::CredentialCorrupt,
            ),
            (
                "epoch_binding",
                |vt| vt.epoch_id = EpochId([2; 8]),
                FatalError::ChainInvalid,
            ),
            (
                "nonce_echo",
                |vt| vt.nonce_c_echo = [0xAA; 32],
                FatalError::NonceMismatch,
            ),
            (
                "machine_binding",
                |vt| vt.machine_id = MachineId([0xBB; 16]),
                FatalError::MachineMismatch,
            ),
            (
                "revocation_monotonicity",
                |vt| vt.revocation_epoch = 41,
                FatalError::RevocationRollback,
            ),
            (
                "security_floor_monotonicity",
                |vt| vt.security_floor = 2,
                FatalError::SecurityFloorRegression,
            ),
            (
                "refresh_in_the_future",
                |vt| vt.next_refresh_after = vt.server_time,
                FatalError::CredentialCorrupt,
            ),
        ];

        for (name, mutate, want) in cases {
            let mut vt = ticket();
            mutate(&mut vt);
            let mut clock = ClockState::new(NOW - 100);
            assert_eq!(
                check_ticket(&vt, &ctx(), &mut clock, NOW).err(),
                Some(*want),
                "check `{name}` failed to catch its violation"
            );
            // A failed ticket must not have advanced the clock.
            assert_eq!(
                clock.last_server_time(),
                NOW - 100,
                "check `{name}` leaked a clock update on failure"
            );
        }
    }

    #[test]
    fn a_newer_revocation_epoch_is_accepted() {
        // Progress is fine; only regression is fatal.
        let mut vt = ticket();
        vt.revocation_epoch = 43;
        vt.security_floor = 4;
        let mut clock = ClockState::new(NOW);
        assert!(check_ticket(&vt, &ctx(), &mut clock, NOW).is_ok());
    }

    #[test]
    fn large_clock_divergence_is_recorded_but_not_fatal() {
        // The local clock is the less trustworthy party (`protocol-spec.md §5`, check 6).
        let mut clock = ClockState::new(NOW - 100);
        let local_far_behind = NOW - 3 * 86_400;
        let obs = check_ticket(&ticket(), &ctx(), &mut clock, local_far_behind).unwrap();
        assert_eq!(obs.clock_divergence, Some(3 * 86_400));
        assert_eq!(clock.last_server_time(), NOW, "still authoritative");
    }

    #[test]
    fn divergence_just_inside_the_skew_window_is_not_recorded() {
        let mut clock = ClockState::new(NOW - 100);
        let obs = check_ticket(&ticket(), &ctx(), &mut clock, NOW - MAX_SKEW_SECS).unwrap();
        assert_eq!(obs.clock_divergence, None);
    }

    #[test]
    fn extreme_times_do_not_overflow() {
        let mut vt = ticket();
        vt.server_time = i64::MAX - 10;
        vt.next_refresh_after = i64::MAX;
        let mut clock = ClockState::new(0);
        let obs = check_ticket(&vt, &ctx(), &mut clock, i64::MIN + 10).unwrap();
        assert!(obs.clock_divergence.is_some());
    }
}
