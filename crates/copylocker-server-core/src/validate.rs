//! Validation: the hot path (`10-server-worker.md §2.1`).
//!
//! Every online check runs through here. The decision is a pure function of the licence record,
//! the policy, and the request, so the whole verdict table is testable without a network.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use copylocker_types::{Entitlements, KillReason, MachineId, Verdict, VersionScope};

use crate::entitlement::resolve;
use crate::policy::Policy;
use crate::store::{ActivationStatus, LicenseRecord, LicenseStatus};
use crate::version::{decide, CompromisedAction, ReleaseRegistry, VersionDecision};
use crate::{Catalog, ClientFault};

/// The request, reduced to what the decision actually depends on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidateInput<'a> {
    /// Which activation is asking.
    pub machine_id: MachineId,
    /// Client nonce, echoed back to prove freshness.
    pub nonce_c: [u8; 32],
    /// Release the client reports.
    pub release_id: &'a str,
    /// Revocation sequence the client already holds.
    pub known_revocation_epoch: u64,
    /// Highest security floor the client has seen.
    pub known_security_floor: u64,
    /// Whether the device proof verified. Checked by the caller, which owns the suite.
    pub proof_valid: bool,
    /// Whether the nonce was fresh. Checked by the caller against durable storage.
    pub nonce_fresh: bool,
}

/// What the server decided.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ValidateOutcome {
    /// Issue a ticket.
    Ticket(Box<TicketPlan>),
    /// Issue a kill order and wipe the device.
    Kill {
        /// Why.
        reason: KillReason,
        /// Message for the end user.
        user_message: Option<String>,
    },
}

/// The contents a ticket should carry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TicketPlan {
    /// Server verdict.
    pub verdict: Verdict,
    /// Next validation deadline.
    pub next_refresh_after: i64,
    /// Possibly-extended hard expiry.
    pub not_after: i64,
    /// Current revocation sequence.
    pub revocation_epoch: u64,
    /// Current security floor.
    pub security_floor: u64,
    /// Entitlements, when they changed since issuance.
    pub entitlements: Option<Entitlements>,
    /// Release status to report: 0 active, 1 deprecated, 2 compromised.
    pub release_status: Option<u8>,
    /// Whether to ask the client to revalidate promptly.
    pub refresh_now: bool,
    /// Variant whose keys the client should hold.
    pub variant_id: Option<u64>,
}

/// Decide what to return for a validation request.
///
/// The order of checks is deliberate. Cheap structural rejections come first; a kill order is
/// only produced for conditions that genuinely warrant destroying the client's credential, since
/// that is irreversible without a fresh activation.
#[allow(clippy::too_many_arguments)]
pub fn validate(
    license: &LicenseRecord,
    policy: &Policy,
    catalog: &Catalog,
    registry: &ReleaseRegistry,
    version_scope: &VersionScope,
    input: &ValidateInput<'_>,
    revocation_epoch: u64,
    security_floor: u64,
    now: i64,
) -> Result<ValidateOutcome, ClientFault> {
    // A replayed nonce means someone is resending a captured request.
    if !input.nonce_fresh {
        return Err(ClientFault::ReplayedNonce);
    }
    // Without a valid device signature, `machine_id` alone would be enough to impersonate a
    // device — or to burn its rate limit.
    if !input.proof_valid {
        return Err(ClientFault::ProofInvalid);
    }
    // A client must never move backwards on either monotonic counter.
    if input.known_revocation_epoch > revocation_epoch
        || input.known_security_floor > security_floor
    {
        return Err(ClientFault::RollbackAttempt);
    }

    let Some(activation) = license.activation(&input.machine_id) else {
        // An unknown activation is not a kill order: the credential may simply predate a
        // storage migration, and re-activation is the safe recovery.
        return Err(ClientFault::NeedsReactivation);
    };

    // Conditions that justify destroying the credential.
    if license.status == LicenseStatus::Revoked {
        return Ok(ValidateOutcome::Kill {
            reason: KillReason::RevokedLicense,
            user_message: Some(
                "This licence has been revoked. Please contact support.".to_string(),
            ),
        });
    }
    match activation.status {
        ActivationStatus::Revoked => {
            return Ok(ValidateOutcome::Kill {
                reason: KillReason::RevokedActivation,
                user_message: Some("This device's activation was revoked.".to_string()),
            })
        }
        ActivationStatus::Released => {
            return Ok(ValidateOutcome::Kill {
                reason: KillReason::SeatReclaimed,
                user_message: Some(
                    "This device's seat was released. Activate again to continue.".to_string(),
                ),
            })
        }
        ActivationStatus::Active | ActivationStatus::Pending => {}
    }

    // A suspended or expired licence stops being refreshed, but the existing credential is left
    // to run out its own clock. Killing it immediately would punish a user whose payment is
    // merely in flight (`licensing-model.md §3.2`).
    if matches!(
        license.status,
        LicenseStatus::Suspended | LicenseStatus::Expired
    ) {
        return Err(ClientFault::InvalidCredential);
    }
    if license.expires_at.is_some_and(|e| now >= e) {
        return Err(ClientFault::InvalidCredential);
    }

    let release_decision = decide(registry, version_scope, input.release_id);
    let (verdict, variant_id, release_status) = match &release_decision {
        VersionDecision::InScope { variant_id } => {
            let status = registry.get(input.release_id).map(|r| r.status as u8);
            (Verdict::Ok, Some(*variant_id), status)
        }
        VersionDecision::NotRegistered => {
            return Err(ClientFault::ReleaseNotRegistered {
                release_id: input.release_id.to_string(),
            })
        }
        VersionDecision::OutOfScope { highest_allowed } => {
            // Restricted mode, not a kill. This is a paying customer running a build newer than
            // they bought; the client shows an upgrade path (`licensing-model.md §4.3`).
            let _ = highest_allowed;
            (Verdict::VersionOutOfScope, None, Some(0))
        }
        VersionDecision::Compromised { action } => match action {
            CompromisedAction::Warn => {
                let variant = registry.get(input.release_id).map(|r| r.variant_id);
                (Verdict::Ok, variant, Some(2))
            }
            CompromisedAction::ForceUpgrade => (Verdict::NeedsReactivation, None, Some(2)),
            CompromisedAction::Revoke => {
                return Ok(ValidateOutcome::Kill {
                    reason: KillReason::Fraud,
                    user_message: Some(
                        "This application version has been withdrawn. Please update.".to_string(),
                    ),
                })
            }
        },
    };

    let entitlements = resolve(catalog, &policy.entitlement, now).ok();
    let next_refresh_after = now.saturating_add(policy.runtime.refresh_after_secs);
    let not_after = policy
        .expires_at(now)
        .or(license.expires_at)
        .unwrap_or(copylocker_types::TimeWindow::UNLIMITED);

    Ok(ValidateOutcome::Ticket(Box::new(TicketPlan {
        verdict,
        next_refresh_after,
        not_after,
        revocation_epoch,
        security_floor,
        entitlements,
        release_status,
        // Ask for a prompt recheck when the client's revocation view is stale, so a revocation
        // propagates without waiting a whole refresh interval.
        refresh_now: input.known_revocation_epoch < revocation_epoch,
        variant_id,
    })))
}

/// Record a successful validation against the activation.
pub fn touch(license: &mut LicenseRecord, machine_id: &MachineId, plan: &TicketPlan, now: i64) {
    if let Some(a) = license.activation_mut(machine_id) {
        a.last_seen_at = Some(now);
        a.refresh_after = plan.next_refresh_after;
        a.not_after = plan.not_after;
        if let Some(v) = plan.variant_id {
            a.variant_id = Some(v);
        }
    }
}

/// Machine identifiers that a revocation batch should list for a licence.
#[must_use]
pub fn revoked_machines(license: &LicenseRecord) -> Vec<MachineId> {
    license
        .activations
        .iter()
        .filter(|a| a.status == ActivationStatus::Revoked)
        .map(|a| a.machine_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activate::{commit_seat, reserve_seat, ActivateInput, PATH_ONLINE};
    use crate::catalog::fixtures::sample;
    use crate::policy::Preset;
    use crate::store::LicenseRecord;
    use crate::version::{Release, ReleaseStatus};
    use copylocker_types::{Fingerprint, LicenseId};

    const NOW: i64 = 1_800_000_000;
    const MID: MachineId = MachineId([7; 16]);

    fn registry() -> ReleaseRegistry {
        ReleaseRegistry {
            releases: alloc::vec![Release {
                id: "rel_1".to_string(),
                product_id: "acme".to_string(),
                app_version: "1.0.0".to_string(),
                variant_id: 11,
                build_fingerprint: "bf1".to_string(),
                channel: "stable".to_string(),
                status: ReleaseStatus::Active,
                compromised_action: None,
                published_at: NOW - 86_400,
            }],
        }
    }

    fn policy() -> Policy {
        Preset::Perpetual.build("p", "acme", "pro", NOW)
    }

    /// A licence with one committed activation.
    fn activated() -> LicenseRecord {
        let mut lic = LicenseRecord {
            id: LicenseId([1; 16]),
            product_id: "acme".to_string(),
            policy_id: "p".to_string(),
            status: LicenseStatus::Active,
            seats_override: None,
            expires_at: None,
            revoked_at_epoch: None,
            activations: Vec::new(),
        };
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        reserve_seat(
            &mut lic,
            &policy(),
            &sample(),
            &registry(),
            &ActivateInput {
                fingerprint: &fp,
                attrs: None,
                device_kem_ek: &[1],
                device_sig_vk: &[2],
                release_id: "rel_1",
                activation_path: PATH_ONLINE,
                is_virtual_machine: false,
            },
            &VersionScope::Unlimited,
            MID,
            NOW,
        )
        .expect("activation must succeed");
        commit_seat(&mut lic, &MID).unwrap();
        lic
    }

    fn input<'a>() -> ValidateInput<'a> {
        ValidateInput {
            machine_id: MID,
            nonce_c: [9; 32],
            release_id: "rel_1",
            known_revocation_epoch: 5,
            known_security_floor: 2,
            proof_valid: true,
            nonce_fresh: true,
        }
    }

    fn run(
        lic: &LicenseRecord,
        inp: &ValidateInput<'_>,
        scope: &VersionScope,
    ) -> Result<ValidateOutcome, ClientFault> {
        validate(
            lic,
            &policy(),
            &sample(),
            &registry(),
            scope,
            inp,
            5,
            2,
            NOW,
        )
    }

    fn plan(o: ValidateOutcome) -> TicketPlan {
        match o {
            ValidateOutcome::Ticket(p) => *p,
            ValidateOutcome::Kill { .. } => unreachable!("expected a ticket"),
        }
    }

    #[test]
    fn a_healthy_activation_gets_an_ok_ticket() {
        let p = plan(run(&activated(), &input(), &VersionScope::Unlimited).unwrap());
        assert_eq!(p.verdict, Verdict::Ok);
        assert_eq!(p.variant_id, Some(11));
        assert_eq!(p.revocation_epoch, 5);
        assert!(!p.refresh_now);
        assert!(p.entitlements.is_some());
        assert_eq!(
            p.next_refresh_after,
            NOW + policy().runtime.refresh_after_secs
        );
    }

    #[test]
    fn a_replayed_nonce_is_rejected() {
        let inp = ValidateInput {
            nonce_fresh: false,
            ..input()
        };
        assert_eq!(
            run(&activated(), &inp, &VersionScope::Unlimited),
            Err(ClientFault::ReplayedNonce)
        );
    }

    #[test]
    fn an_invalid_device_proof_is_rejected() {
        // Without this check, knowing a machine_id would be enough to impersonate a device.
        let inp = ValidateInput {
            proof_valid: false,
            ..input()
        };
        assert_eq!(
            run(&activated(), &inp, &VersionScope::Unlimited),
            Err(ClientFault::ProofInvalid)
        );
    }

    #[test]
    fn both_credential_rejections_share_one_wire_code() {
        assert_eq!(
            ClientFault::ReplayedNonce.code(),
            ClientFault::ProofInvalid.code()
        );
    }

    #[test]
    fn a_client_claiming_a_future_revocation_epoch_is_rejected() {
        // Guards the monotonic counter: a client must not be able to assert it has seen more
        // than the server has issued.
        let inp = ValidateInput {
            known_revocation_epoch: 99,
            ..input()
        };
        assert_eq!(
            run(&activated(), &inp, &VersionScope::Unlimited),
            Err(ClientFault::RollbackAttempt)
        );
    }

    #[test]
    fn a_client_claiming_a_future_security_floor_is_rejected() {
        let inp = ValidateInput {
            known_security_floor: 99,
            ..input()
        };
        assert_eq!(
            run(&activated(), &inp, &VersionScope::Unlimited),
            Err(ClientFault::RollbackAttempt)
        );
    }

    #[test]
    fn a_stale_client_is_asked_to_refresh_promptly() {
        let inp = ValidateInput {
            known_revocation_epoch: 1,
            ..input()
        };
        let p = plan(run(&activated(), &inp, &VersionScope::Unlimited).unwrap());
        assert!(
            p.refresh_now,
            "a client behind on revocations should recheck soon"
        );
    }

    #[test]
    fn a_revoked_licence_produces_a_kill_order() {
        // The acceptance criterion: after revocation the next validate returns a KillOrder.
        let mut lic = activated();
        lic.status = LicenseStatus::Revoked;
        assert_eq!(
            run(&lic, &input(), &VersionScope::Unlimited).unwrap(),
            ValidateOutcome::Kill {
                reason: KillReason::RevokedLicense,
                user_message: Some(
                    "This licence has been revoked. Please contact support.".to_string()
                )
            }
        );
    }

    #[test]
    fn a_revoked_activation_produces_a_kill_order() {
        let mut lic = activated();
        lic.activation_mut(&MID).unwrap().status = ActivationStatus::Revoked;
        assert!(matches!(
            run(&lic, &input(), &VersionScope::Unlimited).unwrap(),
            ValidateOutcome::Kill {
                reason: KillReason::RevokedActivation,
                ..
            }
        ));
    }

    #[test]
    fn a_released_seat_produces_a_kill_order_naming_the_recovery() {
        let mut lic = activated();
        lic.activation_mut(&MID).unwrap().status = ActivationStatus::Released;
        let ValidateOutcome::Kill {
            reason,
            user_message,
        } = run(&lic, &input(), &VersionScope::Unlimited).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(reason, KillReason::SeatReclaimed);
        assert!(user_message.unwrap().contains("Activate again"));
    }

    #[test]
    fn an_unknown_activation_asks_for_reactivation_rather_than_killing() {
        // Destroying a credential is irreversible; a missing record may be a migration artefact.
        let inp = ValidateInput {
            machine_id: MachineId([0xaa; 16]),
            ..input()
        };
        assert_eq!(
            run(&activated(), &inp, &VersionScope::Unlimited),
            Err(ClientFault::NeedsReactivation)
        );
    }

    #[test]
    fn a_suspended_licence_stops_refreshing_without_killing() {
        // The existing credential runs out its own clock; a payment may be in flight.
        let mut lic = activated();
        lic.status = LicenseStatus::Suspended;
        assert_eq!(
            run(&lic, &input(), &VersionScope::Unlimited),
            Err(ClientFault::InvalidCredential)
        );
    }

    #[test]
    fn an_expired_licence_stops_refreshing() {
        let mut lic = activated();
        lic.expires_at = Some(NOW);
        assert_eq!(
            run(&lic, &input(), &VersionScope::Unlimited),
            Err(ClientFault::InvalidCredential)
        );
    }

    #[test]
    fn an_out_of_scope_release_yields_restricted_mode_not_a_kill() {
        // This is a paying customer running a newer build. It must never look like piracy.
        let p = plan(
            run(
                &activated(),
                &input(),
                &VersionScope::ReleasedBefore(NOW - 100_000),
            )
            .unwrap(),
        );
        assert_eq!(p.verdict, Verdict::VersionOutOfScope);
        assert_eq!(
            p.variant_id, None,
            "no keys are issued for a release outside the scope"
        );
    }

    #[test]
    fn an_unregistered_release_is_reported_actionably() {
        let inp = ValidateInput {
            release_id: "rel_ghost",
            ..input()
        };
        assert_eq!(
            run(&activated(), &inp, &VersionScope::Unlimited),
            Err(ClientFault::ReleaseNotRegistered {
                release_id: "rel_ghost".to_string()
            })
        );
    }

    #[test]
    fn compromise_actions_escalate_correctly() {
        let lic = activated();

        let mut warn = registry();
        warn.releases[0].status = ReleaseStatus::Compromised;
        warn.releases[0].compromised_action = Some(CompromisedAction::Warn);
        let p = plan(
            validate(
                &lic,
                &policy(),
                &sample(),
                &warn,
                &VersionScope::Unlimited,
                &input(),
                5,
                2,
                NOW,
            )
            .unwrap(),
        );
        assert_eq!(p.verdict, Verdict::Ok, "a warning keeps the user working");
        assert_eq!(p.release_status, Some(2));

        let mut force = warn.clone();
        force.releases[0].compromised_action = Some(CompromisedAction::ForceUpgrade);
        let p = plan(
            validate(
                &lic,
                &policy(),
                &sample(),
                &force,
                &VersionScope::Unlimited,
                &input(),
                5,
                2,
                NOW,
            )
            .unwrap(),
        );
        assert_eq!(p.verdict, Verdict::NeedsReactivation);
        assert_eq!(p.variant_id, None);

        let mut revoke = warn.clone();
        revoke.releases[0].compromised_action = Some(CompromisedAction::Revoke);
        assert!(matches!(
            validate(
                &lic,
                &policy(),
                &sample(),
                &revoke,
                &VersionScope::Unlimited,
                &input(),
                5,
                2,
                NOW,
            )
            .unwrap(),
            ValidateOutcome::Kill { .. }
        ));
    }

    #[test]
    fn touching_records_the_new_deadlines() {
        let mut lic = activated();
        let p = plan(run(&lic, &input(), &VersionScope::Unlimited).unwrap());
        touch(&mut lic, &MID, &p, NOW + 10);
        let a = lic.activation(&MID).unwrap();
        assert_eq!(a.last_seen_at, Some(NOW + 10));
        assert_eq!(a.refresh_after, p.next_refresh_after);
        assert_eq!(a.variant_id, Some(11));
    }

    #[test]
    fn touching_an_unknown_activation_is_a_no_op() {
        let mut lic = activated();
        let p = plan(run(&lic, &input(), &VersionScope::Unlimited).unwrap());
        let before = lic.clone();
        touch(&mut lic, &MachineId([0xff; 16]), &p, NOW);
        assert_eq!(lic, before);
    }

    #[test]
    fn revoked_machines_are_listed_for_the_revocation_batch() {
        let mut lic = activated();
        assert!(revoked_machines(&lic).is_empty());
        lic.activation_mut(&MID).unwrap().status = ActivationStatus::Revoked;
        assert_eq!(revoked_machines(&lic), alloc::vec![MID]);
    }
}
