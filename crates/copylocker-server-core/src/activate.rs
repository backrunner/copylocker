//! Activation (`system-architecture.md §4`).
//!
//! # Two-phase seat reservation
//!
//! Signing a credential is the slow part, and it can fail. Reserving the seat *after* signing
//! would let two concurrent requests both pass the seat check; reserving before and never
//! releasing on failure would leak seats until support intervened. So:
//!
//! ```text
//! Phase 1 (durable object): insert activation as PENDING, arm a 60-second reclaim alarm
//! Phase 2 (worker):         sign the credential
//! Phase 3 (durable object): commit -> ACTIVE
//! failure:                  never commit; the alarm reclaims the seat
//! ```
//!
//! [`reserve_seat`] is phase one and [`commit_seat`] is phase three. Both are pure functions
//! over a [`LicenseRecord`], so the hundred-way concurrent race in the acceptance criteria can
//! be exercised without a network.

use alloc::string::ToString;
use alloc::vec::Vec;

use copylocker_suite::device::{DeviceAttrs, FingerprintScheme};
use copylocker_types::{Fingerprint, MachineId, Mode, VersionScope};

use crate::entitlement::resolve;
use crate::fingerprint_match::{best_match, MatchOutcome};
use crate::policy::Policy;
use crate::store::{ActivationRecord, ActivationStatus, LicenseRecord, LicenseStatus};
use crate::version::{decide, CompromisedAction, ReleaseRegistry, VersionDecision};
use crate::{Catalog, ClientFault};

/// How long a pending reservation is held before the alarm reclaims it.
pub const PENDING_TTL_SECS: i64 = 60;

/// What a caller must supply to activate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ActivateInput<'a> {
    /// Device fingerprint digest.
    pub fingerprint: &'a Fingerprint,
    /// Normalised attributes, present only when the policy permits reporting them.
    pub attrs: Option<&'a DeviceAttrs>,
    /// Device KEM encapsulation key.
    pub device_kem_ek: &'a [u8],
    /// Device signature verifying key.
    pub device_sig_vk: &'a [u8],
    /// Release the client reports.
    pub release_id: &'a str,
    /// How the activation is happening: `online`, `offline_ar`, `olk`, or `account`.
    pub activation_path: &'a str,
    /// Whether the device reports running in a virtual machine.
    pub is_virtual_machine: bool,
}

/// A successful seat reservation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reservation {
    /// The activation identifier assigned or reused.
    pub machine_id: MachineId,
    /// Whether an existing activation was reused rather than a new seat taken.
    pub reused_existing: bool,
    /// Why, when it was reused.
    pub match_outcome: Option<MatchOutcome>,
    /// The variant whose keys should be issued.
    pub variant_id: u64,
    /// When the client must next validate.
    pub refresh_after: i64,
    /// Hard expiry, `0` meaning unlimited.
    pub not_after: i64,
    /// The resolved entitlement snapshot to sign into the credential.
    pub entitlements: copylocker_types::Entitlements,
}

/// Reserve a seat: phase one of the two-phase protocol.
///
/// Mutates `license` in place, leaving a `Pending` activation. The caller signs the credential
/// and then calls [`commit_seat`]. If signing fails, the caller does nothing and the
/// reservation expires.
///
/// `new_machine_id` is supplied rather than generated here so that this function stays pure and
/// the randomness source remains an explicit, auditable choice.
#[allow(clippy::too_many_arguments)] // Domain inputs stay explicit at this security boundary.
pub fn reserve_seat(
    license: &mut LicenseRecord,
    policy: &Policy,
    catalog: &Catalog,
    registry: &ReleaseRegistry,
    input: &ActivateInput<'_>,
    version_scope: &VersionScope,
    new_machine_id: MachineId,
    now: i64,
) -> Result<Reservation, ClientFault> {
    // Administrative state first: a revoked licence must not reveal anything further.
    match license.status {
        LicenseStatus::Active => {}
        LicenseStatus::Suspended | LicenseStatus::Expired | LicenseStatus::Revoked => {
            return Err(ClientFault::InvalidCredential);
        }
    }
    if license.expires_at.is_some_and(|e| now >= e) {
        return Err(ClientFault::InvalidCredential);
    }

    if input.is_virtual_machine && !policy.runtime.allow_vm {
        return Err(ClientFault::VirtualMachineNotAllowed);
    }

    // The release must be registered and in scope before a seat is spent on it.
    let variant_id = match decide(registry, version_scope, input.release_id) {
        VersionDecision::InScope { variant_id } => variant_id,
        VersionDecision::NotRegistered => {
            return Err(ClientFault::ReleaseNotRegistered {
                release_id: input.release_id.to_string(),
            })
        }
        VersionDecision::OutOfScope { highest_allowed } => {
            return Err(ClientFault::VersionOutOfScope { highest_allowed })
        }
        VersionDecision::Compromised { action } => {
            // A warning must not block activation; the client is told and carries on.
            if action == CompromisedAction::Warn {
                registry
                    .get(input.release_id)
                    .map(|r| r.variant_id)
                    .unwrap_or_default()
            } else {
                return Err(ClientFault::ReleaseCompromised {
                    action: action.as_str().to_string(),
                });
            }
        }
    };

    let entitlements = resolve(catalog, &policy.entitlement, now).map_err(|_| {
        // A broken catalog is an operator problem, but at this layer the only honest thing to
        // report to the client is that the credential is not usable right now.
        ClientFault::InvalidCredential
    })?;

    let seats = license.seats_override.unwrap_or(policy.seats.seats);
    let refresh_after = now.saturating_add(policy.runtime.refresh_after_secs);
    let not_after = policy
        .expires_at(now)
        .or(license.expires_at)
        .unwrap_or(copylocker_types::TimeWindow::UNLIMITED);

    // Reuse an existing activation when this is the same device coming back.
    let candidates: Vec<(&Fingerprint, Option<&DeviceAttrs>)> = license
        .activations
        .iter()
        .filter(|a| a.status == ActivationStatus::Active)
        .map(|a| (&a.fingerprint, a.attrs.as_ref()))
        .collect();

    let matched = best_match::<CatalogFpr, _>(
        candidates,
        input.fingerprint,
        input.attrs,
        policy.runtime.fpr_tolerance,
    );

    if let Some((idx, ref outcome)) = matched {
        if outcome.reuses_seat() {
            let active: Vec<MachineId> = license
                .activations
                .iter()
                .filter(|a| a.status == ActivationStatus::Active)
                .map(|a| a.machine_id)
                .collect();
            // `best_match` indexes into the same filtered sequence built above.
            let Some(mid) = active.get(idx).copied() else {
                return Err(ClientFault::InvalidCredential);
            };
            let Some(rec) = license.activation_mut(&mid) else {
                return Err(ClientFault::InvalidCredential);
            };
            // Adapt to gradual hardware change so the device keeps matching next time.
            rec.fingerprint = input.fingerprint.clone();
            if input.attrs.is_some() {
                rec.attrs = input.attrs.cloned();
            }
            rec.device_kem_ek = input.device_kem_ek.to_vec();
            rec.device_sig_vk = input.device_sig_vk.to_vec();
            rec.release_id = Some(input.release_id.to_string());
            rec.variant_id = Some(variant_id);
            rec.refresh_after = refresh_after;
            rec.not_after = not_after;
            rec.last_seen_at = Some(now);
            // A tolerance match can require a credential reissue, but hardware drift is not a
            // machine transfer and therefore leaves `transfer_count` unchanged.
            return Ok(Reservation {
                machine_id: mid,
                reused_existing: true,
                match_outcome: Some(outcome.clone()),
                variant_id,
                refresh_after,
                not_after,
                entitlements,
            });
        }
    }

    // A genuinely new device needs a free seat.
    if license.occupied_seats() >= seats {
        return Err(ClientFault::SeatExhausted);
    }

    license.activations.push(ActivationRecord {
        machine_id: new_machine_id,
        fingerprint: input.fingerprint.clone(),
        attrs: input.attrs.cloned(),
        device_kem_ek: input.device_kem_ek.to_vec(),
        device_sig_vk: input.device_sig_vk.to_vec(),
        status: ActivationStatus::Pending,
        activation_path: input.activation_path.to_string(),
        release_id: Some(input.release_id.to_string()),
        variant_id: Some(variant_id),
        created_at: now,
        last_seen_at: Some(now),
        refresh_after,
        not_after,
        transfer_count: 0,
    });

    Ok(Reservation {
        machine_id: new_machine_id,
        reused_existing: false,
        match_outcome: matched.map(|(_, o)| o),
        variant_id,
        refresh_after,
        not_after,
        entitlements,
    })
}

/// Commit a reservation: phase three.
///
/// Idempotent, because the worker may retry after a transient failure between signing and
/// commit.
pub fn commit_seat(license: &mut LicenseRecord, machine_id: &MachineId) -> Result<(), ClientFault> {
    let Some(rec) = license.activation_mut(machine_id) else {
        return Err(ClientFault::InvalidCredential);
    };
    match rec.status {
        ActivationStatus::Pending | ActivationStatus::Active => {
            rec.status = ActivationStatus::Active;
            Ok(())
        }
        ActivationStatus::Released | ActivationStatus::Revoked => {
            Err(ClientFault::InvalidCredential)
        }
    }
}

/// Reclaim reservations that were never committed.
///
/// Driven by the durable object's alarm. Returns how many seats were freed.
pub fn reclaim_pending(license: &mut LicenseRecord, now: i64) -> usize {
    let mut freed = 0;
    for a in &mut license.activations {
        if a.status == ActivationStatus::Pending
            && now.saturating_sub(a.created_at) >= PENDING_TTL_SECS
        {
            a.status = ActivationStatus::Released;
            freed += 1;
        }
    }
    freed
}

/// Whether the policy's mode requires a live session.
#[must_use]
pub const fn requires_live_session(policy: &Policy) -> bool {
    matches!(policy.mode, Mode::EnforcedOnline)
}

/// The fingerprint scheme used for tolerance matching.
///
/// Aliased so this module stays independent of which suite is compiled in; the worker
/// substitutes the configured suite's scheme.
type CatalogFpr = DefaultFpr;

/// Default fingerprint comparison, used when no suite-specific scheme is injected.
///
/// Digest computation is never performed here — the server compares what the client reported.
/// Only [`FingerprintScheme::similarity`] is exercised.
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultFpr;

impl FingerprintScheme for DefaultFpr {
    fn compute(_salt: &[u8], _attrs: &DeviceAttrs) -> Fingerprint {
        // The server never recomputes a digest during matching; it compares reported values.
        // Returning an empty fingerprint makes accidental use obvious rather than subtly wrong.
        Fingerprint::from_vec(Vec::new())
    }

    fn similarity(a: &DeviceAttrs, b: &DeviceAttrs) -> u8 {
        let mut total: u32 = 0;
        let mut matched: u32 = 0;
        for (key, weight) in Self::weights() {
            match (a.get_present(key), b.get_present(key)) {
                (None, None) => continue,
                (Some(x), Some(y)) => {
                    total += u32::from(*weight);
                    if x == y {
                        matched += u32::from(*weight);
                    }
                }
                _ => total += u32::from(*weight),
            }
        }
        if total == 0 {
            return 0;
        }
        u8::try_from(matched * 100 / total).unwrap_or(100)
    }

    fn weights() -> &'static [(&'static str, u8)] {
        &[
            ("machine_guid", 40),
            ("cpu_id", 15),
            ("board_serial", 15),
            ("disk_serial", 10),
            ("os_install_id", 10),
            ("platform_uuid", 45),
            ("hw_model_serial", 20),
            ("boot_volume_uuid", 15),
            ("machine_id", 40),
            ("dmi_product_uuid", 20),
            ("rootfs_uuid", 15),
            ("web_device_id", 60),
            ("ua_platform", 15),
            ("hardware_concurrency", 10),
            ("mac_addrs", 10),
            ("hostname", 5),
            ("timezone", 5),
        ]
    }
}

/// The empty string, exposed so callers can name the default activation path.
pub const PATH_ONLINE: &str = "online";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::fixtures::sample;
    use crate::deactivate::deactivate;
    use crate::heartbeat::reclaim_zombies;
    use crate::policy::Preset;
    use crate::version::{Release, ReleaseStatus};
    use copylocker_suite::device::AttrValue;
    use copylocker_types::LicenseId;

    const NOW: i64 = 1_800_000_000;

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

    fn license(seats: u32) -> LicenseRecord {
        let _ = seats;
        LicenseRecord {
            id: LicenseId([1; 16]),
            product_id: "acme".to_string(),
            policy_id: "p".to_string(),
            status: LicenseStatus::Active,
            seats_override: None,
            expires_at: None,
            revoked_at_epoch: None,
            activations: Vec::new(),
        }
    }

    fn policy(seats: u32) -> Policy {
        let mut p = Preset::Perpetual.build("p", "acme", "pro", NOW);
        p.seats.seats = seats;
        p.runtime.report_attrs = true;
        p
    }

    fn attrs(guid: &str, mac: &str) -> DeviceAttrs {
        let mut a = DeviceAttrs::new();
        a.insert("machine_guid", AttrValue::text(guid));
        a.insert("cpu_id", AttrValue::text("CPU-1"));
        a.insert("board_serial", AttrValue::text("BS-1"));
        a.insert("disk_serial", AttrValue::text("DS-1"));
        a.insert("os_install_id", AttrValue::text("2024-01-01"));
        a.insert("mac_addrs", AttrValue::set([mac]));
        a.insert("hostname", AttrValue::text("host"));
        a
    }

    fn input<'a>(fp: &'a Fingerprint, at: Option<&'a DeviceAttrs>) -> ActivateInput<'a> {
        ActivateInput {
            fingerprint: fp,
            attrs: at,
            device_kem_ek: &[1, 2, 3],
            device_sig_vk: &[4, 5, 6],
            release_id: "rel_1",
            activation_path: PATH_ONLINE,
            is_virtual_machine: false,
        }
    }

    fn reserve(
        lic: &mut LicenseRecord,
        pol: &Policy,
        fp: &Fingerprint,
        at: Option<&DeviceAttrs>,
        mid: u8,
    ) -> Result<Reservation, ClientFault> {
        reserve_seat(
            lic,
            pol,
            &sample(),
            &registry(),
            &input(fp, at),
            &VersionScope::Unlimited,
            MachineId([mid; 16]),
            NOW,
        )
    }

    #[test]
    fn a_first_activation_takes_a_seat_and_stays_pending() {
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r = reserve(&mut lic, &policy(1), &fp, None, 9).unwrap();
        assert!(!r.reused_existing);
        assert_eq!(r.variant_id, 11);
        assert_eq!(lic.occupied_seats(), 1);
        assert_eq!(
            lic.activation(&r.machine_id).unwrap().status,
            ActivationStatus::Pending,
            "the seat must not be Active until the credential is signed"
        );
    }

    #[test]
    fn committing_makes_the_activation_active_and_is_idempotent() {
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r = reserve(&mut lic, &policy(1), &fp, None, 9).unwrap();
        commit_seat(&mut lic, &r.machine_id).unwrap();
        assert_eq!(
            lic.activation(&r.machine_id).unwrap().status,
            ActivationStatus::Active
        );
        commit_seat(&mut lic, &r.machine_id).unwrap();
        assert_eq!(lic.occupied_seats(), 1);
    }

    #[test]
    fn a_pending_reservation_blocks_a_concurrent_request() {
        // Without this, two requests racing on a one-seat licence would both succeed.
        let mut lic = license(1);
        let a = Fingerprint::from_vec(alloc::vec![1; 32]);
        let b = Fingerprint::from_vec(alloc::vec![2; 32]);
        reserve(&mut lic, &policy(1), &a, None, 1).unwrap();
        assert_eq!(
            reserve(&mut lic, &policy(1), &b, None, 2),
            Err(ClientFault::SeatExhausted)
        );
    }

    #[test]
    fn a_hundred_concurrent_activations_fill_exactly_three_seats() {
        // The acceptance criterion from `roadmap.md` M1.
        let pol = policy(3);
        let mut lic = license(3);
        let mut granted = 0;
        for i in 0..100u8 {
            let fp = Fingerprint::from_vec(alloc::vec![i; 32]);
            if reserve(&mut lic, &pol, &fp, None, i).is_ok() {
                granted += 1;
            }
        }
        assert_eq!(granted, 3);
        assert_eq!(lic.occupied_seats(), 3);
    }

    #[test]
    fn an_uncommitted_reservation_is_reclaimed_after_the_ttl() {
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        reserve(&mut lic, &policy(1), &fp, None, 1).unwrap();
        assert_eq!(reclaim_pending(&mut lic, NOW + PENDING_TTL_SECS - 1), 0);
        assert_eq!(lic.occupied_seats(), 1);
        assert_eq!(reclaim_pending(&mut lic, NOW + PENDING_TTL_SECS), 1);
        assert_eq!(lic.occupied_seats(), 0, "the seat must come back");
    }

    #[test]
    fn a_committed_activation_is_never_reclaimed_as_pending() {
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r = reserve(&mut lic, &policy(1), &fp, None, 1).unwrap();
        commit_seat(&mut lic, &r.machine_id).unwrap();
        assert_eq!(reclaim_pending(&mut lic, NOW + 10_000), 0);
        assert_eq!(lic.occupied_seats(), 1);
    }

    #[test]
    fn the_same_device_returning_reuses_its_seat() {
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r1 = reserve(&mut lic, &policy(1), &fp, None, 1).unwrap();
        commit_seat(&mut lic, &r1.machine_id).unwrap();

        let r2 = reserve(&mut lic, &policy(1), &fp, None, 2).unwrap();
        assert!(r2.reused_existing);
        assert_eq!(r2.machine_id, r1.machine_id);
        assert_eq!(lic.occupied_seats(), 1);
    }

    #[test]
    fn hardware_drift_reuses_the_seat_and_rebinds_the_fingerprint() {
        let pol = policy(1);
        let mut lic = license(1);
        let old_attrs = attrs("G1", "aa:bb");
        let fp_old = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r1 = reserve(&mut lic, &pol, &fp_old, Some(&old_attrs), 1).unwrap();
        commit_seat(&mut lic, &r1.machine_id).unwrap();

        let new_attrs = attrs("G1", "ee:ff");
        let fp_new = Fingerprint::from_vec(alloc::vec![2; 32]);
        let r2 = reserve(&mut lic, &pol, &fp_new, Some(&new_attrs), 2).unwrap();

        assert!(r2.reused_existing);
        assert!(r2.match_outcome.unwrap().requires_reissue());
        assert_eq!(lic.occupied_seats(), 1);
        let rec = lic.activation(&r1.machine_id).unwrap();
        assert_eq!(
            rec.fingerprint, fp_new,
            "the record must adapt to the drift"
        );
        assert_eq!(rec.attrs.as_ref(), Some(&new_attrs));
    }

    #[test]
    fn without_reported_attributes_a_drifted_device_needs_a_new_seat() {
        // The documented cost of `report_attrs = false`.
        let mut pol = policy(1);
        pol.runtime.report_attrs = false;
        let mut lic = license(1);
        let fp_old = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r1 = reserve(&mut lic, &pol, &fp_old, None, 1).unwrap();
        commit_seat(&mut lic, &r1.machine_id).unwrap();

        let fp_new = Fingerprint::from_vec(alloc::vec![2; 32]);
        assert_eq!(
            reserve(&mut lic, &pol, &fp_new, None, 2),
            Err(ClientFault::SeatExhausted)
        );
    }

    #[test]
    fn deactivating_frees_the_seat_for_someone_else() {
        let pol = policy(1);
        let mut lic = license(1);
        let a = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r = reserve(&mut lic, &pol, &a, None, 1).unwrap();
        commit_seat(&mut lic, &r.machine_id).unwrap();
        deactivate(&mut lic, &r.machine_id).unwrap();
        assert_eq!(lic.occupied_seats(), 0);

        let b = Fingerprint::from_vec(alloc::vec![2; 32]);
        assert!(reserve(&mut lic, &pol, &b, None, 2).is_ok());
    }

    #[test]
    fn deactivating_an_unknown_or_revoked_activation_fails() {
        let mut lic = license(1);
        assert_eq!(
            deactivate(&mut lic, &MachineId([9; 16])),
            Err(ClientFault::InvalidCredential)
        );

        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r = reserve(&mut lic, &policy(1), &fp, None, 1).unwrap();
        lic.activation_mut(&r.machine_id).unwrap().status = ActivationStatus::Revoked;
        assert_eq!(
            deactivate(&mut lic, &r.machine_id),
            Err(ClientFault::InvalidCredential)
        );
    }

    #[test]
    fn revoked_suspended_and_expired_licences_all_fail_identically() {
        // Anti-enumeration: the client cannot tell which administrative state applies.
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        for status in [
            LicenseStatus::Revoked,
            LicenseStatus::Suspended,
            LicenseStatus::Expired,
        ] {
            let mut lic = license(1);
            lic.status = status;
            assert_eq!(
                reserve(&mut lic, &policy(1), &fp, None, 1),
                Err(ClientFault::InvalidCredential),
                "{status:?} must be indistinguishable"
            );
        }
        let mut expired = license(1);
        expired.expires_at = Some(NOW);
        assert_eq!(
            reserve(&mut expired, &policy(1), &fp, None, 1),
            Err(ClientFault::InvalidCredential)
        );
    }

    #[test]
    fn an_unregistered_release_is_reported_distinctly_from_a_bad_credential() {
        // A release-engineering mistake deserves an actionable error, not "invalid licence".
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let err = reserve_seat(
            &mut lic,
            &policy(1),
            &sample(),
            &registry(),
            &ActivateInput {
                release_id: "rel_ghost",
                ..input(&fp, None)
            },
            &VersionScope::Unlimited,
            MachineId([1; 16]),
            NOW,
        );
        assert_eq!(
            err,
            Err(ClientFault::ReleaseNotRegistered {
                release_id: "rel_ghost".to_string()
            })
        );
        assert_eq!(lic.occupied_seats(), 0, "a failed activation costs no seat");
    }

    #[test]
    fn an_out_of_scope_release_does_not_consume_a_seat() {
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let err = reserve_seat(
            &mut lic,
            &policy(1),
            &sample(),
            &registry(),
            &input(&fp, None),
            &VersionScope::ReleasedBefore(NOW - 100_000),
            MachineId([1; 16]),
            NOW,
        );
        assert!(matches!(err, Err(ClientFault::VersionOutOfScope { .. })));
        assert_eq!(lic.occupied_seats(), 0);
    }

    #[test]
    fn a_warn_level_compromise_still_activates() {
        let mut reg = registry();
        reg.releases[0].status = ReleaseStatus::Compromised;
        reg.releases[0].compromised_action = Some(CompromisedAction::Warn);
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r = reserve_seat(
            &mut lic,
            &policy(1),
            &sample(),
            &reg,
            &input(&fp, None),
            &VersionScope::Unlimited,
            MachineId([1; 16]),
            NOW,
        );
        assert!(r.is_ok(), "a warning must not block the user");
    }

    #[test]
    fn a_force_upgrade_compromise_blocks_activation() {
        let mut reg = registry();
        reg.releases[0].status = ReleaseStatus::Compromised;
        reg.releases[0].compromised_action = Some(CompromisedAction::Revoke);
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r = reserve_seat(
            &mut lic,
            &policy(1),
            &sample(),
            &reg,
            &input(&fp, None),
            &VersionScope::Unlimited,
            MachineId([1; 16]),
            NOW,
        );
        assert!(matches!(r, Err(ClientFault::ReleaseCompromised { .. })));
    }

    #[test]
    fn a_virtual_machine_is_refused_when_the_policy_forbids_it() {
        let mut pol = policy(1);
        pol.runtime.allow_vm = false;
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r = reserve_seat(
            &mut lic,
            &pol,
            &sample(),
            &registry(),
            &ActivateInput {
                is_virtual_machine: true,
                ..input(&fp, None)
            },
            &VersionScope::Unlimited,
            MachineId([1; 16]),
            NOW,
        );
        assert_eq!(r, Err(ClientFault::VirtualMachineNotAllowed));
        // And permitted by default.
        assert!(reserve_seat(
            &mut license(1),
            &policy(1),
            &sample(),
            &registry(),
            &ActivateInput {
                is_virtual_machine: true,
                ..input(&fp, None)
            },
            &VersionScope::Unlimited,
            MachineId([1; 16]),
            NOW,
        )
        .is_ok());
    }

    #[test]
    fn the_reservation_carries_the_resolved_entitlements() {
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r = reserve(&mut lic, &policy(1), &fp, None, 1).unwrap();
        assert_eq!(r.entitlements.tier_id, "pro");
        assert!(r.entitlements.has_feature("ai.assist"));
    }

    #[test]
    fn zombie_seats_are_reclaimed_only_when_heartbeats_are_configured() {
        let mut pol = policy(1);
        let mut lic = license(1);
        let fp = Fingerprint::from_vec(alloc::vec![1; 32]);
        let r = reserve(&mut lic, &pol, &fp, None, 1).unwrap();
        commit_seat(&mut lic, &r.machine_id).unwrap();

        // No heartbeat configured: nothing is ever reclaimed.
        assert_eq!(reclaim_zombies(&mut lic, &pol, NOW + 10 * 86_400), 0);

        pol.seats.heartbeat_secs = Some(3_600);
        // A weekend offline must not cost the seat: the deadline is three intervals.
        assert_eq!(reclaim_zombies(&mut lic, &pol, NOW + 3 * 3_600), 0);
        assert_eq!(reclaim_zombies(&mut lic, &pol, NOW + 3 * 3_600 + 1), 1);
        assert_eq!(lic.occupied_seats(), 0);
    }

    #[test]
    fn a_seat_override_beats_the_policy_seat_count() {
        let mut lic = license(1);
        lic.seats_override = Some(2);
        let pol = policy(1);
        let a = Fingerprint::from_vec(alloc::vec![1; 32]);
        let b = Fingerprint::from_vec(alloc::vec![2; 32]);
        assert!(reserve(&mut lic, &pol, &a, None, 1).is_ok());
        assert!(reserve(&mut lic, &pol, &b, None, 2).is_ok());
        assert_eq!(lic.occupied_seats(), 2);
    }

    #[test]
    fn enforced_online_mode_is_reported() {
        assert!(!requires_live_session(&policy(1)));
        let mut p = policy(1);
        p.mode = Mode::EnforcedOnline;
        assert!(requires_live_session(&p));
    }
}
