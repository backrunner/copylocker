//! Administrative license and machine revocation.
//!
//! Revocation epochs are allocated by the global revocation log. A `LicenseDO` receives that
//! epoch and uses this module to reject stale state changes while allowing exact retries.

use copylocker_types::MachineId;

use crate::store::{ActivationStatus, LicenseRecord, LicenseStatus};

/// What an administrative revocation targets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RevokeTarget {
    /// Revoke the whole license while preserving machine state for a possible administrative
    /// undo during the recovery window.
    License,
    /// Revoke one activation.
    Machine(MachineId),
}

/// Why a revocation request cannot be applied.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RevokeError {
    /// No activation has the requested machine identifier.
    UnknownMachine,
    /// A new state change attempted to use a non-increasing or zero epoch.
    StaleEpoch,
}

/// Storage work required by a revocation request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RevokePlan {
    /// Whether the target's status must change to revoked.
    pub state_changed: bool,
    /// Whether the local view of the global revocation epoch must advance.
    pub epoch_changed: bool,
    /// The epoch that must remain after applying the plan.
    pub revocation_epoch: u64,
}

fn plan_for_state(
    already_revoked: bool,
    current_epoch: u64,
    requested_epoch: u64,
) -> Result<RevokePlan, RevokeError> {
    if requested_epoch == 0 {
        return Err(RevokeError::StaleEpoch);
    }
    if already_revoked {
        let revocation_epoch = current_epoch.max(requested_epoch);
        return Ok(RevokePlan {
            state_changed: false,
            epoch_changed: revocation_epoch != current_epoch,
            revocation_epoch,
        });
    }
    if requested_epoch <= current_epoch {
        return Err(RevokeError::StaleEpoch);
    }
    Ok(RevokePlan {
        state_changed: true,
        epoch_changed: true,
        revocation_epoch: requested_epoch,
    })
}

/// Plan a whole-license revocation.
pub fn plan_license(
    status: LicenseStatus,
    current_epoch: u64,
    requested_epoch: u64,
) -> Result<RevokePlan, RevokeError> {
    plan_for_state(
        status == LicenseStatus::Revoked,
        current_epoch,
        requested_epoch,
    )
}

/// Plan a single-machine revocation.
pub fn plan_machine(
    status: Option<ActivationStatus>,
    current_epoch: u64,
    requested_epoch: u64,
) -> Result<RevokePlan, RevokeError> {
    let Some(status) = status else {
        return Err(RevokeError::UnknownMachine);
    };
    plan_for_state(
        status == ActivationStatus::Revoked,
        current_epoch,
        requested_epoch,
    )
}

/// Apply a revocation to an in-memory license record.
pub fn revoke(
    license: &mut LicenseRecord,
    target: RevokeTarget,
    current_epoch: u64,
    requested_epoch: u64,
) -> Result<RevokePlan, RevokeError> {
    match target {
        RevokeTarget::License => {
            let plan = plan_license(license.status, current_epoch, requested_epoch)?;
            if plan.state_changed {
                license.status = LicenseStatus::Revoked;
                license.revoked_at_epoch = Some(plan.revocation_epoch);
            } else if license.revoked_at_epoch.is_none() {
                license.revoked_at_epoch = Some(plan.revocation_epoch);
            }
            Ok(plan)
        }
        RevokeTarget::Machine(machine_id) => {
            let status = license
                .activation(&machine_id)
                .map(|activation| activation.status);
            let plan = plan_machine(status, current_epoch, requested_epoch)?;
            if plan.state_changed {
                if let Some(activation) = license.activation_mut(&machine_id) {
                    activation.status = ActivationStatus::Revoked;
                }
            }
            Ok(plan)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_revocation_requires_a_strictly_new_epoch() {
        assert_eq!(
            plan_license(LicenseStatus::Active, 7, 7),
            Err(RevokeError::StaleEpoch)
        );
        assert_eq!(
            plan_machine(Some(ActivationStatus::Active), 7, 6),
            Err(RevokeError::StaleEpoch)
        );
        assert_eq!(
            plan_license(LicenseStatus::Active, 0, 0),
            Err(RevokeError::StaleEpoch)
        );
    }

    #[test]
    fn an_exact_retry_is_idempotent() {
        assert_eq!(
            plan_machine(Some(ActivationStatus::Revoked), 8, 8),
            Ok(RevokePlan {
                state_changed: false,
                epoch_changed: false,
                revocation_epoch: 8,
            })
        );
        assert_eq!(
            plan_license(LicenseStatus::Revoked, 9, 8),
            Ok(RevokePlan {
                state_changed: false,
                epoch_changed: false,
                revocation_epoch: 9,
            })
        );
    }

    #[test]
    fn an_already_revoked_target_can_advance_the_local_epoch_view() {
        assert_eq!(
            plan_license(LicenseStatus::Revoked, 8, 10),
            Ok(RevokePlan {
                state_changed: false,
                epoch_changed: true,
                revocation_epoch: 10,
            })
        );
    }

    #[test]
    fn an_unknown_machine_is_not_a_revocation() {
        assert_eq!(plan_machine(None, 1, 2), Err(RevokeError::UnknownMachine));
    }
}
