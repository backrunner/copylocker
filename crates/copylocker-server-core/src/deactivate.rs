//! Device-initiated seat release.
//!
//! The transition is split into a decision and an in-memory mutation so platform adapters can
//! apply exactly the same rule to their own durable representation.

use copylocker_types::MachineId;

use crate::store::{ActivationStatus, LicenseRecord};
use crate::ClientFault;

/// Storage work required by a deactivation request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeactivatePlan {
    /// Whether the activation changes from a seat-holding state to released.
    pub changed: bool,
    /// Whether this release counts as a machine transfer.
    pub record_transfer: bool,
}

/// Decide a deactivation transition from the activation's current state.
pub const fn plan(status: ActivationStatus) -> Result<DeactivatePlan, ClientFault> {
    match status {
        ActivationStatus::Active | ActivationStatus::Pending => Ok(DeactivatePlan {
            changed: true,
            record_transfer: true,
        }),
        ActivationStatus::Released => Ok(DeactivatePlan {
            changed: false,
            record_transfer: false,
        }),
        ActivationStatus::Revoked => Err(ClientFault::InvalidCredential),
    }
}

/// Release a seat at the user's request.
///
/// Repeating a successful deactivation is idempotent and does not consume another transfer.
pub fn deactivate(
    license: &mut LicenseRecord,
    machine_id: &MachineId,
) -> Result<DeactivatePlan, ClientFault> {
    let Some(activation) = license.activation_mut(machine_id) else {
        return Err(ClientFault::InvalidCredential);
    };
    let plan = plan(activation.status)?;
    if plan.changed {
        activation.status = ActivationStatus::Released;
        if plan.record_transfer {
            activation.transfer_count = activation.transfer_count.saturating_add(1);
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_and_pending_activations_release_once() {
        for status in [ActivationStatus::Active, ActivationStatus::Pending] {
            assert_eq!(
                plan(status),
                Ok(DeactivatePlan {
                    changed: true,
                    record_transfer: true,
                })
            );
        }
        assert_eq!(
            plan(ActivationStatus::Released),
            Ok(DeactivatePlan {
                changed: false,
                record_transfer: false,
            })
        );
    }

    #[test]
    fn revoked_activations_cannot_be_released() {
        assert_eq!(
            plan(ActivationStatus::Revoked),
            Err(ClientFault::InvalidCredential)
        );
    }
}
