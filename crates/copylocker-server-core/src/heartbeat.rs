//! Heartbeat state transitions and zombie-seat recovery.

use copylocker_types::MachineId;

use crate::policy::Policy;
use crate::store::{ActivationStatus, LicenseRecord, LicenseStatus};
use crate::ClientFault;

/// Number of missed heartbeat intervals tolerated before a seat is reclaimed.
pub const HEARTBEAT_GRACE_MULTIPLIER: i64 = 3;

/// Result of an accepted heartbeat.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HeartbeatPlan {
    /// When the client should send its next heartbeat.
    pub next_after: i64,
}

/// Decide whether a heartbeat may update the activation.
pub fn plan(
    license_status: LicenseStatus,
    license_expires_at: Option<i64>,
    activation_status: ActivationStatus,
    heartbeat_secs: Option<i64>,
    now: i64,
) -> Result<HeartbeatPlan, ClientFault> {
    if license_status != LicenseStatus::Active
        || license_expires_at.is_some_and(|expires_at| now >= expires_at)
        || activation_status != ActivationStatus::Active
    {
        return Err(ClientFault::InvalidCredential);
    }
    let interval = heartbeat_secs.filter(|value| *value > 0).unwrap_or(0);
    Ok(HeartbeatPlan {
        next_after: now.saturating_add(interval),
    })
}

/// Record a successful heartbeat in an in-memory license record.
pub fn heartbeat(
    license: &mut LicenseRecord,
    policy: &Policy,
    machine_id: &MachineId,
    now: i64,
) -> Result<HeartbeatPlan, ClientFault> {
    let Some(status) = license
        .activation(machine_id)
        .map(|activation| activation.status)
    else {
        return Err(ClientFault::InvalidCredential);
    };
    let plan = plan(
        license.status,
        license.expires_at,
        status,
        policy.seats.heartbeat_secs,
        now,
    )?;
    if let Some(activation) = license.activation_mut(machine_id) {
        activation.last_seen_at = Some(now);
    }
    Ok(plan)
}

/// Compute the last-seen cutoff before which an active seat is a zombie.
#[must_use]
pub fn zombie_cutoff(heartbeat_secs: i64, now: i64) -> Option<i64> {
    (heartbeat_secs > 0)
        .then(|| now.saturating_sub(heartbeat_secs.saturating_mul(HEARTBEAT_GRACE_MULTIPLIER)))
}

/// Reclaim seats whose heartbeat has lapsed.
pub fn reclaim_zombies(license: &mut LicenseRecord, policy: &Policy, now: i64) -> usize {
    let Some(heartbeat_secs) = policy.seats.heartbeat_secs else {
        return 0;
    };
    let Some(cutoff) = zombie_cutoff(heartbeat_secs, now) else {
        return 0;
    };
    let mut freed = 0;
    for activation in &mut license.activations {
        if activation.status != ActivationStatus::Active {
            continue;
        }
        let last_seen = activation.last_seen_at.unwrap_or(activation.created_at);
        if last_seen < cutoff {
            activation.status = ActivationStatus::Released;
            freed += 1;
        }
    }
    freed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_requires_an_active_license_and_activation() {
        assert_eq!(
            plan(
                LicenseStatus::Active,
                None,
                ActivationStatus::Active,
                Some(60),
                100,
            ),
            Ok(HeartbeatPlan { next_after: 160 })
        );
        for license_status in [
            LicenseStatus::Suspended,
            LicenseStatus::Expired,
            LicenseStatus::Revoked,
        ] {
            assert_eq!(
                plan(
                    license_status,
                    None,
                    ActivationStatus::Active,
                    Some(60),
                    100,
                ),
                Err(ClientFault::InvalidCredential)
            );
        }
        assert_eq!(
            plan(
                LicenseStatus::Active,
                Some(100),
                ActivationStatus::Active,
                Some(60),
                100,
            ),
            Err(ClientFault::InvalidCredential)
        );
        assert_eq!(
            plan(
                LicenseStatus::Active,
                None,
                ActivationStatus::Released,
                Some(60),
                100,
            ),
            Err(ClientFault::InvalidCredential)
        );
    }

    #[test]
    fn zombie_cutoff_uses_three_intervals_and_disables_non_positive_values() {
        assert_eq!(zombie_cutoff(60, 1_000), Some(820));
        assert_eq!(zombie_cutoff(0, 1_000), None);
        assert_eq!(zombie_cutoff(-1, 1_000), None);
    }
}
