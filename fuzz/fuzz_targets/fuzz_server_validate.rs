#![no_main]

mod support;

use copylocker_server_core::store::{ActivationStatus, LicenseStatus};
use copylocker_server_core::validate::{validate, ValidateInput};
use copylocker_server_core::version::{CompromisedAction, ReleaseStatus};
use copylocker_types::{MachineId, VersionScope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(_) = data.first() else {
        return;
    };
    let catalog = support::catalog();

    for (index, chunk) in data.chunks(9).take(1_024).enumerate() {
        let mut policy = support::policy(u32::from(value(chunk, 0) % 8 + 1));
        policy.runtime.refresh_after_secs = i64::from(value(chunk, 1) as i8);
        let release_status = match value(chunk, 2) % 3 {
            0 => ReleaseStatus::Active,
            1 => ReleaseStatus::Deprecated,
            _ => ReleaseStatus::Compromised,
        };
        let action = match value(chunk, 3) % 3 {
            0 => CompromisedAction::Warn,
            1 => CompromisedAction::ForceUpgrade,
            _ => CompromisedAction::Revoke,
        };
        let registry = support::registry(release_status, Some(action));
        let mut license = support::activated_license();
        license.status = license_status(value(chunk, 4));
        license.expires_at = (value(chunk, 5) & 1 != 0).then_some(support::NOW);
        if let Some(activation) = license.activations.first_mut() {
            activation.status = activation_status(value(chunk, 6));
        }

        let revocation_epoch = u64::from(value(chunk, 7));
        let security_floor = u64::from(value(chunk, 8));
        let machine_id = if value(chunk, 0) & 1 == 0 {
            support::MACHINE_ID
        } else {
            MachineId([value(chunk, 0); 16])
        };
        let input = ValidateInput {
            machine_id,
            nonce_c: [value(chunk, 1); 32],
            release_id: if value(chunk, 2) & 1 == 0 {
                "rel_1"
            } else {
                "missing"
            },
            known_revocation_epoch: u64::from(value(chunk, 3)),
            known_security_floor: u64::from(value(chunk, 4)),
            proof_valid: value(chunk, 5) & 1 == 0,
            nonce_fresh: value(chunk, 6) & 1 == 0,
        };
        let scope = version_scope(value(chunk, 7));
        let now = support::NOW.saturating_add(index as i64);
        let _ = validate(
            &license,
            &policy,
            &catalog,
            &registry,
            &scope,
            &input,
            revocation_epoch,
            security_floor,
            now,
        );
    }
});

fn value(chunk: &[u8], index: usize) -> u8 {
    chunk.get(index).copied().unwrap_or_default()
}

fn license_status(value: u8) -> LicenseStatus {
    match value % 4 {
        0 => LicenseStatus::Active,
        1 => LicenseStatus::Suspended,
        2 => LicenseStatus::Expired,
        _ => LicenseStatus::Revoked,
    }
}

fn activation_status(value: u8) -> ActivationStatus {
    match value % 4 {
        0 => ActivationStatus::Active,
        1 => ActivationStatus::Released,
        2 => ActivationStatus::Revoked,
        _ => ActivationStatus::Pending,
    }
}

fn version_scope(value: u8) -> VersionScope {
    match value % 4 {
        0 => VersionScope::Unlimited,
        1 => VersionScope::ReleasedBefore(support::NOW.saturating_sub(i64::from(value))),
        2 => VersionScope::Pinned(vec!["rel_1".to_owned()]),
        _ => VersionScope::SemverRange("^1".to_owned()),
    }
}
