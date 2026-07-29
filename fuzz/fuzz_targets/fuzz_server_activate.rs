#![no_main]

mod support;

use copylocker_server_core::activate::{
    commit_seat, reclaim_pending, reserve_seat, ActivateInput, PATH_ONLINE,
};
use copylocker_server_core::store::LicenseStatus;
use copylocker_server_core::version::ReleaseStatus;
use copylocker_types::{Fingerprint, MachineId, VersionScope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(first) = data.first().copied() else {
        return;
    };
    let mut policy = support::policy(u32::from(first % 8 + 1));
    policy.runtime.fpr_tolerance = byte(data, 1) % 101;
    policy.runtime.allow_vm = byte(data, 2) & 1 == 0;
    policy.runtime.refresh_after_secs = i64::from(byte(data, 3) as i8);
    let catalog = support::catalog();
    let registry = support::registry(ReleaseStatus::Active, None);
    let mut license = support::empty_license(license_status(byte(data, 4)));
    license.seats_override = (byte(data, 5) & 1 != 0).then_some(u32::from(byte(data, 6) % 8 + 1));
    license.expires_at = (byte(data, 7) & 1 != 0).then_some(support::NOW);

    for (index, chunk) in data.chunks(8).take(128).enumerate() {
        let marker = chunk.first().copied().unwrap_or_default();
        let fingerprint = Fingerprint::from_vec(vec![marker; usize::from(marker % 64)]);
        let machine_id = machine_id(index, marker);
        let release_id = if chunk.get(1).copied().unwrap_or_default() % 5 == 0 {
            "missing"
        } else {
            "rel_1"
        };
        let scope = version_scope(chunk.get(2).copied().unwrap_or_default());
        let key_material = chunk.get(3..).unwrap_or_default();
        let input = ActivateInput {
            fingerprint: &fingerprint,
            attrs: None,
            device_kem_ek: key_material,
            device_sig_vk: key_material,
            release_id,
            activation_path: PATH_ONLINE,
            is_virtual_machine: chunk.get(3).copied().unwrap_or_default() & 1 != 0,
        };
        let now = support::NOW.saturating_add(index as i64);
        if let Ok(reservation) = reserve_seat(
            &mut license,
            &policy,
            &catalog,
            &registry,
            &input,
            &scope,
            machine_id,
            now,
        ) {
            if chunk.get(4).copied().unwrap_or_default() & 1 == 0 {
                let _ = commit_seat(&mut license, &reservation.machine_id);
            }
        }
        if chunk.get(5).copied().unwrap_or_default() & 1 != 0 {
            let _ = reclaim_pending(&mut license, now.saturating_add(120));
        }
        let _ = license.occupied_seats();
    }
});

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index % data.len()).copied().unwrap_or_default()
}

fn machine_id(index: usize, marker: u8) -> MachineId {
    let mut bytes = [marker; 16];
    bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
    MachineId(bytes)
}

fn license_status(value: u8) -> LicenseStatus {
    match value % 4 {
        0 => LicenseStatus::Active,
        1 => LicenseStatus::Suspended,
        2 => LicenseStatus::Expired,
        _ => LicenseStatus::Revoked,
    }
}

fn version_scope(value: u8) -> VersionScope {
    match value % 4 {
        0 => VersionScope::Unlimited,
        1 => VersionScope::ReleasedBefore(support::NOW.saturating_sub(i64::from(value))),
        2 => VersionScope::Pinned(vec![if value & 1 == 0 {
            "rel_1".to_owned()
        } else {
            "other".to_owned()
        }]),
        _ => VersionScope::SemverRange(if value & 1 == 0 {
            "^1".to_owned()
        } else {
            "not-a-range".to_owned()
        }),
    }
}
