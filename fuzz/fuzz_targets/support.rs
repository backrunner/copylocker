use std::collections::BTreeMap;

use copylocker_server_core::store::{
    ActivationRecord, ActivationStatus, LicenseRecord, LicenseStatus,
};
use copylocker_server_core::version::{CompromisedAction, Release, ReleaseRegistry, ReleaseStatus};
use copylocker_server_core::{Catalog, Feature, Policy, Preset, Tier};
use copylocker_types::{Fingerprint, LicenseId, MachineId};

pub const NOW: i64 = 1_800_000_000;
#[allow(dead_code)]
pub const MACHINE_ID: MachineId = MachineId([7; 16]);

pub fn catalog() -> Catalog {
    Catalog {
        product_id: "acme".to_owned(),
        version: 1,
        features: vec![Feature {
            id: "feature.alpha".to_owned(),
            label: "Alpha".to_owned(),
            description: None,
            deprecated_at: None,
        }],
        groups: Vec::new(),
        tiers: vec![Tier {
            id: "pro".to_owned(),
            label: "Pro".to_owned(),
            rank: 1,
            groups: Vec::new(),
            features: vec!["feature.alpha".to_owned()],
            limits: BTreeMap::new(),
            archived_at: None,
        }],
    }
}

pub fn policy(seats: u32) -> Policy {
    let mut policy = Preset::Perpetual.build("policy", "acme", "pro", NOW);
    policy.seats.seats = seats;
    policy
}

pub fn registry(status: ReleaseStatus, action: Option<CompromisedAction>) -> ReleaseRegistry {
    ReleaseRegistry {
        releases: vec![Release {
            id: "rel_1".to_owned(),
            product_id: "acme".to_owned(),
            app_version: "1.0.0".to_owned(),
            variant_id: 11,
            build_fingerprint: "build-1".to_owned(),
            channel: "stable".to_owned(),
            status,
            compromised_action: action,
            published_at: NOW - 86_400,
        }],
    }
}

pub fn empty_license(status: LicenseStatus) -> LicenseRecord {
    LicenseRecord {
        id: LicenseId([1; 16]),
        product_id: "acme".to_owned(),
        policy_id: "policy".to_owned(),
        status,
        seats_override: None,
        expires_at: None,
        revoked_at_epoch: None,
        activations: Vec::new(),
    }
}

#[allow(dead_code)]
pub fn activated_license() -> LicenseRecord {
    let mut license = empty_license(LicenseStatus::Active);
    license.activations.push(ActivationRecord {
        machine_id: MACHINE_ID,
        fingerprint: Fingerprint::from_vec(vec![1; 32]),
        attrs: None,
        device_kem_ek: vec![2; 32],
        device_sig_vk: vec![3; 32],
        status: ActivationStatus::Active,
        activation_path: "online".to_owned(),
        release_id: Some("rel_1".to_owned()),
        variant_id: Some(11),
        created_at: NOW - 100,
        last_seen_at: Some(NOW - 10),
        refresh_after: NOW + 3_600,
        not_after: 0,
        transfer_count: 0,
    });
    license
}
