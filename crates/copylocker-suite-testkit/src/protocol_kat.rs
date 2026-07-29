//! Deterministic protocol fixtures carried by the public KAT file.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use copylocker_proto::artifacts::{
    ActivationResponse, EpochCert, IntegrityManifest, KillOrder, MachineCredential,
    OfflineLicenseKey, RevocationBatch, ValidationTicket,
};
use copylocker_proto::chain::{PinnedRoots, VerifiedChain};
use copylocker_proto::envelope::Envelope;
use copylocker_proto::requests::{
    ActivationRequest, ClientInfo, Credential, DeactivateRequest, HeartbeatRequest, TelemetryBlock,
    ValidateRequest,
};
use copylocker_suite::device::{AttrValue, DeviceAttrs};
use copylocker_suite::{Artifact, CryptoSuite, HashScheme, SignatureScheme};
use copylocker_types::{
    ArtifactKind, Digest, Entitlements, EpochId, Fingerprint, KillReason, LicenseId, MachineId,
    Mode, SuiteId, Verdict, VersionScope,
};

use crate::kat::{ArtifactVector, ChainVector, KatError};
use crate::TestRng;

const PRODUCT: &str = "kat-product";
const NOW: i64 = 5_000;
const EPOCH_ID: EpochId = EpochId([0x42; 8]);
const FAST_VERIFYING_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

pub(crate) fn generate<S: CryptoSuite>() -> (Vec<ArtifactVector>, Vec<ChainVector>) {
    type Sig<S> = <S as CryptoSuite>::Sig;

    let mut rng = TestRng::new(0x5052_4f54_4f4b_4154);
    let (root_sk, root_vk) = Sig::<S>::generate(&mut rng);
    let (epoch_sk, epoch_vk) = Sig::<S>::generate(&mut rng);
    let root_vk_bytes = Sig::<S>::encode_vk(&root_vk);
    let root_digest = <S::Hash as HashScheme>::hash(&root_vk_bytes);

    let epoch = EpochCert {
        proto_ver: S::PROTO_VER,
        suite_id: S::SUITE_ID,
        epoch_id: EPOCH_ID,
        vk: Sig::<S>::encode_vk(&epoch_vk),
        vk_fast: FAST_VERIFYING_KEY.to_vec(),
        not_before: 1_000,
        not_after: 9_000,
        product_scope: Some(String::from(PRODUCT)),
        issuer_vk_digest: root_digest,
    };
    let machine = machine_credential(S::SUITE_ID);

    let epoch_envelope = Envelope::seal::<Sig<S>, _>(&epoch, S::SUITE_ID, PRODUCT, None, &root_sk);
    let machine_envelope =
        Envelope::seal::<Sig<S>, _>(&machine, S::SUITE_ID, PRODUCT, Some(EPOCH_ID), &epoch_sk);

    let activation_response = ActivationResponse {
        proto_ver: S::PROTO_VER,
        suite_id: S::SUITE_ID,
        nonce_c_echo: [0x71; 32],
        credential: machine_envelope
            .as_ref()
            .map(Envelope::encode)
            .unwrap_or_default(),
        chain: epoch_envelope
            .as_ref()
            .map(|env| vec![env.encode()])
            .unwrap_or_default(),
        server_time: NOW,
        valid_until: 8_000,
    };

    let mut artifacts = Vec::new();
    push_artifact(&mut artifacts, &epoch);
    push_artifact(&mut artifacts, &machine);
    push_artifact(&mut artifacts, &validation_ticket(S::SUITE_ID));
    push_artifact(&mut artifacts, &kill_order(S::SUITE_ID));
    push_artifact(&mut artifacts, &revocation_batch(S::SUITE_ID));
    push_artifact(&mut artifacts, &offline_license(S::SUITE_ID));
    push_artifact(&mut artifacts, &integrity_manifest(S::SUITE_ID));
    push_artifact(&mut artifacts, &activation_request(S::SUITE_ID));
    push_artifact(&mut artifacts, &activation_response);
    push_artifact(&mut artifacts, &validate_request(S::SUITE_ID));
    push_artifact(&mut artifacts, &heartbeat_request(S::SUITE_ID));
    push_artifact(&mut artifacts, &deactivate_request(S::SUITE_ID));

    let mut chains = Vec::new();
    if let (Ok(epoch_env), Ok(artifact_env)) = (epoch_envelope, machine_envelope) {
        let positive = ChainVector {
            name: String::from("positive/root-epoch-machine-cred"),
            product_id: String::from(PRODUCT),
            root_verifying_key: hex::encode(root_vk_bytes),
            pinned_root_digest: hex::encode(root_digest.as_bytes()),
            epoch_envelope: hex::encode(epoch_env.encode()),
            artifact_kind: String::from(ArtifactKind::MachineCred.ctx_name()),
            artifact_envelope: hex::encode(artifact_env.encode()),
            now: NOW,
            expect_valid: true,
        };
        chains.push(positive.clone());

        let mut unpinned_root = positive.clone();
        unpinned_root.name = String::from("negative/unpinned-root");
        unpinned_root.pinned_root_digest = hex::encode([0xee; 32]);
        unpinned_root.expect_valid = false;
        chains.push(unpinned_root);

        let mut expired_epoch = positive;
        expired_epoch.name = String::from("negative/expired-epoch");
        expired_epoch.now = 9_000;
        expired_epoch.expect_valid = false;
        chains.push(expired_epoch);
    }

    (artifacts, chains)
}

fn push_artifact<A: Artifact>(out: &mut Vec<ArtifactVector>, artifact: &A) {
    if let Ok(canonical) = artifact.to_canonical() {
        out.push(ArtifactVector {
            name: format!("canonical/{}", A::KIND.ctx_name()),
            kind: String::from(A::KIND.ctx_name()),
            canonical: hex::encode(canonical),
        });
    }
}

pub(crate) fn replay_artifact(vector: &ArtifactVector) -> Result<(), KatError> {
    let kind = kind_by_name(&vector.kind)?;
    let bytes = decode_hex("artifact.canonical", &vector.canonical)?;
    let encoded = decode_and_encode(kind, &bytes).map_err(|error| KatError::Mismatch {
        name: vector.name.clone(),
        detail: format!("canonical artifact did not decode: {error:?}"),
    })?;
    if encoded != bytes {
        return Err(KatError::Mismatch {
            name: vector.name.clone(),
            detail: String::from("artifact did not re-encode to the committed canonical bytes"),
        });
    }
    Ok(())
}

pub(crate) fn replay_chain<S: CryptoSuite>(vector: &ChainVector) -> Result<(), KatError> {
    type Sig<S> = <S as CryptoSuite>::Sig;

    let result = (|| {
        let root_vk_bytes = decode_hex("chain.root_verifying_key", &vector.root_verifying_key)?;
        let root_vk = Sig::<S>::decode_vk(&root_vk_bytes)
            .map_err(|_| KatError::BadKey(String::from("chain.root_verifying_key")))?;
        let digest_bytes = decode_hex("chain.pinned_root_digest", &vector.pinned_root_digest)?;
        let digest = Digest::from_slice(&digest_bytes)
            .ok_or_else(|| KatError::BadHex(String::from("chain.pinned_root_digest length")))?;
        let epoch_bytes = decode_hex("chain.epoch_envelope", &vector.epoch_envelope)?;
        let artifact_bytes = decode_hex("chain.artifact_envelope", &vector.artifact_envelope)?;
        let epoch_envelope =
            Envelope::decode(&epoch_bytes).map_err(|error| KatError::Mismatch {
                name: vector.name.clone(),
                detail: format!("epoch envelope did not decode: {error:?}"),
            })?;
        let artifact_envelope =
            Envelope::decode(&artifact_bytes).map_err(|error| KatError::Mismatch {
                name: vector.name.clone(),
                detail: format!("artifact envelope did not decode: {error:?}"),
            })?;
        let kind = kind_by_name(&vector.artifact_kind)?;
        if artifact_envelope.kind != kind {
            return Err(KatError::Mismatch {
                name: vector.name.clone(),
                detail: String::from("declared artifact kind differs from the envelope"),
            });
        }

        let mut chain = VerifiedChain::<Sig<S>>::new(PinnedRoots::single(digest));
        chain
            .add_epoch::<S::Hash>(&epoch_envelope, &vector.product_id, &root_vk, vector.now)
            .map_err(|error| KatError::Mismatch {
                name: vector.name.clone(),
                detail: format!("epoch verification failed: {error:?}"),
            })?;
        verify_chained_artifact(
            &chain,
            kind,
            &artifact_envelope,
            &vector.product_id,
            vector.now,
        )
        .map_err(|error| KatError::Mismatch {
            name: vector.name.clone(),
            detail: format!("artifact verification failed: {error:?}"),
        })
    })();

    match (vector.expect_valid, result) {
        (true, Ok(())) | (false, Err(_)) => Ok(()),
        (true, Err(error)) => Err(error),
        (false, Ok(())) => Err(KatError::Mismatch {
            name: vector.name.clone(),
            detail: String::from("invalid chain unexpectedly verified"),
        }),
    }
}

fn verify_chained_artifact<S: SignatureScheme>(
    chain: &VerifiedChain<S>,
    kind: ArtifactKind,
    envelope: &Envelope,
    product_id: &str,
    now: i64,
) -> Result<(), copylocker_proto::ProtoError> {
    macro_rules! verify {
        ($artifact:ty) => {
            chain
                .verify_artifact::<$artifact>(envelope, product_id, now)
                .map(|_| ())
        };
    }
    match kind {
        ArtifactKind::EpochCert => verify!(EpochCert),
        ArtifactKind::MachineCred => verify!(MachineCredential),
        ArtifactKind::ValidationTicket => verify!(ValidationTicket),
        ArtifactKind::KillOrder => verify!(KillOrder),
        ArtifactKind::RevocationBatch => verify!(RevocationBatch),
        ArtifactKind::OfflineLicenseKey => verify!(OfflineLicenseKey),
        ArtifactKind::IntegrityManifest => verify!(IntegrityManifest),
        ArtifactKind::ActivationRequest => verify!(ActivationRequest),
        ArtifactKind::ActivationResponse => verify!(ActivationResponse),
        ArtifactKind::ValidateRequest => verify!(ValidateRequest),
        ArtifactKind::HeartbeatRequest => verify!(HeartbeatRequest),
        ArtifactKind::DeactivateRequest => verify!(DeactivateRequest),
    }
}

fn decode_and_encode(
    kind: ArtifactKind,
    bytes: &[u8],
) -> Result<Vec<u8>, copylocker_proto::ProtoError> {
    macro_rules! roundtrip {
        ($artifact:ty) => {
            <$artifact>::decode(bytes).map(|artifact| artifact.encode())
        };
    }
    match kind {
        ArtifactKind::EpochCert => roundtrip!(EpochCert),
        ArtifactKind::MachineCred => roundtrip!(MachineCredential),
        ArtifactKind::ValidationTicket => roundtrip!(ValidationTicket),
        ArtifactKind::KillOrder => roundtrip!(KillOrder),
        ArtifactKind::RevocationBatch => roundtrip!(RevocationBatch),
        ArtifactKind::OfflineLicenseKey => roundtrip!(OfflineLicenseKey),
        ArtifactKind::IntegrityManifest => roundtrip!(IntegrityManifest),
        ArtifactKind::ActivationRequest => roundtrip!(ActivationRequest),
        ArtifactKind::ActivationResponse => roundtrip!(ActivationResponse),
        ArtifactKind::ValidateRequest => roundtrip!(ValidateRequest),
        ArtifactKind::HeartbeatRequest => roundtrip!(HeartbeatRequest),
        ArtifactKind::DeactivateRequest => roundtrip!(DeactivateRequest),
    }
}

fn kind_by_name(name: &str) -> Result<ArtifactKind, KatError> {
    ArtifactKind::ALL
        .into_iter()
        .find(|kind| kind.ctx_name() == name)
        .ok_or_else(|| KatError::UnknownKind(String::from(name)))
}

fn decode_hex(field: &str, value: &str) -> Result<Vec<u8>, KatError> {
    hex::decode(value).map_err(|_| KatError::BadHex(String::from(field)))
}

fn entitlements() -> Entitlements {
    let mut features = BTreeSet::new();
    features.insert(String::from("export.pdf"));
    features.insert(String::from("sync.cloud"));
    let mut limits = BTreeMap::new();
    limits.insert(String::from("max_projects"), 100);
    Entitlements {
        features,
        limits,
        tier_id: String::from("pro"),
        tier_label: String::from("Pro"),
        catalog_version: 3,
        version_scope: Some(VersionScope::ReleasedBefore(1_900_000_000)),
        subscription_hint: None,
    }
}

fn machine_credential(suite_id: SuiteId) -> MachineCredential {
    let mut wrapped_keks = BTreeMap::new();
    wrapped_keks.insert(String::from("export.pdf"), vec![0x61; 72]);
    let mut next_keks = BTreeMap::new();
    next_keks.insert(String::from("export.pdf"), vec![0x62; 72]);
    let mut preloaded_keks = BTreeMap::new();
    preloaded_keks.insert(8, next_keks);
    MachineCredential {
        proto_ver: 1,
        suite_id,
        product_id: String::from(PRODUCT),
        license_id: LicenseId([0x11; 16]),
        machine_id: MachineId([0x22; 16]),
        fingerprint: Fingerprint::from_vec(vec![0x33; 32]),
        kem_ct: vec![0x44; 64],
        sealed_cs: vec![0x45; 72],
        offline_nonce: [0x46; 32],
        entitlements: entitlements(),
        issued_at: 2_000,
        not_after: 100_000,
        refresh_after: 8_000,
        grace_seconds: 604_800,
        mode: Mode::OfflineHybrid,
        revocation_epoch: 42,
        epoch_id: EPOCH_ID,
        build_fingerprint: Some(String::from("build-kat")),
        policy_flags: Some(5),
        security_floor: 3,
        variant_id: 7,
        wrapped_keks,
        preloaded_keks: Some(preloaded_keks),
    }
}

fn validation_ticket(suite_id: SuiteId) -> ValidationTicket {
    ValidationTicket {
        proto_ver: 1,
        suite_id,
        machine_id: MachineId([0x22; 16]),
        nonce_c_echo: [0x51; 32],
        server_nonce: [0x52; 32],
        server_time: NOW,
        next_refresh_after: 12_000,
        not_after: 100_000,
        revocation_epoch: 42,
        verdict: Verdict::Ok,
        entitlements: Some(entitlements()),
        epoch_id: EPOCH_ID,
        suspicion_score: Some(12),
        security_floor: 3,
        release_status: Some(0),
        wrapped_keks: None,
        refresh_now: Some(false),
    }
}

fn kill_order(suite_id: SuiteId) -> KillOrder {
    KillOrder {
        proto_ver: 1,
        suite_id,
        machine_id: MachineId([0x22; 16]),
        nonce_c_echo: [0x51; 32],
        server_time: NOW,
        reason: KillReason::Refund,
        user_message: Some(String::from("Purchase refunded")),
        revocation_epoch: 43,
    }
}

fn revocation_batch(suite_id: SuiteId) -> RevocationBatch {
    RevocationBatch {
        proto_ver: 1,
        suite_id,
        from_epoch: 40,
        to_epoch: 43,
        issued_at: NOW,
        revoked_license_ids: vec![LicenseId([0x11; 16])],
        revoked_machine_ids: vec![MachineId([0x22; 16])],
        revoked_epoch_ids: vec![EpochId([0x91; 8])],
        bloom_filter: Some(vec![0xa5; 16]),
    }
}

fn offline_license(suite_id: SuiteId) -> OfflineLicenseKey {
    OfflineLicenseKey {
        proto_ver: 1,
        suite_id,
        product_id: String::from(PRODUCT),
        license_id: LicenseId([0x11; 16]),
        entitlements: entitlements(),
        issued_at: 2_000,
        not_after: 100_000,
        bound_fingerprint: Some(Fingerprint::from_vec(vec![0x33; 32])),
        max_seats: 3,
        epoch_id: EPOCH_ID,
        machine_id: MachineId([0x22; 16]),
        offline_nonce: [0x44; 32],
        key_seed: [0x55; 32],
        build_fingerprint: String::from("build-kat"),
        variant_id: 7,
        security_floor: 3,
        revocation_epoch: 4,
        wrapped_keks: BTreeMap::new(),
    }
}

fn integrity_manifest(suite_id: SuiteId) -> IntegrityManifest {
    let mut entries = BTreeMap::new();
    entries.insert(String::from("/assets/main.js"), vec![0xa1; 32]);
    entries.insert(String::from("/assets/vendor.js"), vec![0xa2; 32]);
    let mut guarded = BTreeMap::new();
    guarded.insert(String::from("render_export"), vec![0xa3; 32]);
    IntegrityManifest {
        proto_ver: 1,
        suite_id,
        product_id: String::from(PRODUCT),
        build_fingerprint: String::from("build-kat"),
        built_at: 2_000,
        hash_alg: String::from("blake3"),
        entries,
        guarded: Some(guarded),
        sealed_assets: Some(vec![String::from("templates.bin")]),
        root: vec![0xa4; 32],
    }
}

fn client_info(suite_id: SuiteId) -> ClientInfo {
    ClientInfo {
        app_version: String::from("4.2.0"),
        sdk_version: String::from("0.1.0"),
        os: String::from("linux"),
        arch: String::from("x86_64"),
        build_fingerprint: String::from("build-kat"),
        release_id: String::from("rel_kat"),
        variant_id: 7,
        supported_suites: vec![suite_id],
        supported_variants: vec![7, 6, 5, 4],
    }
}

fn activation_request(suite_id: SuiteId) -> ActivationRequest {
    let mut attrs = DeviceAttrs::new();
    attrs.insert("machine_guid", AttrValue::text("A1B2-C3D4"));
    attrs.insert("mac_addrs", AttrValue::set(["aa:bb", "cc:dd"]));
    attrs.insert("hardware_concurrency", AttrValue::Int(8));
    attrs.insert("board_serial", AttrValue::Absent);
    ActivationRequest {
        proto_ver: 1,
        suite_id,
        product_id: String::from(PRODUCT),
        credential: Credential::LicenseKey(String::from("CL1-ABCDE-FGHJK-MNPQR-STVWX")),
        fingerprint: Fingerprint::from_vec(vec![0x33; 32]),
        device_attrs: Some(attrs),
        device_kem_ek: vec![0xb1; 64],
        device_sig_vk: vec![0xb2; 32],
        nonce_c: [0xb3; 32],
        client_time: 4_000,
        client_info: client_info(suite_id),
        attestation: Some(vec![0xb4; 24]),
        proof: vec![0xb5; 64],
    }
}

fn validate_request(suite_id: SuiteId) -> ValidateRequest {
    let mut feature_hits = BTreeMap::new();
    feature_hits.insert(String::from("export.pdf"), 3);
    ValidateRequest {
        proto_ver: 1,
        suite_id,
        license_id: LicenseId([0x11; 16]),
        machine_id: MachineId([0x22; 16]),
        fingerprint: Fingerprint::from_vec(vec![0x33; 32]),
        nonce_c: [0xc1; 32],
        client_time: 4_000,
        known_revocation_epoch: 42,
        client_info: client_info(suite_id),
        proof: vec![0xc2; 64],
        integrity_summary: Some(vec![0xc3; 32]),
        known_security_floor: 3,
        telemetry: Some(TelemetryBlock {
            consent_version: 2,
            window_start: 3_000,
            session_count: 5,
            session_duration_histogram: [1, 2, 1, 1],
            feature_hits,
            days_active: 4,
        }),
    }
}

fn heartbeat_request(suite_id: SuiteId) -> HeartbeatRequest {
    HeartbeatRequest {
        proto_ver: 1,
        suite_id,
        license_id: LicenseId([0x11; 16]),
        machine_id: MachineId([0x22; 16]),
        nonce_c: [0xd1; 32],
        client_time: 4_001,
        proof: vec![0xd2; 64],
    }
}

fn deactivate_request(suite_id: SuiteId) -> DeactivateRequest {
    DeactivateRequest {
        proto_ver: 1,
        suite_id,
        license_id: LicenseId([0x11; 16]),
        machine_id: MachineId([0x22; 16]),
        nonce_c: [0xe1; 32],
        client_time: 4_002,
        proof: vec![0xe2; 64],
    }
}
