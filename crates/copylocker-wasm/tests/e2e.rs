//! Host-side end-to-end tests for the opaque session core.
//!
//! A scripted issuer (the same pattern as `copylocker-client`'s `FakeServer`) signs epoch
//! certificates, machine credentials, validation tickets, and kill orders, so the full
//! lifecycle runs without a network: keygen → activate → validate → derive `M` → snapshot
//! round-trip → revocation and clock-rollback handling.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use copylocker_core::keys::{KeyMaterial, SessionKind};
use copylocker_proto::keywrap::{seal_credential_secret, CredentialSealContext};
use copylocker_proto::{
    ActivationRequest, Envelope, EpochCert, Keyset, KillOrder, MachineCredential, TelemetryBlock,
    ValidateRequest, ValidationTicket, MAX_TELEMETRY_BLOCK_BYTES,
};
use copylocker_suite::cbor::{decode_canonical, CborValue, Limits, MapBuilder};
use copylocker_suite::{
    CryptoRng, CryptoSuite, DomainCtx, EnvEvidence, HashScheme, KeyEncapsulation, Secret,
    SharedSecret, Signature, SignatureScheme,
};
use copylocker_suite_std::{ClStd1, FastSig, HybridSig, Sha256Scheme, XWingKem};
use copylocker_types::{
    ArtifactKind, Digest, Entitlements, EpochId, Fingerprint, KillReason, LicenseId, LicenseState,
    MachineId, Mode, Verdict, PROTO_VER,
};
use copylocker_wasm::{codes, Session, SessionRng};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

const NOW: i64 = 1_800_000_000;
const YEAR: i64 = 365 * 86_400;
const PRODUCT: &str = "test-product";
const FEATURE: &str = "export.pdf";
const FEATURE_TWO: &str = "ai.assist";
const MACHINE_ID: MachineId = MachineId([0x22; 16]);
const LICENSE_ID: LicenseId = LicenseId([0x11; 16]);
const EPOCH_ID: EpochId = EpochId([0x33; 8]);

const TEST_LIMITS: Limits = Limits {
    max_depth: copylocker_types::MAX_CBOR_DEPTH,
    max_items: 4_096,
    max_string: 1024 * 1024,
};

/// A seeded RNG, adequate for tests only.
struct TestRng(ChaCha20Rng);

impl CryptoRng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
}

impl SessionRng for TestRng {
    fn failed(&self) -> bool {
        false
    }

    fn reset(&mut self) {}
}

fn rng(seed: u64) -> TestRng {
    TestRng(ChaCha20Rng::seed_from_u64(seed))
}

/// Signs server-side artifacts exactly like the desktop client tests' `FakeServer`.
struct Issuer {
    root_vk: Vec<u8>,
    epoch_cert: Vec<u8>,
    epoch_sk: Vec<u8>,
    fast_sk: Vec<u8>,
    /// Device signing key from the last activation request, for proof verification.
    device_sig_vk: Option<Vec<u8>>,
    seed: u64,
}

impl Issuer {
    fn new() -> Self {
        let mut r = rng(1);
        let (root_sk, root_vk) = HybridSig::generate(&mut r);
        let (epoch_sk, epoch_vk) = HybridSig::generate(&mut r);
        let (fast_sk, fast_vk) = FastSig::generate(&mut r);
        let root_vk = HybridSig::encode_vk(&root_vk);
        let cert = EpochCert {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            epoch_id: EPOCH_ID,
            vk: HybridSig::encode_vk(&epoch_vk),
            vk_fast: FastSig::encode_vk(&fast_vk),
            not_before: NOW - 86_400,
            not_after: NOW + 86_400,
            product_scope: Some(String::from(PRODUCT)),
            issuer_vk_digest: Sha256Scheme::hash(&root_vk),
        };
        let epoch_cert =
            Envelope::seal::<HybridSig, _>(&cert, ClStd1::SUITE_ID, PRODUCT, None, &root_sk)
                .unwrap()
                .encode();
        Self {
            root_vk,
            epoch_cert,
            epoch_sk: HybridSig::encode_sk(&epoch_sk),
            fast_sk: FastSig::encode_sk(&fast_sk),
            device_sig_vk: None,
            seed: 100,
        }
    }

    fn keyset(&self) -> Vec<u8> {
        Keyset {
            proto_ver: PROTO_VER,
            epoch_certificates: vec![self.epoch_cert.clone()],
            revocation_epoch: 0,
        }
        .encode()
    }

    fn next_rng(&mut self) -> TestRng {
        self.seed += 1;
        rng(self.seed)
    }

    /// A `/v1/activate` response: a machine credential sealed to the requesting device key.
    fn activate(&mut self, request_bytes: &[u8]) -> Vec<u8> {
        self.activate_with(request_bytes, BTreeMap::new(), None, None)
    }

    /// `activate` with issuer-side wrapped KEKs and an optional credential variant override
    /// (the offline-upgrade shape: issued for an older variant, carrying `preloaded_keks`).
    fn activate_with(
        &mut self,
        request_bytes: &[u8],
        wrapped_keks: BTreeMap<String, Vec<u8>>,
        preloaded_keks: Option<BTreeMap<u64, BTreeMap<String, Vec<u8>>>>,
        variant_override: Option<u64>,
    ) -> Vec<u8> {
        let request = ActivationRequest::decode(request_bytes).unwrap();
        self.device_sig_vk = Some(request.device_sig_vk.clone());
        let device_ek = XWingKem::decode_ek(&request.device_kem_ek).unwrap();
        let mut r = self.next_rng();
        let (kem_ct, kem_shared) = XWingKem::encap(&device_ek, &mut r).unwrap();
        let offline_nonce = [0x44; 32];
        let variant_id = variant_override.unwrap_or(request.client_info.variant_id);
        let context = CredentialSealContext {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            product_id: PRODUCT,
            license_id: LICENSE_ID,
            machine_id: MACHINE_ID,
            fingerprint: &request.fingerprint,
            kem_ct: kem_ct.as_bytes(),
            offline_nonce: &offline_nonce,
            epoch_id: EPOCH_ID,
            variant_id,
        };
        let sealed_cs = seal_credential_secret::<ClStd1>(
            &kem_shared,
            &context,
            &Secret::new([0x55; 32]),
            &mut r,
        )
        .unwrap();
        let mut entitlements = Entitlements::default();
        entitlements.features.insert(String::from(FEATURE));
        entitlements.features.insert(String::from(FEATURE_TWO));
        entitlements.tier_id = String::from("pro");
        entitlements.tier_label = String::from("Pro");
        entitlements.catalog_version = 1;
        let credential = MachineCredential {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            product_id: String::from(PRODUCT),
            license_id: LICENSE_ID,
            machine_id: MACHINE_ID,
            fingerprint: request.fingerprint,
            kem_ct: kem_ct.0,
            sealed_cs,
            offline_nonce,
            entitlements,
            issued_at: NOW,
            not_after: NOW + 86_400,
            refresh_after: NOW + 3_600,
            grace_seconds: 3_600,
            mode: Mode::OfflineHybrid,
            revocation_epoch: 0,
            epoch_id: EPOCH_ID,
            build_fingerprint: Some(request.client_info.build_fingerprint),
            policy_flags: None,
            security_floor: 3,
            variant_id,
            wrapped_keks,
            preloaded_keks,
        };
        let epoch_sk = HybridSig::decode_sk(&self.epoch_sk).unwrap();
        Envelope::seal::<HybridSig, _>(
            &credential,
            ClStd1::SUITE_ID,
            PRODUCT,
            Some(EPOCH_ID),
            &epoch_sk,
        )
        .unwrap()
        .encode()
    }

    /// A `/v1/validate` ticket answering the given request.
    fn ticket(&self, request_bytes: &[u8]) -> Vec<u8> {
        let request = ValidateRequest::decode(request_bytes).unwrap();
        self.ticket_for(request.nonce_c, Verdict::Ok, 3)
    }

    /// A ticket carrying refreshed wrapped KEKs (proto field 15).
    fn ticket_with_keks(&self, request_bytes: &[u8], keks: BTreeMap<String, Vec<u8>>) -> Vec<u8> {
        let request = ValidateRequest::decode(request_bytes).unwrap();
        self.ticket_for_full(request.nonce_c, Verdict::Ok, 3, Some(keks))
    }

    fn ticket_for(&self, nonce: [u8; 32], verdict: Verdict, security_floor: u64) -> Vec<u8> {
        self.ticket_for_full(nonce, verdict, security_floor, None)
    }

    fn ticket_for_full(
        &self,
        nonce: [u8; 32],
        verdict: Verdict,
        security_floor: u64,
        wrapped_keks: Option<BTreeMap<String, Vec<u8>>>,
    ) -> Vec<u8> {
        let fast_sk = FastSig::decode_sk(&self.fast_sk).unwrap();
        let ticket = ValidationTicket {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            machine_id: MACHINE_ID,
            nonce_c_echo: nonce,
            server_nonce: [0x66; 32],
            server_time: NOW,
            next_refresh_after: NOW + 3_600,
            not_after: NOW + 86_400,
            revocation_epoch: 0,
            verdict,
            entitlements: None,
            epoch_id: EPOCH_ID,
            suspicion_score: Some(0),
            security_floor,
            release_status: Some(0),
            wrapped_keks,
            refresh_now: None,
        };
        Envelope::seal::<FastSig, _>(&ticket, ClStd1::SUITE_ID, PRODUCT, Some(EPOCH_ID), &fast_sk)
            .unwrap()
            .encode()
    }

    /// A kill order answering the given validate request.
    fn kill_order(&self, request_bytes: &[u8]) -> Vec<u8> {
        let request = ValidateRequest::decode(request_bytes).unwrap();
        let fast_sk = FastSig::decode_sk(&self.fast_sk).unwrap();
        let order = KillOrder {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            machine_id: MACHINE_ID,
            nonce_c_echo: request.nonce_c,
            server_time: NOW,
            reason: KillReason::Refund,
            user_message: None,
            revocation_epoch: 0,
        };
        Envelope::seal::<FastSig, _>(&order, ClStd1::SUITE_ID, PRODUCT, Some(EPOCH_ID), &fast_sk)
            .unwrap()
            .encode()
    }
}

fn cfg(issuer: &Issuer) -> Vec<u8> {
    let mut b = MapBuilder::new();
    b.put(0, CborValue::Uint(1));
    b.put(1, CborValue::Text(String::from(PRODUCT)));
    b.put(2, CborValue::Bytes(issuer.root_vk.clone()));
    b.put(4, CborValue::Bytes(vec![0x07; 32]));
    b.put(5, CborValue::Bytes(vec![0x88; 32]));
    b.put(6, CborValue::Bytes(vec![0x99; 32]));
    b.put(7, CborValue::Text(String::from("build-test")));
    b.put(8, CborValue::Text(String::from("1.0.0")));
    b.put(9, CborValue::Text(String::from("0.1.0")));
    b.put(10, CborValue::Text(String::from("web")));
    b.put(11, CborValue::Text(String::from("wasm32")));
    b.put(12, CborValue::Text(String::from("release-test")));
    b.put(13, CborValue::Uint(7));
    b.put(18, CborValue::int(NOW));
    b.finish()
}

fn op(code: u64) -> MapBuilder {
    let mut b = MapBuilder::new();
    b.put(0, CborValue::Uint(code));
    b
}

fn call(session: &mut Session, request: CborValue) -> Result<CborValue, u16> {
    let out = session.step(&request.to_canonical())?;
    decode_canonical(&out, TEST_LIMITS).map_err(|_| u16::MAX)
}

fn payload(response: &CborValue) -> Vec<u8> {
    response
        .get(8)
        .and_then(CborValue::as_bytes)
        .unwrap()
        .to_vec()
}

fn state_of(response: &CborValue) -> u64 {
    response.get(1).and_then(CborValue::as_uint).unwrap()
}

fn effects_of(response: &CborValue) -> Vec<u64> {
    response
        .get(90)
        .and_then(CborValue::as_array)
        .unwrap()
        .iter()
        .filter_map(CborValue::as_uint)
        .collect()
}

fn derive_m(session: &mut Session, feature: &str, kind: u64, now: i64) -> Result<CborValue, u16> {
    let mut b = op(codes::OP_DERIVE_M);
    b.put(1, CborValue::Text(String::from(feature)));
    b.put(2, CborValue::Uint(kind));
    b.put(3, CborValue::int(now));
    call(session, b.build())
}

fn tick(session: &mut Session, now: i64) -> CborValue {
    let mut b = op(codes::OP_EVENT);
    b.put(1, CborValue::Uint(codes::EVENT_TICK));
    b.put(2, CborValue::int(now));
    call(session, b.build()).unwrap()
}

/// keygen → build-activate-request → ingest-keyset → ingest-activate-response.
fn activated() -> (Session, Issuer) {
    let mut issuer = Issuer::new();
    let mut session = Session::new(&cfg(&issuer), Box::new(rng(7))).unwrap();
    call(&mut session, op(codes::OP_DEVICE_KEYGEN).build()).unwrap();

    let mut b = op(codes::OP_BUILD_ACTIVATE_REQUEST);
    b.put(1, CborValue::Text(String::from("CL1-TEST-KEY")));
    b.put(2, CborValue::int(NOW));
    let request = payload(&call(&mut session, b.build()).unwrap());
    // The request must be a well-formed, proof-carrying activation request.
    let decoded = ActivationRequest::decode(&request).unwrap();
    assert!(!decoded.proof.is_empty());
    assert_eq!(decoded.product_id, PRODUCT);

    let mut b = op(codes::OP_INGEST_KEYSET);
    b.put(1, CborValue::Bytes(issuer.keyset()));
    b.put(2, CborValue::int(NOW));
    call(&mut session, b.build()).unwrap();

    let response = issuer.activate(&request);
    let mut b = op(codes::OP_INGEST_ACTIVATE_RESPONSE);
    b.put(1, CborValue::Bytes(response));
    b.put(2, CborValue::int(NOW));
    let summary = call(&mut session, b.build()).unwrap();
    assert_eq!(state_of(&summary), 2, "active after activation");
    assert_eq!(
        summary.get(6).and_then(CborValue::as_uint),
        Some(1),
        "credential held"
    );
    (session, issuer)
}

/// keygen → build-activate-request, returning the request bytes for a custom issuer response.
fn activation_request(session: &mut Session) -> Vec<u8> {
    call(session, op(codes::OP_DEVICE_KEYGEN).build()).unwrap();
    let mut b = op(codes::OP_BUILD_ACTIVATE_REQUEST);
    b.put(1, CborValue::Text(String::from("CL1-TEST-KEY")));
    b.put(2, CborValue::int(NOW));
    payload(&call(session, b.build()).unwrap())
}

fn ingest_keyset(session: &mut Session, issuer: &Issuer) {
    let mut b = op(codes::OP_INGEST_KEYSET);
    b.put(1, CborValue::Bytes(issuer.keyset()));
    b.put(2, CborValue::int(NOW));
    call(session, b.build()).unwrap();
}

fn ingest_activation(session: &mut Session, envelope: Vec<u8>) -> Result<CborValue, u16> {
    let mut b = op(codes::OP_INGEST_ACTIVATE_RESPONSE);
    b.put(1, CborValue::Bytes(envelope));
    b.put(2, CborValue::int(NOW));
    call(session, b.build())
}

fn unseal_asset(session: &mut Session, feature: &str, now: i64) -> Result<CborValue, u16> {
    let mut b = op(codes::OP_UNSEAL_ASSET);
    b.put(1, CborValue::Text(String::from(feature)));
    b.put(2, CborValue::int(now));
    call(session, b.build())
}

/// The wrap a server would produce for one asset KEK (`wrap_offline_keks` /
/// `wrap_online_keks` in the worker): the session's own evidence, variant, and session kind.
fn wrap_kek_for(
    variant_id: u64,
    feature: &str,
    kind: SessionKind,
    kek: [u8; 32],
    seed: u64,
) -> Vec<u8> {
    wrap_kek_with_evidence([0x99; 32], variant_id, feature, kind, kek, seed)
}

fn wrap_kek_with_evidence(
    module_digest: [u8; 32],
    variant_id: u64,
    feature: &str,
    kind: SessionKind,
    kek: [u8; 32],
    seed: u64,
) -> Vec<u8> {
    let secret = SharedSecret::new([0x55; 32]);
    let evidence = EnvEvidence {
        module_digest: Digest(module_digest),
        build_fingerprint: b"build-test".to_vec(),
        extra: Vec::new(),
    };
    let mut material = KeyMaterial::bind::<ClStd1>(
        &secret,
        &Fingerprint::from_vec(vec![0x07; 32]),
        &evidence,
        PRODUCT,
        LICENSE_ID,
        MACHINE_ID,
        EPOCH_ID,
        variant_id,
        [0x88; 32],
        [0x44; 32],
    )
    .unwrap();
    if kind == SessionKind::Online {
        material.set_online_session([0x66; 32], EPOCH_ID);
    }
    let mut entitlements = Entitlements::default();
    entitlements.features.insert(String::from(FEATURE));
    entitlements.features.insert(String::from(FEATURE_TWO));
    let mut r = rng(seed);
    material
        .wrap_kek::<ClStd1>(
            LicenseState::Active,
            &entitlements,
            feature,
            kind,
            &Secret::new(kek),
            &mut r,
        )
        .unwrap()
}

#[test]
fn malformed_and_unknown_inputs_yield_numeric_errors_not_panics() {
    let issuer = Issuer::new();
    let mut session = Session::new(&cfg(&issuer), Box::new(rng(3))).unwrap();

    assert_eq!(session.step(&[]), Err(codes::ERR_MALFORMED));
    assert_eq!(session.step(&[0xff]), Err(codes::ERR_MALFORMED));
    assert_eq!(
        session.step(&[0xbf, 0x00, 0x00, 0xff]),
        Err(codes::ERR_MALFORMED)
    );

    // A valid map without an op, and an unknown op.
    assert_eq!(
        call(&mut session, MapBuilder::new().build()),
        Err(codes::ERR_BAD_FIELD)
    );
    assert_eq!(
        call(&mut session, op(99).build()),
        Err(codes::ERR_UNKNOWN_OP)
    );

    // Truncated derive-m requests: every cut of a valid encoding must fail cleanly.
    let mut b = op(codes::OP_DERIVE_M);
    b.put(1, CborValue::Text(String::from(FEATURE)));
    b.put(2, CborValue::Uint(0));
    b.put(3, CborValue::int(NOW));
    let full = b.finish();
    for cut in 0..full.len() {
        assert!(session.step(&full[..cut]).is_err(), "cut {cut}");
    }

    // Missing required fields.
    assert_eq!(
        call(&mut session, op(codes::OP_SNAPSHOT_IMPORT).build()),
        Err(codes::ERR_BAD_FIELD)
    );

    // A bad constructor config is a numeric error too.
    assert!(Session::new(&[0xa1, 0x00, 0x02], Box::new(rng(4))).is_err());
    assert_eq!(
        Session::new(&[], Box::new(rng(4))).err(),
        Some(codes::ERR_MALFORMED)
    );
}

#[test]
fn activation_end_to_end_and_deterministic_m() {
    let (mut session, _issuer) = activated();

    let first = payload(&derive_m(&mut session, FEATURE, 0, NOW).unwrap());
    let second = payload(&derive_m(&mut session, FEATURE, 0, NOW).unwrap());
    assert_eq!(first.len(), 32);
    assert_eq!(first, second, "same input, same M");

    let other = payload(&derive_m(&mut session, FEATURE_TWO, 0, NOW).unwrap());
    assert_ne!(first, other, "different feature, different M");

    assert_eq!(
        derive_m(&mut session, "render.4k", 0, NOW).err(),
        Some(codes::ERR_NOT_ENTITLED)
    );
    assert_eq!(
        derive_m(&mut session, FEATURE, 0, NOW + 1)
            .ok()
            .map(|v| payload(&v)),
        Some(first),
        "a later tick must not change M"
    );
}

#[test]
fn unseal_asset_unwraps_the_credentials_offline_kek() {
    let mut issuer = Issuer::new();
    let mut session = Session::new(&cfg(&issuer), Box::new(rng(7))).unwrap();
    let request = activation_request(&mut session);
    ingest_keyset(&mut session, &issuer);

    let kek = [0x5A; 32];
    let mut wrapped = BTreeMap::new();
    wrapped.insert(
        String::from(FEATURE),
        wrap_kek_for(7, FEATURE, SessionKind::Offline, kek, 501),
    );
    let response = issuer.activate_with(&request, wrapped, None, None);
    ingest_activation(&mut session, response).unwrap();

    let out = unseal_asset(&mut session, FEATURE, NOW).unwrap();
    assert_eq!(payload(&out), kek, "the op returns the unwrapped asset KEK");
    assert_eq!(
        payload(&unseal_asset(&mut session, FEATURE, NOW + 1).unwrap()),
        kek,
        "a later tick unwraps the same KEK"
    );
    // Entitled but never wrapped, and not entitled at all: one indistinguishable failure.
    assert_eq!(
        unseal_asset(&mut session, FEATURE_TWO, NOW).err(),
        Some(codes::ERR_NOT_ENTITLED)
    );
    assert_eq!(
        unseal_asset(&mut session, "render.4k", NOW).err(),
        Some(codes::ERR_NOT_ENTITLED)
    );
}

#[test]
fn unseal_asset_requires_a_credential_and_well_formed_fields() {
    let issuer = Issuer::new();
    let mut session = Session::new(&cfg(&issuer), Box::new(rng(3))).unwrap();
    assert_eq!(
        unseal_asset(&mut session, FEATURE, NOW).err(),
        Some(codes::ERR_NO_CREDENTIAL)
    );
    let mut b = op(codes::OP_UNSEAL_ASSET);
    b.put(2, CborValue::int(NOW));
    assert_eq!(
        call(&mut session, b.build()).err(),
        Some(codes::ERR_BAD_FIELD)
    );
}

#[test]
fn unseal_asset_fails_on_a_kek_wrapped_for_other_evidence() {
    // The "wrong wasm digest / wrong build" case: the wrap's module-digest evidence no longer
    // matches this session, so the unwrap fails closed with the indistinguishable error —
    // never a panic, and the session stays usable.
    let mut issuer = Issuer::new();
    let mut session = Session::new(&cfg(&issuer), Box::new(rng(7))).unwrap();
    let request = activation_request(&mut session);
    ingest_keyset(&mut session, &issuer);
    let mut wrapped = BTreeMap::new();
    wrapped.insert(
        String::from(FEATURE),
        wrap_kek_with_evidence(
            [0x77; 32],
            7,
            FEATURE,
            SessionKind::Offline,
            [0x5A; 32],
            502,
        ),
    );
    let response = issuer.activate_with(&request, wrapped, None, None);
    ingest_activation(&mut session, response).unwrap();
    assert_eq!(
        unseal_asset(&mut session, FEATURE, NOW).err(),
        Some(codes::ERR_NOT_ENTITLED)
    );
}

#[test]
fn unseal_asset_prefers_the_tickets_online_kek() {
    let mut issuer = Issuer::new();
    let mut session = Session::new(&cfg(&issuer), Box::new(rng(7))).unwrap();
    let request = activation_request(&mut session);
    ingest_keyset(&mut session, &issuer);

    let offline_kek = [0x0F; 32];
    let mut wrapped = BTreeMap::new();
    wrapped.insert(
        String::from(FEATURE),
        wrap_kek_for(7, FEATURE, SessionKind::Offline, offline_kek, 503),
    );
    let response = issuer.activate_with(&request, wrapped, None, None);
    ingest_activation(&mut session, response).unwrap();

    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(2, CborValue::int(NOW));
    let validate = payload(&call(&mut session, b.build()).unwrap());
    let online_kek = [0x60; 32];
    let mut refreshed = BTreeMap::new();
    refreshed.insert(
        String::from(FEATURE),
        wrap_kek_for(7, FEATURE, SessionKind::Online, online_kek, 504),
    );
    let ticket = issuer.ticket_with_keks(&validate, refreshed);
    let mut b = op(codes::OP_INGEST_VALIDATE_RESPONSE);
    b.put(1, CborValue::Bytes(ticket));
    b.put(2, CborValue::int(NOW));
    call(&mut session, b.build()).unwrap();

    assert_eq!(
        payload(&unseal_asset(&mut session, FEATURE, NOW).unwrap()),
        online_kek,
        "the ticket's refreshed KEK wins over the credential's offline wrap"
    );
}

#[test]
fn unseal_asset_survives_a_snapshot_round_trip() {
    let mut issuer = Issuer::new();
    let mut session = Session::new(&cfg(&issuer), Box::new(rng(7))).unwrap();
    let request = activation_request(&mut session);
    ingest_keyset(&mut session, &issuer);

    let kek = [0x5A; 32];
    let mut wrapped = BTreeMap::new();
    wrapped.insert(
        String::from(FEATURE),
        wrap_kek_for(7, FEATURE, SessionKind::Offline, kek, 505),
    );
    let response = issuer.activate_with(&request, wrapped, None, None);
    ingest_activation(&mut session, response).unwrap();

    let blob = payload(&call(&mut session, op(codes::OP_SNAPSHOT_EXPORT).build()).unwrap());
    let mut restored = Session::new(&cfg(&issuer), Box::new(rng(8))).unwrap();
    let mut b = op(codes::OP_SNAPSHOT_IMPORT);
    b.put(1, CborValue::Bytes(blob));
    b.put(2, CborValue::int(NOW));
    call(&mut restored, b.build()).unwrap();
    assert_eq!(
        payload(&unseal_asset(&mut restored, FEATURE, NOW).unwrap()),
        kek,
        "the re-opened credential unwraps the same KEK after a persist/restore cycle"
    );
}

#[test]
fn preloaded_keks_cover_an_offline_variant_upgrade() {
    let mut issuer = Issuer::new();
    let mut session = Session::new(&cfg(&issuer), Box::new(rng(7))).unwrap();
    let request = activation_request(&mut session);
    ingest_keyset(&mut session, &issuer);

    // Issued for variant 8 (the older release); this build is variant 7. The credential's own
    // field-21 wrap is a decoy under variant-8 material that must NOT be consulted; the
    // preloaded entry for variant 7 is the one that opens (`preload_n`, proto field 22).
    let kek = [0x5A; 32];
    let mut wrapped = BTreeMap::new();
    wrapped.insert(
        String::from(FEATURE),
        wrap_kek_for(8, FEATURE, SessionKind::Offline, [0xEE; 32], 506),
    );
    let mut preloaded = BTreeMap::new();
    let mut for_current = BTreeMap::new();
    for_current.insert(
        String::from(FEATURE),
        wrap_kek_for(7, FEATURE, SessionKind::Offline, kek, 507),
    );
    preloaded.insert(7_u64, for_current);
    let response = issuer.activate_with(&request, wrapped, Some(preloaded), Some(8));
    ingest_activation(&mut session, response).unwrap();

    assert_eq!(
        payload(&unseal_asset(&mut session, FEATURE, NOW).unwrap()),
        kek,
        "an offline-upgraded build unwraps the preloaded KEK for its own variant"
    );
}

#[test]
fn a_variant_mismatch_without_preloaded_keks_is_rejected() {
    let mut issuer = Issuer::new();
    let mut session = Session::new(&cfg(&issuer), Box::new(rng(7))).unwrap();
    let request = activation_request(&mut session);
    ingest_keyset(&mut session, &issuer);
    let response = issuer.activate_with(&request, BTreeMap::new(), None, Some(8));
    assert_eq!(
        ingest_activation(&mut session, response).err(),
        Some(codes::fatal_code(
            copylocker_core::FatalError::CredentialCorrupt
        )),
        "without a preloaded entry the mismatched credential fails closed"
    );
    assert_eq!(
        unseal_asset(&mut session, FEATURE, NOW).err(),
        Some(codes::ERR_NO_CREDENTIAL)
    );
}

#[test]
fn snapshot_round_trip_preserves_state_and_m() {
    let (mut session, issuer) = activated();
    let before = payload(&derive_m(&mut session, FEATURE, 0, NOW).unwrap());

    let blob = payload(&call(&mut session, op(codes::OP_SNAPSHOT_EXPORT).build()).unwrap());

    let mut restored = Session::new(&cfg(&issuer), Box::new(rng(8))).unwrap();
    let mut b = op(codes::OP_SNAPSHOT_IMPORT);
    b.put(1, CborValue::Bytes(blob.clone()));
    b.put(2, CborValue::int(NOW));
    let summary = call(&mut restored, b.build()).unwrap();
    assert_eq!(state_of(&summary), 2, "active after restore");

    let after = payload(&derive_m(&mut restored, FEATURE, 0, NOW).unwrap());
    assert_eq!(before, after, "M survives a persist/restore cycle");

    // Importing into a non-fresh session is rejected.
    let mut b = op(codes::OP_SNAPSHOT_IMPORT);
    b.put(1, CborValue::Bytes(blob));
    b.put(2, CborValue::int(NOW));
    assert_eq!(
        call(&mut restored, b.build()).err(),
        Some(codes::ERR_BAD_STATE)
    );
}

#[test]
fn a_denied_ticket_stays_denied_across_a_snapshot_round_trip() {
    // The desktop startup restore replays `TicketDenied` for a stored denied ticket; the
    // snapshot import must do the same, or a reload would silently fail open.
    let (mut session, issuer) = activated();

    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(2, CborValue::int(NOW));
    let request = payload(&call(&mut session, b.build()).unwrap());
    let nonce = ValidateRequest::decode(&request).unwrap().nonce_c;
    let denied = issuer.ticket_for(nonce, Verdict::NeedsReactivation, 3);
    let mut b = op(codes::OP_INGEST_VALIDATE_RESPONSE);
    b.put(1, CborValue::Bytes(denied));
    b.put(2, CborValue::int(NOW));
    let summary = call(&mut session, b.build()).unwrap();
    assert_eq!(state_of(&summary), 5, "locked by the denied ticket");
    assert_eq!(
        derive_m(&mut session, FEATURE, 0, NOW).err(),
        Some(codes::ERR_NOT_ENTITLED)
    );

    let blob = payload(&call(&mut session, op(codes::OP_SNAPSHOT_EXPORT).build()).unwrap());
    let mut restored = Session::new(&cfg(&issuer), Box::new(rng(8))).unwrap();
    let mut b = op(codes::OP_SNAPSHOT_IMPORT);
    b.put(1, CborValue::Bytes(blob));
    b.put(2, CborValue::int(NOW));
    let summary = call(&mut restored, b.build()).unwrap();
    assert_eq!(
        state_of(&summary),
        5,
        "the denial survives a persist/restore cycle"
    );
    assert_eq!(
        derive_m(&mut restored, FEATURE, 0, NOW).err(),
        Some(codes::ERR_NOT_ENTITLED),
        "key derivation stays denied after restore"
    );
    assert_eq!(
        unseal_asset(&mut restored, FEATURE, NOW).err(),
        Some(codes::ERR_NOT_ENTITLED),
        "asset unsealing stays denied after restore"
    );
}

#[test]
fn online_validation_arms_the_online_session() {
    let (mut session, issuer) = activated();

    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(2, CborValue::int(NOW));
    let request = payload(&call(&mut session, b.build()).unwrap());
    let decoded = ValidateRequest::decode(&request).unwrap();
    assert!(!decoded.proof.is_empty());

    // The online session root does not exist before the first ticket.
    assert_eq!(
        derive_m(&mut session, FEATURE, 1, NOW).err(),
        Some(codes::ERR_DERIVATION)
    );

    let ticket = issuer.ticket(&request);
    let mut b = op(codes::OP_INGEST_VALIDATE_RESPONSE);
    b.put(1, CborValue::Bytes(ticket));
    b.put(2, CborValue::int(NOW));
    let summary = call(&mut session, b.build()).unwrap();
    assert_eq!(state_of(&summary), 2);
    assert_eq!(summary.get(7).and_then(CborValue::as_uint), Some(0));

    let offline = payload(&derive_m(&mut session, FEATURE, 0, NOW).unwrap());
    let online = payload(&derive_m(&mut session, FEATURE, 1, NOW).unwrap());
    assert_eq!(online.len(), 32);
    assert_ne!(offline, online, "online and offline roots differ");
}

#[test]
fn validate_request_signs_the_telemetry_block() {
    let (mut session, issuer) = activated();

    let mut feature_hits = BTreeMap::new();
    feature_hits.insert(String::from(FEATURE), 3_u64);
    let block = TelemetryBlock {
        consent_version: 2,
        window_start: (NOW - 3_600) as u64,
        session_count: 5,
        session_duration_histogram: [1, 2, 1, 1],
        feature_hits,
        days_active: 4,
    };
    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(1, CborValue::Bytes(block.encode()));
    b.put(2, CborValue::int(NOW));
    let request = payload(&call(&mut session, b.build()).unwrap());

    // The block round-trips at proto key 11 of the built request.
    let decoded = ValidateRequest::decode(&request).unwrap();
    assert_eq!(decoded.telemetry, Some(block));

    // The device proof verifies over the telemetry-inclusive proof input...
    assert!(verify_device_proof(&issuer, &decoded));
    // ...and not once the block is stripped: the signature covers key 11.
    let mut stripped = decoded.clone();
    stripped.telemetry = None;
    assert!(
        !verify_device_proof(&issuer, &stripped),
        "a re-encoded, telemetry-free proof input must not verify"
    );
}

#[test]
fn validate_request_without_telemetry_keeps_the_legacy_shape() {
    let (mut session, issuer) = activated();

    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(2, CborValue::int(NOW));
    let request = payload(&call(&mut session, b.build()).unwrap());

    // Key 11 is absent from the wire bytes, and the proof still verifies.
    let value = decode_canonical(&request, TEST_LIMITS).unwrap();
    assert!(
        value.get(11).is_none(),
        "no telemetry key without the op field"
    );
    let decoded = ValidateRequest::decode(&request).unwrap();
    assert_eq!(decoded.telemetry, None);
    assert!(verify_device_proof(&issuer, &decoded));
}

#[test]
fn malformed_telemetry_blocks_are_rejected_without_panicking() {
    let (mut session, _issuer) = activated();

    // Non-CBOR bytes.
    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(1, CborValue::Bytes(vec![0xff, 0xff]));
    b.put(2, CborValue::int(NOW));
    assert_eq!(
        call(&mut session, b.build()).err(),
        Some(codes::ERR_BAD_FIELD)
    );
    // Beyond the block size cap (rejected before parsing).
    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(
        1,
        CborValue::Bytes(vec![0xa0; MAX_TELEMETRY_BLOCK_BYTES + 1]),
    );
    b.put(2, CborValue::int(NOW));
    assert_eq!(
        call(&mut session, b.build()).err(),
        Some(codes::ERR_BAD_FIELD)
    );
    // The wrong field type.
    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(1, CborValue::Uint(7));
    b.put(2, CborValue::int(NOW));
    assert_eq!(
        call(&mut session, b.build()).err(),
        Some(codes::ERR_BAD_FIELD)
    );
    // Canonical CBOR that is not a telemetry block.
    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(1, CborValue::Bytes(MapBuilder::new().finish()));
    b.put(2, CborValue::int(NOW));
    assert_eq!(
        call(&mut session, b.build()).err(),
        Some(codes::ERR_BAD_FIELD)
    );

    // The session is unharmed: a plain validate build still works.
    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(2, CborValue::int(NOW));
    assert!(call(&mut session, b.build()).is_ok());
}

/// Verify a built validate request's device proof, mirroring the server's check.
fn verify_device_proof(issuer: &Issuer, request: &ValidateRequest) -> bool {
    let device_vk = FastSig::decode_vk(issuer.device_sig_vk.as_ref().unwrap()).unwrap();
    FastSig::verify(
        &device_vk,
        DomainCtx::new(ArtifactKind::ValidateRequest, ClStd1::SUITE_ID, PRODUCT),
        &request.proof_input(),
        &Signature(request.proof.clone()),
    )
    .is_ok()
}

#[test]
fn a_kill_order_revokes_and_wipes() {
    let (mut session, issuer) = activated();

    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(2, CborValue::int(NOW));
    let request = payload(&call(&mut session, b.build()).unwrap());

    let kill = issuer.kill_order(&request);
    let mut b = op(codes::OP_INGEST_VALIDATE_RESPONSE);
    b.put(1, CborValue::Bytes(kill));
    b.put(2, CborValue::int(NOW));
    let summary = call(&mut session, b.build()).unwrap();
    assert_eq!(state_of(&summary), 6, "revoked");
    assert!(
        effects_of(&summary).contains(&codes::EFFECT_WIPE_ALL),
        "the host must be told to wipe storage"
    );

    assert_eq!(
        derive_m(&mut session, FEATURE, 0, NOW).err(),
        Some(codes::ERR_NO_CREDENTIAL)
    );
    let summary = call(&mut session, op(codes::OP_STATE_QUERY).build()).unwrap();
    assert_eq!(summary.get(6).and_then(CborValue::as_uint), Some(0));
}

#[test]
fn a_one_year_clock_rollback_locks_after_the_threshold() {
    let (mut session, _issuer) = activated();

    // First rollback: Active → NeedsRevalidation with a validation request.
    let summary = tick(&mut session, NOW - YEAR);
    assert_eq!(state_of(&summary), 3, "needs revalidation");
    assert!(effects_of(&summary).contains(&codes::EFFECT_SEND_VALIDATION));

    // M still derives during NeedsRevalidation (fail-open window).
    assert!(derive_m(&mut session, FEATURE, 0, NOW - YEAR).is_ok());

    // Repeated rollbacks past the threshold lock the client.
    tick(&mut session, NOW - YEAR);
    tick(&mut session, NOW - YEAR);
    let summary = tick(&mut session, NOW - YEAR);
    assert_eq!(state_of(&summary), 5, "locked");
    assert_eq!(
        derive_m(&mut session, FEATURE, 0, NOW - YEAR).err(),
        Some(codes::ERR_NOT_ENTITLED)
    );
}

#[test]
fn a_tampered_credential_fails_closed() {
    let mut issuer = Issuer::new();
    let mut session = Session::new(&cfg(&issuer), Box::new(rng(7))).unwrap();
    call(&mut session, op(codes::OP_DEVICE_KEYGEN).build()).unwrap();
    let mut b = op(codes::OP_BUILD_ACTIVATE_REQUEST);
    b.put(1, CborValue::Text(String::from("CL1-TEST-KEY")));
    b.put(2, CborValue::int(NOW));
    let request = payload(&call(&mut session, b.build()).unwrap());
    let mut b = op(codes::OP_INGEST_KEYSET);
    b.put(1, CborValue::Bytes(issuer.keyset()));
    b.put(2, CborValue::int(NOW));
    call(&mut session, b.build()).unwrap();

    let mut envelope = Envelope::decode(&issuer.activate(&request)).unwrap();
    envelope.sig[0] ^= 0xff;
    let mut b = op(codes::OP_INGEST_ACTIVATE_RESPONSE);
    b.put(1, CborValue::Bytes(envelope.encode()));
    b.put(2, CborValue::int(NOW));
    assert_eq!(
        call(&mut session, b.build()).err(),
        Some(codes::fatal_code(
            copylocker_core::FatalError::SignatureInvalid
        ))
    );
    let summary = call(&mut session, op(codes::OP_STATE_QUERY).build()).unwrap();
    assert_eq!(state_of(&summary), 7, "tampered");
}

#[test]
fn ticket_semantic_violations_fail_closed() {
    // Nonce mismatch.
    let (mut session, issuer) = activated();
    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(2, CborValue::int(NOW));
    call(&mut session, b.build()).unwrap();
    let mut b = op(codes::OP_INGEST_VALIDATE_RESPONSE);
    b.put(
        1,
        CborValue::Bytes(issuer.ticket_for([0x99; 32], Verdict::Ok, 3)),
    );
    b.put(2, CborValue::int(NOW));
    assert_eq!(call(&mut session, b.build()).err(), Some(103));

    // Security-floor regression.
    let (mut session, issuer) = activated();
    let mut b = op(codes::OP_BUILD_VALIDATE_REQUEST);
    b.put(2, CborValue::int(NOW));
    let request = payload(&call(&mut session, b.build()).unwrap());
    let nonce = ValidateRequest::decode(&request).unwrap().nonce_c;
    let mut b = op(codes::OP_INGEST_VALIDATE_RESPONSE);
    b.put(
        1,
        CborValue::Bytes(issuer.ticket_for(nonce, Verdict::Ok, 2)),
    );
    b.put(2, CborValue::int(NOW));
    assert_eq!(call(&mut session, b.build()).err(), Some(108));

    // A validate response with no pending request is a lifecycle error, not a wipe.
    let (mut session, issuer) = activated();
    let ticket = issuer.ticket_for([0x00; 32], Verdict::Ok, 3);
    let mut b = op(codes::OP_INGEST_VALIDATE_RESPONSE);
    b.put(1, CborValue::Bytes(ticket));
    b.put(2, CborValue::int(NOW));
    assert_eq!(
        call(&mut session, b.build()).err(),
        Some(codes::ERR_NO_PENDING)
    );
    let summary = call(&mut session, op(codes::OP_STATE_QUERY).build()).unwrap();
    assert_eq!(state_of(&summary), 2, "still active");
}

#[test]
fn user_deactivate_wipes_locally() {
    let (mut session, _issuer) = activated();
    let mut b = op(codes::OP_BUILD_DEACTIVATE_REQUEST);
    b.put(2, CborValue::int(NOW));
    let request = payload(&call(&mut session, b.build()).unwrap());
    assert!(copylocker_proto::DeactivateRequest::decode(&request).is_ok());

    let mut b = op(codes::OP_EVENT);
    b.put(1, CborValue::Uint(codes::EVENT_USER_DEACTIVATE));
    b.put(2, CborValue::int(NOW));
    let summary = call(&mut session, b.build()).unwrap();
    assert_eq!(state_of(&summary), 0, "unlicensed after deactivate");
    assert!(effects_of(&summary).contains(&codes::EFFECT_WIPE_ALL));
}
