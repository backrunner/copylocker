use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use copylocker_core::{CoreError, FatalError, KeyMaterial, SessionKind, TransientError};
use copylocker_fingerprint::{FingerprintError, FingerprintProvider};
use copylocker_proto::keywrap::{seal_credential_secret, CredentialSealContext};
use copylocker_proto::{
    ActivationRequest, ClientInfo, DeactivateRequest, Envelope, EpochCert, Keyset, KillOrder,
    MachineCredential, RevocationBatch, ValidateRequest, ValidationTicket,
};
use copylocker_store::{KeyStore, StoreError};
use copylocker_suite::cbor::{CborValue, MapBuilder};
use copylocker_suite::{
    AttrValue, CryptoSuite, DeviceAttrs, DomainCtx, EnvClass, EnvEvidence, HashScheme,
    KeyEncapsulation, Secret, SharedSecret, Signature, SignatureScheme,
};
use copylocker_suite_std::{ClStd1, FastSig, HybridSig};
use copylocker_types::{
    ArtifactKind, Digest, Entitlements, EpochId, KillReason, LicenseId, LicenseState, MachineId,
    Mode, Verdict, PROTO_VER,
};
use tokio::sync::Notify;

use super::*;

const PRODUCT_ID: &str = "test-product";
const FEATURE_ID: &str = "export.pdf";
const MACHINE_ID: MachineId = MachineId([0x22; 16]);
const LICENSE_ID: LicenseId = LicenseId([0x11; 16]);
const EPOCH_ID: EpochId = EpochId([0x33; 8]);

#[derive(Default)]
struct MemoryStore {
    value: Mutex<Option<Vec<u8>>>,
    wipes: AtomicUsize,
}

impl MemoryStore {
    fn is_empty(&self) -> bool {
        self.value.lock().unwrap().is_none()
    }
}

impl KeyStore for MemoryStore {
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.value.lock().unwrap().clone())
    }

    fn save(&self, blob: &[u8]) -> Result<(), StoreError> {
        *self.value.lock().unwrap() = Some(blob.to_vec());
        Ok(())
    }

    fn wipe(&self) -> Result<(), StoreError> {
        *self.value.lock().unwrap() = None;
        self.wipes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct FixedFingerprint;

impl FingerprintProvider for FixedFingerprint {
    fn collect(&self) -> Result<DeviceAttrs, FingerprintError> {
        let mut attrs = DeviceAttrs::new();
        attrs.insert("machine_id", AttrValue::text("client-test-machine"));
        attrs.set_env_class(EnvClass::Bare);
        Ok(attrs)
    }
}

#[derive(Clone)]
enum ValidationBehavior {
    Ok,
    Timeout,
    ServerError,
    Malformed,
    BadSignature,
    NonceMismatch,
    FloorRollback,
    Verdict(Verdict),
    Kill,
    BadContentType,
    Oversized,
    Wait(Arc<Notify>),
}

#[derive(Clone, Copy)]
enum EndpointFailure {
    TransportTooLarge,
    BadContentType,
    MalformedBody,
}

struct FakeServer {
    root_vk: Vec<u8>,
    epoch_certificate: Vec<u8>,
    epoch_sk: Vec<u8>,
    fast_sk: Vec<u8>,
    behaviors: Mutex<VecDeque<ValidationBehavior>>,
    device_sig_vk: Mutex<Option<Vec<u8>>>,
    validation_calls: AtomicUsize,
    revocation_epoch: AtomicU64,
    revoked_license_at: AtomicU64,
    revocation_requests: Mutex<Vec<u64>>,
    activation_failure: Mutex<Option<EndpointFailure>>,
    deactivation_failure: Mutex<Option<EndpointFailure>>,
    seed: AtomicU64,
}

impl FakeServer {
    fn new() -> Arc<Self> {
        let now = now();
        let mut rng = copylocker_suite_std::test_rng(1);
        let (root_sk, root_vk) = HybridSig::generate(&mut rng);
        let (epoch_sk, epoch_vk) = HybridSig::generate(&mut rng);
        let (fast_sk, fast_vk) = FastSig::generate(&mut rng);
        let root_vk = HybridSig::encode_vk(&root_vk);
        let certificate = EpochCert {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            epoch_id: EPOCH_ID,
            vk: HybridSig::encode_vk(&epoch_vk),
            vk_fast: FastSig::encode_vk(&fast_vk),
            not_before: now - 86_400,
            not_after: now + 86_400,
            product_scope: Some(String::from(PRODUCT_ID)),
            issuer_vk_digest: <ClStd1 as CryptoSuite>::Hash::hash(&root_vk),
        };
        let epoch_certificate = Envelope::seal::<HybridSig, _>(
            &certificate,
            ClStd1::SUITE_ID,
            PRODUCT_ID,
            None,
            &root_sk,
        )
        .unwrap()
        .encode();
        Arc::new(Self {
            root_vk,
            epoch_certificate,
            epoch_sk: HybridSig::encode_sk(&epoch_sk),
            fast_sk: FastSig::encode_sk(&fast_sk),
            behaviors: Mutex::new(VecDeque::new()),
            device_sig_vk: Mutex::new(None),
            validation_calls: AtomicUsize::new(0),
            revocation_epoch: AtomicU64::new(0),
            revoked_license_at: AtomicU64::new(u64::MAX),
            revocation_requests: Mutex::new(Vec::new()),
            activation_failure: Mutex::new(None),
            deactivation_failure: Mutex::new(None),
            seed: AtomicU64::new(100),
        })
    }

    fn enqueue(&self, behavior: ValidationBehavior) {
        self.behaviors.lock().unwrap().push_back(behavior);
    }

    fn fail_activation_with(&self, failure: EndpointFailure) {
        *self.activation_failure.lock().unwrap() = Some(failure);
    }

    fn fail_deactivation_with(&self, failure: EndpointFailure) {
        *self.deactivation_failure.lock().unwrap() = Some(failure);
    }

    fn sealed_asset(&self, plaintext: &[u8]) -> Vec<u8> {
        let seed = self.seed.fetch_add(1, Ordering::SeqCst);
        let mut rng = copylocker_suite_std::test_rng(seed);
        copylocker_proto::SealedAsset::seal::<ClStd1>(
            PRODUCT_ID,
            7,
            FEATURE_ID,
            "fixture.bin",
            plaintext,
            &Secret::new([0xaa; 32]),
            &mut rng,
        )
        .unwrap()
        .encode()
    }

    fn olk_bundle(&self, config: &Config, binding: Option<Fingerprint>) -> String {
        let seed = self.seed.fetch_add(1, Ordering::SeqCst);
        let mut rng = copylocker_suite_std::test_rng(seed);
        let issued_at = now();
        let mut entitlements = Entitlements::default();
        entitlements.features.insert(String::from(FEATURE_ID));
        entitlements.tier_id = String::from("pro");
        entitlements.tier_label = String::from("Pro");
        entitlements.catalog_version = 1;
        let key_seed = [0x5a; 32];
        let offline_nonce = [0x44; 32];
        let binding_input = copylocker_proto::olk_binding_fingerprint(binding.as_ref());
        let material = KeyMaterial::bind_olk::<ClStd1>(
            &key_seed,
            &binding_input,
            config.evidence(),
            PRODUCT_ID,
            LICENSE_ID,
            MACHINE_ID,
            EPOCH_ID,
            config.client_info().variant_id,
            *config.variant_const(),
            offline_nonce,
        )
        .unwrap();
        let mut wrapped_keks = BTreeMap::new();
        wrapped_keks.insert(
            String::from(FEATURE_ID),
            material
                .wrap_kek::<ClStd1>(
                    LicenseState::Active,
                    &entitlements,
                    FEATURE_ID,
                    SessionKind::Offline,
                    &Secret::new([0xaa; 32]),
                    &mut rng,
                )
                .unwrap(),
        );
        let license = copylocker_proto::OfflineLicenseKey {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            product_id: String::from(PRODUCT_ID),
            license_id: LICENSE_ID,
            entitlements,
            issued_at,
            not_after: issued_at + 86_400,
            bound_fingerprint: binding,
            max_seats: 1,
            epoch_id: EPOCH_ID,
            machine_id: MACHINE_ID,
            offline_nonce,
            key_seed,
            build_fingerprint: config.client_info().build_fingerprint.clone(),
            variant_id: config.client_info().variant_id,
            security_floor: 3,
            revocation_epoch: self.revocation_epoch.load(Ordering::SeqCst),
            wrapped_keks,
        };
        let epoch_sk = HybridSig::decode_sk(&self.epoch_sk).unwrap();
        let envelope = Envelope::seal::<HybridSig, _>(
            &license,
            ClStd1::SUITE_ID,
            PRODUCT_ID,
            Some(EPOCH_ID),
            &epoch_sk,
        )
        .unwrap();
        copylocker_proto::OfflineLicenseBundle::new(
            envelope.encode(),
            vec![self.epoch_certificate.clone()],
        )
        .to_armored()
    }

    fn offline_response(&self, request_bytes: &[u8]) -> Vec<u8> {
        let request = ActivationRequest::decode(request_bytes).unwrap();
        let credential = self.activate(request_bytes).unwrap().body;
        let server_time = now();
        let response = copylocker_proto::ActivationResponse {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            nonce_c_echo: request.nonce_c,
            credential,
            chain: vec![self.epoch_certificate.clone()],
            server_time,
            valid_until: server_time + 3_600,
        };
        let epoch_sk = HybridSig::decode_sk(&self.epoch_sk).unwrap();
        Envelope::seal::<HybridSig, _>(
            &response,
            ClStd1::SUITE_ID,
            PRODUCT_ID,
            Some(EPOCH_ID),
            &epoch_sk,
        )
        .unwrap()
        .encode()
    }

    fn response(body: Vec<u8>) -> TransportResponse {
        TransportResponse {
            status: 200,
            content_type: Some(String::from("application/cbor")),
            protocol_version: Some(String::from("1")),
            retry_after: None,
            body,
        }
    }

    async fn handle(&self, request: TransportRequest) -> Result<TransportResponse, TransportError> {
        let parsed = url::Url::parse(&request.url).map_err(|_| TransportError::InvalidRequest)?;
        match (request.method, parsed.path()) {
            (HttpMethod::Post, "/v1/activate") => {
                if let Some(failure) = *self.activation_failure.lock().unwrap() {
                    return Self::endpoint_failure(failure);
                }
                self.activate(&request.body)
            }
            (HttpMethod::Get, "/v1/keys") => Ok(Self::response(
                Keyset {
                    proto_ver: PROTO_VER,
                    epoch_certificates: vec![self.epoch_certificate.clone()],
                    revocation_epoch: self.revocation_epoch.load(Ordering::SeqCst),
                }
                .encode(),
            )),
            (HttpMethod::Get, "/v1/revocations") => self.revocations(&parsed),
            (HttpMethod::Post, "/v1/validate") => self.validate(&request.body).await,
            (HttpMethod::Post, "/v1/deactivate") => {
                if let Some(failure) = *self.deactivation_failure.lock().unwrap() {
                    return Self::endpoint_failure(failure);
                }
                let deactivate = DeactivateRequest::decode(&request.body)
                    .map_err(|_| TransportError::Failure)?;
                self.verify_device_proof(
                    ArtifactKind::DeactivateRequest,
                    &deactivate.proof_input(),
                    &deactivate.proof,
                )?;
                let mut response = MapBuilder::new();
                response.put(0, CborValue::Bool(true));
                Ok(Self::response(response.finish()))
            }
            _ => Err(TransportError::InvalidRequest),
        }
    }

    fn endpoint_failure(failure: EndpointFailure) -> Result<TransportResponse, TransportError> {
        match failure {
            EndpointFailure::TransportTooLarge => Err(TransportError::ResponseTooLarge),
            EndpointFailure::BadContentType => {
                let mut response = Self::response(Vec::new());
                response.content_type = Some(String::from("text/html"));
                Ok(response)
            }
            EndpointFailure::MalformedBody => Ok(Self::response(vec![0xff])),
        }
    }

    fn revocations(&self, request_url: &url::Url) -> Result<TransportResponse, TransportError> {
        let since = request_url
            .query_pairs()
            .find_map(|(name, value)| {
                if name == "since" {
                    value.parse::<u64>().ok()
                } else {
                    None
                }
            })
            .ok_or(TransportError::InvalidRequest)?;
        let target = self.revocation_epoch.load(Ordering::SeqCst);
        if since == 0 || since > target {
            return Err(TransportError::InvalidRequest);
        }
        self.revocation_requests.lock().unwrap().push(since);
        let revoked_license_ids = if self.revoked_license_at.load(Ordering::SeqCst) == since {
            vec![LICENSE_ID]
        } else {
            Vec::new()
        };
        let batch = RevocationBatch {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            from_epoch: since,
            to_epoch: since,
            issued_at: now(),
            revoked_license_ids,
            revoked_machine_ids: Vec::new(),
            revoked_epoch_ids: Vec::new(),
            bloom_filter: None,
        };
        let epoch_sk = HybridSig::decode_sk(&self.epoch_sk).map_err(|_| TransportError::Failure)?;
        let envelope = Envelope::seal::<HybridSig, _>(
            &batch,
            ClStd1::SUITE_ID,
            PRODUCT_ID,
            Some(EPOCH_ID),
            &epoch_sk,
        )
        .map_err(|_| TransportError::Failure)?;
        Ok(Self::response(envelope.encode()))
    }

    fn activate(&self, body: &[u8]) -> Result<TransportResponse, TransportError> {
        let request = ActivationRequest::decode(body).map_err(|_| TransportError::Failure)?;
        let device_vk =
            FastSig::decode_vk(&request.device_sig_vk).map_err(|_| TransportError::Failure)?;
        FastSig::verify(
            &device_vk,
            DomainCtx::new(
                ArtifactKind::ActivationRequest,
                ClStd1::SUITE_ID,
                PRODUCT_ID,
            ),
            &request.proof_input(),
            &Signature(request.proof.clone()),
        )
        .map_err(|_| TransportError::Failure)?;
        *self.device_sig_vk.lock().unwrap() = Some(request.device_sig_vk.clone());

        let device_ek = <ClStd1 as CryptoSuite>::Kem::decode_ek(&request.device_kem_ek)
            .map_err(|_| TransportError::Failure)?;
        let seed = self.seed.fetch_add(1, Ordering::SeqCst);
        let mut rng = copylocker_suite_std::test_rng(seed);
        let (kem_ct, kem_shared) = <ClStd1 as CryptoSuite>::Kem::encap(&device_ek, &mut rng)
            .map_err(|_| TransportError::Failure)?;
        let offline_nonce = [0x44; 32];
        let context = CredentialSealContext {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            product_id: PRODUCT_ID,
            license_id: LICENSE_ID,
            machine_id: MACHINE_ID,
            fingerprint: &request.fingerprint,
            kem_ct: kem_ct.as_bytes(),
            offline_nonce: &offline_nonce,
            epoch_id: EPOCH_ID,
            variant_id: request.client_info.variant_id,
        };
        let sealed_cs = seal_credential_secret::<ClStd1>(
            &kem_shared,
            &context,
            &Secret::new([0x55; 32]),
            &mut rng,
        )
        .map_err(|_| TransportError::Failure)?;
        let issued_at = now();
        let mut entitlements = Entitlements::default();
        entitlements.features.insert(String::from(FEATURE_ID));
        entitlements.tier_id = String::from("pro");
        entitlements.tier_label = String::from("Pro");
        entitlements.catalog_version = 1;
        let material = KeyMaterial::bind::<ClStd1>(
            &SharedSecret::new([0x55; 32]),
            &request.fingerprint,
            &EnvEvidence {
                module_digest: Digest([0x99; 32]),
                build_fingerprint: b"build-test".to_vec(),
                extra: Vec::new(),
            },
            PRODUCT_ID,
            LICENSE_ID,
            MACHINE_ID,
            EPOCH_ID,
            request.client_info.variant_id,
            [0x88; 32],
            offline_nonce,
        )
        .map_err(|_| TransportError::Failure)?;
        let mut wrapped_keks = BTreeMap::new();
        wrapped_keks.insert(
            String::from(FEATURE_ID),
            material
                .wrap_kek::<ClStd1>(
                    LicenseState::Active,
                    &entitlements,
                    FEATURE_ID,
                    SessionKind::Offline,
                    &Secret::new([0xaa; 32]),
                    &mut rng,
                )
                .map_err(|_| TransportError::Failure)?,
        );
        let credential = MachineCredential {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            product_id: String::from(PRODUCT_ID),
            license_id: LICENSE_ID,
            machine_id: MACHINE_ID,
            fingerprint: request.fingerprint,
            kem_ct: kem_ct.0,
            sealed_cs,
            offline_nonce,
            entitlements,
            issued_at,
            not_after: issued_at + 86_400,
            refresh_after: issued_at + 3_600,
            grace_seconds: 3_600,
            mode: Mode::OfflineHybrid,
            revocation_epoch: self.revocation_epoch.load(Ordering::SeqCst),
            epoch_id: EPOCH_ID,
            build_fingerprint: Some(request.client_info.build_fingerprint),
            policy_flags: None,
            security_floor: 3,
            variant_id: request.client_info.variant_id,
            wrapped_keks,
            preloaded_keks: None,
        };
        let epoch_sk = HybridSig::decode_sk(&self.epoch_sk).map_err(|_| TransportError::Failure)?;
        let envelope = Envelope::seal::<HybridSig, _>(
            &credential,
            ClStd1::SUITE_ID,
            PRODUCT_ID,
            Some(EPOCH_ID),
            &epoch_sk,
        )
        .map_err(|_| TransportError::Failure)?;
        Ok(Self::response(envelope.encode()))
    }

    async fn validate(&self, body: &[u8]) -> Result<TransportResponse, TransportError> {
        self.validation_calls.fetch_add(1, Ordering::SeqCst);
        let request = ValidateRequest::decode(body).map_err(|_| TransportError::Failure)?;
        self.verify_device_proof(
            ArtifactKind::ValidateRequest,
            &request.proof_input(),
            &request.proof,
        )?;
        let behavior = self
            .behaviors
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(ValidationBehavior::Ok);
        if let ValidationBehavior::Wait(notify) = &behavior {
            notify.notified().await;
        }
        match &behavior {
            ValidationBehavior::Timeout => return Err(TransportError::Timeout),
            ValidationBehavior::ServerError => {
                return Ok(TransportResponse {
                    status: 503,
                    content_type: Some(String::from("application/cbor")),
                    protocol_version: Some(String::from("1")),
                    retry_after: None,
                    body: Vec::new(),
                });
            }
            ValidationBehavior::Malformed => return Ok(Self::response(vec![0xff])),
            ValidationBehavior::Oversized => {
                return Ok(Self::response(vec![0; ARTIFACT_RESPONSE_LIMIT + 1]));
            }
            _ => {}
        }

        let fast_sk = FastSig::decode_sk(&self.fast_sk).map_err(|_| TransportError::Failure)?;
        let revocation_epoch = self.revocation_epoch.load(Ordering::SeqCst);
        if matches!(&behavior, ValidationBehavior::Kill) {
            let order = KillOrder {
                proto_ver: PROTO_VER,
                suite_id: ClStd1::SUITE_ID,
                machine_id: MACHINE_ID,
                nonce_c_echo: request.nonce_c,
                server_time: now(),
                reason: KillReason::Refund,
                user_message: Some(String::from("refunded")),
                revocation_epoch,
            };
            let envelope = Envelope::seal::<FastSig, _>(
                &order,
                ClStd1::SUITE_ID,
                PRODUCT_ID,
                Some(EPOCH_ID),
                &fast_sk,
            )
            .map_err(|_| TransportError::Failure)?;
            return Ok(Self::response(envelope.encode()));
        }

        let server_time = now();
        let verdict = match &behavior {
            ValidationBehavior::Verdict(verdict) => *verdict,
            _ => Verdict::Ok,
        };
        let ticket = ValidationTicket {
            proto_ver: PROTO_VER,
            suite_id: ClStd1::SUITE_ID,
            machine_id: MACHINE_ID,
            nonce_c_echo: if matches!(&behavior, ValidationBehavior::NonceMismatch) {
                [0x99; 32]
            } else {
                request.nonce_c
            },
            server_nonce: [0x66; 32],
            server_time,
            next_refresh_after: server_time + 3_600,
            not_after: server_time + 86_400,
            revocation_epoch,
            verdict,
            entitlements: None,
            epoch_id: EPOCH_ID,
            suspicion_score: Some(0),
            security_floor: if matches!(&behavior, ValidationBehavior::FloorRollback) {
                2
            } else {
                3
            },
            release_status: Some(0),
            wrapped_keks: None,
            refresh_now: None,
        };
        let mut envelope = Envelope::seal::<FastSig, _>(
            &ticket,
            ClStd1::SUITE_ID,
            PRODUCT_ID,
            Some(EPOCH_ID),
            &fast_sk,
        )
        .map_err(|_| TransportError::Failure)?;
        if matches!(&behavior, ValidationBehavior::BadSignature) {
            envelope.sig[0] ^= 0xff;
        }
        let mut response = Self::response(envelope.encode());
        if matches!(&behavior, ValidationBehavior::BadContentType) {
            response.content_type = Some(String::from("text/html"));
        }
        Ok(response)
    }

    fn verify_device_proof(
        &self,
        kind: ArtifactKind,
        input: &[u8],
        proof: &[u8],
    ) -> Result<(), TransportError> {
        let encoded = self
            .device_sig_vk
            .lock()
            .unwrap()
            .clone()
            .ok_or(TransportError::Failure)?;
        let key = FastSig::decode_vk(&encoded).map_err(|_| TransportError::Failure)?;
        FastSig::verify(
            &key,
            DomainCtx::new(kind, ClStd1::SUITE_ID, PRODUCT_ID),
            input,
            &Signature(proof.to_vec()),
        )
        .map_err(|_| TransportError::Failure)
    }
}

#[derive(Clone)]
struct FakeTransport(Arc<FakeServer>);

impl Transport for FakeTransport {
    fn send(&self, request: TransportRequest) -> crate::TransportFuture<'_> {
        let server = Arc::clone(&self.0);
        Box::pin(async move { server.handle(request).await })
    }
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn config(server: &FakeServer) -> Config {
    let info = ClientInfo {
        app_version: String::from("1.0.0"),
        sdk_version: String::from("0.1.0"),
        os: String::from("test"),
        arch: String::from("test"),
        build_fingerprint: String::from("build-test"),
        release_id: String::from("release-test"),
        variant_id: 7,
        supported_suites: vec![ClStd1::SUITE_ID],
        supported_variants: vec![7],
    };
    Config::new(
        "https://license.test/",
        "com.example.copylocker-test",
        PRODUCT_ID,
        info,
        server.root_vk.clone(),
        vec![0x77; 32],
        [0x88; 32],
        EnvEvidence {
            module_digest: Digest([0x99; 32]),
            build_fingerprint: b"build-test".to_vec(),
            extra: Vec::new(),
        },
    )
    .unwrap()
}

async fn client(server: Arc<FakeServer>, store: Arc<MemoryStore>) -> CopyLockerClient<ClStd1> {
    CopyLockerClient::with_components(
        config(&server),
        Arc::new(FakeTransport(server)),
        store,
        &FixedFingerprint,
    )
    .await
    .unwrap()
}

async fn activated() -> (CopyLockerClient<ClStd1>, Arc<FakeServer>, Arc<MemoryStore>) {
    let server = FakeServer::new();
    let store = Arc::new(MemoryStore::default());
    let client = client(Arc::clone(&server), Arc::clone(&store)).await;
    client.activate("CL1-TEST-LICENSE").await.unwrap();
    (client, server, store)
}

#[tokio::test]
async fn activation_restart_preserves_the_feature_key() {
    let (first, server, store) = activated().await;
    let first_key = *first.feature_key(FEATURE_ID).unwrap().expose();
    drop(first);

    let restarted = client(server, store).await;
    let restarted_key = *restarted.feature_key(FEATURE_ID).unwrap().expose();
    assert_eq!(first_key, restarted_key);
}

#[tokio::test]
async fn unseal_uses_the_wrapped_kek_and_authenticates_metadata() {
    let (client, server, _) = activated().await;
    let sealed = server.sealed_asset(b"protected payload");
    assert_eq!(
        client.unseal(FEATURE_ID, &sealed).unwrap(),
        b"protected payload"
    );

    let mut changed = copylocker_proto::SealedAsset::decode(&sealed).unwrap();
    changed.asset_id.push('x');
    assert!(matches!(
        client.unseal(FEATURE_ID, &changed.encode()),
        Err(CoreError::AssetCorrupt)
    ));
    assert!(matches!(
        client.unseal("other-feature", &sealed),
        Err(CoreError::AssetCorrupt)
    ));
}

#[tokio::test]
async fn challenge_returns_feature_bound_material_not_a_verdict() {
    let (client, _, _) = activated().await;
    let request = copylocker_proto::FeatureChallenge::new(FEATURE_ID, vec![0x31; 32])
        .unwrap()
        .encode();
    let first =
        copylocker_proto::FeatureResponse::decode(&client.challenge(&request).unwrap()).unwrap();
    let repeated =
        copylocker_proto::FeatureResponse::decode(&client.challenge(&request).unwrap()).unwrap();
    assert_eq!(first, repeated);
    assert_ne!(first.material, [0; 32]);

    let different = copylocker_proto::FeatureChallenge::new(FEATURE_ID, vec![0x32; 32])
        .unwrap()
        .encode();
    let different =
        copylocker_proto::FeatureResponse::decode(&client.challenge(&different).unwrap()).unwrap();
    assert_ne!(first.material, different.material);

    let missing = copylocker_proto::FeatureChallenge::new("other-feature", vec![0x31; 32])
        .unwrap()
        .encode();
    assert!(matches!(
        client.challenge(&missing),
        Err(CoreError::NotEntitled)
    ));
    assert!(matches!(
        client.challenge(&[0xff]),
        Err(CoreError::AssetCorrupt)
    ));
}

#[tokio::test]
async fn offline_request_response_installs_a_device_bound_credential() {
    let server = FakeServer::new();
    let store = Arc::new(MemoryStore::default());
    let client = client(Arc::clone(&server), Arc::clone(&store)).await;
    let request = client.build_offline_request("CL1-OFFLINE-LICENSE").unwrap();
    assert!(store.value.lock().unwrap().is_some());
    let response = server.offline_response(&request);
    client.import_offline_response(&response).unwrap();
    assert_eq!(client.state(), LicenseState::Active);
    assert!(client.feature_key(FEATURE_ID).is_ok());
}

#[tokio::test]
async fn offline_response_must_match_the_pending_nonce() {
    let server = FakeServer::new();
    let store = Arc::new(MemoryStore::default());
    let client = client(Arc::clone(&server), Arc::clone(&store)).await;
    let request = client.build_offline_request("CL1-OFFLINE-LICENSE").unwrap();
    let mut envelope = Envelope::decode(&server.offline_response(&request)).unwrap();
    let mut response: copylocker_proto::ActivationResponse = envelope.peek_unverified().unwrap();
    response.nonce_c_echo = [0xfe; 32];
    let epoch_sk = HybridSig::decode_sk(&server.epoch_sk).unwrap();
    envelope = Envelope::seal::<HybridSig, _>(
        &response,
        ClStd1::SUITE_ID,
        PRODUCT_ID,
        Some(EPOCH_ID),
        &epoch_sk,
    )
    .unwrap();
    assert!(matches!(
        client.import_offline_response(&envelope.encode()),
        Err(OfflineError::Fatal(FatalError::NonceMismatch))
    ));
    assert_eq!(client.state(), LicenseState::Tampered);
    assert!(store.is_empty());
}

#[tokio::test]
async fn concurrent_triggers_share_one_validation_flight() {
    let (client, server, _) = activated().await;
    let release = Arc::new(Notify::new());
    server.enqueue(ValidationBehavior::Wait(Arc::clone(&release)));
    let validating = {
        let client = client.clone();
        tokio::spawn(async move { client.validate().await })
    };
    for _ in 0..100 {
        if server.validation_calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(server.validation_calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        client.validate().await,
        Err(ValidationError::AlreadyInFlight)
    ));
    for _ in 0..8 {
        client.hint_online();
    }
    tokio::task::yield_now().await;
    assert_eq!(server.validation_calls.load(Ordering::SeqCst), 1);
    release.notify_one();
    validating.await.unwrap().unwrap();
}

#[tokio::test]
async fn timeouts_and_server_errors_are_transient() {
    let (client, server, _) = activated().await;
    server.enqueue(ValidationBehavior::Timeout);
    assert!(matches!(
        client.validate().await,
        Err(ValidationError::Transient(TransientError::Timeout))
    ));
    server.enqueue(ValidationBehavior::ServerError);
    assert!(matches!(
        client.validate().await,
        Err(ValidationError::Transient(TransientError::ServerError(503)))
    ));
    assert!(client.feature_key(FEATURE_ID).is_ok());
}

#[tokio::test]
async fn malformed_signed_and_rollback_failures_wipe() {
    for (behavior, expected) in [
        (ValidationBehavior::Malformed, FatalError::CredentialCorrupt),
        (
            ValidationBehavior::BadSignature,
            FatalError::SignatureInvalid,
        ),
        (ValidationBehavior::NonceMismatch, FatalError::NonceMismatch),
        (
            ValidationBehavior::FloorRollback,
            FatalError::SecurityFloorRegression,
        ),
    ] {
        let (client, server, store) = activated().await;
        server.enqueue(behavior);
        assert!(matches!(
            client.validate().await,
            Err(ValidationError::Fatal(error)) if error == expected
        ));
        assert_eq!(client.state(), LicenseState::Tampered);
        assert!(store.is_empty());
    }
}

#[tokio::test]
async fn locked_state_recovers_only_after_an_ok_ticket() {
    let (client, server, _) = activated().await;
    server.enqueue(ValidationBehavior::Verdict(Verdict::NeedsReactivation));
    assert!(matches!(
        client.validate().await,
        Err(ValidationError::ReactivationRequired)
    ));
    assert_eq!(client.state(), LicenseState::Locked);
    assert!(matches!(
        client.feature_key(FEATURE_ID),
        Err(CoreError::NotEntitled)
    ));

    server.enqueue(ValidationBehavior::Timeout);
    assert!(matches!(
        client.validate().await,
        Err(ValidationError::Transient(_))
    ));
    assert_eq!(client.state(), LicenseState::Locked);

    server.enqueue(ValidationBehavior::Ok);
    client.validate().await.unwrap();
    assert_eq!(client.state(), LicenseState::Active);
    assert!(client.feature_key(FEATURE_ID).is_ok());
}

#[tokio::test]
async fn kill_order_wipes_immediately() {
    let (client, server, store) = activated().await;
    server.enqueue(ValidationBehavior::Kill);
    client.validate().await.unwrap();
    assert_eq!(client.state(), LicenseState::Revoked);
    assert!(store.is_empty());
    assert!(matches!(
        client.feature_key(FEATURE_ID),
        Err(CoreError::NoCredential)
    ));
}

#[tokio::test]
async fn content_type_and_response_bounds_are_fail_closed() {
    for behavior in [
        ValidationBehavior::BadContentType,
        ValidationBehavior::Oversized,
    ] {
        let (client, server, store) = activated().await;
        server.enqueue(behavior);
        assert!(matches!(
            client.validate().await,
            Err(ValidationError::Fatal(FatalError::CredentialCorrupt))
        ));
        assert_eq!(client.state(), LicenseState::Tampered);
        assert!(store.is_empty());
    }
}

#[tokio::test]
async fn activation_fatal_responses_wipe_generated_device_state() {
    for failure in [
        EndpointFailure::TransportTooLarge,
        EndpointFailure::BadContentType,
        EndpointFailure::MalformedBody,
    ] {
        let server = FakeServer::new();
        server.fail_activation_with(failure);
        let store = Arc::new(MemoryStore::default());
        let client = client(Arc::clone(&server), Arc::clone(&store)).await;

        assert!(matches!(
            client.activate("CL1-TEST-LICENSE").await,
            Err(ActivateError::Fatal(FatalError::CredentialCorrupt))
        ));
        assert_eq!(client.state(), LicenseState::Tampered);
        assert!(store.is_empty());
        assert!(store.wipes.load(Ordering::SeqCst) >= 1);
    }
}

#[tokio::test]
async fn deactivation_fatal_responses_fail_closed() {
    for failure in [
        EndpointFailure::TransportTooLarge,
        EndpointFailure::BadContentType,
        EndpointFailure::MalformedBody,
    ] {
        let (client, server, store) = activated().await;
        server.fail_deactivation_with(failure);

        assert!(matches!(
            client.deactivate().await,
            Err(DeactivateError::Fatal(FatalError::CredentialCorrupt))
        ));
        assert_eq!(client.state(), LicenseState::Tampered);
        assert!(store.is_empty());
    }
}

#[tokio::test]
async fn revocation_batches_advance_one_verified_page_at_a_time() {
    let (client, server, _) = activated().await;
    server.revocation_epoch.store(3, Ordering::SeqCst);

    client.validate().await.unwrap();
    assert_eq!(*server.revocation_requests.lock().unwrap(), [1, 2, 3]);
    assert_eq!(client.state(), LicenseState::Active);
    assert!(client.feature_key(FEATURE_ID).is_ok());

    client.validate().await.unwrap();
    assert_eq!(*server.revocation_requests.lock().unwrap(), [1, 2, 3]);

    server.revocation_epoch.store(4, Ordering::SeqCst);
    client.validate().await.unwrap();
    assert_eq!(*server.revocation_requests.lock().unwrap(), [1, 2, 3, 4]);
}

#[tokio::test]
async fn a_revocation_batch_for_the_current_license_wipes_immediately() {
    let (client, server, store) = activated().await;
    server.revoked_license_at.store(2, Ordering::SeqCst);
    server.revocation_epoch.store(3, Ordering::SeqCst);

    assert!(matches!(
        client.validate().await,
        Err(ValidationError::Fatal(FatalError::Revoked(
            KillReason::RevokedLicense
        )))
    ));
    assert_eq!(*server.revocation_requests.lock().unwrap(), [1, 2]);
    assert_eq!(client.state(), LicenseState::Revoked);
    assert!(store.is_empty());
    assert!(matches!(
        client.feature_key(FEATURE_ID),
        Err(CoreError::NoCredential)
    ));
}

#[tokio::test]
async fn a_bound_olk_survives_restart_unseals_assets_and_deactivates_locally() {
    let server = FakeServer::new();
    let store = Arc::new(MemoryStore::default());
    let first = client(Arc::clone(&server), Arc::clone(&store)).await;
    let armor = server.olk_bundle(&first.inner.config, Some(first.inner.fingerprint.clone()));
    let sealed = server.sealed_asset(b"air-gapped payload");

    first.import_olk(&armor).unwrap();
    assert_eq!(first.state(), LicenseState::Active);
    assert_eq!(
        first.unseal(FEATURE_ID, &sealed).unwrap(),
        b"air-gapped payload"
    );
    drop(first);

    let restarted = client(Arc::clone(&server), Arc::clone(&store)).await;
    assert_eq!(restarted.state(), LicenseState::Active);
    assert_eq!(
        restarted.unseal(FEATURE_ID, &sealed).unwrap(),
        b"air-gapped payload"
    );
    restarted.deactivate().await.unwrap();
    assert_eq!(restarted.state(), LicenseState::Unlicensed);
    assert!(store.is_empty());
    assert!(server.device_sig_vk.lock().unwrap().is_none());
}

#[tokio::test]
async fn an_unbound_olk_requires_explicit_client_opt_in() {
    let server = FakeServer::new();
    let store = Arc::new(MemoryStore::default());
    let default_client = client(Arc::clone(&server), Arc::clone(&store)).await;
    let armor = server.olk_bundle(&default_client.inner.config, None);

    assert!(matches!(
        default_client.import_olk(&armor),
        Err(OfflineError::UnboundOlkDisabled)
    ));
    assert_eq!(default_client.state(), LicenseState::Unlicensed);
    drop(default_client);

    let opted_in = CopyLockerClient::<ClStd1>::with_components(
        config(&server).with_unbound_olk(true).unwrap(),
        Arc::new(FakeTransport(Arc::clone(&server))),
        store,
        &FixedFingerprint,
    )
    .await
    .unwrap();
    opted_in.import_olk(&armor).unwrap();
    assert_eq!(opted_in.state(), LicenseState::Active);
    assert!(opted_in.feature_key(FEATURE_ID).is_ok());
}

#[tokio::test]
async fn olk_device_mismatch_and_signature_tampering_fail_closed() {
    let server = FakeServer::new();
    let store = Arc::new(MemoryStore::default());
    let mismatched = client(Arc::clone(&server), Arc::clone(&store)).await;
    let wrong_device = server.olk_bundle(
        &mismatched.inner.config,
        Some(Fingerprint::from_vec(vec![0xee; 32])),
    );
    assert!(matches!(
        mismatched.import_olk(&wrong_device),
        Err(OfflineError::Fatal(FatalError::MachineMismatch))
    ));
    assert_eq!(mismatched.state(), LicenseState::Tampered);
    assert!(store.is_empty());

    let server = FakeServer::new();
    let store = Arc::new(MemoryStore::default());
    let tampered = client(Arc::clone(&server), Arc::clone(&store)).await;
    let armor = server.olk_bundle(
        &tampered.inner.config,
        Some(tampered.inner.fingerprint.clone()),
    );
    let mut bundle = copylocker_proto::OfflineLicenseBundle::from_armored(&armor).unwrap();
    let mut envelope = Envelope::decode(&bundle.license_envelope).unwrap();
    envelope.sig[0] ^= 0xff;
    bundle.license_envelope = envelope.encode();
    assert!(matches!(
        tampered.import_olk(&bundle.to_armored()),
        Err(OfflineError::Fatal(FatalError::SignatureInvalid))
    ));
    assert_eq!(tampered.state(), LicenseState::Tampered);
    assert!(store.is_empty());
}
