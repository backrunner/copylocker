use core::fmt::Write as _;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use copylocker_core::{
    check_ticket, ClockState, CoreError, Deadlines, Effect, Event, FatalError, KeyMaterial,
    StateMachine, TicketChecks, TransientError,
};
use copylocker_fingerprint::{collect_with, FingerprintProvider, SystemFingerprintProvider};
use copylocker_proto::keywrap::{open_credential_secret, CredentialSealContext};
use copylocker_proto::{
    olk_binding_fingerprint, AckResponse, ActivationRequest, ActivationResponse, Credential,
    DeactivateRequest, Envelope, FeatureChallenge, FeatureResponse, Keyset, KillOrder,
    MachineCredential, OfflineLicenseBundle, OfflineLicenseKey, ProtocolErrorResponse,
    RevocationBatch, SealedAsset, ValidateRequest, ValidationTicket, VerifiedChain,
};
use copylocker_store::{KeyStore, MonotonicState, SecureStore, StoreConfig, StoreRecord};
use copylocker_suite::{
    Ciphertext, CryptoSuite, DeviceAttrs, DomainCtx, KeyDerivation, KeyEncapsulation, Secret,
    SharedSecret, SignatureScheme,
};
use copylocker_suite_std::{ClStd1, FastSig};
use copylocker_types::{
    ArtifactKind, Entitlements, Fingerprint, KillReason, LicenseState, StateReason, Verdict,
    PROTO_VER,
};
use futures_util::stream::{self, BoxStream};
use futures_util::{Stream, StreamExt};
use tokio::sync::{watch, Notify};

use crate::error::{
    ActivateError, ActivationRejection, ClientInitError, DeactivateError, LocalError, OfflineError,
    ValidationError,
};
use crate::platform::{
    random_array, CryptoRngAdapter, RandomSource, SystemRandomSource, SystemTimeSource, TimeSource,
};
use crate::scheduler::SchedulerState;
use crate::snapshot::ClientSnapshot;
use crate::transport::{
    HttpMethod, Transport, TransportError, TransportRequest, TransportResponse,
};
use crate::trust::TrustAnchors;
use crate::{Config, ConfigError};

const ARTIFACT_RESPONSE_LIMIT: usize = 1024 * 1024;
const ERROR_RESPONSE_LIMIT: usize = copylocker_types::MAX_BODY_BYTES;
const FEATURE_CHALLENGE_SALT: &[u8] = b"copylocker/challenge/v1";

/// A state transition emitted for UI presentation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StateChange {
    /// New advisory state.
    pub state: LicenseState,
    /// Why it changed. `None` is the initial subscription snapshot.
    pub reason: Option<StateReason>,
}

/// Stream of advisory state changes.
pub struct StateSubscription {
    inner: BoxStream<'static, StateChange>,
}

impl core::fmt::Debug for StateSubscription {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("StateSubscription(..)")
    }
}

impl Stream for StateSubscription {
    type Item = StateChange;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(context)
    }
}

struct Runtime<S: CryptoSuite> {
    state: StateMachine,
    snapshot: Option<ClientSnapshot>,
    credential: Option<MachineCredential>,
    olk: Option<OfflineLicenseKey>,
    material: Option<KeyMaterial>,
    entitlements: Entitlements,
    offline_wrapped_keks: BTreeMap<String, Vec<u8>>,
    online_wrapped_keks: BTreeMap<String, Vec<u8>>,
    chain: Option<VerifiedChain<S::Sig>>,
    max_security_floor: u64,
    max_revocation_epoch: u64,
}

struct Inner<S: CryptoSuite> {
    config: Config,
    transport: Arc<dyn Transport>,
    store: Arc<dyn KeyStore>,
    fingerprint: Fingerprint,
    attributes: DeviceAttrs,
    anchors: TrustAnchors<S>,
    runtime: Mutex<Runtime<S>>,
    time: Arc<dyn TimeSource>,
    random: Arc<dyn RandomSource>,
    validation_in_flight: AtomicBool,
    validation_requested: AtomicBool,
    online_hint: AtomicBool,
    scheduler: Mutex<SchedulerState>,
    scheduler_notify: Arc<Notify>,
    state_changes: watch::Sender<StateChange>,
    suite: PhantomData<S>,
}

/// Productive CopyLocker desktop client.
pub struct CopyLockerClient<S: CryptoSuite = ClStd1> {
    inner: Arc<Inner<S>>,
}

impl<S: CryptoSuite> Clone for CopyLockerClient<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S: CryptoSuite> core::fmt::Debug for CopyLockerClient<S>
where
    <S::Sig as SignatureScheme>::VerifyingKey: Send + Sync,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CopyLockerClient")
            .field("product_id", &self.inner.config.product_id())
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "transport-reqwest")]
impl<S: CryptoSuite> CopyLockerClient<S>
where
    <S::Sig as SignatureScheme>::VerifyingKey: Send + Sync,
{
    /// Construct the normal desktop client using system fingerprinting, secure storage, and
    /// Rustls-backed asynchronous HTTP.
    pub async fn new(config: Config) -> Result<Self, ClientInitError> {
        config.validate()?;
        let evidence =
            collect_with::<_, S::Fpr>(&SystemFingerprintProvider, config.fingerprint_salt())?;
        let (fingerprint, attributes) = evidence.into_parts();
        let store_config = StoreConfig::new(config.app_id()).map_err(LocalError::from)?;
        let store =
            SecureStore::new(store_config, fingerprint.as_bytes()).map_err(LocalError::from)?;
        let transport = crate::ReqwestTransport::new()?;
        Self::construct(
            config,
            Arc::new(transport),
            Arc::new(store),
            fingerprint,
            attributes,
            Arc::new(SystemTimeSource),
            Arc::new(SystemRandomSource),
        )
    }
}

impl<S: CryptoSuite> CopyLockerClient<S>
where
    <S::Sig as SignatureScheme>::VerifyingKey: Send + Sync,
{
    /// Construct with an injected transport, store, and fingerprint provider.
    ///
    /// This is the supported integration point for proxies, private network relays, portable
    /// stores, and host-defined device identities. Entropy remains the operating-system CSPRNG.
    pub async fn with_components(
        config: Config,
        transport: Arc<dyn Transport>,
        store: Arc<dyn KeyStore>,
        fingerprint_provider: &dyn FingerprintProvider,
    ) -> Result<Self, ClientInitError> {
        config.validate()?;
        let evidence = collect_with::<_, S::Fpr>(fingerprint_provider, config.fingerprint_salt())?;
        let (fingerprint, attributes) = evidence.into_parts();
        Self::construct(
            config,
            transport,
            store,
            fingerprint,
            attributes,
            Arc::new(SystemTimeSource),
            Arc::new(SystemRandomSource),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn construct(
        config: Config,
        transport: Arc<dyn Transport>,
        store: Arc<dyn KeyStore>,
        fingerprint: Fingerprint,
        attributes: DeviceAttrs,
        time: Arc<dyn TimeSource>,
        random: Arc<dyn RandomSource>,
    ) -> Result<Self, ClientInitError> {
        if !config.client_info().supported_suites.contains(&S::SUITE_ID) {
            return Err(ConfigError::InvalidClientInfo.into());
        }
        let anchors = TrustAnchors::<S>::decode(config.current_root_key(), config.next_root_key())
            .map_err(ClientInitError::Fatal)?;
        let now = time.unix_seconds();
        let loaded = store.load().map_err(LocalError::from)?;
        let (mut state, snapshot, monotonic) = match loaded {
            Some(bytes) => {
                let record = StoreRecord::decode(&bytes).map_err(LocalError::from)?;
                let monotonic = record.monotonic();
                let snapshot = ClientSnapshot::decode(record.payload())
                    .map_err(|_| LocalError::SnapshotCorrupt)?;
                validate_device_keys::<S>(&snapshot).map_err(ClientInitError::Fatal)?;
                let clock = ClockState::from_persisted(
                    monotonic.last_seen_max(),
                    monotonic.last_server_time(),
                    monotonic.rollback_events(),
                )
                .ok_or(LocalError::SnapshotCorrupt)?;
                let mut state = StateMachine::new(config.core(), monotonic.last_seen_max());
                *state.clock_mut() = clock;
                (state, snapshot, monotonic)
            }
            None => (
                StateMachine::new(config.core(), now),
                generate_snapshot::<S>(random.as_ref())?,
                MonotonicState::new(now, now, 0, 0, 0),
            ),
        };

        let mut credential = None;
        let mut olk = None;
        let mut material = None;
        let mut entitlements = Entitlements::default();
        let mut offline_wrapped_keks = BTreeMap::new();
        let mut online_wrapped_keks = BTreeMap::new();
        let mut chain = None;
        let mut max_security_floor = monotonic.max_seen_security_floor();
        let mut max_revocation_epoch = monotonic.max_seen_revocation_epoch();

        if let Some(encoded_credential) = snapshot.credential_envelope() {
            let stored_envelope = Envelope::decode(encoded_credential)
                .map_err(|error| ClientInitError::Fatal(FatalError::from(error)))?;
            if stored_envelope.kind == ArtifactKind::OfflineLicenseKey {
                if snapshot.validation_ticket().is_some() {
                    return Err(ClientInitError::Fatal(FatalError::CredentialCorrupt));
                }
                let preview = stored_envelope
                    .peek_unverified::<OfflineLicenseKey>()
                    .map_err(|error| ClientInitError::Fatal(FatalError::from(error)))?;
                let keyset = Keyset {
                    proto_ver: PROTO_VER,
                    epoch_certificates: snapshot.epoch_certificates().to_vec(),
                    revocation_epoch: max_revocation_epoch,
                };
                let verified_chain = anchors
                    .verify_keyset(
                        &keyset,
                        config.product_id(),
                        preview.issued_at,
                        max_revocation_epoch,
                        snapshot.revoked_epochs(),
                    )
                    .map_err(ClientInitError::Fatal)?;
                let (opened, keys) = open_offline_license::<S>(
                    &stored_envelope,
                    &verified_chain,
                    &config,
                    &fingerprint,
                    state.clock().effective_now(now),
                    max_security_floor,
                    max_revocation_epoch,
                )
                .map_err(|error| match error {
                    OpenOlkError::Fatal(error) => ClientInitError::Fatal(error),
                    OpenOlkError::UnboundDisabled => ClientInitError::UnboundOlkDisabled,
                })?;
                max_security_floor = max_security_floor.max(opened.security_floor);
                max_revocation_epoch = max_revocation_epoch.max(opened.revocation_epoch);
                entitlements = opened.entitlements.clone();
                offline_wrapped_keks = opened.wrapped_keks.clone();
                state.set_deadlines(olk_deadlines(&opened));
                let _ = state.handle(Event::CredentialLoaded, now);
                let _ = state.handle(Event::Tick, now);
                olk = Some(opened);
                material = Some(keys);
                chain = Some(verified_chain);
            } else if stored_envelope.kind == ArtifactKind::MachineCred {
                let keyset = Keyset {
                    proto_ver: PROTO_VER,
                    epoch_certificates: snapshot.epoch_certificates().to_vec(),
                    revocation_epoch: max_revocation_epoch,
                };
                let verified_chain = anchors
                    .verify_keyset(
                        &keyset,
                        config.product_id(),
                        state.clock().effective_now(now),
                        max_revocation_epoch,
                        snapshot.revoked_epochs(),
                    )
                    .map_err(ClientInitError::Fatal)?;
                let (opened, mut keys) = open_machine_credential::<S>(
                    encoded_credential,
                    &verified_chain,
                    &snapshot,
                    &config,
                    &fingerprint,
                    state.clock().effective_now(now),
                    max_security_floor,
                    max_revocation_epoch,
                )
                .map_err(ClientInitError::Fatal)?;
                max_security_floor = max_security_floor.max(opened.security_floor);
                max_revocation_epoch = max_revocation_epoch.max(opened.revocation_epoch);
                entitlements = opened.entitlements.clone();
                offline_wrapped_keks = opened.wrapped_keks.clone();
                let mut deadlines = Deadlines {
                    refresh_after: opened.refresh_after,
                    grace_deadline: opened.grace_deadline(),
                    not_after: opened.not_after,
                };
                let mut restored_verdict = None;

                if let Some(ticket_bytes) = snapshot.validation_ticket() {
                    let envelope = Envelope::decode(ticket_bytes)
                        .map_err(|error| ClientInitError::Fatal(FatalError::from(error)))?;
                    let ticket: ValidationTicket = verified_chain
                        .verify_artifact_fast::<FastSig, _>(
                            &envelope,
                            config.product_id(),
                            state.clock().effective_now(now),
                        )
                        .map_err(|error| ClientInitError::Fatal(FatalError::from(error)))?;
                    let verified_epoch = envelope
                        .epoch_ref
                        .ok_or(ClientInitError::Fatal(FatalError::ChainInvalid))?;
                    check_ticket(
                        &ticket,
                        &TicketChecks {
                            supported_suites: &config.client_info().supported_suites,
                            verified_epoch,
                            sent_nonce: ticket.nonce_c_echo,
                            machine_id: opened.machine_id,
                            known_revocation_epoch: max_revocation_epoch,
                            known_security_floor: max_security_floor,
                        },
                        state.clock_mut(),
                        now,
                    )
                    .map_err(ClientInitError::Fatal)?;
                    max_security_floor = max_security_floor.max(ticket.security_floor);
                    max_revocation_epoch = max_revocation_epoch.max(ticket.revocation_epoch);
                    if let Some(updated) = ticket.entitlements.as_ref() {
                        entitlements = updated.clone();
                    }
                    deadlines = deadlines_from_ticket(&opened, &ticket);
                    if ticket.verdict == Verdict::Ok {
                        keys.set_online_session(ticket.server_nonce, ticket.epoch_id);
                        online_wrapped_keks = ticket.wrapped_keks.unwrap_or_default();
                    }
                    restored_verdict = Some(ticket.verdict);
                }

                state.set_deadlines(deadlines);
                let _ = state.handle(Event::CredentialLoaded, now);
                let _ = state.handle(Event::Tick, now);
                if let Some(verdict @ (Verdict::NeedsReactivation | Verdict::VersionOutOfScope)) =
                    restored_verdict
                {
                    let _ = state.handle(Event::TicketDenied(verdict), now);
                }
                credential = Some(opened);
                material = Some(keys);
                chain = Some(verified_chain);
            } else {
                return Err(ClientInitError::Fatal(FatalError::CredentialCorrupt));
            }
        }

        let initial = StateChange {
            state: state.state(),
            reason: None,
        };
        let scheduler_enabled = credential.is_some();
        let (state_changes, _) = watch::channel(initial);
        let client = Self {
            inner: Arc::new(Inner {
                config,
                transport,
                store,
                fingerprint,
                attributes,
                anchors,
                runtime: Mutex::new(Runtime {
                    state,
                    snapshot: Some(snapshot),
                    credential,
                    olk,
                    material,
                    entitlements,
                    offline_wrapped_keks,
                    online_wrapped_keks,
                    chain,
                    max_security_floor,
                    max_revocation_epoch,
                }),
                time,
                random,
                validation_in_flight: AtomicBool::new(false),
                validation_requested: AtomicBool::new(false),
                online_hint: AtomicBool::new(false),
                scheduler: Mutex::new(SchedulerState::new(scheduler_enabled)),
                scheduler_notify: Arc::new(Notify::new()),
                state_changes,
                suite: PhantomData,
            }),
        };
        client.start_scheduler()?;
        Ok(client)
    }

    /// Activate using a license key.
    pub async fn activate(&self, key: &str) -> Result<(), ActivateError> {
        self.activate_credential(Credential::LicenseKey(key.to_owned()))
            .await
    }

    /// Activate using an account bearer token.
    pub async fn activate_with_account(&self, token: &[u8]) -> Result<(), ActivateError> {
        self.activate_credential(Credential::AccountToken(token.to_vec()))
            .await
    }

    /// Build and persist a device-bound offline activation request.
    pub fn build_offline_request(&self, key: &str) -> Result<Vec<u8>, OfflineError> {
        self.ensure_device_keys().map_err(OfflineError::Local)?;
        let nonce = random_array::<32>(self.inner.random.as_ref()).map_err(OfflineError::Local)?;
        let now = self.inner.time.unix_seconds();
        let mut runtime = self.lock_runtime().map_err(OfflineError::Local)?;
        if runtime.credential.is_some() || runtime.olk.is_some() {
            return Err(OfflineError::AlreadyActivated);
        }
        let snapshot = runtime
            .snapshot
            .as_ref()
            .ok_or(OfflineError::Local(LocalError::StateUnavailable))?;
        let request = build_activation_request::<S>(
            &self.inner.config,
            &self.inner.fingerprint,
            &self.inner.attributes,
            snapshot,
            Credential::LicenseKey(key.to_owned()),
            nonce,
            now,
        )
        .map_err(OfflineError::Fatal)?;
        runtime
            .snapshot
            .as_mut()
            .ok_or(OfflineError::Local(LocalError::StateUnavailable))?
            .set_pending_activation_nonce(Some(nonce));
        self.persist_locked(&runtime).map_err(OfflineError::Local)?;
        Ok(request)
    }

    /// Verify and install a signed response to the most recent offline activation request.
    pub fn import_offline_response(&self, bytes: &[u8]) -> Result<(), OfflineError> {
        let envelope = match Envelope::decode(bytes) {
            Ok(envelope) => envelope,
            Err(error) => {
                let fatal = FatalError::from(error);
                self.fail_closed(fatal);
                return Err(OfflineError::Fatal(fatal));
            }
        };
        let unverified = match envelope.peek_unverified::<ActivationResponse>() {
            Ok(response) => response,
            Err(error) => {
                let fatal = FatalError::from(error);
                self.fail_closed(fatal);
                return Err(OfflineError::Fatal(fatal));
            }
        };

        let now = self.inner.time.unix_seconds();
        let mut runtime = self.lock_runtime().map_err(OfflineError::Local)?;
        if runtime.credential.is_some() || runtime.olk.is_some() {
            return Err(OfflineError::AlreadyActivated);
        }
        let pending_nonce = runtime
            .snapshot
            .as_ref()
            .ok_or(OfflineError::NoPendingRequest)?
            .pending_activation_nonce()
            .ok_or(OfflineError::NoPendingRequest)?;
        let effective_now = runtime.state.clock().effective_now(now);
        let result = (|| {
            let keyset = Keyset {
                proto_ver: PROTO_VER,
                epoch_certificates: unverified.chain.clone(),
                revocation_epoch: runtime.max_revocation_epoch,
            };
            let revoked_epochs = runtime
                .snapshot
                .as_ref()
                .ok_or(FatalError::CredentialCorrupt)?
                .revoked_epochs();
            let chain = self.inner.anchors.verify_keyset(
                &keyset,
                self.inner.config.product_id(),
                effective_now,
                runtime.max_revocation_epoch,
                revoked_epochs,
            )?;
            let response: ActivationResponse = chain
                .verify_artifact(&envelope, self.inner.config.product_id(), effective_now)
                .map_err(FatalError::from)?;
            if response.proto_ver != PROTO_VER
                || response.suite_id != S::SUITE_ID
                || response.nonce_c_echo != pending_nonce
                || response.valid_until <= response.server_time
                || effective_now >= response.valid_until
            {
                return Err(if response.nonce_c_echo != pending_nonce {
                    FatalError::NonceMismatch
                } else {
                    FatalError::CredentialCorrupt
                });
            }
            let snapshot = runtime
                .snapshot
                .as_ref()
                .ok_or(FatalError::CredentialCorrupt)?;
            let (credential, material) = open_machine_credential::<S>(
                &response.credential,
                &chain,
                snapshot,
                &self.inner.config,
                &self.inner.fingerprint,
                effective_now.max(response.server_time),
                runtime.max_security_floor,
                runtime.max_revocation_epoch,
            )?;
            Ok((response, credential, material, chain))
        })();
        let (response, credential, material, chain) = match result {
            Ok(value) => value,
            Err(error) => {
                self.fail_closed_locked(&mut runtime, error);
                return Err(OfflineError::Fatal(error));
            }
        };

        runtime
            .snapshot
            .as_mut()
            .ok_or(OfflineError::Local(LocalError::StateUnavailable))?
            .set_credential_envelope(Some(response.credential));
        let snapshot = runtime
            .snapshot
            .as_mut()
            .ok_or(OfflineError::Local(LocalError::StateUnavailable))?;
        snapshot.set_epoch_certificates(response.chain);
        snapshot.set_validation_ticket(None);
        snapshot.set_pending_activation_nonce(None);
        runtime.max_security_floor = runtime.max_security_floor.max(credential.security_floor);
        runtime.max_revocation_epoch = runtime
            .max_revocation_epoch
            .max(credential.revocation_epoch);
        runtime
            .state
            .clock_mut()
            .observe_server_time(response.server_time);
        runtime.state.set_deadlines(Deadlines {
            refresh_after: credential.refresh_after,
            grace_deadline: credential.grace_deadline(),
            not_after: credential.not_after,
        });
        let effects = runtime.state.handle(Event::ActivationVerified, now);
        runtime.entitlements = credential.entitlements.clone();
        runtime.offline_wrapped_keks = credential.wrapped_keks.clone();
        runtime.online_wrapped_keks.clear();
        runtime.credential = Some(credential);
        runtime.olk = None;
        runtime.material = Some(material);
        runtime.chain = Some(chain);
        let refresh_start = response.server_time;
        let refresh_deadline = runtime.state.deadlines().refresh_after;
        self.persist_locked(&runtime).map_err(OfflineError::Local)?;
        self.emit_effects(&effects);
        drop(runtime);
        self.record_scheduler_success(now, refresh_start, refresh_deadline);
        Ok(())
    }

    /// Verify and install a self-contained armored Offline License Key bundle.
    ///
    /// OLKs do not create a server-side activation and cannot release a seat. Unbound OLKs are
    /// rejected unless [`Config::with_unbound_olk`] was explicitly enabled.
    pub fn import_olk(&self, armored: &str) -> Result<(), OfflineError> {
        let bundle = match OfflineLicenseBundle::from_armored(armored) {
            Ok(bundle) => bundle,
            Err(error) => {
                let fatal = FatalError::from(error);
                self.fail_closed(fatal);
                return Err(OfflineError::Fatal(fatal));
            }
        };
        let envelope = match Envelope::decode(&bundle.license_envelope) {
            Ok(envelope) => envelope,
            Err(error) => {
                let fatal = FatalError::from(error);
                self.fail_closed(fatal);
                return Err(OfflineError::Fatal(fatal));
            }
        };
        if envelope.suite_id != S::SUITE_ID
            || !self
                .inner
                .config
                .client_info()
                .supported_suites
                .contains(&envelope.suite_id)
        {
            return Err(OfflineError::UnsupportedCredential);
        }
        let preview = match envelope.peek_unverified::<OfflineLicenseKey>() {
            Ok(preview) => preview,
            Err(error) => {
                let fatal = FatalError::from(error);
                self.fail_closed(fatal);
                return Err(OfflineError::Fatal(fatal));
            }
        };

        let now = self.inner.time.unix_seconds();
        let mut runtime = self.lock_runtime().map_err(OfflineError::Local)?;
        if runtime.credential.is_some() || runtime.olk.is_some() {
            return Err(OfflineError::AlreadyActivated);
        }
        let keyset = Keyset {
            proto_ver: PROTO_VER,
            epoch_certificates: bundle.epoch_certificates.clone(),
            revocation_epoch: runtime.max_revocation_epoch,
        };
        let result = (|| {
            let revoked_epochs = runtime
                .snapshot
                .as_ref()
                .ok_or(OpenOlkError::Fatal(FatalError::CredentialCorrupt))?
                .revoked_epochs();
            let chain = self
                .inner
                .anchors
                .verify_keyset(
                    &keyset,
                    self.inner.config.product_id(),
                    preview.issued_at,
                    runtime.max_revocation_epoch,
                    revoked_epochs,
                )
                .map_err(OpenOlkError::Fatal)?;
            let (license, material) = open_offline_license::<S>(
                &envelope,
                &chain,
                &self.inner.config,
                &self.inner.fingerprint,
                runtime.state.clock().effective_now(now),
                runtime.max_security_floor,
                runtime.max_revocation_epoch,
            )?;
            Ok((license, material, chain))
        })();
        let (license, material, chain) = match result {
            Ok(value) => value,
            Err(OpenOlkError::UnboundDisabled) => {
                return Err(OfflineError::UnboundOlkDisabled);
            }
            Err(OpenOlkError::Fatal(error)) => {
                self.fail_closed_locked(&mut runtime, error);
                return Err(OfflineError::Fatal(error));
            }
        };

        let snapshot = runtime
            .snapshot
            .as_mut()
            .ok_or(OfflineError::Local(LocalError::StateUnavailable))?;
        snapshot.set_credential_envelope(Some(bundle.license_envelope));
        snapshot.set_epoch_certificates(bundle.epoch_certificates);
        snapshot.set_validation_ticket(None);
        snapshot.set_pending_activation_nonce(None);
        runtime.max_security_floor = runtime.max_security_floor.max(license.security_floor);
        runtime.max_revocation_epoch = runtime.max_revocation_epoch.max(license.revocation_epoch);
        runtime
            .state
            .clock_mut()
            .observe_server_time(license.issued_at);
        runtime.state.set_deadlines(olk_deadlines(&license));
        let effects = runtime.state.handle(Event::ActivationVerified, now);
        runtime.entitlements = license.entitlements.clone();
        runtime.offline_wrapped_keks = license.wrapped_keks.clone();
        runtime.online_wrapped_keks.clear();
        runtime.credential = None;
        runtime.olk = Some(license);
        runtime.material = Some(material);
        runtime.chain = Some(chain);
        self.persist_locked(&runtime).map_err(OfflineError::Local)?;
        self.emit_effects(&effects);
        drop(runtime);
        self.disable_scheduler();
        Ok(())
    }

    async fn activate_credential(&self, credential: Credential) -> Result<(), ActivateError> {
        self.ensure_device_keys().map_err(ActivateError::Local)?;
        let nonce = random_array::<32>(self.inner.random.as_ref()).map_err(ActivateError::Local)?;
        let (body, idempotency_key) = {
            let mut runtime = self.lock_runtime().map_err(ActivateError::Local)?;
            if runtime.credential.is_some() || runtime.olk.is_some() {
                return Err(ActivateError::AlreadyActivated);
            }
            let snapshot = runtime
                .snapshot
                .as_ref()
                .ok_or(ActivateError::Local(LocalError::StateUnavailable))?;
            let body = match build_activation_request::<S>(
                &self.inner.config,
                &self.inner.fingerprint,
                &self.inner.attributes,
                snapshot,
                credential,
                nonce,
                self.inner.time.unix_seconds(),
            ) {
                Ok(body) => body,
                Err(error) => {
                    self.fail_closed_locked(&mut runtime, error);
                    return Err(ActivateError::Fatal(error));
                }
            };
            let idempotency_key =
                random_idempotency_key(self.inner.random.as_ref()).map_err(ActivateError::Local)?;
            (body, idempotency_key)
        };

        let response = self
            .send_post(
                "v1/activate",
                body,
                Some(&idempotency_key),
                ARTIFACT_RESPONSE_LIMIT,
            )
            .await
            .map_err(|error| self.resolve_activate_transport(error))?;
        let credential_bytes = match activation_response(response) {
            Ok(bytes) => bytes,
            Err(ActivateResponseError::Transient(error)) => {
                return Err(ActivateError::Transient(error));
            }
            Err(ActivateResponseError::Rejected(error)) => {
                return Err(ActivateError::Rejected(error));
            }
            Err(ActivateResponseError::Fatal(error)) => {
                self.fail_closed(error);
                return Err(ActivateError::Fatal(error));
            }
        };

        let keyset = match self.fetch_keyset().await {
            Ok(keyset) => keyset,
            Err(ValidationError::Transient(error)) => {
                return Err(ActivateError::Transient(error));
            }
            Err(ValidationError::Fatal(error)) => {
                self.fail_closed(error);
                return Err(ActivateError::Fatal(error));
            }
            Err(ValidationError::Local(error)) => return Err(ActivateError::Local(error)),
            Err(
                ValidationError::NotActivated
                | ValidationError::AlreadyInFlight
                | ValidationError::ReactivationRequired
                | ValidationError::VersionOutOfScope,
            ) => {
                return Err(ActivateError::Local(LocalError::StateUnavailable));
            }
        };
        let revocation_target = keyset.revocation_epoch;
        match self.install_keyset(keyset) {
            Ok(()) => {}
            Err(ValidationError::Fatal(error)) => {
                self.fail_closed(error);
                return Err(ActivateError::Fatal(error));
            }
            Err(ValidationError::Local(error)) => return Err(ActivateError::Local(error)),
            Err(
                ValidationError::NotActivated
                | ValidationError::AlreadyInFlight
                | ValidationError::ReactivationRequired
                | ValidationError::VersionOutOfScope,
            ) => {
                return Err(ActivateError::Local(LocalError::StateUnavailable));
            }
            Err(ValidationError::Transient(error)) => {
                return Err(ActivateError::Transient(error));
            }
        }
        match self.sync_revocations(revocation_target).await {
            Ok(()) => {}
            Err(ValidationError::Transient(error)) => {
                self.record_scheduler_failure(error);
                return Err(ActivateError::Transient(error));
            }
            Err(ValidationError::Fatal(error)) => {
                self.fail_closed(error);
                return Err(ActivateError::Fatal(error));
            }
            Err(ValidationError::Local(error)) => return Err(ActivateError::Local(error)),
            Err(
                ValidationError::NotActivated
                | ValidationError::AlreadyInFlight
                | ValidationError::ReactivationRequired
                | ValidationError::VersionOutOfScope,
            ) => {
                return Err(ActivateError::Local(LocalError::StateUnavailable));
            }
        }

        let now = self.inner.time.unix_seconds();
        let mut runtime = self.lock_runtime().map_err(ActivateError::Local)?;
        let effective_now = runtime.state.clock().effective_now(now);
        let max_security_floor = runtime.max_security_floor;
        let max_revocation_epoch = runtime.max_revocation_epoch;
        let opened = {
            let snapshot = runtime
                .snapshot
                .as_ref()
                .ok_or(ActivateError::Local(LocalError::StateUnavailable))?;
            let chain = match runtime.chain.as_ref() {
                Some(chain) => chain,
                None => {
                    let error = FatalError::ChainInvalid;
                    self.fail_closed_locked(&mut runtime, error);
                    return Err(ActivateError::Fatal(error));
                }
            };
            open_machine_credential::<S>(
                &credential_bytes,
                chain,
                snapshot,
                &self.inner.config,
                &self.inner.fingerprint,
                effective_now,
                max_security_floor,
                max_revocation_epoch,
            )
        };
        let (opened, material) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                self.fail_closed_locked(&mut runtime, error);
                return Err(ActivateError::Fatal(error));
            }
        };

        let snapshot = runtime
            .snapshot
            .as_mut()
            .ok_or(ActivateError::Local(LocalError::StateUnavailable))?;
        snapshot.set_credential_envelope(Some(credential_bytes));
        snapshot.set_validation_ticket(None);
        snapshot.set_pending_activation_nonce(None);
        runtime.max_security_floor = runtime.max_security_floor.max(opened.security_floor);
        runtime.max_revocation_epoch = runtime
            .max_revocation_epoch
            .max(opened.revocation_epoch)
            .max(revocation_target);
        runtime.state.set_deadlines(Deadlines {
            refresh_after: opened.refresh_after,
            grace_deadline: opened.grace_deadline(),
            not_after: opened.not_after,
        });
        let effects = runtime.state.handle(Event::ActivationVerified, now);
        runtime.entitlements = opened.entitlements.clone();
        runtime.offline_wrapped_keks = opened.wrapped_keks.clone();
        runtime.online_wrapped_keks.clear();
        runtime.credential = Some(opened);
        runtime.olk = None;
        runtime.material = Some(material);
        let refresh_start = runtime
            .credential
            .as_ref()
            .map_or(now, |credential| credential.issued_at);
        let refresh_deadline = runtime.state.deadlines().refresh_after;
        self.persist_locked(&runtime)
            .map_err(ActivateError::Local)?;
        self.emit_effects(&effects);
        drop(runtime);
        self.record_scheduler_success(now, refresh_start, refresh_deadline);
        Ok(())
    }

    /// Perform an immediate online validation.
    pub async fn validate(&self) -> Result<(), ValidationError> {
        let _guard = ValidationFlight::acquire(&self.inner.validation_in_flight)?;
        let nonce =
            random_array::<32>(self.inner.random.as_ref()).map_err(ValidationError::Local)?;
        let body = {
            let mut runtime = self.lock_runtime().map_err(ValidationError::Local)?;
            let now = self.inner.time.unix_seconds();
            runtime.state.note_validation_attempt(now);
            let credential = runtime
                .credential
                .as_ref()
                .ok_or(ValidationError::NotActivated)?;
            let snapshot = runtime
                .snapshot
                .as_ref()
                .ok_or(ValidationError::NotActivated)?;
            build_validate_request::<S>(
                &self.inner.config,
                &self.inner.fingerprint,
                snapshot,
                credential,
                nonce,
                runtime.max_revocation_epoch,
                runtime.max_security_floor,
                now,
            )
            .map_err(ValidationError::Fatal)?
        };
        self.mark_scheduler_attempt(self.inner.time.unix_seconds());
        let response = match self
            .send_post("v1/validate", body, None, ARTIFACT_RESPONSE_LIMIT)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Err(self.resolve_validation_stage_error(map_transport_validation(error)));
            }
        };
        let envelope_bytes = match validation_response(response) {
            Ok(bytes) => bytes,
            Err(ValidationResponseError::Transient(error)) => {
                self.record_scheduler_failure(error);
                self.apply_transient_failure(error)?;
                return Err(ValidationError::Transient(error));
            }
            Err(ValidationResponseError::Fatal(error)) => {
                self.fail_closed(error);
                return Err(ValidationError::Fatal(error));
            }
        };
        let envelope = Envelope::decode(&envelope_bytes).map_err(|error| {
            let fatal = FatalError::from(error);
            self.fail_closed(fatal);
            ValidationError::Fatal(fatal)
        })?;

        if self.needs_epoch_refresh(&envelope)? {
            let keyset = self
                .fetch_keyset()
                .await
                .map_err(|error| self.resolve_validation_stage_error(error))?;
            let revocation_target = keyset.revocation_epoch;
            self.install_keyset(keyset)
                .map_err(|error| self.resolve_validation_stage_error(error))?;
            self.sync_revocations(revocation_target)
                .await
                .map_err(|error| self.resolve_validation_stage_error(error))?;
        }

        let now = self.inner.time.unix_seconds();
        match envelope.kind {
            ArtifactKind::ValidationTicket => {
                let preview = {
                    let mut runtime = self.lock_runtime().map_err(ValidationError::Local)?;
                    let result = (|| {
                        let credential = runtime
                            .credential
                            .as_ref()
                            .ok_or(FatalError::CredentialCorrupt)?;
                        let chain = runtime.chain.as_ref().ok_or(FatalError::ChainInvalid)?;
                        let ticket: ValidationTicket = chain
                            .verify_artifact_fast::<FastSig, _>(
                                &envelope,
                                self.inner.config.product_id(),
                                runtime.state.clock().effective_now(now),
                            )
                            .map_err(FatalError::from)?;
                        let verified_epoch = envelope.epoch_ref.ok_or(FatalError::ChainInvalid)?;
                        let checks = TicketChecks {
                            supported_suites: &self.inner.config.client_info().supported_suites,
                            verified_epoch,
                            sent_nonce: nonce,
                            machine_id: credential.machine_id,
                            known_revocation_epoch: runtime.max_revocation_epoch,
                            known_security_floor: runtime.max_security_floor,
                        };
                        let mut preview_clock = *runtime.state.clock();
                        check_ticket(&ticket, &checks, &mut preview_clock, now)?;
                        Ok(ticket)
                    })();
                    match result {
                        Ok(ticket) => ticket,
                        Err(error) => {
                            self.fail_closed_locked(&mut runtime, error);
                            return Err(ValidationError::Fatal(error));
                        }
                    }
                };
                self.sync_revocations(preview.revocation_epoch)
                    .await
                    .map_err(|error| self.resolve_validation_stage_error(error))?;

                let mut runtime = self.lock_runtime().map_err(ValidationError::Local)?;
                let credential = runtime
                    .credential
                    .as_ref()
                    .ok_or(ValidationError::NotActivated)?
                    .clone();
                let ticket_result = runtime
                    .chain
                    .as_ref()
                    .ok_or(FatalError::ChainInvalid)
                    .and_then(|chain| {
                        chain
                            .verify_artifact_fast::<FastSig, _>(
                                &envelope,
                                self.inner.config.product_id(),
                                runtime.state.clock().effective_now(now),
                            )
                            .map_err(FatalError::from)
                    });
                let ticket = match ticket_result {
                    Ok(ticket) => ticket,
                    Err(error) => {
                        self.fail_closed_locked(&mut runtime, error);
                        return Err(ValidationError::Fatal(error));
                    }
                };
                let verified_epoch = match envelope.epoch_ref {
                    Some(epoch) => epoch,
                    None => {
                        let error = FatalError::ChainInvalid;
                        self.fail_closed_locked(&mut runtime, error);
                        return Err(ValidationError::Fatal(error));
                    }
                };
                let supported_suites = self.inner.config.client_info().supported_suites.clone();
                let checks = TicketChecks {
                    supported_suites: &supported_suites,
                    verified_epoch,
                    sent_nonce: nonce,
                    machine_id: credential.machine_id,
                    known_revocation_epoch: runtime.max_revocation_epoch,
                    known_security_floor: runtime.max_security_floor,
                };
                if let Err(error) = check_ticket(&ticket, &checks, runtime.state.clock_mut(), now) {
                    self.fail_closed_locked(&mut runtime, error);
                    return Err(ValidationError::Fatal(error));
                }
                runtime.max_security_floor = runtime.max_security_floor.max(ticket.security_floor);
                runtime.max_revocation_epoch =
                    runtime.max_revocation_epoch.max(ticket.revocation_epoch);
                if let Some(entitlements) = ticket.entitlements.as_ref() {
                    runtime.entitlements = entitlements.clone();
                }
                if ticket.verdict == Verdict::Ok {
                    runtime.online_wrapped_keks = ticket.wrapped_keks.clone().unwrap_or_default();
                    runtime
                        .material
                        .as_mut()
                        .ok_or(ValidationError::NotActivated)?
                        .set_online_session(ticket.server_nonce, ticket.epoch_id);
                } else {
                    runtime.online_wrapped_keks.clear();
                }
                runtime
                    .state
                    .set_deadlines(deadlines_from_ticket(&credential, &ticket));
                let event = match ticket.verdict {
                    Verdict::Ok => Event::TicketVerified,
                    Verdict::NeedsReactivation | Verdict::VersionOutOfScope => {
                        Event::TicketDenied(ticket.verdict)
                    }
                };
                let effects = runtime.state.handle(event, now);
                runtime
                    .snapshot
                    .as_mut()
                    .ok_or(ValidationError::NotActivated)?
                    .set_validation_ticket(Some(envelope_bytes));
                self.persist_locked(&runtime)
                    .map_err(ValidationError::Local)?;
                self.emit_effects(&effects);
                let refresh_start = ticket.server_time;
                let refresh_deadline = ticket.next_refresh_after;
                drop(runtime);
                self.record_scheduler_success(now, refresh_start, refresh_deadline);
                match ticket.verdict {
                    Verdict::Ok => Ok(()),
                    Verdict::NeedsReactivation => Err(ValidationError::ReactivationRequired),
                    Verdict::VersionOutOfScope => Err(ValidationError::VersionOutOfScope),
                }
            }
            ArtifactKind::KillOrder => {
                let mut runtime = self.lock_runtime().map_err(ValidationError::Local)?;
                let credential = runtime
                    .credential
                    .as_ref()
                    .ok_or(ValidationError::NotActivated)?
                    .clone();
                let order_result = runtime
                    .chain
                    .as_ref()
                    .ok_or(FatalError::ChainInvalid)
                    .and_then(|chain| {
                        chain
                            .verify_artifact_fast::<FastSig, _>(
                                &envelope,
                                self.inner.config.product_id(),
                                runtime.state.clock().effective_now(now),
                            )
                            .map_err(FatalError::from)
                    });
                let order: KillOrder = match order_result {
                    Ok(order) => order,
                    Err(error) => {
                        self.fail_closed_locked(&mut runtime, error);
                        return Err(ValidationError::Fatal(error));
                    }
                };
                let semantic_error =
                    if order.proto_ver != PROTO_VER || order.suite_id != S::SUITE_ID {
                        Some(FatalError::CredentialCorrupt)
                    } else if order.machine_id != credential.machine_id {
                        Some(FatalError::MachineMismatch)
                    } else if order.nonce_c_echo != nonce {
                        Some(FatalError::NonceMismatch)
                    } else if order.revocation_epoch < runtime.max_revocation_epoch {
                        Some(FatalError::RevocationRollback)
                    } else {
                        None
                    };
                if let Some(error) = semantic_error {
                    self.fail_closed_locked(&mut runtime, error);
                    return Err(ValidationError::Fatal(error));
                }
                runtime
                    .state
                    .clock_mut()
                    .observe_server_time(order.server_time);
                self.revoke_locked(&mut runtime, order.reason)
                    .map_err(ValidationError::Local)?;
                Ok(())
            }
            _ => {
                let error = FatalError::CredentialCorrupt;
                self.fail_closed(error);
                Err(ValidationError::Fatal(error))
            }
        }
    }

    /// Release the server-side seat, then wipe local credential material.
    pub async fn deactivate(&self) -> Result<(), DeactivateError> {
        {
            let mut runtime = self.lock_runtime().map_err(DeactivateError::Local)?;
            if runtime.olk.is_some() {
                self.user_deactivate_locked(&mut runtime)
                    .map_err(DeactivateError::Local)?;
                drop(runtime);
                self.disable_scheduler();
                return Ok(());
            }
            if runtime.credential.is_none() {
                return Err(DeactivateError::NotActivated);
            }
        }
        let nonce =
            random_array::<32>(self.inner.random.as_ref()).map_err(DeactivateError::Local)?;
        let (body, idempotency_key) = {
            let mut runtime = self.lock_runtime().map_err(DeactivateError::Local)?;
            let credential = runtime
                .credential
                .as_ref()
                .ok_or(DeactivateError::NotActivated)?;
            let snapshot = runtime
                .snapshot
                .as_ref()
                .ok_or(DeactivateError::NotActivated)?;
            let body = match build_deactivate_request::<S>(
                self.inner.config.product_id(),
                snapshot,
                credential,
                nonce,
                self.inner.time.unix_seconds(),
            ) {
                Ok(body) => body,
                Err(error) => {
                    self.fail_closed_locked(&mut runtime, error);
                    return Err(DeactivateError::Fatal(error));
                }
            };
            let key = random_idempotency_key(self.inner.random.as_ref())
                .map_err(DeactivateError::Local)?;
            (body, key)
        };
        let response = self
            .send_post(
                "v1/deactivate",
                body,
                Some(&idempotency_key),
                ERROR_RESPONSE_LIMIT,
            )
            .await
            .map_err(|error| self.resolve_deactivate_transport(error))?;
        if let Some(error) = transient_status(&response) {
            return Err(DeactivateError::Transient(error));
        }
        let verified = (|| {
            require_success_headers(&response)?;
            if !(200..300).contains(&response.status) {
                return Err(FatalError::CredentialCorrupt);
            }
            let ack = AckResponse::decode(&response.body).map_err(FatalError::from)?;
            if !ack.ok {
                return Err(FatalError::CredentialCorrupt);
            }
            Ok(())
        })();
        if let Err(error) = verified {
            self.fail_closed(error);
            return Err(DeactivateError::Fatal(error));
        }

        let mut runtime = self.lock_runtime().map_err(DeactivateError::Local)?;
        self.user_deactivate_locked(&mut runtime)
            .map_err(DeactivateError::Local)?;
        drop(runtime);
        self.disable_scheduler();
        Ok(())
    }

    /// Derive the stable offline Feature Key for an entitled feature.
    ///
    /// Calling this also runs the clock guard. No key is returned after grace, hard expiry,
    /// revocation, or a fatal verification failure.
    pub fn feature_key(&self, feature: &str) -> Result<Secret<[u8; 32]>, CoreError> {
        let now = self.inner.time.unix_seconds();
        let mut runtime = self
            .lock_runtime()
            .map_err(|_| CoreError::Fatal(FatalError::IntegrityFailure))?;
        let effects = runtime.state.handle(Event::Tick, now);
        if runtime.snapshot.is_some() && self.persist_locked(&runtime).is_err() {
            return Err(CoreError::Fatal(FatalError::IntegrityFailure));
        }
        self.emit_effects(&effects);
        let validation_requested = effects
            .iter()
            .any(|effect| matches!(effect, Effect::SendValidation));
        let result = runtime
            .material
            .as_ref()
            .ok_or(CoreError::NoCredential)?
            .feature_key::<S>(
                runtime.state.state(),
                &runtime.entitlements,
                feature,
                copylocker_core::SessionKind::Offline,
            );
        drop(runtime);
        if validation_requested {
            self.request_validation();
        }
        result
    }

    /// Unwrap the entitled feature's asset KEK and authenticate one sealed asset.
    pub fn unseal(&self, feature: &str, sealed: &[u8]) -> Result<Vec<u8>, CoreError> {
        let asset = SealedAsset::decode(sealed).map_err(|_| CoreError::AssetCorrupt)?;
        if asset.suite_id != S::SUITE_ID
            || asset.product_id != self.inner.config.product_id()
            || asset.variant_id != self.inner.config.client_info().variant_id
            || asset.feature_id != feature
        {
            return Err(CoreError::AssetCorrupt);
        }

        let now = self.inner.time.unix_seconds();
        let mut runtime = self
            .lock_runtime()
            .map_err(|_| CoreError::Fatal(FatalError::IntegrityFailure))?;
        let effects = runtime.state.handle(Event::Tick, now);
        if runtime.snapshot.is_some() && self.persist_locked(&runtime).is_err() {
            return Err(CoreError::Fatal(FatalError::IntegrityFailure));
        }
        self.emit_effects(&effects);
        let validation_requested = effects
            .iter()
            .any(|effect| matches!(effect, Effect::SendValidation));
        let material = runtime.material.as_ref().ok_or(CoreError::NoCredential)?;
        let offline = runtime
            .offline_wrapped_keks
            .get(feature)
            .map_or(&[][..], Vec::as_slice);
        let online = runtime
            .online_wrapped_keks
            .get(feature)
            .map_or(&[][..], Vec::as_slice);
        let kek = material.unwrap_kek_any::<S>(
            runtime.state.state(),
            &runtime.entitlements,
            feature,
            online,
            offline,
        )?;
        drop(runtime);
        if validation_requested {
            self.request_validation();
        }
        asset.open::<S>(&kek).map_err(|_| CoreError::AssetCorrupt)
    }

    /// Answer an opaque, feature-bound challenge with material for a host-side second step.
    ///
    /// The input and output are versioned canonical CBOR. The returned bytes are derived below
    /// the entitled Feature Key and never contain a boolean licence verdict or the Feature Key
    /// itself.
    pub fn challenge(&self, input: &[u8]) -> Result<Vec<u8>, CoreError> {
        let challenge = FeatureChallenge::decode(input).map_err(|_| CoreError::AssetCorrupt)?;
        let feature_key = self.feature_key(&challenge.feature_id)?;
        let response = <S::Kdf as KeyDerivation>::derive_from(
            FEATURE_CHALLENGE_SALT,
            feature_key.as_slice(),
            &[challenge.feature_id.as_bytes(), &challenge.challenge],
        )
        .map_err(|_| CoreError::DerivationFailed)?;
        Ok(FeatureResponse::new(*response.expose()).encode())
    }

    /// ⚠️ Advisory only. Do NOT gate features on this value — use `feature_key()`.
    #[must_use]
    pub fn state(&self) -> LicenseState {
        match self.inner.runtime.lock() {
            Ok(runtime) => runtime.state.state(),
            Err(_) => LicenseState::Tampered,
        }
    }

    /// Subscribe to advisory state transitions.
    pub fn subscribe(&self) -> StateSubscription {
        let receiver = self.inner.state_changes.subscribe();
        let initial = *receiver.borrow();
        let changes = stream::unfold(receiver, |mut receiver| async move {
            if receiver.changed().await.is_err() {
                return None;
            }
            let change = *receiver.borrow_and_update();
            Some((change, receiver))
        });
        StateSubscription {
            inner: stream::once(async move { initial }).chain(changes).boxed(),
        }
    }

    /// Hint that a host network request just succeeded.
    ///
    /// Background scheduling is installed by the desktop wrappers; the hint itself remains
    /// non-blocking and only records that an immediate validation is useful.
    pub fn hint_online(&self) {
        self.inner.online_hint.store(true, Ordering::Release);
        self.inner.scheduler_notify.notify_one();
    }

    fn start_scheduler(&self) -> Result<(), LocalError> {
        let handle =
            tokio::runtime::Handle::try_current().map_err(|_| LocalError::RuntimeUnavailable)?;
        let weak = Arc::downgrade(&self.inner);
        let notify = Arc::clone(&self.inner.scheduler_notify);
        handle.spawn(async move {
            Self::scheduler_loop(weak, notify).await;
        });
        self.inner.scheduler_notify.notify_one();
        Ok(())
    }

    async fn scheduler_loop(weak: Weak<Inner<S>>, notify: Arc<Notify>) {
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let now = inner.time.unix_seconds();
            let poll_interval = inner.config.scheduler().poll_interval;
            let delay = inner.scheduler.lock().map_or(poll_interval, |scheduler| {
                scheduler.next_delay(now, poll_interval)
            });
            drop(inner);

            if delay.is_zero() {
                tokio::task::yield_now().await;
            } else {
                let _ = tokio::time::timeout(delay, notify.notified()).await;
            }

            let Some(inner) = weak.upgrade() else {
                return;
            };
            let client = Self { inner };
            client.run_scheduler_cycle().await;
        }
    }

    async fn run_scheduler_cycle(&self) {
        let now = self.inner.time.unix_seconds();
        let online_hint = self.inner.online_hint.swap(false, Ordering::AcqRel);
        let explicitly_requested = self
            .inner
            .validation_requested
            .swap(false, Ordering::AcqRel);
        let (has_credential, core_requested) = match self.inner.runtime.lock() {
            Ok(mut runtime) => {
                let event = if online_hint {
                    Event::NetworkAvailable
                } else {
                    Event::Tick
                };
                let effects = runtime.state.handle(event, now);
                let core_requested = effects
                    .iter()
                    .any(|effect| matches!(effect, Effect::SendValidation));
                if runtime.snapshot.is_some() {
                    let _ = self.persist_locked(&runtime);
                }
                self.emit_effects(&effects);
                (runtime.state.has_credential(), core_requested)
            }
            Err(_) => return,
        };
        let minimum_interval = self.inner.config.core().min_validation_interval_secs;
        let should_attempt = self.inner.scheduler.lock().is_ok_and(|mut scheduler| {
            scheduler.should_attempt(
                now,
                has_credential,
                online_hint,
                explicitly_requested || core_requested,
                minimum_interval,
            )
        });
        if !should_attempt {
            return;
        }

        match self.validate().await {
            Ok(())
            | Err(ValidationError::Transient(_))
            | Err(ValidationError::Fatal(_))
            | Err(ValidationError::Local(_))
            | Err(ValidationError::AlreadyInFlight)
            | Err(ValidationError::ReactivationRequired)
            | Err(ValidationError::VersionOutOfScope)
            | Err(ValidationError::NotActivated) => {}
        }
    }

    fn request_validation(&self) {
        self.inner
            .validation_requested
            .store(true, Ordering::Release);
        self.inner.scheduler_notify.notify_one();
    }

    fn mark_scheduler_attempt(&self, now: i64) {
        if let Ok(mut scheduler) = self.inner.scheduler.lock() {
            scheduler.mark_attempt(now);
        }
    }

    fn record_scheduler_success(&self, now: i64, start: i64, deadline: i64) {
        let sample = self.scheduler_random_sample();
        if let Ok(mut scheduler) = self.inner.scheduler.lock() {
            scheduler.record_success(now, start, deadline, sample);
        }
        self.inner.scheduler_notify.notify_one();
    }

    fn record_scheduler_failure(&self, error: TransientError) {
        let retry_after = match error {
            TransientError::RateLimited { retry_after } => {
                Some(Duration::from_secs(u64::from(retry_after)))
            }
            TransientError::Offline
            | TransientError::Timeout
            | TransientError::ServerError(_)
            | TransientError::TransportFailure => None,
            _ => None,
        };
        let now = self.inner.time.unix_seconds();
        let sample = self.scheduler_random_sample();
        if let Ok(mut scheduler) = self.inner.scheduler.lock() {
            scheduler.record_failure(now, self.inner.config.scheduler(), retry_after, sample);
        }
        self.inner.scheduler_notify.notify_one();
    }

    fn disable_scheduler(&self) {
        if let Ok(mut scheduler) = self.inner.scheduler.lock() {
            scheduler.disable();
        }
        self.inner.scheduler_notify.notify_one();
    }

    fn scheduler_random_sample(&self) -> u64 {
        random_array::<8>(self.inner.random.as_ref())
            .map(u64::from_le_bytes)
            .unwrap_or(1_500)
    }

    fn ensure_device_keys(&self) -> Result<(), LocalError> {
        let needs_keys = self.lock_runtime()?.snapshot.is_none();
        if !needs_keys {
            return Ok(());
        }
        let generated = generate_snapshot::<S>(self.inner.random.as_ref())?;
        let mut runtime = self.lock_runtime()?;
        if runtime.snapshot.is_none() {
            runtime.snapshot = Some(generated);
        }
        Ok(())
    }

    async fn fetch_keyset(&self) -> Result<Keyset, ValidationError> {
        let response = self
            .send_get("v1/keys", copylocker_proto::responses::MAX_KEYSET_BYTES)
            .await
            .map_err(map_transport_validation)?;
        if let Some(error) = transient_status(&response) {
            return Err(ValidationError::Transient(error));
        }
        require_success_headers(&response).map_err(ValidationError::Fatal)?;
        if !(200..300).contains(&response.status) {
            return Err(ValidationError::Fatal(FatalError::CredentialCorrupt));
        }
        Keyset::decode(&response.body)
            .map_err(|error| ValidationError::Fatal(FatalError::from(error)))
    }

    async fn sync_revocations(&self, target_epoch: u64) -> Result<(), ValidationError> {
        loop {
            let current_epoch = self
                .lock_runtime()
                .map_err(ValidationError::Local)?
                .max_revocation_epoch;
            if target_epoch < current_epoch {
                return Err(ValidationError::Fatal(FatalError::RevocationRollback));
            }
            if target_epoch == current_epoch {
                return Ok(());
            }
            let cursor = current_epoch
                .checked_add(1)
                .ok_or(ValidationError::Fatal(FatalError::CredentialCorrupt))?;
            let response = self
                .send_get(
                    &format!("v1/revocations?since={cursor}"),
                    ARTIFACT_RESPONSE_LIMIT,
                )
                .await
                .map_err(map_transport_validation)?;
            if let Some(error) = transient_status(&response) {
                return Err(ValidationError::Transient(error));
            }
            require_success_headers(&response).map_err(ValidationError::Fatal)?;
            if !(200..300).contains(&response.status) {
                return Err(ValidationError::Fatal(FatalError::CredentialCorrupt));
            }
            let envelope = Envelope::decode(&response.body)
                .map_err(|error| ValidationError::Fatal(FatalError::from(error)))?;

            let now = self.inner.time.unix_seconds();
            let mut runtime = self.lock_runtime().map_err(ValidationError::Local)?;
            if runtime.max_revocation_epoch != current_epoch {
                continue;
            }
            let effective_now = runtime.state.clock().effective_now(now);
            let batch: RevocationBatch = runtime
                .chain
                .as_ref()
                .ok_or(ValidationError::Fatal(FatalError::ChainInvalid))?
                .verify_artifact(&envelope, self.inner.config.product_id(), effective_now)
                .map_err(|error| ValidationError::Fatal(FatalError::from(error)))?;
            if batch.proto_ver != PROTO_VER
                || batch.suite_id != S::SUITE_ID
                || batch.from_epoch != cursor
                || batch.to_epoch < batch.from_epoch
                || batch.to_epoch > target_epoch
                || envelope
                    .epoch_ref
                    .is_some_and(|signer| batch.revoked_epoch_ids.contains(&signer))
            {
                return Err(ValidationError::Fatal(FatalError::CredentialCorrupt));
            }

            let credential_ids = runtime
                .credential
                .as_ref()
                .map(|credential| {
                    (
                        credential.license_id,
                        credential.machine_id,
                        credential.epoch_id,
                    )
                })
                .or_else(|| {
                    runtime
                        .olk
                        .as_ref()
                        .map(|license| (license.license_id, license.machine_id, license.epoch_id))
                });
            let revocation_reason =
                credential_ids.and_then(|(license_id, machine_id, epoch_id)| {
                    if batch.revoked_license_ids.contains(&license_id) {
                        Some(KillReason::RevokedLicense)
                    } else if batch.revoked_machine_ids.contains(&machine_id) {
                        Some(KillReason::RevokedActivation)
                    } else if batch.revoked_epoch_ids.contains(&epoch_id) {
                        Some(KillReason::EpochRevoked)
                    } else {
                        None
                    }
                });
            let mut revoked_epochs = runtime
                .snapshot
                .as_ref()
                .ok_or(ValidationError::NotActivated)?
                .revoked_epochs()
                .to_vec();
            for epoch in &batch.revoked_epoch_ids {
                if !revoked_epochs.contains(epoch) {
                    revoked_epochs.push(*epoch);
                }
            }
            runtime
                .chain
                .as_mut()
                .ok_or(ValidationError::Fatal(FatalError::ChainInvalid))?
                .revocation_mut()
                .advance(batch.to_epoch, batch.revoked_epoch_ids)
                .map_err(|error| ValidationError::Fatal(FatalError::from(error)))?;
            runtime.max_revocation_epoch = batch.to_epoch;
            runtime
                .snapshot
                .as_mut()
                .ok_or(ValidationError::NotActivated)?
                .set_revoked_epochs(revoked_epochs);

            if let Some(reason) = revocation_reason {
                self.revoke_locked(&mut runtime, reason)
                    .map_err(ValidationError::Local)?;
                return Err(ValidationError::Fatal(FatalError::Revoked(reason)));
            }
            self.persist_locked(&runtime)
                .map_err(ValidationError::Local)?;
        }
    }

    fn needs_epoch_refresh(&self, envelope: &Envelope) -> Result<bool, ValidationError> {
        let epoch = envelope
            .epoch_ref
            .ok_or(ValidationError::Fatal(FatalError::ChainInvalid))?;
        let runtime = self.lock_runtime().map_err(ValidationError::Local)?;
        Ok(runtime
            .chain
            .as_ref()
            .is_none_or(|chain| chain.epoch(&epoch).is_none()))
    }

    fn install_keyset(&self, keyset: Keyset) -> Result<(), ValidationError> {
        let now = self.inner.time.unix_seconds();
        let mut runtime = self.lock_runtime().map_err(ValidationError::Local)?;
        let revoked_epochs = runtime
            .snapshot
            .as_ref()
            .ok_or(ValidationError::NotActivated)?
            .revoked_epochs()
            .to_vec();
        let chain = self
            .inner
            .anchors
            .verify_keyset(
                &keyset,
                self.inner.config.product_id(),
                runtime.state.clock().effective_now(now),
                runtime.max_revocation_epoch,
                &revoked_epochs,
            )
            .map_err(ValidationError::Fatal)?;
        runtime
            .snapshot
            .as_mut()
            .ok_or(ValidationError::NotActivated)?
            .set_epoch_certificates(keyset.epoch_certificates);
        runtime.chain = Some(chain);
        Ok(())
    }

    fn apply_transient_failure(&self, error: TransientError) -> Result<(), ValidationError> {
        let now = self.inner.time.unix_seconds();
        let mut runtime = self.lock_runtime().map_err(ValidationError::Local)?;
        let effects = runtime.state.handle(Event::NetworkFailed(error), now);
        self.persist_locked(&runtime)
            .map_err(ValidationError::Local)?;
        self.emit_effects(&effects);
        Ok(())
    }

    fn resolve_validation_stage_error(&self, error: ValidationError) -> ValidationError {
        match error {
            ValidationError::Transient(transient) => {
                self.record_scheduler_failure(transient);
                match self.apply_transient_failure(transient) {
                    Ok(()) => ValidationError::Transient(transient),
                    Err(local_or_fatal) => local_or_fatal,
                }
            }
            ValidationError::Fatal(fatal) => {
                self.fail_closed(fatal);
                ValidationError::Fatal(fatal)
            }
            ValidationError::NotActivated => ValidationError::NotActivated,
            ValidationError::AlreadyInFlight => ValidationError::AlreadyInFlight,
            ValidationError::ReactivationRequired => ValidationError::ReactivationRequired,
            ValidationError::VersionOutOfScope => ValidationError::VersionOutOfScope,
            ValidationError::Local(local) => ValidationError::Local(local),
        }
    }

    fn resolve_activate_transport(&self, error: TransportError) -> ActivateError {
        match map_transport_activate(error) {
            ActivateError::Fatal(fatal) => {
                self.fail_closed(fatal);
                ActivateError::Fatal(fatal)
            }
            other => other,
        }
    }

    fn resolve_deactivate_transport(&self, error: TransportError) -> DeactivateError {
        match map_transport_deactivate(error) {
            DeactivateError::Fatal(fatal) => {
                self.fail_closed(fatal);
                DeactivateError::Fatal(fatal)
            }
            other => other,
        }
    }

    async fn send_get(
        &self,
        path: &str,
        max_response_bytes: usize,
    ) -> Result<TransportResponse, TransportError> {
        let url = self
            .inner
            .config
            .endpoint(path)
            .map_err(|_| TransportError::InvalidRequest)?;
        let response = self
            .inner
            .transport
            .send(TransportRequest {
                method: HttpMethod::Get,
                url: url.to_string(),
                headers: protocol_headers(None),
                body: Vec::new(),
                timeout: self.inner.config.request_timeout(),
                max_response_bytes,
            })
            .await?;
        if response.body.len() > max_response_bytes {
            return Err(TransportError::ResponseTooLarge);
        }
        Ok(response)
    }

    async fn send_post(
        &self,
        path: &str,
        body: Vec<u8>,
        idempotency_key: Option<&str>,
        max_response_bytes: usize,
    ) -> Result<TransportResponse, TransportError> {
        if body.len() > copylocker_types::MAX_BODY_BYTES {
            return Err(TransportError::InvalidRequest);
        }
        let url = self
            .inner
            .config
            .endpoint(path)
            .map_err(|_| TransportError::InvalidRequest)?;
        let response = self
            .inner
            .transport
            .send(TransportRequest {
                method: HttpMethod::Post,
                url: url.to_string(),
                headers: protocol_headers(idempotency_key),
                body,
                timeout: self.inner.config.request_timeout(),
                max_response_bytes,
            })
            .await?;
        if response.body.len() > max_response_bytes {
            return Err(TransportError::ResponseTooLarge);
        }
        Ok(response)
    }

    fn persist_locked(&self, runtime: &Runtime<S>) -> Result<(), LocalError> {
        let snapshot = runtime
            .snapshot
            .as_ref()
            .ok_or(LocalError::StateUnavailable)?;
        let payload = snapshot.encode().map_err(|_| LocalError::SnapshotCorrupt)?;
        let clock = runtime.state.clock();
        let record = StoreRecord::new(
            payload,
            MonotonicState::new(
                clock.last_seen_max(),
                clock.last_server_time(),
                clock.rollback_events(),
                runtime.max_security_floor,
                runtime.max_revocation_epoch,
            ),
        );
        let encoded = record.encode().map_err(LocalError::from)?;
        self.inner.store.save(&encoded).map_err(LocalError::from)
    }

    fn lock_runtime(&self) -> Result<MutexGuard<'_, Runtime<S>>, LocalError> {
        self.inner
            .runtime
            .lock()
            .map_err(|_| LocalError::StateUnavailable)
    }

    fn emit_effects(&self, effects: &[Effect]) {
        for effect in effects {
            if let Effect::StateChanged(state, reason) = effect {
                self.inner.state_changes.send_replace(StateChange {
                    state: *state,
                    reason: Some(*reason),
                });
            }
        }
    }

    fn fail_closed(&self, error: FatalError) {
        if let Ok(mut runtime) = self.inner.runtime.lock() {
            self.fail_closed_locked(&mut runtime, error);
        } else {
            let _ = self.inner.store.wipe();
        }
    }

    fn fail_closed_locked(&self, runtime: &mut Runtime<S>, error: FatalError) {
        let effects = runtime.state.handle(
            Event::VerificationFailed(error),
            self.inner.time.unix_seconds(),
        );
        runtime.snapshot = None;
        runtime.credential = None;
        runtime.olk = None;
        runtime.material = None;
        runtime.entitlements = Entitlements::default();
        runtime.offline_wrapped_keks.clear();
        runtime.online_wrapped_keks.clear();
        runtime.chain = None;
        let _ = self.inner.store.wipe();
        self.disable_scheduler();
        self.emit_effects(&effects);
    }

    fn revoke_locked(
        &self,
        runtime: &mut Runtime<S>,
        reason: KillReason,
    ) -> Result<(), LocalError> {
        let effects = runtime.state.handle(
            Event::KillOrderVerified(reason),
            self.inner.time.unix_seconds(),
        );
        runtime.snapshot = None;
        runtime.credential = None;
        runtime.olk = None;
        runtime.material = None;
        runtime.entitlements = Entitlements::default();
        runtime.offline_wrapped_keks.clear();
        runtime.online_wrapped_keks.clear();
        runtime.chain = None;
        let wipe_result = self.inner.store.wipe().map_err(LocalError::from);
        self.disable_scheduler();
        self.emit_effects(&effects);
        wipe_result
    }

    fn user_deactivate_locked(&self, runtime: &mut Runtime<S>) -> Result<(), LocalError> {
        let effects = runtime
            .state
            .handle(Event::UserDeactivate, self.inner.time.unix_seconds());
        runtime.snapshot = None;
        runtime.credential = None;
        runtime.olk = None;
        runtime.material = None;
        runtime.entitlements = Entitlements::default();
        runtime.offline_wrapped_keks.clear();
        runtime.online_wrapped_keks.clear();
        runtime.chain = None;
        let wipe_result = self.inner.store.wipe().map_err(LocalError::from);
        self.emit_effects(&effects);
        wipe_result
    }
}

fn generate_snapshot<S: CryptoSuite>(
    random: &dyn RandomSource,
) -> Result<ClientSnapshot, LocalError> {
    let mut rng = CryptoRngAdapter::new(random);
    let (mut kem_secret, _) = S::Kem::keygen(&mut rng);
    let (mut signing_secret, _) = FastSig::generate(&mut rng);
    if rng.failed() {
        return Err(LocalError::EntropyUnavailable);
    }
    let kem = S::Kem::encode_dk(&kem_secret);
    let signing = FastSig::encode_sk(&signing_secret);
    use zeroize::Zeroize;
    kem_secret.zeroize();
    signing_secret.zeroize();
    Ok(ClientSnapshot::new(kem, signing))
}

fn validate_device_keys<S: CryptoSuite>(snapshot: &ClientSnapshot) -> Result<(), FatalError> {
    S::Kem::decode_dk(snapshot.kem_secret_key()).map_err(|_| FatalError::CredentialCorrupt)?;
    FastSig::decode_sk(snapshot.signing_secret_key()).map_err(|_| FatalError::CredentialCorrupt)?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OpenOlkError {
    Fatal(FatalError),
    UnboundDisabled,
}

#[allow(clippy::too_many_arguments)]
fn open_offline_license<S: CryptoSuite>(
    envelope: &Envelope,
    chain: &VerifiedChain<S::Sig>,
    config: &Config,
    current_fingerprint: &Fingerprint,
    now: i64,
    known_security_floor: u64,
    known_revocation_epoch: u64,
) -> Result<(OfflineLicenseKey, KeyMaterial), OpenOlkError> {
    let preview = envelope
        .peek_unverified::<OfflineLicenseKey>()
        .map_err(|error| OpenOlkError::Fatal(FatalError::from(error)))?;
    let license: OfflineLicenseKey = chain
        .verify_artifact(envelope, config.product_id(), preview.issued_at)
        .map_err(|error| OpenOlkError::Fatal(FatalError::from(error)))?;
    if license.proto_ver != PROTO_VER
        || license.suite_id != S::SUITE_ID
        || license.product_id != config.product_id()
        || envelope.proto_ver != PROTO_VER
        || envelope.suite_id != S::SUITE_ID
        || envelope.epoch_ref != Some(license.epoch_id)
        || license.build_fingerprint != config.client_info().build_fingerprint
        || license.variant_id != config.client_info().variant_id
        || license.max_seats == 0
        || license.security_floor < known_security_floor
        || license.revocation_epoch < known_revocation_epoch
        || license.issued_at > now
        || (license.not_after != 0
            && (license.not_after <= license.issued_at || now >= license.not_after))
        || license
            .wrapped_keks
            .keys()
            .any(|feature| !license.entitlements.has_feature(feature))
    {
        return Err(OpenOlkError::Fatal(
            if license.security_floor < known_security_floor {
                FatalError::SecurityFloorRegression
            } else if license.revocation_epoch < known_revocation_epoch {
                FatalError::RevocationRollback
            } else {
                FatalError::CredentialCorrupt
            },
        ));
    }
    let binding_fingerprint = match license.bound_fingerprint.as_ref() {
        Some(bound) if bound != current_fingerprint => {
            return Err(OpenOlkError::Fatal(FatalError::MachineMismatch));
        }
        Some(bound) => olk_binding_fingerprint(Some(bound)),
        None if !config.allow_unbound_olk() => return Err(OpenOlkError::UnboundDisabled),
        None => olk_binding_fingerprint(None),
    };
    let material = KeyMaterial::bind_olk::<S>(
        &license.key_seed,
        &binding_fingerprint,
        config.evidence(),
        &license.product_id,
        license.license_id,
        license.machine_id,
        license.epoch_id,
        license.variant_id,
        *config.variant_const(),
        license.offline_nonce,
    )
    .map_err(|_| OpenOlkError::Fatal(FatalError::CredentialCorrupt))?;
    Ok((license, material))
}

fn olk_deadlines(license: &OfflineLicenseKey) -> Deadlines {
    let stop = if license.not_after == 0 {
        i64::MAX
    } else {
        license.not_after
    };
    Deadlines {
        refresh_after: stop,
        grace_deadline: stop,
        not_after: license.not_after,
    }
}

#[allow(clippy::too_many_arguments)]
fn open_machine_credential<S: CryptoSuite>(
    encoded: &[u8],
    chain: &VerifiedChain<S::Sig>,
    snapshot: &ClientSnapshot,
    config: &Config,
    current_fingerprint: &Fingerprint,
    now: i64,
    known_security_floor: u64,
    known_revocation_epoch: u64,
) -> Result<(MachineCredential, KeyMaterial), FatalError> {
    let envelope = Envelope::decode(encoded).map_err(FatalError::from)?;
    if envelope.proto_ver != PROTO_VER || envelope.suite_id != S::SUITE_ID {
        return Err(FatalError::CredentialCorrupt);
    }
    let credential: MachineCredential = chain
        .verify_artifact(&envelope, config.product_id(), now)
        .map_err(FatalError::from)?;
    if credential.proto_ver != PROTO_VER
        || credential.suite_id != S::SUITE_ID
        || credential.product_id != config.product_id()
        || envelope.epoch_ref != Some(credential.epoch_id)
        || credential.fingerprint != *current_fingerprint
        || credential.build_fingerprint.as_deref()
            != Some(config.client_info().build_fingerprint.as_str())
        || credential.variant_id != config.client_info().variant_id
        || credential.security_floor < known_security_floor
        || credential.revocation_epoch < known_revocation_epoch
        || credential.issued_at > now
        || credential.refresh_after <= credential.issued_at
        || (credential.not_after != 0 && credential.not_after <= now)
    {
        return Err(if credential.security_floor < known_security_floor {
            FatalError::SecurityFloorRegression
        } else if credential.revocation_epoch < known_revocation_epoch {
            FatalError::RevocationRollback
        } else if credential.fingerprint != *current_fingerprint {
            FatalError::MachineMismatch
        } else {
            FatalError::CredentialCorrupt
        });
    }

    let decapsulation_key =
        S::Kem::decode_dk(snapshot.kem_secret_key()).map_err(|_| FatalError::CredentialCorrupt)?;
    let kem_shared = S::Kem::decap(&decapsulation_key, &Ciphertext(credential.kem_ct.clone()))
        .map_err(|_| FatalError::CredentialCorrupt)?;
    let context = CredentialSealContext {
        proto_ver: credential.proto_ver,
        suite_id: credential.suite_id,
        product_id: &credential.product_id,
        license_id: credential.license_id,
        machine_id: credential.machine_id,
        fingerprint: &credential.fingerprint,
        kem_ct: &credential.kem_ct,
        offline_nonce: &credential.offline_nonce,
        epoch_id: credential.epoch_id,
        variant_id: credential.variant_id,
    };
    let credential_secret =
        open_credential_secret::<S>(&kem_shared, &context, &credential.sealed_cs)
            .map_err(|_| FatalError::CredentialCorrupt)?;
    let shared_secret = SharedSecret::new(*credential_secret.expose());
    let material = KeyMaterial::bind::<S>(
        &shared_secret,
        &credential.fingerprint,
        config.evidence(),
        &credential.product_id,
        credential.license_id,
        credential.machine_id,
        credential.epoch_id,
        credential.variant_id,
        *config.variant_const(),
        credential.offline_nonce,
    )
    .map_err(|_| FatalError::CredentialCorrupt)?;
    Ok((credential, material))
}

#[allow(clippy::too_many_arguments)]
fn build_activation_request<S: CryptoSuite>(
    config: &Config,
    fingerprint: &Fingerprint,
    attributes: &DeviceAttrs,
    snapshot: &ClientSnapshot,
    credential: Credential,
    nonce: [u8; 32],
    now: i64,
) -> Result<Vec<u8>, FatalError> {
    let kem_secret =
        S::Kem::decode_dk(snapshot.kem_secret_key()).map_err(|_| FatalError::CredentialCorrupt)?;
    let signature_secret = FastSig::decode_sk(snapshot.signing_secret_key())
        .map_err(|_| FatalError::CredentialCorrupt)?;
    let mut request = ActivationRequest {
        proto_ver: PROTO_VER,
        suite_id: S::SUITE_ID,
        product_id: config.product_id().to_owned(),
        credential,
        fingerprint: fingerprint.clone(),
        device_attrs: config
            .report_device_attributes()
            .then(|| attributes.clone()),
        device_kem_ek: S::Kem::encode_ek(&S::Kem::encap_key(&kem_secret)),
        device_sig_vk: FastSig::encode_vk(&FastSig::verifying_key(&signature_secret)),
        nonce_c: nonce,
        client_time: now,
        client_info: config.client_info().clone(),
        attestation: None,
        proof: Vec::new(),
    };
    request.proof = FastSig::sign(
        &signature_secret,
        DomainCtx::new(
            ArtifactKind::ActivationRequest,
            S::SUITE_ID,
            config.product_id(),
        ),
        &request.proof_input(),
    )
    .map_err(|_| FatalError::CredentialCorrupt)?
    .0;
    let encoded = request.encode();
    if encoded.len() > copylocker_types::MAX_BODY_BYTES {
        return Err(FatalError::CredentialCorrupt);
    }
    Ok(encoded)
}

#[allow(clippy::too_many_arguments)]
fn build_validate_request<S: CryptoSuite>(
    config: &Config,
    fingerprint: &Fingerprint,
    snapshot: &ClientSnapshot,
    credential: &MachineCredential,
    nonce: [u8; 32],
    known_revocation_epoch: u64,
    known_security_floor: u64,
    now: i64,
) -> Result<Vec<u8>, FatalError> {
    let signature_secret = FastSig::decode_sk(snapshot.signing_secret_key())
        .map_err(|_| FatalError::CredentialCorrupt)?;
    let mut request = ValidateRequest {
        proto_ver: PROTO_VER,
        suite_id: S::SUITE_ID,
        license_id: credential.license_id,
        machine_id: credential.machine_id,
        fingerprint: fingerprint.clone(),
        nonce_c: nonce,
        client_time: now,
        known_revocation_epoch,
        client_info: config.client_info().clone(),
        proof: Vec::new(),
        integrity_summary: None,
        known_security_floor,
        telemetry: None,
    };
    request.proof = FastSig::sign(
        &signature_secret,
        DomainCtx::new(
            ArtifactKind::ValidateRequest,
            S::SUITE_ID,
            config.product_id(),
        ),
        &request.proof_input(),
    )
    .map_err(|_| FatalError::CredentialCorrupt)?
    .0;
    Ok(request.encode())
}

fn build_deactivate_request<S: CryptoSuite>(
    product_id: &str,
    snapshot: &ClientSnapshot,
    credential: &MachineCredential,
    nonce: [u8; 32],
    now: i64,
) -> Result<Vec<u8>, FatalError> {
    let signature_secret = FastSig::decode_sk(snapshot.signing_secret_key())
        .map_err(|_| FatalError::CredentialCorrupt)?;
    let mut request = DeactivateRequest {
        proto_ver: PROTO_VER,
        suite_id: S::SUITE_ID,
        license_id: credential.license_id,
        machine_id: credential.machine_id,
        nonce_c: nonce,
        client_time: now,
        proof: Vec::new(),
    };
    request.proof = FastSig::sign(
        &signature_secret,
        DomainCtx::new(ArtifactKind::DeactivateRequest, S::SUITE_ID, product_id),
        &request.proof_input(),
    )
    .map_err(|_| FatalError::CredentialCorrupt)?
    .0;
    Ok(request.encode())
}

fn deadlines_from_ticket(credential: &MachineCredential, ticket: &ValidationTicket) -> Deadlines {
    let grace_deadline = ticket
        .next_refresh_after
        .saturating_add(i64::from(credential.grace_seconds));
    Deadlines {
        refresh_after: ticket.next_refresh_after,
        grace_deadline: if ticket.not_after == 0 {
            grace_deadline
        } else {
            grace_deadline.min(ticket.not_after)
        },
        not_after: ticket.not_after,
    }
}

fn protocol_headers(idempotency_key: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        (String::from("Accept"), String::from("application/cbor")),
        (String::from("X-CL-Proto"), String::from("1")),
        (
            String::from("Content-Type"),
            String::from("application/cbor"),
        ),
    ];
    if let Some(key) = idempotency_key {
        headers.push((String::from("Idempotency-Key"), key.to_owned()));
    }
    headers
}

fn require_success_headers(response: &TransportResponse) -> Result<(), FatalError> {
    let content_type_ok = response.content_type.as_deref().is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/cbor"))
    });
    if !content_type_ok || response.protocol_version.as_deref() != Some("1") {
        return Err(FatalError::CredentialCorrupt);
    }
    Ok(())
}

fn transient_status(response: &TransportResponse) -> Option<TransientError> {
    if response.status == 429 {
        let body_retry = ProtocolErrorResponse::decode(&response.body)
            .ok()
            .and_then(|error| error.retry_after);
        return Some(TransientError::RateLimited {
            retry_after: response.retry_after.or(body_retry).unwrap_or(60),
        });
    }
    if (500..600).contains(&response.status) {
        return Some(TransientError::ServerError(response.status));
    }
    None
}

enum ActivateResponseError {
    Transient(TransientError),
    Rejected(ActivationRejection),
    Fatal(FatalError),
}

fn activation_response(response: TransportResponse) -> Result<Vec<u8>, ActivateResponseError> {
    if let Some(error) = transient_status(&response) {
        return Err(ActivateResponseError::Transient(error));
    }
    require_success_headers(&response).map_err(ActivateResponseError::Fatal)?;
    if !(200..300).contains(&response.status) {
        let error = ProtocolErrorResponse::decode(&response.body)
            .map_err(|_| ActivateResponseError::Fatal(FatalError::CredentialCorrupt))?;
        return Err(ActivateResponseError::Rejected(
            ActivationRejection::from_code(error.code),
        ));
    }
    Ok(response.body)
}

enum ValidationResponseError {
    Transient(TransientError),
    Fatal(FatalError),
}

fn validation_response(response: TransportResponse) -> Result<Vec<u8>, ValidationResponseError> {
    if let Some(error) = transient_status(&response) {
        return Err(ValidationResponseError::Transient(error));
    }
    require_success_headers(&response).map_err(ValidationResponseError::Fatal)?;
    if !(200..300).contains(&response.status) {
        return Err(ValidationResponseError::Fatal(
            FatalError::CredentialCorrupt,
        ));
    }
    Ok(response.body)
}

fn map_transport_activate(error: TransportError) -> ActivateError {
    match error {
        TransportError::Offline => ActivateError::Transient(TransientError::Offline),
        TransportError::Timeout => ActivateError::Transient(TransientError::Timeout),
        TransportError::Failure => ActivateError::Transient(TransientError::TransportFailure),
        TransportError::ResponseTooLarge | TransportError::InvalidRequest => {
            ActivateError::Fatal(FatalError::CredentialCorrupt)
        }
    }
}

fn map_transport_validation(error: TransportError) -> ValidationError {
    match error {
        TransportError::Offline => ValidationError::Transient(TransientError::Offline),
        TransportError::Timeout => ValidationError::Transient(TransientError::Timeout),
        TransportError::Failure => ValidationError::Transient(TransientError::TransportFailure),
        TransportError::ResponseTooLarge | TransportError::InvalidRequest => {
            ValidationError::Fatal(FatalError::CredentialCorrupt)
        }
    }
}

fn map_transport_deactivate(error: TransportError) -> DeactivateError {
    match error {
        TransportError::Offline => DeactivateError::Transient(TransientError::Offline),
        TransportError::Timeout => DeactivateError::Transient(TransientError::Timeout),
        TransportError::Failure => DeactivateError::Transient(TransientError::TransportFailure),
        TransportError::ResponseTooLarge | TransportError::InvalidRequest => {
            DeactivateError::Fatal(FatalError::CredentialCorrupt)
        }
    }
}

fn random_idempotency_key(random: &dyn RandomSource) -> Result<String, LocalError> {
    let bytes = random_array::<16>(random)?;
    let mut output = String::with_capacity(32);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").map_err(|_| LocalError::EntropyUnavailable)?;
    }
    Ok(output)
}

struct ValidationFlight<'a> {
    flag: &'a AtomicBool,
}

impl<'a> ValidationFlight<'a> {
    fn acquire(flag: &'a AtomicBool) -> Result<Self, ValidationError> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ValidationError::AlreadyInFlight)?;
        Ok(Self { flag })
    }
}

impl Drop for ValidationFlight<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
