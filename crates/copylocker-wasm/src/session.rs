//! The platform-independent session core (`40-web-sdk-wasm-ts.md §3`).
//!
//! One opaque entry point — [`Session::step`] — dispatches CBOR-encoded ops over the full
//! license lifecycle: device key generation, snapshot export/import, activation, validation,
//! half-baked material derivation, asset-KEK unwrapping, and state-machine events. The
//! verification semantics replicate `copylocker-client` (`activate_credential` /
//! `open_machine_credential`, `validate`, `feature_key`, `unseal`) against the same
//! `copylocker-core` state machine, minus the pieces a browser shell owns (transport, timers,
//! storage, scheduling, and the web v1 container itself).
//!
//! Two deliberate scope cuts versus the desktop client: Offline License Keys (the air-gapped
//! flow) are not supported on the web, and the `/v1/revocations` delta sync is left to a later
//! milestone — kill orders still arrive through validation responses, so revocation
//! enforcement is intact.
//!
//! No function here panics: every parse is bounded and every failure is a numeric code.

use std::string::String;
use std::vec::Vec;

use std::collections::BTreeMap;

use copylocker_core::{
    check_ticket, ClockState, CoreConfig, Deadlines, Effect, Event, FatalError, KeyMaterial,
    SessionKind, StateMachine, TicketChecks, TransientError,
};
use copylocker_proto::keywrap::{open_credential_secret, CredentialSealContext};
use copylocker_proto::{
    ActivationRequest, ClientInfo, Credential, DeactivateRequest, Envelope, EpochCert, Keyset,
    KillOrder, MachineCredential, PinnedRoots, TelemetryBlock, ValidateRequest, ValidationTicket,
    VerifiedChain,
};
use copylocker_suite::cbor::{decode_canonical, CborValue, Limits, MapBuilder};
use copylocker_suite::{
    CryptoSuite, DomainCtx, EnvEvidence, HashScheme, KeyDerivation, KeyEncapsulation, Secret,
    SharedSecret, SignatureScheme,
};
use copylocker_suite_std::{ClStd1, FastSig, HybridSig};
use copylocker_types::{
    ArtifactKind, Digest, Entitlements, Fingerprint, StateReason, SuiteId, Verdict, PROTO_VER,
};
use zeroize::Zeroize;

use crate::codes;
use crate::rng::SessionRng;

/// The web SDK ships the CL-STD-1 reference suite; a private-suite build swaps this alias.
type Suite = ClStd1;
type Sig = HybridSig;
type Kem = <Suite as CryptoSuite>::Kem;
type Kdf = <Suite as CryptoSuite>::Kdf;
type Hash = <Suite as CryptoSuite>::Hash;

/// Hard cap on any `step` input, before CBOR parsing.
const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
/// Hard cap on an exported snapshot blob.
const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
/// Bounds for op envelopes and snapshots (mirrors `CLIENT_LIMITS` with artifact headroom).
const OP_LIMITS: Limits = Limits {
    max_depth: copylocker_types::MAX_CBOR_DEPTH,
    max_items: 4_096,
    max_string: 1024 * 1024,
};
const MAX_SECRET_KEY_BYTES: usize = 64 * 1024;
const MAX_IDENTIFIER_LEN: usize = 128;
const MAX_INFO_STRING_LEN: usize = 1024;
const SNAPSHOT_SCHEMA: u64 = 1;
const CONFIG_SCHEMA: u64 = 1;

/// HKDF salt for the half-baked material `M` (`40-web-sdk-wasm-ts.md §3.2`). Protocol-visible
/// and frozen. `M` is a *sibling* of the Feature Key — derived under a different salt from the
/// same session root — so it can never open a wrapped KEK itself.
const WEB_M_SALT: &[u8] = b"cl/web/m/v1";

/// Static session configuration, decoded from the constructor's CBOR map.
struct SessionConfig {
    product_id: String,
    client_info: ClientInfo,
    fingerprint: Fingerprint,
    variant_const: Secret<[u8; 32]>,
    evidence: EnvEvidence,
    core: CoreConfig,
}

impl core::fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionConfig")
            .field("product_id", &self.product_id)
            .field("client_info", &self.client_info)
            .field("fingerprint", &"<redacted>")
            .field("variant_const", &"<redacted>")
            .field("evidence", &"<redacted>")
            .field("core", &self.core)
            .finish()
    }
}

/// Pinned root anchors: the verifying keys plus their pinned digests.
struct Anchors {
    current: (Digest, <Sig as SignatureScheme>::VerifyingKey),
    next: Option<(Digest, <Sig as SignatureScheme>::VerifyingKey)>,
    pins: PinnedRoots,
}

impl core::fmt::Debug for Anchors {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Anchors")
            .field("current_digest", &self.current.0)
            .field("has_next", &self.next.is_some())
            .finish()
    }
}

impl Anchors {
    fn decode(current: &[u8], next: Option<&[u8]>) -> Result<Self, u16> {
        let current = decode_root(current)?;
        let next = next.map(decode_root).transpose()?;
        let pins = match next.as_ref() {
            Some(successor) => PinnedRoots::with_next(current.0, successor.0),
            None => PinnedRoots::single(current.0),
        };
        Ok(Self {
            current,
            next,
            pins,
        })
    }

    /// Verify a `/v1/keys` keyset into a trusted chain.
    ///
    /// Replicates `TrustAnchors::verify_keyset` from `copylocker-client` (kept crate-local so
    /// the desktop client needs no changes): the unsigned keyset container is only a fetch
    /// hint — every certificate still verifies against a pinned root, and the revocation
    /// watermark never moves backwards.
    fn verify_keyset(
        &self,
        keyset: &Keyset,
        product_id: &str,
        now: i64,
        known_revocation_epoch: u64,
    ) -> Result<VerifiedChain<Sig>, FatalError> {
        if keyset.proto_ver != PROTO_VER {
            return Err(FatalError::CredentialCorrupt);
        }
        if keyset.revocation_epoch < known_revocation_epoch {
            return Err(FatalError::RevocationRollback);
        }
        let mut chain = VerifiedChain::new(self.pins.clone());
        chain
            .revocation_mut()
            .advance(known_revocation_epoch, Vec::new())
            .map_err(FatalError::from)?;
        for encoded in &keyset.epoch_certificates {
            let envelope = Envelope::decode(encoded).map_err(FatalError::from)?;
            let certificate = envelope
                .peek_unverified::<EpochCert>()
                .map_err(FatalError::from)?;
            if certificate.product_scope.as_deref() != Some(product_id) {
                continue;
            }
            if envelope.proto_ver != PROTO_VER
                || envelope.suite_id != Suite::SUITE_ID
                || envelope.epoch_ref.is_some()
                || certificate.proto_ver != PROTO_VER
                || certificate.suite_id != Suite::SUITE_ID
                || certificate.not_after <= certificate.not_before
            {
                return Err(FatalError::CredentialCorrupt);
            }
            if !certificate.window().contains(now) {
                continue;
            }
            let root = self
                .root_for(&certificate.issuer_vk_digest)
                .ok_or(FatalError::ChainInvalid)?;
            chain
                .add_epoch::<Hash>(&envelope, product_id, root, now)
                .map_err(FatalError::from)?;
        }
        Ok(chain)
    }

    fn root_for(&self, digest: &Digest) -> Option<&<Sig as SignatureScheme>::VerifyingKey> {
        if self.current.0 == *digest {
            return Some(&self.current.1);
        }
        self.next
            .as_ref()
            .filter(|next| next.0 == *digest)
            .map(|next| &next.1)
    }
}

fn decode_root(encoded: &[u8]) -> Result<(Digest, <Sig as SignatureScheme>::VerifyingKey), u16> {
    let key = Sig::decode_vk(encoded).map_err(|_| codes::ERR_BAD_CONFIG)?;
    Ok((Hash::hash(encoded), key))
}

/// Encoded device key material, wiped on drop via `Secret`.
struct DeviceKeys {
    kem_dk: Secret<Vec<u8>>,
    sig_sk: Secret<Vec<u8>>,
}

impl core::fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceKeys").finish_non_exhaustive()
    }
}

/// A browser-shell CopyLocker session over CL-STD-1.
///
/// Construct with [`Session::new`], drive with [`Session::step`]. All wall-clock time is
/// supplied by the host per call; the core keeps no clock and performs no I/O.
pub struct Session {
    cfg: SessionConfig,
    anchors: Anchors,
    state: StateMachine,
    device: Option<DeviceKeys>,
    credential: Option<MachineCredential>,
    credential_envelope: Option<Vec<u8>>,
    ticket_envelope: Option<Vec<u8>>,
    epoch_certificates: Vec<Vec<u8>>,
    chain: Option<VerifiedChain<Sig>>,
    material: Option<KeyMaterial>,
    entitlements: Entitlements,
    /// The most recent verified ticket's refreshed wrapped KEKs (proto field 15), present only
    /// while the ticket's verdict is `Ok` — the online half of `unseal-asset`.
    online_wrapped_keks: BTreeMap<String, Vec<u8>>,
    max_security_floor: u64,
    max_revocation_epoch: u64,
    pending_activation_nonce: Option<[u8; 32]>,
    pending_validate_nonce: Option<[u8; 32]>,
    last_reason: Option<StateReason>,
    rng: Box<dyn SessionRng>,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("product_id", &self.cfg.product_id)
            .field("state", &self.state.state())
            .field("has_credential", &self.credential.is_some())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Build a session from the CBOR configuration map.
    ///
    /// ```cddl
    /// cfg = {
    ///   0: 1,                  ; schema
    ///   1: tstr,               ; product_id
    ///   2: bstr,               ; pinned current root verifying key (HybridSig encoding)
    ///   3: ? bstr,             ; pinned successor root verifying key
    ///   4: bstr,               ; device fingerprint digest collected by the TS shell
    ///   5: bstr .size 32,      ; variant_const (build-time constant)
    ///   6: bstr .size 32,      ; module digest (wasm build digest evidence)
    ///   7: tstr,               ; build_fingerprint (== evidence)
    ///   8: tstr, 9: tstr,      ; app_version, sdk_version
    ///   10: tstr, 11: tstr,    ; os, arch
    ///   12: tstr,              ; release_id
    ///   13: uint,              ; variant_id
    ///   14: ? [bstr .size 4],  ; supported suites (default [CL-STD-1])
    ///   15: ? [uint],          ; supported variants (default [variant_id])
    ///   16: ? uint,            ; rollback threshold (default 3)
    ///   17: ? int,             ; min validation interval secs (default 60)
    ///   18: int,               ; host wall clock, unix seconds
    /// }
    /// ```
    pub fn new(cfg: &[u8], rng: Box<dyn SessionRng>) -> Result<Self, u16> {
        if cfg.is_empty() || cfg.len() > MAX_INPUT_BYTES {
            return Err(codes::ERR_MALFORMED);
        }
        let value = decode_canonical(cfg, OP_LIMITS).map_err(|_| codes::ERR_MALFORMED)?;
        if f_uint(&value, 0).map_err(|_| codes::ERR_BAD_CONFIG)? != CONFIG_SCHEMA {
            return Err(codes::ERR_BAD_CONFIG);
        }
        let product_id = f_text(&value, 1).map_err(|_| codes::ERR_BAD_CONFIG)?;
        validate_identifier(&product_id)?;
        let anchors = Anchors::decode(
            &f_bytes(&value, 2).map_err(|_| codes::ERR_BAD_CONFIG)?,
            f_opt_bytes(&value, 3)
                .map_err(|_| codes::ERR_BAD_CONFIG)?
                .as_deref(),
        )?;
        let fingerprint =
            Fingerprint::from_vec(f_bytes(&value, 4).map_err(|_| codes::ERR_BAD_CONFIG)?);
        if fingerprint.as_bytes().is_empty() || fingerprint.as_bytes().len() > MAX_SECRET_KEY_BYTES
        {
            return Err(codes::ERR_BAD_CONFIG);
        }
        let variant_const =
            Secret::new(f_fixed::<32>(&value, 5).map_err(|_| codes::ERR_BAD_CONFIG)?);
        let module_digest = Digest(f_fixed::<32>(&value, 6).map_err(|_| codes::ERR_BAD_CONFIG)?);
        let build_fingerprint = f_text(&value, 7).map_err(|_| codes::ERR_BAD_CONFIG)?;
        let client_info = ClientInfo {
            app_version: f_text(&value, 8).map_err(|_| codes::ERR_BAD_CONFIG)?,
            sdk_version: f_text(&value, 9).map_err(|_| codes::ERR_BAD_CONFIG)?,
            os: f_text(&value, 10).map_err(|_| codes::ERR_BAD_CONFIG)?,
            arch: f_text(&value, 11).map_err(|_| codes::ERR_BAD_CONFIG)?,
            build_fingerprint: build_fingerprint.clone(),
            release_id: f_text(&value, 12).map_err(|_| codes::ERR_BAD_CONFIG)?,
            variant_id: f_uint(&value, 13).map_err(|_| codes::ERR_BAD_CONFIG)?,
            supported_suites: f_suite_list(&value, 14).map_err(|_| codes::ERR_BAD_CONFIG)?,
            supported_variants: f_uint_list(&value, 15).map_err(|_| codes::ERR_BAD_CONFIG)?,
        };
        let rollback_threshold = f_opt_uint(&value, 16)
            .map_err(|_| codes::ERR_BAD_CONFIG)?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| codes::ERR_BAD_CONFIG)?
            .unwrap_or(copylocker_core::DEFAULT_ROLLBACK_THRESHOLD);
        let min_interval = f_opt_int(&value, 17)
            .map_err(|_| codes::ERR_BAD_CONFIG)?
            .unwrap_or(60);
        let seed_now = f_int(&value, 18).map_err(|_| codes::ERR_BAD_CONFIG)?;

        // The same validation the desktop `Config` enforces.
        let strings = [
            client_info.app_version.as_str(),
            client_info.sdk_version.as_str(),
            client_info.os.as_str(),
            client_info.arch.as_str(),
            client_info.build_fingerprint.as_str(),
            client_info.release_id.as_str(),
        ];
        if strings
            .iter()
            .any(|s| s.is_empty() || s.len() > MAX_INFO_STRING_LEN || s.contains('\0'))
            || client_info.supported_suites.is_empty()
            || !client_info.supported_suites.contains(&Suite::SUITE_ID)
            || !client_info
                .supported_variants
                .contains(&client_info.variant_id)
            || min_interval < 0
        {
            return Err(codes::ERR_BAD_CONFIG);
        }
        let evidence = EnvEvidence {
            module_digest,
            build_fingerprint: build_fingerprint.into_bytes(),
            extra: Vec::new(),
        };
        let core = CoreConfig {
            rollback_threshold,
            min_validation_interval_secs: min_interval,
        };

        Ok(Self {
            state: StateMachine::new(core, seed_now),
            cfg: SessionConfig {
                product_id,
                client_info,
                fingerprint,
                variant_const,
                evidence,
                core,
            },
            anchors,
            device: None,
            credential: None,
            credential_envelope: None,
            ticket_envelope: None,
            epoch_certificates: Vec::new(),
            chain: None,
            material: None,
            entitlements: Entitlements::default(),
            online_wrapped_keks: BTreeMap::new(),
            max_security_floor: 0,
            max_revocation_epoch: 0,
            pending_activation_nonce: None,
            pending_validate_nonce: None,
            last_reason: None,
            rng,
        })
    }

    /// The single opaque entry point: CBOR op map in, CBOR result map out, numeric error code.
    ///
    /// Request schema: `{0: op, ...}` with op codes from [`crate::codes`]. Every summary
    /// response carries `{1: state, 2: reason, 3: refresh_after, 4: grace_deadline,
    /// 5: not_after, 6: has_credential, 90: [effect codes], 91: ?wake_at}`; payload bytes ride
    /// in key 8 (request bodies, snapshots, `M`, or an unwrapped asset KEK) and the validation
    /// verdict (or kill reason) in key 7.
    pub fn step(&mut self, input: &[u8]) -> Result<Vec<u8>, u16> {
        if input.is_empty() || input.len() > MAX_INPUT_BYTES {
            return Err(codes::ERR_MALFORMED);
        }
        let value = decode_canonical(input, OP_LIMITS).map_err(|_| codes::ERR_MALFORMED)?;
        let op = f_uint(&value, 0)?;
        match op {
            codes::OP_DEVICE_KEYGEN => {
                self.ensure_device_keys()?;
                Ok(self.summary(&[], None).finish())
            }
            codes::OP_SNAPSHOT_EXPORT => self.op_snapshot_export(),
            codes::OP_SNAPSHOT_IMPORT => self.op_snapshot_import(&value),
            codes::OP_BUILD_ACTIVATE_REQUEST => self.op_build_activate_request(&value),
            codes::OP_INGEST_KEYSET => self.op_ingest_keyset(&value),
            codes::OP_INGEST_ACTIVATE_RESPONSE => self.op_ingest_activate_response(&value),
            codes::OP_BUILD_VALIDATE_REQUEST => self.op_build_validate_request(&value),
            codes::OP_INGEST_VALIDATE_RESPONSE => self.op_ingest_validate_response(&value),
            codes::OP_DERIVE_M => self.op_derive_m(&value),
            codes::OP_EVENT => self.op_event(&value),
            codes::OP_STATE_QUERY => Ok(self.summary(&[], None).finish()),
            codes::OP_BUILD_DEACTIVATE_REQUEST => self.op_build_deactivate_request(&value),
            codes::OP_UNSEAL_ASSET => self.op_unseal_asset(&value),
            _ => Err(codes::ERR_UNKNOWN_OP),
        }
    }

    // --- device keys ---------------------------------------------------------

    /// Generate the device KEM + signing key pair on first use (idempotent).
    fn ensure_device_keys(&mut self) -> Result<(), u16> {
        if self.device.is_some() {
            return Ok(());
        }
        self.rng.reset();
        let (mut kem_dk, mut sig_sk);
        {
            // `&mut &mut dyn SessionRng` satisfies `&mut dyn CryptoRng` through the blanket
            // impl, without relying on trait-upcasting coercions.
            let mut borrow = &mut *self.rng;
            let generated = Kem::keygen(&mut borrow);
            let signed = FastSig::generate(&mut borrow);
            kem_dk = generated.0;
            sig_sk = signed.0;
        }
        if self.rng.failed() {
            kem_dk.zeroize();
            sig_sk.zeroize();
            return Err(codes::ERR_ENTROPY);
        }
        let kem = Kem::encode_dk(&kem_dk);
        let sig = FastSig::encode_sk(&sig_sk);
        kem_dk.zeroize();
        sig_sk.zeroize();
        self.device = Some(DeviceKeys {
            kem_dk: Secret::new(kem),
            sig_sk: Secret::new(sig),
        });
        Ok(())
    }

    fn draw_nonce(&mut self) -> Result<[u8; 32], u16> {
        let mut nonce = [0u8; 32];
        self.rng.reset();
        copylocker_suite::CryptoRng::fill_bytes(&mut *self.rng, &mut nonce);
        if self.rng.failed() {
            nonce.zeroize();
            return Err(codes::ERR_ENTROPY);
        }
        Ok(nonce)
    }

    fn device(&self) -> Result<&DeviceKeys, u16> {
        self.device.as_ref().ok_or(codes::ERR_NO_DEVICE_KEYS)
    }

    // --- snapshot ------------------------------------------------------------

    /// Export the opaque session snapshot. The TS shell encrypts it with a non-extractable
    /// AES-GCM CryptoKey and stores it in IndexedDB (`40-web-sdk-wasm-ts.md §4.4`).
    ///
    /// ```cddl
    /// snapshot = {
    ///   0: 1,               ; schema
    ///   1: ? bstr,          ; device KEM decapsulation key (absent iff key 2 absent)
    ///   2: ? bstr,          ; device signing key
    ///   3: ? bstr,          ; credential envelope (raw, re-verified on import)
    ///   4: [bstr],          ; epoch certificates from the last keyset
    ///   5: ? bstr,          ; validation ticket envelope (re-verified on import)
    ///   6: ? bstr .size 32, ; pending activation nonce
    ///   7: int, 8: int,     ; clock guard: last_seen_max, last_server_time
    ///   9: uint,            ; rollback events
    ///   10: uint, 11: uint, ; monotonic security floor / revocation epoch watermarks
    /// }
    /// ```
    fn op_snapshot_export(&mut self) -> Result<Vec<u8>, u16> {
        let clock = self.state.clock();
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(SNAPSHOT_SCHEMA));
        if let Some(device) = self.device.as_ref() {
            b.put(1, CborValue::Bytes(device.kem_dk.expose().clone()));
            b.put(2, CborValue::Bytes(device.sig_sk.expose().clone()));
        }
        b.put_opt(3, self.credential_envelope.clone().map(CborValue::Bytes));
        b.put(
            4,
            CborValue::Array(
                self.epoch_certificates
                    .iter()
                    .cloned()
                    .map(CborValue::Bytes)
                    .collect(),
            ),
        );
        b.put_opt(5, self.ticket_envelope.clone().map(CborValue::Bytes));
        b.put_opt(
            6,
            self.pending_activation_nonce
                .map(|nonce| CborValue::Bytes(nonce.to_vec())),
        );
        b.put(7, CborValue::int(clock.last_seen_max()));
        b.put(8, CborValue::int(clock.last_server_time()));
        b.put(9, CborValue::Uint(u64::from(clock.rollback_events())));
        b.put(10, CborValue::Uint(self.max_security_floor));
        b.put(11, CborValue::Uint(self.max_revocation_epoch));
        let encoded = b.finish();
        if encoded.len() > MAX_SNAPSHOT_BYTES {
            return Err(codes::ERR_BAD_SNAPSHOT);
        }
        let mut out = self.summary(&[], None);
        out.put(8, CborValue::Bytes(encoded));
        Ok(out.finish())
    }

    /// Import a snapshot and rebuild every verified structure from it.
    ///
    /// Replicates the desktop client's startup path: the stored credential envelope is
    /// re-verified against the rebuilt chain, the KEM secret re-decapsulated, the key material
    /// re-bound, and a stored ticket re-checked — nothing in the blob is trusted without
    /// re-verification. Fields: `1: bstr snapshot`, `2: int now`.
    fn op_snapshot_import(&mut self, value: &CborValue) -> Result<Vec<u8>, u16> {
        if self.device.is_some() || self.credential.is_some() {
            return Err(codes::ERR_BAD_STATE);
        }
        let blob = f_bytes(value, 1)?;
        let now = f_int(value, 2)?;
        if blob.is_empty() || blob.len() > MAX_SNAPSHOT_BYTES {
            return Err(codes::ERR_BAD_SNAPSHOT);
        }
        let snap = decode_canonical(&blob, OP_LIMITS).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        if f_uint(&snap, 0).map_err(|_| codes::ERR_BAD_SNAPSHOT)? != SNAPSHOT_SCHEMA {
            return Err(codes::ERR_BAD_SNAPSHOT);
        }
        let kem_dk = f_opt_bytes(&snap, 1).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let sig_sk = f_opt_bytes(&snap, 2).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let device = match (kem_dk, sig_sk) {
            (None, None) => None,
            (Some(kem), Some(sig)) => {
                if kem.is_empty()
                    || kem.len() > MAX_SECRET_KEY_BYTES
                    || sig.is_empty()
                    || sig.len() > MAX_SECRET_KEY_BYTES
                {
                    return Err(codes::ERR_BAD_SNAPSHOT);
                }
                // Reject undecodable key material before it is ever used.
                Kem::decode_dk(&kem).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
                FastSig::decode_sk(&sig).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
                Some(DeviceKeys {
                    kem_dk: Secret::new(kem),
                    sig_sk: Secret::new(sig),
                })
            }
            _ => return Err(codes::ERR_BAD_SNAPSHOT),
        };
        let credential_envelope = f_opt_bytes(&snap, 3).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let ticket_envelope = f_opt_bytes(&snap, 5).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let epoch_certificates = f_bytes_list(&snap, 4).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let pending_nonce = f_opt_bytes(&snap, 6)
            .map_err(|_| codes::ERR_BAD_SNAPSHOT)?
            .map(|bytes| <[u8; 32]>::try_from(bytes.as_slice()))
            .transpose()
            .map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let last_seen_max = f_int(&snap, 7).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let last_server_time = f_int(&snap, 8).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let rollback_events = u32::try_from(f_uint(&snap, 9).map_err(|_| codes::ERR_BAD_SNAPSHOT)?)
            .map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let max_security_floor = f_uint(&snap, 10).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let max_revocation_epoch = f_uint(&snap, 11).map_err(|_| codes::ERR_BAD_SNAPSHOT)?;
        let clock = ClockState::from_persisted(last_seen_max, last_server_time, rollback_events)
            .ok_or(codes::ERR_BAD_SNAPSHOT)?;

        let mut state = StateMachine::new(self.cfg.core, last_seen_max);
        *state.clock_mut() = clock;
        self.state = state;
        self.device = device;
        self.max_security_floor = max_security_floor;
        self.max_revocation_epoch = max_revocation_epoch;
        self.epoch_certificates = epoch_certificates;
        self.pending_activation_nonce = pending_nonce;

        let mut effects = Vec::new();
        if let Some(envelope_bytes) = credential_envelope {
            let device_kem = self
                .device
                .as_ref()
                .ok_or(codes::ERR_BAD_SNAPSHOT)?
                .kem_dk
                .expose()
                .clone();
            let effective_now = self.state.clock().effective_now(now);
            let keyset = Keyset {
                proto_ver: PROTO_VER,
                epoch_certificates: self.epoch_certificates.clone(),
                revocation_epoch: self.max_revocation_epoch,
            };
            let chain = match self.anchors.verify_keyset(
                &keyset,
                &self.cfg.product_id,
                effective_now,
                self.max_revocation_epoch,
            ) {
                Ok(chain) => chain,
                Err(error) => return Err(self.fail_closed(error, now)),
            };
            let opened = open_machine_credential(
                &envelope_bytes,
                &chain,
                &device_kem,
                &self.cfg,
                effective_now,
                self.max_security_floor,
                self.max_revocation_epoch,
            );
            let (credential, mut material) = match opened {
                Ok(opened) => opened,
                Err(error) => return Err(self.fail_closed(error, now)),
            };
            self.max_security_floor = self.max_security_floor.max(credential.security_floor);
            self.max_revocation_epoch = self.max_revocation_epoch.max(credential.revocation_epoch);
            self.entitlements = credential.entitlements.clone();
            let mut deadlines = Deadlines {
                refresh_after: credential.refresh_after,
                grace_deadline: credential.grace_deadline(),
                not_after: credential.not_after,
            };

            let mut restored_verdict = None;
            if let Some(ticket_bytes) = ticket_envelope {
                restored_verdict = Some(self.restore_ticket(
                    &chain,
                    &credential,
                    &mut material,
                    &ticket_bytes,
                    &mut deadlines,
                    now,
                )?);
            }

            self.state.set_deadlines(deadlines);
            effects.extend(self.state.handle(Event::CredentialLoaded, now));
            effects.extend(self.state.handle(Event::Tick, now));
            // Mirror the desktop startup restore: a ticket that denied productive use must
            // keep denying it after a reload, or a persist/restore cycle would fail open.
            if let Some(verdict @ (Verdict::NeedsReactivation | Verdict::VersionOutOfScope)) =
                restored_verdict
            {
                effects.extend(self.state.handle(Event::TicketDenied(verdict), now));
            }
            self.credential = Some(credential);
            self.credential_envelope = Some(envelope_bytes);
            self.material = Some(material);
            self.chain = Some(chain);
        }
        Ok(self.summary(&effects, None).finish())
    }

    /// Re-verify a persisted validation ticket during snapshot import.
    ///
    /// Mirrors the desktop startup restore: `check_ticket` runs with the ticket's own nonce
    /// echo as the expected nonce (anti-replay is meaningless across restarts), and an `Ok`
    /// verdict re-arms the online session root. Returns the restored verdict so the caller can
    /// replay a denial into the state machine.
    fn restore_ticket(
        &mut self,
        chain: &VerifiedChain<Sig>,
        credential: &MachineCredential,
        material: &mut KeyMaterial,
        ticket_bytes: &[u8],
        deadlines: &mut Deadlines,
        now: i64,
    ) -> Result<Verdict, u16> {
        let envelope = match Envelope::decode(ticket_bytes) {
            Ok(envelope) => envelope,
            Err(error) => return Err(self.fail_closed(FatalError::from(error), now)),
        };
        let effective_now = self.state.clock().effective_now(now);
        let ticket: ValidationTicket = match chain.verify_artifact_fast::<FastSig, _>(
            &envelope,
            &self.cfg.product_id,
            effective_now,
        ) {
            Ok(ticket) => ticket,
            Err(error) => return Err(self.fail_closed(FatalError::from(error), now)),
        };
        let verified_epoch = match envelope.epoch_ref {
            Some(epoch) => epoch,
            None => return Err(self.fail_closed(FatalError::ChainInvalid, now)),
        };
        let checks = TicketChecks {
            supported_suites: &self.cfg.client_info.supported_suites,
            verified_epoch,
            sent_nonce: ticket.nonce_c_echo,
            machine_id: credential.machine_id,
            known_revocation_epoch: self.max_revocation_epoch,
            known_security_floor: self.max_security_floor,
        };
        if let Err(error) = check_ticket(&ticket, &checks, self.state.clock_mut(), now) {
            return Err(self.fail_closed(error, now));
        }
        self.max_security_floor = self.max_security_floor.max(ticket.security_floor);
        self.max_revocation_epoch = self.max_revocation_epoch.max(ticket.revocation_epoch);
        if let Some(updated) = ticket.entitlements.as_ref() {
            self.entitlements = updated.clone();
        }
        *deadlines = deadlines_from_ticket(credential, &ticket);
        if ticket.verdict == Verdict::Ok {
            material.set_online_session(ticket.server_nonce, ticket.epoch_id);
            self.online_wrapped_keks = ticket.wrapped_keks.clone().unwrap_or_default();
        } else {
            self.online_wrapped_keks.clear();
        }
        self.ticket_envelope = Some(ticket_bytes.to_vec());
        Ok(ticket.verdict)
    }

    // --- activation ----------------------------------------------------------

    /// Build a `/v1/activate` request body. Fields: `1: ?tstr license_key`,
    /// `3: ?bstr account_token` (exactly one required), `2: int now`.
    fn op_build_activate_request(&mut self, value: &CborValue) -> Result<Vec<u8>, u16> {
        if self.credential.is_some() {
            return Err(codes::ERR_ALREADY_ACTIVATED);
        }
        let license_key = f_opt_text(value, 1)?;
        let account_token = f_opt_bytes(value, 3)?;
        let credential = match (license_key, account_token) {
            (Some(key), None) => Credential::LicenseKey(key),
            (None, Some(token)) => Credential::AccountToken(token),
            _ => return Err(codes::ERR_BAD_FIELD),
        };
        let now = f_int(value, 2)?;
        self.ensure_device_keys()?;
        let nonce = self.draw_nonce()?;
        let body = build_activation_request(&self.cfg, self.device()?, credential, nonce, now)
            .map_err(codes::fatal_code)?;
        self.pending_activation_nonce = Some(nonce);
        let mut out = self.summary(&[], None);
        out.put(8, CborValue::Bytes(body));
        Ok(out.finish())
    }

    /// Ingest a `/v1/keys` response. Fields: `1: bstr keyset`, `2: int now`.
    fn op_ingest_keyset(&mut self, value: &CborValue) -> Result<Vec<u8>, u16> {
        let bytes = f_bytes(value, 1)?;
        let now = f_int(value, 2)?;
        let keyset = match Keyset::decode(&bytes) {
            Ok(keyset) => keyset,
            Err(error) => return Err(self.fail_closed(FatalError::from(error), now)),
        };
        let effective_now = self.state.clock().effective_now(now);
        match self.anchors.verify_keyset(
            &keyset,
            &self.cfg.product_id,
            effective_now,
            self.max_revocation_epoch,
        ) {
            Ok(chain) => {
                self.epoch_certificates = keyset.epoch_certificates;
                self.max_revocation_epoch = self.max_revocation_epoch.max(keyset.revocation_epoch);
                self.chain = Some(chain);
                Ok(self.summary(&[], None).finish())
            }
            Err(error) => Err(self.fail_closed(error, now)),
        }
    }

    /// Ingest a `/v1/activate` response: the full desktop verification pipeline (chain →
    /// semantic field checks → KEM decapsulation → credential-secret unsealing → binding →
    /// state machine). Fields: `1: bstr envelope`, `2: int now`.
    fn op_ingest_activate_response(&mut self, value: &CborValue) -> Result<Vec<u8>, u16> {
        if self.credential.is_some() {
            return Err(codes::ERR_ALREADY_ACTIVATED);
        }
        let bytes = f_bytes(value, 1)?;
        let now = f_int(value, 2)?;
        let Some(chain) = self.chain.clone() else {
            return Err(codes::ERR_NO_CHAIN);
        };
        let device_kem = self.device()?.kem_dk.expose().clone();
        let effective_now = self.state.clock().effective_now(now);
        let opened = open_machine_credential(
            &bytes,
            &chain,
            &device_kem,
            &self.cfg,
            effective_now,
            self.max_security_floor,
            self.max_revocation_epoch,
        );
        let (credential, material) = match opened {
            Ok(opened) => opened,
            Err(error) => return Err(self.fail_closed(error, now)),
        };
        self.max_security_floor = self.max_security_floor.max(credential.security_floor);
        self.max_revocation_epoch = self.max_revocation_epoch.max(credential.revocation_epoch);
        self.state.set_deadlines(Deadlines {
            refresh_after: credential.refresh_after,
            grace_deadline: credential.grace_deadline(),
            not_after: credential.not_after,
        });
        let effects = self.state.handle(Event::ActivationVerified, now);
        self.entitlements = credential.entitlements.clone();
        self.pending_activation_nonce = None;
        self.credential = Some(credential);
        self.credential_envelope = Some(bytes);
        self.material = Some(material);
        Ok(self.summary(&effects, None).finish())
    }

    // --- validation ----------------------------------------------------------

    /// Build a `/v1/validate` request body. Fields: `1: ? bstr telemetry_block` (canonical-CBOR
    /// `TelemetryBlock`, embedded at proto key 11 *before* signing so the device proof covers
    /// it), `2: int now`.
    fn op_build_validate_request(&mut self, value: &CborValue) -> Result<Vec<u8>, u16> {
        let now = f_int(value, 2)?;
        let telemetry = f_opt_bytes(value, 1)?
            .map(|bytes| TelemetryBlock::decode(&bytes).map_err(|_| codes::ERR_BAD_FIELD))
            .transpose()?;
        self.state.note_validation_attempt(now);
        let nonce = self.draw_nonce()?;
        let credential = self.credential.as_ref().ok_or(codes::ERR_NO_CREDENTIAL)?;
        let body = build_validate_request(
            &self.cfg,
            self.device()?,
            credential,
            nonce,
            self.max_revocation_epoch,
            self.max_security_floor,
            now,
            telemetry,
        )
        .map_err(codes::fatal_code)?;
        self.pending_validate_nonce = Some(nonce);
        let mut out = self.summary(&[], None);
        out.put(8, CborValue::Bytes(body));
        Ok(out.finish())
    }

    /// Ingest a `/v1/validate` response — a validation ticket or a kill order.
    /// Fields: `1: bstr envelope`, `2: int now`.
    fn op_ingest_validate_response(&mut self, value: &CborValue) -> Result<Vec<u8>, u16> {
        let bytes = f_bytes(value, 1)?;
        let now = f_int(value, 2)?;
        let nonce = self
            .pending_validate_nonce
            .take()
            .ok_or(codes::ERR_NO_PENDING)?;
        let envelope = match Envelope::decode(&bytes) {
            Ok(envelope) => envelope,
            Err(error) => return Err(self.fail_closed(FatalError::from(error), now)),
        };
        match envelope.kind {
            ArtifactKind::ValidationTicket => self.ingest_ticket(&envelope, bytes, nonce, now),
            ArtifactKind::KillOrder => self.ingest_kill_order(&envelope, nonce, now),
            _ => Err(self.fail_closed(FatalError::CredentialCorrupt, now)),
        }
    }

    /// The eight-check ticket pipeline, replicating the desktop `validate` flow.
    fn ingest_ticket(
        &mut self,
        envelope: &Envelope,
        envelope_bytes: Vec<u8>,
        nonce: [u8; 32],
        now: i64,
    ) -> Result<Vec<u8>, u16> {
        let credential = self
            .credential
            .as_ref()
            .ok_or(codes::ERR_NO_CREDENTIAL)?
            .clone();
        let Some(chain) = self.chain.clone() else {
            return Err(codes::ERR_NO_CHAIN);
        };
        let effective_now = self.state.clock().effective_now(now);
        let ticket: ValidationTicket = match chain.verify_artifact_fast::<FastSig, _>(
            envelope,
            &self.cfg.product_id,
            effective_now,
        ) {
            Ok(ticket) => ticket,
            Err(error) => return Err(self.fail_closed(FatalError::from(error), now)),
        };
        let verified_epoch = match envelope.epoch_ref {
            Some(epoch) => epoch,
            None => return Err(self.fail_closed(FatalError::ChainInvalid, now)),
        };
        let checks = TicketChecks {
            supported_suites: &self.cfg.client_info.supported_suites,
            verified_epoch,
            sent_nonce: nonce,
            machine_id: credential.machine_id,
            known_revocation_epoch: self.max_revocation_epoch,
            known_security_floor: self.max_security_floor,
        };
        if let Err(error) = check_ticket(&ticket, &checks, self.state.clock_mut(), now) {
            return Err(self.fail_closed(error, now));
        }
        self.max_security_floor = self.max_security_floor.max(ticket.security_floor);
        self.max_revocation_epoch = self.max_revocation_epoch.max(ticket.revocation_epoch);
        if let Some(updated) = ticket.entitlements.as_ref() {
            self.entitlements = updated.clone();
        }
        if ticket.verdict == Verdict::Ok {
            let material = self.material.as_mut().ok_or(codes::ERR_NO_CREDENTIAL)?;
            material.set_online_session(ticket.server_nonce, ticket.epoch_id);
            self.online_wrapped_keks = ticket.wrapped_keks.clone().unwrap_or_default();
        } else {
            self.online_wrapped_keks.clear();
        }
        self.state
            .set_deadlines(deadlines_from_ticket(&credential, &ticket));
        let event = match ticket.verdict {
            Verdict::Ok => Event::TicketVerified,
            Verdict::NeedsReactivation | Verdict::VersionOutOfScope => {
                Event::TicketDenied(ticket.verdict)
            }
        };
        let effects = self.state.handle(event, now);
        self.ticket_envelope = Some(envelope_bytes);
        let verdict = ticket.verdict as u64;
        Ok(self.summary(&effects, Some(verdict)).finish())
    }

    /// A verified kill order wipes all local credential material (fail closed).
    /// Key 7 of the summary carries the kill-reason code in this case.
    fn ingest_kill_order(
        &mut self,
        envelope: &Envelope,
        nonce: [u8; 32],
        now: i64,
    ) -> Result<Vec<u8>, u16> {
        let credential = self
            .credential
            .as_ref()
            .ok_or(codes::ERR_NO_CREDENTIAL)?
            .clone();
        let Some(chain) = self.chain.clone() else {
            return Err(codes::ERR_NO_CHAIN);
        };
        let effective_now = self.state.clock().effective_now(now);
        let order: KillOrder = match chain.verify_artifact_fast::<FastSig, _>(
            envelope,
            &self.cfg.product_id,
            effective_now,
        ) {
            Ok(order) => order,
            Err(error) => return Err(self.fail_closed(FatalError::from(error), now)),
        };
        let semantic_error = if order.proto_ver != PROTO_VER || order.suite_id != Suite::SUITE_ID {
            Some(FatalError::CredentialCorrupt)
        } else if order.machine_id != credential.machine_id {
            Some(FatalError::MachineMismatch)
        } else if order.nonce_c_echo != nonce {
            Some(FatalError::NonceMismatch)
        } else if order.revocation_epoch < self.max_revocation_epoch {
            Some(FatalError::RevocationRollback)
        } else {
            None
        };
        if let Some(error) = semantic_error {
            return Err(self.fail_closed(error, now));
        }
        self.state
            .clock_mut()
            .observe_server_time(order.server_time);
        let effects = self
            .state
            .handle(Event::KillOrderVerified(order.reason), now);
        self.wipe_material();
        Ok(self
            .summary(&effects, Some(u64::from(order.reason as u8)))
            .finish())
    }

    // --- derivation ----------------------------------------------------------

    /// Derive the 32-byte half-baked material `M` for an entitled feature.
    /// Fields: `1: tstr feature_id`, `2: uint session kind (0 offline, 1 online)`,
    /// `3: int now`. The material rides in response key 8.
    ///
    /// `M` is *not* a Feature Key: it derives from the session root under the separate
    /// `cl/web/m/v1` salt, so it cannot unwrap an asset KEK. The TypeScript shell completes
    /// the two-stage transform (`FinalKey = H(M ‖ K_build ‖ R ‖ H(wasmBytes))`,
    /// `40-web-sdk-wasm-ts.md §2`). The same entitlement and state gating as
    /// `KeyMaterial::feature_key` applies, with the same indistinguishable error.
    fn op_derive_m(&mut self, value: &CborValue) -> Result<Vec<u8>, u16> {
        let feature = f_text(value, 1)?;
        if feature.len() > copylocker_proto::MAX_FEATURE_ID_BYTES {
            return Err(codes::ERR_BAD_FIELD);
        }
        let kind = match f_uint(value, 2)? {
            0 => SessionKind::Offline,
            1 => SessionKind::Online,
            _ => return Err(codes::ERR_BAD_FIELD),
        };
        let now = f_int(value, 3)?;
        // The clock guard runs before any derivation, exactly like the desktop `feature_key`.
        let effects = self.state.handle(Event::Tick, now);
        let material = self.material.as_ref().ok_or(codes::ERR_NO_CREDENTIAL)?;
        if !self.state.permits_key_derivation() || !self.entitlements.has_feature(&feature) {
            return Err(codes::ERR_NOT_ENTITLED);
        }
        let root = material
            .session_root::<Suite>(kind)
            .map_err(|_| codes::ERR_DERIVATION)?;
        let variant_id = self.cfg.client_info.variant_id.to_be_bytes();
        let prk = Kdf::extract(WEB_M_SALT, root.as_slice());
        let mut m = [0u8; 32];
        let derived = Kdf::expand_parts(
            &prk,
            &[
                self.cfg.product_id.as_bytes(),
                &variant_id,
                self.cfg.variant_const.expose(),
                feature.as_bytes(),
            ],
            &mut m,
        );
        if derived.is_err() {
            m.zeroize();
            return Err(codes::ERR_DERIVATION);
        }
        let mut out = self.summary(&effects, None);
        out.put(8, CborValue::Bytes(m.to_vec()));
        m.zeroize();
        Ok(out.finish())
    }

    /// Unwrap an entitled feature's asset KEK — the web half of the desktop
    /// `CopyLockerClient::unseal` (`client.rs`): the container itself stays with the TS shell
    /// (web v1 AES-256-GCM, WebCrypto-aligned), the core only produces the KEK, and only when
    /// the credential, state, and entitlement chain all check out.
    /// Fields: `1: tstr feature_id`, `2: int now`. The 32-byte KEK rides in response key 8.
    ///
    /// KEK selection mirrors the desktop: the most recent `Ok` ticket's refreshed KEKs (online
    /// session root) win, then the credential's offline `wrapped_keks` — or, after an offline
    /// upgrade, the `preloaded_keks` entry for this build's variant (proto field 22 semantics,
    /// `versioning-and-variants.md` §3.2). Every failure is the same indistinguishable
    /// `ERR_NOT_ENTITLED`, so probing reveals nothing about which link broke.
    fn op_unseal_asset(&mut self, value: &CborValue) -> Result<Vec<u8>, u16> {
        let feature = f_text(value, 1)?;
        if feature.len() > copylocker_proto::MAX_FEATURE_ID_BYTES {
            return Err(codes::ERR_BAD_FIELD);
        }
        let now = f_int(value, 2)?;
        // The clock guard runs before any key material is produced, exactly like `feature_key`.
        let effects = self.state.handle(Event::Tick, now);
        let credential = self.credential.as_ref().ok_or(codes::ERR_NO_CREDENTIAL)?;
        let material = self.material.as_ref().ok_or(codes::ERR_NO_CREDENTIAL)?;
        let offline = offline_wrapped_kek(credential, &self.cfg, &feature);
        let online = self
            .online_wrapped_keks
            .get(&feature)
            .map_or(&[][..], Vec::as_slice);
        let kek = material
            .unwrap_kek_any::<Suite>(
                self.state.state(),
                &self.entitlements,
                &feature,
                online,
                offline,
            )
            .map_err(|_| codes::ERR_NOT_ENTITLED)?;
        let mut out = self.summary(&effects, None);
        out.put(8, CborValue::Bytes(kek.as_slice().to_vec()));
        Ok(out.finish())
    }

    // --- events --------------------------------------------------------------

    /// Drive the state machine. Fields: `1: uint event kind`, `2: int now`,
    /// `3: ?uint monotonic gap ms` (resume only). Kinds are the `EVENT_*` constants.
    fn op_event(&mut self, value: &CborValue) -> Result<Vec<u8>, u16> {
        let kind = f_uint(value, 1)?;
        let now = f_int(value, 2)?;
        let event = match kind {
            codes::EVENT_TICK => Event::Tick,
            codes::EVENT_NETWORK_AVAILABLE => Event::NetworkAvailable,
            codes::EVENT_APP_RESUMED => Event::AppResumed {
                monotonic_gap_ms: f_uint(value, 3)?,
            },
            codes::EVENT_NETWORK_FAILED => Event::NetworkFailed(TransientError::Offline),
            codes::EVENT_USER_DEACTIVATE => Event::UserDeactivate,
            _ => return Err(codes::ERR_BAD_FIELD),
        };
        let effects = self.state.handle(event, now);
        if kind == codes::EVENT_USER_DEACTIVATE {
            self.wipe_material();
        }
        Ok(self.summary(&effects, None).finish())
    }

    // --- deactivate ------------------------------------------------------------

    /// Build a `/v1/deactivate` request body. Fields: `2: int now`. The local wipe happens
    /// through `EVENT_USER_DEACTIVATE` once the host has the server's acknowledgement.
    fn op_build_deactivate_request(&mut self, value: &CborValue) -> Result<Vec<u8>, u16> {
        let now = f_int(value, 2)?;
        let nonce = self.draw_nonce()?;
        let credential = self.credential.as_ref().ok_or(codes::ERR_NO_CREDENTIAL)?;
        let mut sig_sk_bytes = self.device()?.sig_sk.expose().clone();
        let signature_secret = FastSig::decode_sk(&sig_sk_bytes);
        sig_sk_bytes.zeroize();
        let signature_secret = match signature_secret {
            Ok(secret) => secret,
            Err(_) => return Err(self.fail_closed(FatalError::CredentialCorrupt, now)),
        };
        let mut request = DeactivateRequest {
            proto_ver: PROTO_VER,
            suite_id: Suite::SUITE_ID,
            license_id: credential.license_id,
            machine_id: credential.machine_id,
            nonce_c: nonce,
            client_time: now,
            proof: Vec::new(),
        };
        request.proof = match FastSig::sign(
            &signature_secret,
            DomainCtx::new(
                ArtifactKind::DeactivateRequest,
                Suite::SUITE_ID,
                &self.cfg.product_id,
            ),
            &request.proof_input(),
        ) {
            Ok(signature) => signature.0,
            Err(_) => return Err(self.fail_closed(FatalError::CredentialCorrupt, now)),
        };
        let mut out = self.summary(&[], None);
        out.put(8, CborValue::Bytes(request.encode()));
        Ok(out.finish())
    }

    // --- shared helpers --------------------------------------------------------

    /// Fail closed: drive the verification-failure event, wipe everything, return the code.
    fn fail_closed(&mut self, error: FatalError, now: i64) -> u16 {
        let effects = self.state.handle(Event::VerificationFailed(error), now);
        self.note_effects(&effects);
        self.wipe_material();
        codes::fatal_code(error)
    }

    /// Drop every secret and verified structure. The monotonic watermarks stay: they are
    /// anti-rollback protection, not secrets.
    fn wipe_material(&mut self) {
        self.credential = None;
        self.credential_envelope.zeroize();
        self.ticket_envelope.zeroize();
        self.material = None;
        self.entitlements = Entitlements::default();
        self.online_wrapped_keks.clear();
        self.chain = None;
        self.epoch_certificates.zeroize();
        self.device = None;
        self.pending_activation_nonce.zeroize();
        self.pending_validate_nonce.zeroize();
    }

    fn note_effects(&mut self, effects: &[Effect]) {
        for effect in effects {
            if let Effect::StateChanged(_, reason) = effect {
                self.last_reason = Some(*reason);
            }
        }
    }

    /// The advisory summary map every response carries. Never usable for gating (ADR-0004).
    fn summary(&mut self, effects: &[Effect], verdict: Option<u64>) -> MapBuilder {
        self.note_effects(effects);
        let deadlines = self.state.deadlines();
        let mut effect_codes: Vec<CborValue> = Vec::with_capacity(effects.len());
        let mut wake_at = None;
        for effect in effects {
            let code = match effect {
                Effect::Persist(_) => codes::EFFECT_PERSIST,
                Effect::SendValidation => codes::EFFECT_SEND_VALIDATION,
                Effect::WipeAll => codes::EFFECT_WIPE_ALL,
                Effect::StateChanged(_, _) => codes::EFFECT_STATE_CHANGED,
                Effect::ScheduleWake { at } => {
                    wake_at = Some(*at);
                    codes::EFFECT_SCHEDULE_WAKE
                }
                _ => continue,
            };
            effect_codes.push(CborValue::Uint(code));
        }
        let mut b = MapBuilder::new();
        b.put(1, CborValue::Uint(codes::state_code(self.state.state())));
        b.put(
            2,
            CborValue::Uint(self.last_reason.map_or(0, codes::reason_code)),
        );
        b.put(3, CborValue::int(deadlines.refresh_after));
        b.put(4, CborValue::int(deadlines.grace_deadline));
        b.put(5, CborValue::int(deadlines.not_after));
        b.put(6, CborValue::Uint(u64::from(self.credential.is_some())));
        b.put_opt(7, verdict.map(CborValue::Uint));
        b.put(90, CborValue::Array(effect_codes));
        b.put_opt(91, wake_at.map(CborValue::int));
        b
    }
}

/// The offline wrapped KEK for one feature: the credential's own `wrapped_keks` when its
/// variant is this build's, otherwise the `preloaded_keks` entry the issuer prepared for this
/// build's variant (`preload_n` offline upgrades). An absent entry is an empty slice, which
/// fails the unwrap with the same indistinguishable error as any other mismatch.
fn offline_wrapped_kek<'a>(
    credential: &'a MachineCredential,
    cfg: &'a SessionConfig,
    feature: &str,
) -> &'a [u8] {
    if credential.variant_id == cfg.client_info.variant_id {
        return credential
            .wrapped_keks
            .get(feature)
            .map_or(&[][..], Vec::as_slice);
    }
    credential
        .preloaded_keks
        .as_ref()
        .and_then(|preloaded| preloaded.get(&cfg.client_info.variant_id))
        .and_then(|keks| keks.get(feature))
        .map_or(&[][..], Vec::as_slice)
}

/// Full credential opening, replicating `open_machine_credential` in `copylocker-client`:
/// envelope and chain verification, every semantic field check, KEM decapsulation, credential
/// secret unsealing, and device binding — in that order.
///
/// One deliberate extension over the desktop: a credential whose build fingerprint or variant
/// no longer matches this build is still accepted when its `preloaded_keks` cover this build's
/// variant (the `preload_n` offline-upgrade path, `versioning-and-variants.md` §3.2). The key
/// material then binds to *this* build's variant and evidence — exactly the context the server
/// wrapped the preloaded KEKs under — instead of the issuing release's.
fn open_machine_credential(
    encoded: &[u8],
    chain: &VerifiedChain<Sig>,
    kem_dk_bytes: &[u8],
    cfg: &SessionConfig,
    now: i64,
    known_security_floor: u64,
    known_revocation_epoch: u64,
) -> Result<(MachineCredential, KeyMaterial), FatalError> {
    let envelope = Envelope::decode(encoded).map_err(FatalError::from)?;
    if envelope.proto_ver != PROTO_VER || envelope.suite_id != Suite::SUITE_ID {
        return Err(FatalError::CredentialCorrupt);
    }
    let credential: MachineCredential = chain
        .verify_artifact(&envelope, &cfg.product_id, now)
        .map_err(FatalError::from)?;
    let exact_match = credential.build_fingerprint.as_deref()
        == Some(cfg.client_info.build_fingerprint.as_str())
        && credential.variant_id == cfg.client_info.variant_id;
    let preloaded_upgrade = !exact_match
        && credential
            .preloaded_keks
            .as_ref()
            .is_some_and(|preloaded| preloaded.contains_key(&cfg.client_info.variant_id));
    if credential.proto_ver != PROTO_VER
        || credential.suite_id != Suite::SUITE_ID
        || credential.product_id != cfg.product_id
        || envelope.epoch_ref != Some(credential.epoch_id)
        || credential.fingerprint != cfg.fingerprint
        || !(exact_match || preloaded_upgrade)
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
        } else if credential.fingerprint != cfg.fingerprint {
            FatalError::MachineMismatch
        } else {
            FatalError::CredentialCorrupt
        });
    }

    let decapsulation_key =
        Kem::decode_dk(kem_dk_bytes).map_err(|_| FatalError::CredentialCorrupt)?;
    let kem_shared = Kem::decap(
        &decapsulation_key,
        &copylocker_suite::Ciphertext(credential.kem_ct.clone()),
    )
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
        open_credential_secret::<Suite>(&kem_shared, &context, &credential.sealed_cs)
            .map_err(|_| FatalError::CredentialCorrupt)?;
    let shared_secret = SharedSecret::new(*credential_secret.expose());
    // The preloaded offline-upgrade path binds to this build's variant: that is the context the
    // sibling release's KEKs were wrapped under, and every other derivation input (the secret,
    // the device, the epoch, this build's evidence) is unchanged.
    let bind_variant = if exact_match {
        credential.variant_id
    } else {
        cfg.client_info.variant_id
    };
    let material = KeyMaterial::bind::<Suite>(
        &shared_secret,
        &credential.fingerprint,
        &cfg.evidence,
        &credential.product_id,
        credential.license_id,
        credential.machine_id,
        credential.epoch_id,
        bind_variant,
        *cfg.variant_const.expose(),
        credential.offline_nonce,
    )
    .map_err(|_| FatalError::CredentialCorrupt)?;
    Ok((credential, material))
}

/// Replicates `build_activation_request` in `copylocker-client`, with `device_attrs` always
/// omitted: the web shell never reports raw attributes (privacy default off).
fn build_activation_request(
    cfg: &SessionConfig,
    device: &DeviceKeys,
    credential: Credential,
    nonce: [u8; 32],
    now: i64,
) -> Result<Vec<u8>, FatalError> {
    let kem_secret =
        Kem::decode_dk(device.kem_dk.expose()).map_err(|_| FatalError::CredentialCorrupt)?;
    let signature_secret =
        FastSig::decode_sk(device.sig_sk.expose()).map_err(|_| FatalError::CredentialCorrupt)?;
    let mut request = ActivationRequest {
        proto_ver: PROTO_VER,
        suite_id: Suite::SUITE_ID,
        product_id: cfg.product_id.clone(),
        credential,
        fingerprint: cfg.fingerprint.clone(),
        device_attrs: None,
        device_kem_ek: Kem::encode_ek(&Kem::encap_key(&kem_secret)),
        device_sig_vk: FastSig::encode_vk(&FastSig::verifying_key(&signature_secret)),
        nonce_c: nonce,
        client_time: now,
        client_info: cfg.client_info.clone(),
        attestation: None,
        proof: Vec::new(),
    };
    request.proof = FastSig::sign(
        &signature_secret,
        DomainCtx::new(
            ArtifactKind::ActivationRequest,
            Suite::SUITE_ID,
            &cfg.product_id,
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

/// Replicates `build_validate_request` in `copylocker-client`, extended with the web T1
/// telemetry block: the TS shell passes the consented block in with the op so it is embedded
/// (proto key 11) *before* signing — attaching it after signing would invalidate the proof.
#[allow(clippy::too_many_arguments)]
fn build_validate_request(
    cfg: &SessionConfig,
    device: &DeviceKeys,
    credential: &MachineCredential,
    nonce: [u8; 32],
    known_revocation_epoch: u64,
    known_security_floor: u64,
    now: i64,
    telemetry: Option<TelemetryBlock>,
) -> Result<Vec<u8>, FatalError> {
    let signature_secret =
        FastSig::decode_sk(device.sig_sk.expose()).map_err(|_| FatalError::CredentialCorrupt)?;
    let mut request = ValidateRequest {
        proto_ver: PROTO_VER,
        suite_id: Suite::SUITE_ID,
        license_id: credential.license_id,
        machine_id: credential.machine_id,
        fingerprint: cfg.fingerprint.clone(),
        nonce_c: nonce,
        client_time: now,
        known_revocation_epoch,
        client_info: cfg.client_info.clone(),
        proof: Vec::new(),
        integrity_summary: None,
        known_security_floor,
        telemetry,
    };
    request.proof = FastSig::sign(
        &signature_secret,
        DomainCtx::new(
            ArtifactKind::ValidateRequest,
            Suite::SUITE_ID,
            &cfg.product_id,
        ),
        &request.proof_input(),
    )
    .map_err(|_| FatalError::CredentialCorrupt)?
    .0;
    Ok(request.encode())
}

/// Replicates `deadlines_from_ticket` in `copylocker-client`.
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

// --- CBOR field helpers (bounded, typed; the same discipline as `copylocker-proto::field`) ---

fn field(value: &CborValue, key: u64) -> Result<&CborValue, u16> {
    if value.as_map().is_none() {
        return Err(codes::ERR_MALFORMED);
    }
    value.get(key).ok_or(codes::ERR_BAD_FIELD)
}

fn f_uint(value: &CborValue, key: u64) -> Result<u64, u16> {
    field(value, key)?.as_uint().ok_or(codes::ERR_BAD_FIELD)
}

fn f_opt_uint(value: &CborValue, key: u64) -> Result<Option<u64>, u16> {
    match value.get(key) {
        None => Ok(None),
        Some(item) => item.as_uint().map(Some).ok_or(codes::ERR_BAD_FIELD),
    }
}

fn f_int(value: &CborValue, key: u64) -> Result<i64, u16> {
    field(value, key)?.as_int().ok_or(codes::ERR_BAD_FIELD)
}

fn f_opt_int(value: &CborValue, key: u64) -> Result<Option<i64>, u16> {
    match value.get(key) {
        None => Ok(None),
        Some(item) => item.as_int().map(Some).ok_or(codes::ERR_BAD_FIELD),
    }
}

fn f_bytes(value: &CborValue, key: u64) -> Result<Vec<u8>, u16> {
    field(value, key)?
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or(codes::ERR_BAD_FIELD)
}

fn f_opt_bytes(value: &CborValue, key: u64) -> Result<Option<Vec<u8>>, u16> {
    match value.get(key) {
        None => Ok(None),
        Some(item) => item
            .as_bytes()
            .map(|bytes| Some(bytes.to_vec()))
            .ok_or(codes::ERR_BAD_FIELD),
    }
}

fn f_text(value: &CborValue, key: u64) -> Result<String, u16> {
    field(value, key)?
        .as_text()
        .map(String::from)
        .ok_or(codes::ERR_BAD_FIELD)
}

fn f_opt_text(value: &CborValue, key: u64) -> Result<Option<String>, u16> {
    match value.get(key) {
        None => Ok(None),
        Some(item) => item
            .as_text()
            .map(|text| Some(String::from(text)))
            .ok_or(codes::ERR_BAD_FIELD),
    }
}

fn f_fixed<const N: usize>(value: &CborValue, key: u64) -> Result<[u8; N], u16> {
    f_bytes(value, key)?
        .try_into()
        .map_err(|_| codes::ERR_BAD_FIELD)
}

fn f_suite_list(value: &CborValue, key: u64) -> Result<Vec<SuiteId>, u16> {
    match value.get(key) {
        None => Ok(vec![Suite::SUITE_ID]),
        Some(item) => {
            let items = item.as_array().ok_or(codes::ERR_BAD_FIELD)?;
            let mut out = Vec::with_capacity(items.len());
            for entry in items {
                let bytes: [u8; 4] = entry
                    .as_bytes()
                    .ok_or(codes::ERR_BAD_FIELD)?
                    .try_into()
                    .map_err(|_| codes::ERR_BAD_FIELD)?;
                out.push(SuiteId(bytes));
            }
            Ok(out)
        }
    }
}

fn f_uint_list(value: &CborValue, key: u64) -> Result<Vec<u64>, u16> {
    match value.get(key) {
        None => Ok(vec![f_uint(value, 13)?]),
        Some(item) => {
            let items = item.as_array().ok_or(codes::ERR_BAD_FIELD)?;
            let mut out = Vec::with_capacity(items.len());
            for entry in items {
                out.push(entry.as_uint().ok_or(codes::ERR_BAD_FIELD)?);
            }
            Ok(out)
        }
    }
}

fn f_bytes_list(value: &CborValue, key: u64) -> Result<Vec<Vec<u8>>, u16> {
    let items = field(value, key)?.as_array().ok_or(codes::ERR_BAD_FIELD)?;
    if items.len() > copylocker_proto::responses::MAX_KEYSET_CERTIFICATES {
        return Err(codes::ERR_BAD_FIELD);
    }
    let mut out = Vec::with_capacity(items.len());
    for entry in items {
        let bytes = entry.as_bytes().ok_or(codes::ERR_BAD_FIELD)?;
        if bytes.is_empty()
            || bytes.len() > copylocker_proto::responses::MAX_EPOCH_CERTIFICATE_BYTES
        {
            return Err(codes::ERR_BAD_FIELD);
        }
        out.push(bytes.to_vec());
    }
    Ok(out)
}

fn validate_identifier(value: &str) -> Result<(), u16> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(codes::ERR_BAD_CONFIG);
    }
    Ok(())
}
