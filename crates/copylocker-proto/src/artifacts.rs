//! The signed protocol artifacts (`protocol-spec.md §4`–`§9`).
//!
//! Each type here is the *to-be-signed* body. The signature and the header that identifies it
//! live in [`crate::envelope::Envelope`].
//!
//! Field numbers are protocol-visible and frozen: renumbering one silently invalidates every
//! signature ever made. New fields are appended with new numbers and decoded as optional.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use copylocker_suite::cbor::{decode_canonical, CborValue, MapBuilder};
use copylocker_suite::{Artifact, CodecError};
use copylocker_types::{
    ArtifactKind, Digest, Entitlements, EpochId, Fingerprint, KillReason, LicenseId, MachineId,
    Mode, SuiteId, TimeWindow, Verdict,
};

use crate::entitlements as ent;
use crate::field;
use crate::{ProtoError, BULK_LIMITS, CLIENT_LIMITS};

/// Implement [`Artifact`] in terms of a `to_value`/`from_value` pair plus parse limits.
macro_rules! artifact_impl {
    ($ty:ty, $kind:expr, $limits:expr) => {
        impl Artifact for $ty {
            const KIND: ArtifactKind = $kind;

            fn to_canonical(&self) -> Result<Vec<u8>, CodecError> {
                Ok(self.to_value().to_canonical())
            }

            fn from_canonical(bytes: &[u8]) -> Result<Self, CodecError> {
                let v = decode_canonical(bytes, $limits)?;
                // A structural failure inside the artifact is still a codec failure from the
                // caller's point of view; the specific field is reported by `parse`.
                Self::parse(&v).map_err(|e| match e {
                    ProtoError::Codec(c) => c,
                    _ => CodecError::Malformed,
                })
            }
        }

        impl $ty {
            /// Parse from an already-decoded CBOR value, preserving field-level error detail.
            pub fn parse(v: &CborValue) -> Result<Self, ProtoError> {
                if v.as_map().is_none() {
                    return Err(ProtoError::Codec(CodecError::Malformed));
                }
                Self::from_value(v)
            }

            /// Decode from canonical bytes, preserving field-level error detail.
            pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
                let v = decode_canonical(bytes, $limits)?;
                Self::parse(&v)
            }

            /// Encode to canonical bytes.
            #[must_use]
            pub fn encode(&self) -> Vec<u8> {
                self.to_value().to_canonical()
            }
        }
    };
}

/// Root-signed certificate for an epoch signing key (`crypto-architecture.md §5`).
///
/// This is the only artifact signed by the root key. The root lives on an air-gapped machine,
/// so issuing one is a deliberate ceremony rather than an online operation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EpochCert {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite this epoch signs under.
    pub suite_id: SuiteId,
    /// Epoch identifier, referenced by every artifact this epoch signs.
    pub epoch_id: EpochId,
    /// Encoded hybrid verifying key for durable artifacts.
    pub vk: Vec<u8>,
    /// Encoded Ed25519 verifying key for the per-request fast path
    /// (`protocol-spec.md §5`). Present so that clients can verify tickets without a second
    /// round trip.
    pub vk_fast: Vec<u8>,
    /// Validity window.
    pub not_before: i64,
    /// End of validity, exclusive.
    pub not_after: i64,
    /// Product this epoch is scoped to; `None` means global.
    pub product_scope: Option<String>,
    /// Digest of the root verifying key that signed this certificate. The client checks it
    /// against its pinned roots *before* verifying the signature, so an attacker cannot make it
    /// do work against an attacker-chosen key.
    pub issuer_vk_digest: Digest,
}

impl EpochCert {
    /// Validity window as the shared time helper.
    #[must_use]
    pub fn window(&self) -> TimeWindow {
        TimeWindow::new(self.not_before, self.not_after)
    }

    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Bytes(self.epoch_id.as_bytes().to_vec()));
        b.put(3, CborValue::Bytes(self.vk.clone()));
        b.put(4, CborValue::Bytes(self.vk_fast.clone()));
        b.put(5, CborValue::int(self.not_before));
        b.put(6, CborValue::int(self.not_after));
        b.put_opt(7, self.product_scope.clone().map(CborValue::Text));
        b.put(
            8,
            CborValue::Bytes(self.issuer_vk_digest.as_bytes().to_vec()),
        );
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            epoch_id: field::epoch_id(v, 2)?,
            vk: field::bytes(v, 3)?,
            vk_fast: field::bytes(v, 4)?,
            not_before: field::int(v, 5)?,
            not_after: field::int(v, 6)?,
            product_scope: field::opt_text(v, 7)?,
            issuer_vk_digest: Digest(field::fixed::<32>(v, 8)?),
        })
    }
}

artifact_impl!(EpochCert, ArtifactKind::EpochCert, BULK_LIMITS);

/// The durable per-device credential (`protocol-spec.md §4`).
///
/// This is the artifact that actually matters: it carries the KEM-sealed credential secret from
/// which every feature key descends. Everything else either certifies it or extends its life.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MachineCredential {
    /// Protocol version.
    pub proto_ver: u8,
    /// Negotiated suite.
    pub suite_id: SuiteId,
    /// Product slug.
    pub product_id: String,
    /// License this activation belongs to.
    pub license_id: LicenseId,
    /// Server-assigned activation identifier.
    pub machine_id: MachineId,
    /// Fingerprint at issuance time.
    pub fingerprint: Fingerprint,
    /// KEM ciphertext addressed to the device's encapsulation key.
    pub kem_ct: Vec<u8>,
    /// AEAD-sealed credential secret.
    pub sealed_cs: Vec<u8>,
    /// Nonce used to derive the offline session root, since no ticket is available offline
    /// (`crypto-architecture.md §6`).
    pub offline_nonce: [u8; 32],
    /// Resolved entitlement snapshot.
    pub entitlements: Entitlements,
    /// Server time at issuance.
    pub issued_at: i64,
    /// Hard expiry; `0` means unlimited.
    pub not_after: i64,
    /// When the client should next validate online.
    pub refresh_after: i64,
    /// Additional seconds of use permitted after `refresh_after` when the network is down.
    pub grace_seconds: u32,
    /// Enforcement mode.
    pub mode: Mode,
    /// Revocation epoch at issuance; the client refuses anything older.
    pub revocation_epoch: u64,
    /// Epoch that signed this credential.
    pub epoch_id: EpochId,
    /// Build this credential is restricted to, if any.
    pub build_fingerprint: Option<String>,
    /// Policy bit flags.
    pub policy_flags: Option<u64>,
    /// Monotonic security baseline; the client rejects any credential below the highest value
    /// it has seen, which is what stops a rollback to a weaker build.
    pub security_floor: u64,
    /// Release variant this credential's keys are derived for.
    pub variant_id: u64,
    /// Per-feature wrapped asset key-encryption keys.
    pub wrapped_keks: BTreeMap<String, Vec<u8>>,
    /// Pre-issued KEKs for other variants, for offline upgrade policies.
    pub preloaded_keks: Option<BTreeMap<u64, BTreeMap<String, Vec<u8>>>>,
}

impl MachineCredential {
    /// Hard validity window.
    #[must_use]
    pub fn window(&self) -> TimeWindow {
        TimeWindow::new(self.issued_at, self.not_after)
    }

    /// The instant at which the client must stop working offline: the refresh deadline plus the
    /// grace allowance, never beyond the hard `not_after`.
    #[must_use]
    pub fn grace_deadline(&self) -> i64 {
        let soft = self
            .refresh_after
            .saturating_add(i64::from(self.grace_seconds));
        if self.not_after == TimeWindow::UNLIMITED {
            soft
        } else {
            soft.min(self.not_after)
        }
    }

    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Text(self.product_id.clone()));
        b.put(3, CborValue::Bytes(self.license_id.as_bytes().to_vec()));
        b.put(4, CborValue::Bytes(self.machine_id.as_bytes().to_vec()));
        b.put(5, CborValue::Bytes(self.fingerprint.as_bytes().to_vec()));
        b.put(6, CborValue::Bytes(self.kem_ct.clone()));
        b.put(7, CborValue::Bytes(self.sealed_cs.clone()));
        b.put(8, CborValue::Bytes(self.offline_nonce.to_vec()));
        b.put(9, ent::encode(&self.entitlements));
        b.put(10, CborValue::int(self.issued_at));
        b.put(11, CborValue::int(self.not_after));
        b.put(12, CborValue::int(self.refresh_after));
        b.put(13, CborValue::Uint(u64::from(self.grace_seconds)));
        b.put(14, CborValue::Uint(self.mode as u64));
        b.put(15, CborValue::Uint(self.revocation_epoch));
        b.put(16, CborValue::Bytes(self.epoch_id.as_bytes().to_vec()));
        b.put_opt(17, self.build_fingerprint.clone().map(CborValue::Text));
        b.put_opt(18, self.policy_flags.map(CborValue::Uint));
        b.put(19, CborValue::Uint(self.security_floor));
        b.put(20, CborValue::Uint(self.variant_id));
        b.put(21, field::enc_text_bytes_map(&self.wrapped_keks));
        b.put_opt(
            22,
            self.preloaded_keks.as_ref().map(|m| {
                CborValue::Map(
                    m.iter()
                        .map(|(vid, keks)| (CborValue::Uint(*vid), field::enc_text_bytes_map(keks)))
                        .collect(),
                )
            }),
        );
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        let mode_raw = field::u8_field(v, 14)?;
        let preloaded = match field::opt(v, 22) {
            None => None,
            Some(m) => {
                let entries = m
                    .as_map()
                    .ok_or(ProtoError::Codec(CodecError::TypeMismatch(22)))?;
                let mut out = BTreeMap::new();
                for (k, inner) in entries {
                    let vid = k
                        .as_uint()
                        .ok_or(ProtoError::Codec(CodecError::TypeMismatch(22)))?;
                    let inner_entries = inner
                        .as_map()
                        .ok_or(ProtoError::Codec(CodecError::TypeMismatch(22)))?;
                    let mut keks = BTreeMap::new();
                    for (fk, fv) in inner_entries {
                        let name = fk
                            .as_text()
                            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(22)))?;
                        let blob = fv
                            .as_bytes()
                            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(22)))?;
                        keks.insert(String::from(name), blob.to_vec());
                    }
                    out.insert(vid, keks);
                }
                Some(out)
            }
        };

        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            product_id: field::text(v, 2)?,
            license_id: field::license_id(v, 3)?,
            machine_id: field::machine_id(v, 4)?,
            fingerprint: field::fingerprint(v, 5)?,
            kem_ct: field::bytes(v, 6)?,
            sealed_cs: field::bytes(v, 7)?,
            offline_nonce: field::fixed::<32>(v, 8)?,
            entitlements: ent::decode(field::req(v, 9)?)?,
            issued_at: field::int(v, 10)?,
            not_after: field::int(v, 11)?,
            refresh_after: field::int(v, 12)?,
            grace_seconds: u32::try_from(field::uint(v, 13)?)
                .map_err(|_| ProtoError::FieldOutOfRange(13))?,
            mode: Mode::from_u8(mode_raw)
                .ok_or(ProtoError::Codec(CodecError::UnknownDiscriminant))?,
            revocation_epoch: field::uint(v, 15)?,
            epoch_id: field::epoch_id(v, 16)?,
            build_fingerprint: field::opt_text(v, 17)?,
            policy_flags: field::opt_uint(v, 18)?,
            security_floor: field::uint(v, 19)?,
            variant_id: field::uint(v, 20)?,
            wrapped_keks: field::text_bytes_map(v, 21)?,
            preloaded_keks: preloaded,
        })
    }
}

artifact_impl!(MachineCredential, ArtifactKind::MachineCred, BULK_LIMITS);

/// Per-validation ticket (`protocol-spec.md §5`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidationTicket {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite.
    pub suite_id: SuiteId,
    /// Which activation this ticket is for.
    pub machine_id: MachineId,
    /// Echo of the client nonce. The client compares this to what it sent; a mismatch means
    /// replay (`protocol-spec.md §5`, check 4).
    pub nonce_c_echo: [u8; 32],
    /// Server nonce, mixed into the online session root so that an intercepted response cannot
    /// be reused indefinitely.
    pub server_nonce: [u8; 32],
    /// Authoritative server time.
    pub server_time: i64,
    /// Next validation deadline.
    pub next_refresh_after: i64,
    /// Possibly-extended hard expiry.
    pub not_after: i64,
    /// Current revocation epoch.
    pub revocation_epoch: u64,
    /// Server verdict.
    pub verdict: Verdict,
    /// Updated entitlements, when they changed since issuance.
    pub entitlements: Option<Entitlements>,
    /// Signing epoch.
    pub epoch_id: EpochId,
    /// Anomaly score, `0..=100`.
    pub suspicion_score: Option<u8>,
    /// Current security floor.
    pub security_floor: u64,
    /// Release status: 0 active, 1 deprecated, 2 compromised.
    pub release_status: Option<u8>,
    /// Refreshed wrapped KEKs, sent on variant switch or entitlement change.
    pub wrapped_keks: Option<BTreeMap<String, Vec<u8>>>,
    /// Server request for an early re-validation.
    pub refresh_now: Option<bool>,
}

impl ValidationTicket {
    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Bytes(self.machine_id.as_bytes().to_vec()));
        b.put(3, CborValue::Bytes(self.nonce_c_echo.to_vec()));
        b.put(4, CborValue::Bytes(self.server_nonce.to_vec()));
        b.put(5, CborValue::int(self.server_time));
        b.put(6, CborValue::int(self.next_refresh_after));
        b.put(7, CborValue::int(self.not_after));
        b.put(8, CborValue::Uint(self.revocation_epoch));
        b.put(9, CborValue::Uint(self.verdict as u64));
        b.put_opt(10, self.entitlements.as_ref().map(ent::encode));
        b.put(11, CborValue::Bytes(self.epoch_id.as_bytes().to_vec()));
        b.put_opt(
            12,
            self.suspicion_score.map(|s| CborValue::Uint(u64::from(s))),
        );
        b.put(13, CborValue::Uint(self.security_floor));
        b.put_opt(
            14,
            self.release_status.map(|s| CborValue::Uint(u64::from(s))),
        );
        b.put_opt(
            15,
            self.wrapped_keks.as_ref().map(field::enc_text_bytes_map),
        );
        b.put_opt(16, self.refresh_now.map(CborValue::Bool));
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        let verdict_raw = field::u8_field(v, 9)?;
        let suspicion = field::opt_uint(v, 12)?
            .map(u8::try_from)
            .transpose()
            .map_err(|_| ProtoError::FieldOutOfRange(12))?;
        if suspicion.is_some_and(|s| s > 100) {
            return Err(ProtoError::FieldOutOfRange(12));
        }
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            machine_id: field::machine_id(v, 2)?,
            nonce_c_echo: field::fixed::<32>(v, 3)?,
            server_nonce: field::fixed::<32>(v, 4)?,
            server_time: field::int(v, 5)?,
            next_refresh_after: field::int(v, 6)?,
            not_after: field::int(v, 7)?,
            revocation_epoch: field::uint(v, 8)?,
            verdict: Verdict::from_u8(verdict_raw)
                .ok_or(ProtoError::Codec(CodecError::UnknownDiscriminant))?,
            entitlements: match field::opt(v, 10) {
                None => None,
                Some(e) => Some(ent::decode(e)?),
            },
            epoch_id: field::epoch_id(v, 11)?,
            suspicion_score: suspicion,
            security_floor: field::uint(v, 13)?,
            release_status: field::opt_uint(v, 14)?
                .map(u8::try_from)
                .transpose()
                .map_err(|_| ProtoError::FieldOutOfRange(14))?,
            wrapped_keks: field::opt_text_bytes_map(v, 15)?,
            refresh_now: match field::opt(v, 16) {
                None => None,
                Some(b) => Some(
                    b.as_bool()
                        .ok_or(ProtoError::Codec(CodecError::TypeMismatch(16)))?,
                ),
            },
        })
    }
}

artifact_impl!(
    ValidationTicket,
    ArtifactKind::ValidationTicket,
    CLIENT_LIMITS
);

/// Immediate revocation for one device (`protocol-spec.md §6`).
///
/// Bound to both `machine_id` and `nonce_c_echo`, so a forged kill order only affects the
/// session that requested it — an attacker cannot use one to deny service to someone else.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KillOrder {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite.
    pub suite_id: SuiteId,
    /// Target activation.
    pub machine_id: MachineId,
    /// Echo of the client nonce from the request that triggered this.
    pub nonce_c_echo: [u8; 32],
    /// Server time.
    pub server_time: i64,
    /// Why.
    pub reason: KillReason,
    /// Message to show the end user.
    pub user_message: Option<String>,
    /// Current revocation epoch.
    pub revocation_epoch: u64,
}

impl KillOrder {
    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Bytes(self.machine_id.as_bytes().to_vec()));
        b.put(3, CborValue::Bytes(self.nonce_c_echo.to_vec()));
        b.put(4, CborValue::int(self.server_time));
        b.put(5, CborValue::Uint(self.reason as u64));
        b.put_opt(6, self.user_message.clone().map(CborValue::Text));
        b.put(7, CborValue::Uint(self.revocation_epoch));
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        let reason_raw = field::u8_field(v, 5)?;
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            machine_id: field::machine_id(v, 2)?,
            nonce_c_echo: field::fixed::<32>(v, 3)?,
            server_time: field::int(v, 4)?,
            reason: KillReason::from_u8(reason_raw)
                .ok_or(ProtoError::Codec(CodecError::UnknownDiscriminant))?,
            user_message: field::opt_text(v, 6)?,
            revocation_epoch: field::uint(v, 7)?,
        })
    }
}

artifact_impl!(KillOrder, ArtifactKind::KillOrder, CLIENT_LIMITS);

/// Batched revocation state (`protocol-spec.md §7`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RevocationBatch {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite.
    pub suite_id: SuiteId,
    /// First revocation sequence covered.
    pub from_epoch: u64,
    /// Last revocation sequence covered. Monotonic; the client rejects a batch older than what
    /// it already holds, which is what stops a rollback to a pre-revocation state.
    pub to_epoch: u64,
    /// Issuance time.
    pub issued_at: i64,
    /// Revoked licenses.
    pub revoked_license_ids: Vec<LicenseId>,
    /// Revoked activations.
    pub revoked_machine_ids: Vec<MachineId>,
    /// Revoked signing epochs.
    pub revoked_epoch_ids: Vec<EpochId>,
    /// Optional Bloom filter for large revocation sets. A false positive only forces an extra
    /// online check, so the failure direction is safe (`protocol-spec.md §7`).
    pub bloom_filter: Option<Vec<u8>>,
}

impl RevocationBatch {
    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Uint(self.from_epoch));
        b.put(3, CborValue::Uint(self.to_epoch));
        b.put(4, CborValue::int(self.issued_at));
        b.put(
            5,
            CborValue::Array(
                self.revoked_license_ids
                    .iter()
                    .map(|i| CborValue::Bytes(i.as_bytes().to_vec()))
                    .collect(),
            ),
        );
        b.put(
            6,
            CborValue::Array(
                self.revoked_machine_ids
                    .iter()
                    .map(|i| CborValue::Bytes(i.as_bytes().to_vec()))
                    .collect(),
            ),
        );
        b.put(
            7,
            CborValue::Array(
                self.revoked_epoch_ids
                    .iter()
                    .map(|i| CborValue::Bytes(i.as_bytes().to_vec()))
                    .collect(),
            ),
        );
        b.put_opt(8, self.bloom_filter.clone().map(CborValue::Bytes));
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            from_epoch: field::uint(v, 2)?,
            to_epoch: field::uint(v, 3)?,
            issued_at: field::int(v, 4)?,
            revoked_license_ids: field::fixed_array::<16>(v, 5)?
                .into_iter()
                .map(LicenseId)
                .collect(),
            revoked_machine_ids: field::fixed_array::<16>(v, 6)?
                .into_iter()
                .map(MachineId)
                .collect(),
            revoked_epoch_ids: field::fixed_array::<8>(v, 7)?
                .into_iter()
                .map(EpochId)
                .collect(),
            bloom_filter: field::opt_bytes(v, 8)?,
        })
    }
}

artifact_impl!(RevocationBatch, ArtifactKind::RevocationBatch, BULK_LIMITS);

/// Compact offline license key (`protocol-spec.md §8`).
///
/// An OLK without `bound_fingerprint` can be copied without limit — there is no server to stop
/// it. Policy defaults `allow_unbound_olk` to false for that reason.
#[derive(Clone, PartialEq, Eq)]
pub struct OfflineLicenseKey {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite (the compact suite, for size).
    pub suite_id: SuiteId,
    /// Product slug.
    pub product_id: String,
    /// License identifier.
    pub license_id: LicenseId,
    /// Entitlements.
    pub entitlements: Entitlements,
    /// Issuance time.
    pub issued_at: i64,
    /// Expiry.
    pub not_after: i64,
    /// Device this key is bound to, if any.
    pub bound_fingerprint: Option<Fingerprint>,
    /// Declared seat count. Advisory: with no server there is nothing to enforce it.
    pub max_seats: u64,
    /// Signing epoch.
    pub epoch_id: EpochId,
    /// Logical activation identifier used by wrapped-KEK AAD. Unbound copies intentionally
    /// share this value.
    pub machine_id: MachineId,
    /// Stable nonce for the offline session root.
    pub offline_nonce: [u8; 32],
    /// Signed bearer seed for productive key derivation. This value is not confidential, but
    /// must never be accepted outside a verified OLK envelope.
    pub key_seed: [u8; 32],
    /// Build this OLK is restricted to.
    pub build_fingerprint: String,
    /// Release variant whose assets this OLK opens.
    pub variant_id: u64,
    /// Monotonic security baseline.
    pub security_floor: u64,
    /// Revocation watermark at issuance.
    pub revocation_epoch: u64,
    /// Per-feature asset KEKs wrapped under the offline Feature Key.
    pub wrapped_keks: BTreeMap<String, Vec<u8>>,
}

impl OfflineLicenseKey {
    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Text(self.product_id.clone()));
        b.put(3, CborValue::Bytes(self.license_id.as_bytes().to_vec()));
        b.put(4, ent::encode(&self.entitlements));
        b.put(5, CborValue::int(self.issued_at));
        b.put(6, CborValue::int(self.not_after));
        b.put_opt(
            7,
            self.bound_fingerprint
                .as_ref()
                .map(|f| CborValue::Bytes(f.as_bytes().to_vec())),
        );
        b.put(8, CborValue::Uint(self.max_seats));
        b.put(9, CborValue::Bytes(self.epoch_id.as_bytes().to_vec()));
        b.put(10, CborValue::Bytes(self.machine_id.as_bytes().to_vec()));
        b.put(11, CborValue::Bytes(self.offline_nonce.to_vec()));
        b.put(12, CborValue::Bytes(self.key_seed.to_vec()));
        b.put(13, CborValue::Text(self.build_fingerprint.clone()));
        b.put(14, CborValue::Uint(self.variant_id));
        b.put(15, CborValue::Uint(self.security_floor));
        b.put(16, CborValue::Uint(self.revocation_epoch));
        b.put(17, field::enc_text_bytes_map(&self.wrapped_keks));
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            product_id: field::text(v, 2)?,
            license_id: field::license_id(v, 3)?,
            entitlements: ent::decode(field::req(v, 4)?)?,
            issued_at: field::int(v, 5)?,
            not_after: field::int(v, 6)?,
            bound_fingerprint: field::opt_bytes(v, 7)?.map(Fingerprint::from_vec),
            max_seats: field::uint(v, 8)?,
            epoch_id: field::epoch_id(v, 9)?,
            machine_id: field::machine_id(v, 10)?,
            offline_nonce: field::fixed::<32>(v, 11)?,
            key_seed: field::fixed::<32>(v, 12)?,
            build_fingerprint: field::text(v, 13)?,
            variant_id: field::uint(v, 14)?,
            security_floor: field::uint(v, 15)?,
            revocation_epoch: field::uint(v, 16)?,
            wrapped_keks: field::text_bytes_map(v, 17)?,
        })
    }
}

impl core::fmt::Debug for OfflineLicenseKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OfflineLicenseKey")
            .field("proto_ver", &self.proto_ver)
            .field("suite_id", &self.suite_id)
            .field("product_id", &self.product_id)
            .field("license_id", &self.license_id)
            .field("entitlements", &self.entitlements)
            .field("issued_at", &self.issued_at)
            .field("not_after", &self.not_after)
            .field("bound_fingerprint", &self.bound_fingerprint)
            .field("max_seats", &self.max_seats)
            .field("epoch_id", &self.epoch_id)
            .field("machine_id", &self.machine_id)
            .field("offline_nonce", &"<redacted>")
            .field("key_seed", &"<redacted>")
            .field("build_fingerprint", &self.build_fingerprint)
            .field("variant_id", &self.variant_id)
            .field("security_floor", &self.security_floor)
            .field("revocation_epoch", &self.revocation_epoch)
            .field("wrapped_kek_count", &self.wrapped_keks.len())
            .finish()
    }
}

artifact_impl!(
    OfflineLicenseKey,
    ArtifactKind::OfflineLicenseKey,
    CLIENT_LIMITS
);

/// Build-time integrity manifest (`protocol-spec.md §9`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IntegrityManifest {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite.
    pub suite_id: SuiteId,
    /// Product slug.
    pub product_id: String,
    /// Build fingerprint; participates in feature key derivation.
    pub build_fingerprint: String,
    /// Build time.
    pub built_at: i64,
    /// Digest algorithm identifier, e.g. `blake3`.
    pub hash_alg: String,
    /// Path or URL pattern to digest.
    pub entries: BTreeMap<String, Vec<u8>>,
    /// Guarded function identifier to body digest.
    pub guarded: Option<BTreeMap<String, Vec<u8>>>,
    /// Sealed asset identifiers.
    pub sealed_assets: Option<Vec<String>>,
    /// Merkle root over the entries, so a client can verify one chunk without the whole set.
    pub root: Vec<u8>,
}

impl IntegrityManifest {
    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Text(self.product_id.clone()));
        b.put(3, CborValue::Text(self.build_fingerprint.clone()));
        b.put(4, CborValue::int(self.built_at));
        b.put(5, CborValue::Text(self.hash_alg.clone()));
        b.put(6, field::enc_text_bytes_map(&self.entries));
        b.put_opt(7, self.guarded.as_ref().map(field::enc_text_bytes_map));
        b.put_opt(
            8,
            self.sealed_assets
                .as_ref()
                .map(|a| CborValue::Array(a.iter().cloned().map(CborValue::Text).collect())),
        );
        b.put(9, CborValue::Bytes(self.root.clone()));
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            product_id: field::text(v, 2)?,
            build_fingerprint: field::text(v, 3)?,
            built_at: field::int(v, 4)?,
            hash_alg: field::text(v, 5)?,
            entries: field::text_bytes_map(v, 6)?,
            guarded: field::opt_text_bytes_map(v, 7)?,
            sealed_assets: match field::opt(v, 8) {
                None => None,
                Some(_) => Some(field::text_array(v, 8)?),
            },
            root: field::bytes(v, 9)?,
        })
    }
}

artifact_impl!(
    IntegrityManifest,
    ArtifactKind::IntegrityManifest,
    BULK_LIMITS
);

/// Response to an offline activation request (`system-architecture.md §5`).
///
/// Carries the credential plus the chain needed to verify it, and its own expiry so that a
/// captured response cannot be redeemed indefinitely.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ActivationResponse {
    /// Protocol version.
    pub proto_ver: u8,
    /// Suite.
    pub suite_id: SuiteId,
    /// Echo of the request nonce, binding this response to one request.
    pub nonce_c_echo: [u8; 32],
    /// The enveloped `MachineCredential`.
    pub credential: Vec<u8>,
    /// Enveloped epoch certificates forming the chain.
    pub chain: Vec<Vec<u8>>,
    /// Server time.
    pub server_time: i64,
    /// Deadline for importing this response.
    pub valid_until: i64,
}

impl ActivationResponse {
    fn to_value(&self) -> CborValue {
        let mut b = MapBuilder::new();
        b.put(0, CborValue::Uint(u64::from(self.proto_ver)));
        b.put(1, CborValue::Bytes(self.suite_id.as_bytes().to_vec()));
        b.put(2, CborValue::Bytes(self.nonce_c_echo.to_vec()));
        b.put(3, CborValue::Bytes(self.credential.clone()));
        b.put(
            4,
            CborValue::Array(self.chain.iter().cloned().map(CborValue::Bytes).collect()),
        );
        b.put(5, CborValue::int(self.server_time));
        b.put(6, CborValue::int(self.valid_until));
        b.build()
    }

    fn from_value(v: &CborValue) -> Result<Self, ProtoError> {
        let chain_raw = field::req(v, 4)?
            .as_array()
            .ok_or(ProtoError::Codec(CodecError::TypeMismatch(4)))?;
        let chain = chain_raw
            .iter()
            .map(|c| {
                c.as_bytes()
                    .map(<[u8]>::to_vec)
                    .ok_or(ProtoError::Codec(CodecError::TypeMismatch(4)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            proto_ver: field::u8_field(v, 0)?,
            suite_id: field::suite_id(v, 1)?,
            nonce_c_echo: field::fixed::<32>(v, 2)?,
            credential: field::bytes(v, 3)?,
            chain,
            server_time: field::int(v, 5)?,
            valid_until: field::int(v, 6)?,
        })
    }
}

artifact_impl!(
    ActivationResponse,
    ArtifactKind::ActivationResponse,
    BULK_LIMITS
);

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use alloc::collections::BTreeSet;
    use alloc::string::ToString;
    use alloc::vec;

    pub(crate) fn entitlements() -> Entitlements {
        let mut features = BTreeSet::new();
        features.insert("export.pdf".to_string());
        let mut limits = BTreeMap::new();
        limits.insert("max_projects".to_string(), 100);
        Entitlements {
            features,
            limits,
            tier_id: "pro".to_string(),
            tier_label: "Pro".to_string(),
            catalog_version: 3,
            version_scope: Some(copylocker_types::VersionScope::Unlimited),
            subscription_hint: None,
        }
    }

    pub(crate) fn epoch_cert() -> EpochCert {
        EpochCert {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            epoch_id: EpochId([1; 8]),
            vk: vec![9; 1984],
            vk_fast: vec![8; 32],
            not_before: 1_000,
            not_after: 9_000,
            product_scope: Some("acme".to_string()),
            issuer_vk_digest: Digest([5; 32]),
        }
    }

    pub(crate) fn machine_credential() -> MachineCredential {
        let mut keks = BTreeMap::new();
        keks.insert("export.pdf".to_string(), vec![1, 2, 3]);
        let mut preloaded = BTreeMap::new();
        let mut inner = BTreeMap::new();
        inner.insert("export.pdf".to_string(), vec![4, 5]);
        preloaded.insert(7u64, inner);
        MachineCredential {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            product_id: "acme".to_string(),
            license_id: LicenseId([2; 16]),
            machine_id: MachineId([3; 16]),
            fingerprint: Fingerprint::from_vec(vec![4; 32]),
            kem_ct: vec![6; 1120],
            sealed_cs: vec![7; 72],
            offline_nonce: [8; 32],
            entitlements: entitlements(),
            issued_at: 1_000,
            not_after: 100_000,
            refresh_after: 8_000,
            grace_seconds: 604_800,
            mode: Mode::OfflineHybrid,
            revocation_epoch: 42,
            epoch_id: EpochId([1; 8]),
            build_fingerprint: Some("build-abc".to_string()),
            policy_flags: Some(0b101),
            security_floor: 3,
            variant_id: 7,
            wrapped_keks: keks,
            preloaded_keks: Some(preloaded),
        }
    }

    pub(crate) fn validation_ticket() -> ValidationTicket {
        ValidationTicket {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            machine_id: MachineId([3; 16]),
            nonce_c_echo: [9; 32],
            server_nonce: [10; 32],
            server_time: 5_000,
            next_refresh_after: 12_000,
            not_after: 100_000,
            revocation_epoch: 42,
            verdict: Verdict::Ok,
            entitlements: Some(entitlements()),
            epoch_id: EpochId([1; 8]),
            suspicion_score: Some(12),
            security_floor: 3,
            release_status: Some(0),
            wrapped_keks: None,
            refresh_now: Some(false),
        }
    }

    pub(crate) fn kill_order() -> KillOrder {
        KillOrder {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            machine_id: MachineId([3; 16]),
            nonce_c_echo: [9; 32],
            server_time: 5_000,
            reason: KillReason::Refund,
            user_message: Some("Your purchase was refunded.".to_string()),
            revocation_epoch: 43,
        }
    }

    pub(crate) fn revocation_batch() -> RevocationBatch {
        RevocationBatch {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            from_epoch: 40,
            to_epoch: 43,
            issued_at: 5_000,
            revoked_license_ids: vec![LicenseId([1; 16]), LicenseId([2; 16])],
            revoked_machine_ids: vec![MachineId([3; 16])],
            revoked_epoch_ids: vec![EpochId([4; 8])],
            bloom_filter: Some(vec![0xff; 64]),
        }
    }

    pub(crate) fn olk() -> OfflineLicenseKey {
        OfflineLicenseKey {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            product_id: "acme".to_string(),
            license_id: LicenseId([2; 16]),
            entitlements: entitlements(),
            issued_at: 1_000,
            not_after: 100_000,
            bound_fingerprint: Some(Fingerprint::from_vec(vec![4; 32])),
            max_seats: 3,
            epoch_id: EpochId([1; 8]),
            machine_id: MachineId([5; 16]),
            offline_nonce: [6; 32],
            key_seed: [7; 32],
            build_fingerprint: "build-abc".to_string(),
            variant_id: 4,
            security_floor: 2,
            revocation_epoch: 9,
            wrapped_keks: BTreeMap::new(),
        }
    }

    pub(crate) fn manifest() -> IntegrityManifest {
        let mut entries = BTreeMap::new();
        entries.insert("/assets/main.js".to_string(), vec![1; 32]);
        entries.insert("/assets/vendor.js".to_string(), vec![2; 32]);
        IntegrityManifest {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            product_id: "acme".to_string(),
            build_fingerprint: "build-abc".to_string(),
            built_at: 1_000,
            hash_alg: "blake3".to_string(),
            entries,
            guarded: None,
            sealed_assets: Some(vec!["hero.bin".to_string()]),
            root: vec![3; 32],
        }
    }

    pub(crate) fn activation_response() -> ActivationResponse {
        ActivationResponse {
            proto_ver: 1,
            suite_id: SuiteId::from_u32(0x0100_0001),
            nonce_c_echo: [9; 32],
            credential: vec![1; 128],
            chain: vec![vec![2; 64], vec![3; 64]],
            server_time: 5_000,
            valid_until: 5_000 + 7 * 86_400,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    /// Encode, decode, and compare — for every artifact type.
    macro_rules! roundtrip_test {
        ($name:ident, $make:expr, $ty:ty) => {
            #[test]
            fn $name() {
                let original = $make;
                let bytes = original.encode();
                let parsed = <$ty>::decode(&bytes).expect("must decode");
                assert_eq!(parsed, original);
                // Re-encoding must be byte-identical, or signatures would not reproduce.
                assert_eq!(parsed.encode(), bytes);
            }
        };
    }

    roundtrip_test!(epoch_cert_roundtrips, epoch_cert(), EpochCert);
    roundtrip_test!(
        machine_credential_roundtrips,
        machine_credential(),
        MachineCredential
    );
    roundtrip_test!(
        validation_ticket_roundtrips,
        validation_ticket(),
        ValidationTicket
    );
    roundtrip_test!(kill_order_roundtrips, kill_order(), KillOrder);
    roundtrip_test!(
        revocation_batch_roundtrips,
        revocation_batch(),
        RevocationBatch
    );
    roundtrip_test!(olk_roundtrips, olk(), OfflineLicenseKey);
    roundtrip_test!(manifest_roundtrips, manifest(), IntegrityManifest);
    roundtrip_test!(
        activation_response_roundtrips,
        activation_response(),
        ActivationResponse
    );

    #[test]
    fn artifact_kinds_are_distinct_per_type() {
        assert_eq!(EpochCert::KIND, ArtifactKind::EpochCert);
        assert_eq!(MachineCredential::KIND, ArtifactKind::MachineCred);
        assert_eq!(ValidationTicket::KIND, ArtifactKind::ValidationTicket);
        assert_eq!(KillOrder::KIND, ArtifactKind::KillOrder);
        assert_eq!(RevocationBatch::KIND, ArtifactKind::RevocationBatch);
        assert_eq!(OfflineLicenseKey::KIND, ArtifactKind::OfflineLicenseKey);
        assert_eq!(IntegrityManifest::KIND, ArtifactKind::IntegrityManifest);
        assert_eq!(ActivationResponse::KIND, ArtifactKind::ActivationResponse);
    }

    #[test]
    fn optional_fields_survive_absence() {
        let mut mc = machine_credential();
        mc.build_fingerprint = None;
        mc.policy_flags = None;
        mc.preloaded_keks = None;
        assert_eq!(MachineCredential::decode(&mc.encode()).unwrap(), mc);

        let mut vt = validation_ticket();
        vt.entitlements = None;
        vt.suspicion_score = None;
        vt.release_status = None;
        vt.refresh_now = None;
        assert_eq!(ValidationTicket::decode(&vt.encode()).unwrap(), vt);
    }

    #[test]
    fn truncation_at_every_offset_errors_without_panicking() {
        let bytes = machine_credential().encode();
        for cut in 0..bytes.len() {
            assert!(
                MachineCredential::decode(&bytes[..cut]).is_err(),
                "truncation at {cut} must be rejected"
            );
        }
    }

    #[test]
    fn single_byte_corruption_never_panics() {
        let bytes = validation_ticket().encode();
        for i in 0..bytes.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut bad = bytes.clone();
                bad[i] ^= mask;
                // Some flips land on payload bytes and still parse; the contract is only that
                // nothing panics and nothing over-reads.
                let _ = ValidationTicket::decode(&bad);
            }
        }
    }

    #[test]
    fn unknown_enum_discriminants_are_rejected() {
        let mut v = kill_order().to_value();
        if let CborValue::Map(ref mut entries) = v {
            for (k, val) in entries.iter_mut() {
                if k.as_uint() == Some(5) {
                    *val = CborValue::Uint(99);
                }
            }
        }
        assert_eq!(
            KillOrder::parse(&v),
            Err(ProtoError::Codec(CodecError::UnknownDiscriminant))
        );
    }

    #[test]
    fn wrong_width_identifiers_are_rejected() {
        let mut v = kill_order().to_value();
        if let CborValue::Map(ref mut entries) = v {
            for (k, val) in entries.iter_mut() {
                if k.as_uint() == Some(2) {
                    *val = CborValue::Bytes(alloc::vec![0u8; 15]);
                }
            }
        }
        assert_eq!(KillOrder::parse(&v), Err(ProtoError::FieldOutOfRange(2)));
    }

    #[test]
    fn suspicion_score_above_one_hundred_is_rejected() {
        let mut vt = validation_ticket();
        vt.suspicion_score = Some(200);
        assert_eq!(
            ValidationTicket::decode(&vt.encode()),
            Err(ProtoError::FieldOutOfRange(12))
        );
    }

    #[test]
    fn grace_deadline_never_exceeds_the_hard_expiry() {
        let mut mc = machine_credential();
        mc.refresh_after = 90_000;
        mc.grace_seconds = 604_800;
        mc.not_after = 100_000;
        assert_eq!(mc.grace_deadline(), 100_000);

        mc.not_after = TimeWindow::UNLIMITED;
        assert_eq!(mc.grace_deadline(), 90_000 + 604_800);
    }

    #[test]
    fn grace_deadline_does_not_overflow() {
        let mut mc = machine_credential();
        mc.refresh_after = i64::MAX;
        mc.grace_seconds = u32::MAX;
        mc.not_after = TimeWindow::UNLIMITED;
        assert_eq!(mc.grace_deadline(), i64::MAX);
    }

    #[test]
    fn epoch_cert_window_uses_the_shared_boundary_convention() {
        let c = epoch_cert();
        assert!(!c.window().contains(999));
        assert!(c.window().contains(1_000));
        assert!(!c.window().contains(9_000));
    }
}
