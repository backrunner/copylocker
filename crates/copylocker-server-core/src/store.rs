//! Storage and issuance ports.
//!
//! The server's domain logic never touches Cloudflare. It talks to these traits, which the
//! worker implements over durable objects, D1, and KV — and which the test harness implements
//! in memory. That is what lets a hundred-way concurrent seat race be tested on a laptop
//! (`00-crate-layout.md §3`).
//!
//! The traits are **synchronous**. Real backends are async, so the worker adapter fetches the
//! state it needs, calls the pure decision function, then writes the result back. This is not a
//! limitation but the shape `data-model.md §10.1` mandates: the seat transaction must contain
//! no `await`, because a durable object's atomicity depends on an uninterrupted run of writes.

use alloc::string::String;
use alloc::vec::Vec;

use copylocker_types::{Fingerprint, LicenseId, MachineId};

use crate::catalog::Catalog;
use crate::policy::Policy;
use crate::version::ReleaseRegistry;
use crate::ServerFault;

/// Status of one activation record (`data-model.md §10`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ActivationStatus {
    /// Holding a seat and usable.
    Active = 0,
    /// Released by the user or reclaimed.
    Released = 1,
    /// Revoked by an administrator.
    Revoked = 2,
    /// Reserved but not yet committed.
    ///
    /// Phase one of the two-phase seat reservation: the seat is held while the credential is
    /// signed, and an alarm reclaims it if phase three never arrives
    /// (`data-model.md §10.1`).
    Pending = 3,
}

/// One activation record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ActivationRecord {
    /// Activation identifier.
    pub machine_id: MachineId,
    /// Fingerprint at issuance.
    pub fingerprint: Fingerprint,
    /// Normalised attributes, when the policy permits reporting them.
    pub attrs: Option<copylocker_suite::device::DeviceAttrs>,
    /// The device's KEM encapsulation key.
    pub device_kem_ek: Vec<u8>,
    /// The device's signature verifying key, used to check validation proofs.
    pub device_sig_vk: Vec<u8>,
    /// Current status.
    pub status: ActivationStatus,
    /// How the activation was performed.
    pub activation_path: String,
    /// Release the device reported.
    pub release_id: Option<String>,
    /// Variant its keys are derived for.
    pub variant_id: Option<u64>,
    /// First seen.
    pub created_at: i64,
    /// Last seen.
    pub last_seen_at: Option<i64>,
    /// Next required validation.
    pub refresh_after: i64,
    /// Hard expiry.
    pub not_after: i64,
    /// Machine transfers recorded.
    pub transfer_count: u32,
}

/// The state of one licence, as held by its durable object.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LicenseRecord {
    /// Licence identifier.
    pub id: LicenseId,
    /// Product.
    pub product_id: String,
    /// Policy governing it.
    pub policy_id: String,
    /// Administrative status.
    pub status: LicenseStatus,
    /// Seat override, when this licence differs from its policy.
    pub seats_override: Option<u32>,
    /// Hard expiry; `None` for perpetual.
    pub expires_at: Option<i64>,
    /// Revocation sequence at which this licence was revoked, if it was.
    pub revoked_at_epoch: Option<u64>,
    /// Activations, active and historical.
    pub activations: Vec<ActivationRecord>,
}

/// Administrative status of a licence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LicenseStatus {
    /// Usable.
    Active,
    /// Temporarily disabled.
    Suspended,
    /// Term ended.
    Expired,
    /// Permanently revoked.
    Revoked,
}

impl LicenseRecord {
    /// Activations currently occupying a seat.
    ///
    /// `Pending` counts: an in-flight reservation must block a concurrent request, or the
    /// two-phase protocol would not prevent oversubscription at all.
    #[must_use]
    pub fn occupied_seats(&self) -> u32 {
        u32::try_from(
            self.activations
                .iter()
                .filter(|a| {
                    matches!(
                        a.status,
                        ActivationStatus::Active | ActivationStatus::Pending
                    )
                })
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    /// Find an activation.
    #[must_use]
    pub fn activation(&self, id: &MachineId) -> Option<&ActivationRecord> {
        self.activations.iter().find(|a| a.machine_id == *id)
    }

    /// Find an activation mutably.
    pub fn activation_mut(&mut self, id: &MachineId) -> Option<&mut ActivationRecord> {
        self.activations.iter_mut().find(|a| a.machine_id == *id)
    }

    /// Activations that currently hold a seat.
    pub fn live_activations(&self) -> impl Iterator<Item = &ActivationRecord> {
        self.activations
            .iter()
            .filter(|a| a.status == ActivationStatus::Active)
    }
}

/// Read access to configuration and licence state.
pub trait Storage {
    /// Resolve a licence key's stored HMAC to a licence.
    ///
    /// Takes the HMAC rather than the key: the server never stores plaintext keys, so a
    /// database leak does not yield a list of working licences (`protocol-spec.md §2`).
    fn license_by_key_hmac(&self, key_hmac: &[u8]) -> Result<Option<LicenseRecord>, ServerFault>;

    /// Load a licence by identifier.
    fn license(&self, id: &LicenseId) -> Result<Option<LicenseRecord>, ServerFault>;

    /// Persist a licence record.
    fn put_license(&mut self, record: &LicenseRecord) -> Result<(), ServerFault>;

    /// Load a policy.
    fn policy(&self, id: &str) -> Result<Option<Policy>, ServerFault>;

    /// Load a product's catalog.
    fn catalog(&self, product_id: &str) -> Result<Option<Catalog>, ServerFault>;

    /// Load a product's release registry.
    fn releases(&self, product_id: &str) -> Result<ReleaseRegistry, ServerFault>;

    /// Current global revocation sequence.
    fn revocation_epoch(&self) -> Result<u64, ServerFault>;

    /// Current global security floor.
    fn security_floor(&self) -> Result<u64, ServerFault>;

    /// Record a nonce, returning `false` if it has been seen before.
    ///
    /// The replay guard. Returning `false` must be treated as an attack signal, not a retry.
    fn record_nonce(
        &mut self,
        license: &LicenseId,
        nonce: &[u8; 32],
        now: i64,
    ) -> Result<bool, ServerFault>;
}

/// A monotonic clock the caller supplies.
///
/// Injected rather than read, so that every time-dependent decision is reproducible in a test
/// and a fuzzer can drive the clock backwards to probe the boundary logic.
pub trait Clock {
    /// Current server time in Unix seconds. Authoritative; the client's clock is not trusted.
    fn now(&self) -> i64;
}

/// Signing.
///
/// Split from [`Storage`] because the two have different failure modes and, in production,
/// different backends: storage is durable objects and D1, signing is the secrets store and the
/// issuer durable object (`10-server-worker.md §2.2`).
pub trait Issuer {
    /// The epoch identifier currently used for signing.
    fn current_epoch(&self) -> Result<copylocker_types::EpochId, ServerFault>;

    /// Sign an artifact with the epoch's post-quantum hybrid key.
    ///
    /// Used for durable artifacts. Goes through the issuer durable object in production,
    /// because it needs a monotonic sequence number and a hash-chained audit entry.
    fn sign_durable(
        &self,
        kind: copylocker_types::ArtifactKind,
        product_id: &str,
        tbs: &[u8],
    ) -> Result<Vec<u8>, ServerFault>;

    /// Sign with the epoch's classical fast key.
    ///
    /// Used for per-request tickets, where a PQ signature would exceed the CPU budget. The fast
    /// key is certified by the PQ-signed epoch certificate (`protocol-spec.md §5`).
    fn sign_fast(
        &self,
        kind: copylocker_types::ArtifactKind,
        product_id: &str,
        tbs: &[u8],
    ) -> Result<Vec<u8>, ServerFault>;

    /// Draw cryptographically secure random bytes.
    fn random(&self, out: &mut [u8]) -> Result<(), ServerFault>;
}

/// Verifies a device's proof of key possession.
///
/// Abstracted so that the domain logic does not need to know which signature scheme the suite
/// uses, and so tests can substitute a trivial verifier.
pub trait ProofVerifier {
    /// Check that `proof` is a valid signature by `device_sig_vk` over `message`.
    fn verify_device_proof(
        &self,
        device_sig_vk: &[u8],
        message: &[u8],
        proof: &[u8],
    ) -> Result<bool, ServerFault>;
}
