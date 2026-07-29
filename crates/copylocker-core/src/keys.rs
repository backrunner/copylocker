//! Feature key derivation (`crypto-architecture.md §6`, ADR-0004).
//!
//! # Why there is no `is_licensed()`
//!
//! A boolean check is one instruction. `if (!valid) exit()` becomes `if (false) exit()` with a
//! one-byte patch, whatever algorithm produced `valid`. So CopyLocker has no function returning
//! `bool`: the check is *producing a key*, and the key is what decrypts the asset the
//! application actually needs. Removing the check does not remove the requirement for the key.
//!
//! The chain, from the credential secret down:
//!
//! ```text
//! CredentialSecret  ← KEM-sealed to this device by the server
//!   └─ BoundSecret  = Binder(CredentialSecret, fingerprint, env_evidence)
//!        └─ SessionRoot  = KDF(BoundSecret, server_nonce ‖ epoch_id ‖ build_fp ‖ module_digest)
//!             └─ FeatureKey(f) = KDF(SessionRoot, product_id ‖ variant_id
//!                                      ‖ variant_const ‖ feature_id)
//! ```
//!
//! Every link binds something an attacker would have to reproduce: the device, the build, the
//! epoch, and the specific feature.

use alloc::vec::Vec;

use copylocker_proto::keywrap::{
    open_kek, seal_kek, KekWrapContext, KekWrapKind, WRAPPED_SECRET_LEN,
};
use copylocker_suite::{
    BoundSecret, CryptoRng, CryptoSuite, DeviceBinder, EnvEvidence, KeyDerivation, Secret,
    SharedSecret,
};
use copylocker_types::{Entitlements, EpochId, Fingerprint, LicenseId, LicenseState, MachineId};

use crate::error::CoreError;

/// Salt for the session-root derivation. Protocol-visible and frozen.
const SESSION_ROOT_SALT: &[u8] = b"copylocker/sr/v1";
/// Salt for the feature-key derivation. Protocol-visible and frozen.
const FEATURE_KEY_SALT: &[u8] = b"copylocker/fk/v1";
/// Salt for turning a signed OLK bearer seed into the input of the normal Binder chain.
const OLK_SEED_SALT: &[u8] = b"copylocker/olk-seed/v1";

/// Which session root to derive.
///
/// Both exist because a sealed asset must open online *and* offline. The server wraps each
/// asset's key encryption key twice — once under each root — so the same asset opens either way
/// (`crypto-architecture.md §6`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionKind {
    /// Derived from the server nonce in the most recent validation ticket.
    ///
    /// Refreshed on every successful check, so an intercepted response stops being useful.
    Online,
    /// Derived from the fixed nonce baked into the credential at issuance.
    Offline,
}

/// The material a feature key derives from.
///
/// Holds no state machine and no I/O: given the same inputs it produces the same keys, which is
/// what makes the derivation chain testable end to end.
pub struct KeyMaterial {
    bound: BoundSecret,
    product_id: Vec<u8>,
    license_id: LicenseId,
    machine_id: MachineId,
    offline_epoch_id: EpochId,
    variant_id: u64,
    variant_const: [u8; 32],
    build_fingerprint: Vec<u8>,
    module_digest: Vec<u8>,
    offline_nonce: [u8; 32],
    server_nonce: Option<[u8; 32]>,
    online_epoch_id: Option<EpochId>,
}

impl core::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("bound", &"<redacted>")
            .field("has_server_nonce", &self.server_nonce.is_some())
            .field("has_online_epoch", &self.online_epoch_id.is_some())
            .finish()
    }
}

impl KeyMaterial {
    /// Derive and bind productive key material from a verified OLK bearer seed.
    ///
    /// The caller must verify the complete Root → Epoch → OLK chain before calling this method.
    /// Domain separation keeps an OLK seed from being interpreted as a MachineCredential secret;
    /// every signed identity and variant field participates before the ordinary Binder pipeline.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_olk<S: CryptoSuite>(
        key_seed: &[u8; 32],
        binding_fingerprint: &Fingerprint,
        env: &EnvEvidence,
        product_id: &str,
        license_id: LicenseId,
        machine_id: MachineId,
        epoch_id: EpochId,
        variant_id: u64,
        variant_const: [u8; 32],
        offline_nonce: [u8; 32],
    ) -> Result<Self, CoreError> {
        let variant_bytes = variant_id.to_be_bytes();
        let derived = <S::Kdf as KeyDerivation>::derive_from(
            OLK_SEED_SALT,
            key_seed,
            &[
                S::SUITE_ID.as_bytes(),
                product_id.as_bytes(),
                license_id.as_bytes(),
                machine_id.as_bytes(),
                epoch_id.as_bytes(),
                &variant_bytes,
                binding_fingerprint.as_bytes(),
            ],
        )
        .map_err(|_| CoreError::DerivationFailed)?;
        let secret = SharedSecret::new(*derived.expose());
        Self::bind::<S>(
            &secret,
            binding_fingerprint,
            env,
            product_id,
            license_id,
            machine_id,
            epoch_id,
            variant_id,
            variant_const,
            offline_nonce,
        )
    }

    /// Bind a recovered credential secret to this device.
    ///
    /// `secret` comes from decapsulating the credential's KEM ciphertext with the device's
    /// private key — which is why lifting a credential to another machine fails here rather
    /// than later: that machine's key produces a different secret
    /// (`crypto-architecture.md §6`, step ②).
    #[allow(clippy::too_many_arguments)] // Keep every protocol-bound input explicit at this boundary.
    pub fn bind<S: CryptoSuite>(
        credential_secret: &SharedSecret,
        fingerprint: &Fingerprint,
        env: &EnvEvidence,
        product_id: &str,
        license_id: LicenseId,
        machine_id: MachineId,
        epoch_id: EpochId,
        variant_id: u64,
        variant_const: [u8; 32],
        offline_nonce: [u8; 32],
    ) -> Result<Self, CoreError> {
        let bound = <S::Binder as DeviceBinder>::bind(credential_secret, fingerprint, env)
            .map_err(|_| CoreError::DerivationFailed)?;
        Ok(Self {
            bound,
            product_id: product_id.as_bytes().to_vec(),
            license_id,
            machine_id,
            offline_epoch_id: epoch_id,
            variant_id,
            variant_const,
            build_fingerprint: env.build_fingerprint.clone(),
            module_digest: env.module_digest.as_bytes().to_vec(),
            offline_nonce,
            server_nonce: None,
            online_epoch_id: None,
        })
    }

    /// Record the server nonce from a verified validation ticket.
    ///
    /// This is what makes online feature keys rotate on every successful check.
    pub fn set_server_nonce(&mut self, nonce: [u8; 32]) {
        self.set_online_session(nonce, self.offline_epoch_id);
    }

    /// Record the nonce and signing epoch from a verified validation ticket.
    ///
    /// The online epoch is separate from the credential's issuing epoch because epochs rotate
    /// more frequently than machine credentials. Online KEKs use the ticket's current epoch;
    /// offline KEKs remain bound to the credential's original epoch.
    pub fn set_online_session(&mut self, nonce: [u8; 32], epoch_id: EpochId) {
        self.server_nonce = Some(nonce);
        self.online_epoch_id = Some(epoch_id);
    }

    /// Whether an online session root can currently be derived.
    #[must_use]
    pub const fn has_online_session(&self) -> bool {
        self.server_nonce.is_some()
    }

    /// Derive a session root.
    pub fn session_root<S: CryptoSuite>(
        &self,
        kind: SessionKind,
    ) -> Result<Secret<[u8; 32]>, CoreError> {
        let (nonce, epoch_id): (&[u8], &EpochId) = match kind {
            SessionKind::Online => (
                self.server_nonce
                    .as_ref()
                    .ok_or(CoreError::DerivationFailed)?,
                self.online_epoch_id
                    .as_ref()
                    .ok_or(CoreError::DerivationFailed)?,
            ),
            SessionKind::Offline => (&self.offline_nonce, &self.offline_epoch_id),
        };
        <S::Kdf as KeyDerivation>::derive_from(
            SESSION_ROOT_SALT,
            self.bound.expose(),
            &[
                nonce,
                epoch_id.as_bytes(),
                &self.build_fingerprint,
                &self.module_digest,
            ],
        )
        .map_err(|_| CoreError::DerivationFailed)
    }

    /// Derive a feature key.
    ///
    /// The entitlement check happens here, and it fails by returning `Err` with no key — not by
    /// returning `false`. There is no code path that yields a key for a feature the credential
    /// does not carry.
    pub fn feature_key<S: CryptoSuite>(
        &self,
        state: LicenseState,
        entitlements: &Entitlements,
        feature: &str,
        kind: SessionKind,
    ) -> Result<Secret<[u8; 32]>, CoreError> {
        if !state.permits_key_derivation() {
            return Err(CoreError::NotEntitled);
        }
        if !entitlements.has_feature(feature) {
            // Same error as the state check above, so probing reveals nothing about which
            // features the licence carries.
            return Err(CoreError::NotEntitled);
        }
        let root = self.session_root::<S>(kind)?;
        let variant_id = self.variant_id.to_be_bytes();
        <S::Kdf as KeyDerivation>::derive_from(
            FEATURE_KEY_SALT,
            root.as_slice(),
            &[
                &self.product_id,
                &variant_id,
                &self.variant_const,
                feature.as_bytes(),
            ],
        )
        .map_err(|_| CoreError::DerivationFailed)
    }

    /// Wrap a registered 32-byte asset KEK for this activation and session kind.
    pub fn wrap_kek<S: CryptoSuite>(
        &self,
        state: LicenseState,
        entitlements: &Entitlements,
        feature: &str,
        kind: SessionKind,
        kek: &Secret<[u8; WRAPPED_SECRET_LEN]>,
        rng: &mut dyn CryptoRng,
    ) -> Result<Vec<u8>, CoreError> {
        let feature_key = self.feature_key::<S>(state, entitlements, feature, kind)?;
        let context = self.kek_context::<S>(feature, kind)?;
        seal_kek::<S>(feature_key.as_slice(), &context, kek, rng)
            .map_err(|_| CoreError::DerivationFailed)
    }

    /// Unwrap an asset key encryption key with a feature key.
    ///
    /// The other half of "verification is productive": the credential does not authorise the
    /// application to proceed, it *decrypts* what the application needs
    /// (`crypto-architecture.md §6`).
    pub fn unwrap_kek<S: CryptoSuite>(
        &self,
        state: LicenseState,
        entitlements: &Entitlements,
        feature: &str,
        kind: SessionKind,
        wrapped: &[u8],
    ) -> Result<Secret<[u8; WRAPPED_SECRET_LEN]>, CoreError> {
        let fk = self.feature_key::<S>(state, entitlements, feature, kind)?;
        let context = self.kek_context::<S>(feature, kind)?;
        open_kek::<S>(fk.as_slice(), &context, wrapped).map_err(|_| CoreError::NotEntitled)
    }

    /// Try the online root first, falling back to the offline one.
    ///
    /// The ordinary path for an application that must work both connected and disconnected.
    pub fn unwrap_kek_any<S: CryptoSuite>(
        &self,
        state: LicenseState,
        entitlements: &Entitlements,
        feature: &str,
        wrapped_online: &[u8],
        wrapped_offline: &[u8],
    ) -> Result<Secret<[u8; WRAPPED_SECRET_LEN]>, CoreError> {
        if self.has_online_session() {
            if let Ok(v) = self.unwrap_kek::<S>(
                state,
                entitlements,
                feature,
                SessionKind::Online,
                wrapped_online,
            ) {
                return Ok(v);
            }
        }
        self.unwrap_kek::<S>(
            state,
            entitlements,
            feature,
            SessionKind::Offline,
            wrapped_offline,
        )
    }

    fn kek_context<'a, S: CryptoSuite>(
        &'a self,
        feature: &'a str,
        kind: SessionKind,
    ) -> Result<KekWrapContext<'a>, CoreError> {
        let (kind, session_nonce, epoch_id) = match kind {
            SessionKind::Online => (
                KekWrapKind::Online,
                self.server_nonce
                    .as_ref()
                    .ok_or(CoreError::DerivationFailed)?,
                *self
                    .online_epoch_id
                    .as_ref()
                    .ok_or(CoreError::DerivationFailed)?,
            ),
            SessionKind::Offline => (
                KekWrapKind::Offline,
                &self.offline_nonce,
                self.offline_epoch_id,
            ),
        };
        let product_id =
            core::str::from_utf8(&self.product_id).map_err(|_| CoreError::DerivationFailed)?;
        Ok(KekWrapContext {
            proto_ver: S::PROTO_VER,
            suite_id: S::SUITE_ID,
            product_id,
            license_id: self.license_id,
            machine_id: self.machine_id,
            epoch_id,
            variant_id: self.variant_id,
            feature_id: feature,
            kind,
            session_nonce,
        })
    }
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;
    use alloc::string::ToString;
    use copylocker_suite::CryptoRng;
    use copylocker_suite_std::ClStd1;
    use copylocker_types::Digest;

    struct TestRng(rand_chacha::ChaCha20Rng);
    impl CryptoRng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            use rand_core::Rng;
            self.0.fill_bytes(dest);
        }
    }
    fn rng(seed: u64) -> TestRng {
        use rand_core::SeedableRng;
        TestRng(rand_chacha::ChaCha20Rng::seed_from_u64(seed))
    }

    fn env(module: u8, build: &str) -> EnvEvidence {
        EnvEvidence {
            module_digest: Digest([module; 32]),
            build_fingerprint: build.as_bytes().to_vec(),
            extra: Vec::new(),
        }
    }

    fn entitlements() -> Entitlements {
        let mut features = BTreeSet::new();
        features.insert("export.pdf".to_string());
        features.insert("ai.assist".to_string());
        Entitlements {
            features,
            tier_id: "pro".to_string(),
            ..Default::default()
        }
    }

    /// Material after a real client has opened `sealed_cs` and recovered CredentialSecret.
    fn material(fp_byte: u8, module: u8, build: &str) -> KeyMaterial {
        material_with_variant(fp_byte, module, build, 7, 0x66)
    }

    fn material_with_variant(
        fp_byte: u8,
        module: u8,
        build: &str,
        variant_id: u64,
        variant_const: u8,
    ) -> KeyMaterial {
        material_with_epoch(
            fp_byte,
            module,
            build,
            variant_id,
            variant_const,
            EpochId([1; 8]),
        )
    }

    fn material_with_epoch(
        fp_byte: u8,
        module: u8,
        build: &str,
        variant_id: u64,
        variant_const: u8,
        epoch_id: EpochId,
    ) -> KeyMaterial {
        let credential_secret = SharedSecret::new([0x55; 32]);
        KeyMaterial::bind::<ClStd1>(
            &credential_secret,
            &Fingerprint::from_vec(alloc::vec![fp_byte; 32]),
            &env(module, build),
            "acme",
            LicenseId([0x11; 16]),
            MachineId([0x22; 16]),
            epoch_id,
            variant_id,
            [variant_const; 32],
            [9; 32],
        )
        .unwrap()
    }

    #[test]
    fn a_licensed_feature_yields_a_key() {
        let m = material(1, 1, "build-a");
        let k = m
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .expect("an entitled feature must yield a key");
        assert_ne!(k.as_slice(), [0u8; 32]);
    }

    #[test]
    fn olk_seed_derivation_is_domain_bound_to_identity_and_device_mode() {
        let binding = Fingerprint::from_vec(alloc::vec![0x33; 32]);
        let first = KeyMaterial::bind_olk::<ClStd1>(
            &[0x44; 32],
            &binding,
            &env(1, "build-a"),
            "acme",
            LicenseId([0x11; 16]),
            MachineId([0x22; 16]),
            EpochId([1; 8]),
            7,
            [0x66; 32],
            [9; 32],
        )
        .unwrap();
        let other_binding = KeyMaterial::bind_olk::<ClStd1>(
            &[0x44; 32],
            &Fingerprint::from_vec(alloc::vec![0x34; 32]),
            &env(1, "build-a"),
            "acme",
            LicenseId([0x11; 16]),
            MachineId([0x22; 16]),
            EpochId([1; 8]),
            7,
            [0x66; 32],
            [9; 32],
        )
        .unwrap();
        let first_key = first
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        let other_key = other_binding
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        assert!(!first_key.ct_eq(&other_key));
    }

    #[test]
    fn an_unlicensed_feature_yields_no_key() {
        let m = material(1, 1, "build-a");
        assert_eq!(
            m.feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "render.4k",
                SessionKind::Offline,
            )
            .err(),
            Some(CoreError::NotEntitled)
        );
    }

    #[test]
    fn probing_reveals_nothing_about_which_check_failed() {
        // "feature absent" and "state forbids" are the same error, so an attacker cannot use
        // the error to map the licence.
        let m = material(1, 1, "build-a");
        let absent = m.feature_key::<ClStd1>(
            LicenseState::Active,
            &entitlements(),
            "render.4k",
            SessionKind::Offline,
        );
        let locked = m.feature_key::<ClStd1>(
            LicenseState::Locked,
            &entitlements(),
            "export.pdf",
            SessionKind::Offline,
        );
        assert_eq!(absent.err(), locked.err());
    }

    #[test]
    fn no_key_is_produced_in_any_non_permitting_state() {
        let m = material(1, 1, "build-a");
        for st in [
            LicenseState::Unlicensed,
            LicenseState::Activating,
            LicenseState::Locked,
            LicenseState::Revoked,
            LicenseState::Tampered,
        ] {
            assert!(
                m.feature_key::<ClStd1>(st, &entitlements(), "export.pdf", SessionKind::Offline)
                    .is_err(),
                "{st} must yield no key"
            );
        }
        for st in [
            LicenseState::Active,
            LicenseState::NeedsRevalidation,
            LicenseState::Grace,
        ] {
            assert!(
                m.feature_key::<ClStd1>(st, &entitlements(), "export.pdf", SessionKind::Offline)
                    .is_ok(),
                "{st} must yield a key"
            );
        }
    }

    #[test]
    fn different_features_derive_different_keys() {
        // Otherwise one unlocked feature would unseal every asset.
        let m = material(1, 1, "build-a");
        let a = m
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        let b = m
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "ai.assist",
                SessionKind::Offline,
            )
            .unwrap();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn a_different_device_derives_different_keys() {
        // Copying the credential store to another machine must not work.
        let a = material(1, 1, "build-a");
        let b = material(2, 1, "build-a");
        let ka = a
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        let kb = b
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        assert!(!ka.ct_eq(&kb));
    }

    #[test]
    fn a_patched_binary_derives_different_keys() {
        // The integrity property: modifying the module changes its digest, so the patched build
        // cannot unseal anything even though it holds a valid credential.
        let honest = material(1, 1, "build-a");
        let patched = material(1, 2, "build-a");
        let a = honest
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        let b = patched
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn a_different_build_derives_different_keys() {
        let a = material(1, 1, "build-a");
        let b = material(1, 1, "build-b");
        let ka = a
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        let kb = b
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        assert!(!ka.ct_eq(&kb));
    }

    #[test]
    fn a_different_variant_id_or_constant_derives_a_different_key() {
        let base = material_with_variant(1, 1, "build-a", 7, 0x66);
        let other_id = material_with_variant(1, 1, "build-a", 8, 0x66);
        let other_const = material_with_variant(1, 1, "build-a", 7, 0x67);
        let key = |material: &KeyMaterial| {
            material
                .feature_key::<ClStd1>(
                    LicenseState::Active,
                    &entitlements(),
                    "export.pdf",
                    SessionKind::Offline,
                )
                .unwrap()
        };
        let base_key = key(&base);
        assert!(!base_key.ct_eq(&key(&other_id)));
        assert!(!base_key.ct_eq(&key(&other_const)));
    }

    #[test]
    fn the_online_root_needs_a_server_nonce() {
        let mut m = material(1, 1, "build-a");
        assert!(!m.has_online_session());
        assert_eq!(
            m.session_root::<ClStd1>(SessionKind::Online).err(),
            Some(CoreError::DerivationFailed)
        );
        m.set_server_nonce([7; 32]);
        assert!(m.has_online_session());
        assert!(m.session_root::<ClStd1>(SessionKind::Online).is_ok());
    }

    #[test]
    fn online_and_offline_roots_differ() {
        let mut m = material(1, 1, "build-a");
        m.set_server_nonce([7; 32]);
        let on = m.session_root::<ClStd1>(SessionKind::Online).unwrap();
        let off = m.session_root::<ClStd1>(SessionKind::Offline).unwrap();
        assert!(!on.ct_eq(&off));
    }

    #[test]
    fn a_new_server_nonce_rotates_the_online_key() {
        // What makes an intercepted response stop being useful after the next check.
        let mut m = material(1, 1, "build-a");
        m.set_server_nonce([7; 32]);
        let first = m
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Online,
            )
            .unwrap();
        m.set_server_nonce([8; 32]);
        let second = m
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Online,
            )
            .unwrap();
        assert!(!first.ct_eq(&second));
    }

    #[test]
    fn online_keks_follow_the_ticket_epoch_after_rotation() {
        let mut r = rng(19);
        let ticket_epoch = EpochId([2; 8]);
        let mut server = material_with_epoch(1, 1, "build-a", 7, 0x66, ticket_epoch);
        server.set_server_nonce([7; 32]);
        let wrapped = server
            .wrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Online,
                &Secret::new([0x51; 32]),
                &mut r,
            )
            .unwrap();

        // The credential was issued by epoch 1, but this ticket and its online wrapping were
        // issued by epoch 2. Recording both ticket fields is required to open it.
        let mut client = material(1, 1, "build-a");
        client.set_online_session([7; 32], ticket_epoch);
        assert!(client
            .unwrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Online,
                &wrapped,
            )
            .is_ok());

        let mut stale = material(1, 1, "build-a");
        stale.set_server_nonce([7; 32]);
        assert!(stale
            .unwrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Online,
                &wrapped,
            )
            .is_err());
    }

    #[test]
    fn an_asset_wrapped_for_a_feature_unwraps_with_that_feature_key() {
        let mut r = rng(2);
        let m = material(1, 1, "build-a");
        let kek = Secret::new([0x41; 32]);
        let wrapped = m
            .wrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
                &kek,
                &mut r,
            )
            .unwrap();

        let out = m
            .unwrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
                &wrapped,
            )
            .unwrap();
        assert!(out.ct_eq(&kek));
    }

    #[test]
    fn an_asset_does_not_unwrap_with_a_different_features_key() {
        let mut r = rng(3);
        let m = material(1, 1, "build-a");
        let wrapped = m
            .wrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
                &Secret::new([0x42; 32]),
                &mut r,
            )
            .unwrap();
        assert!(m
            .unwrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "ai.assist",
                SessionKind::Offline,
                &wrapped,
            )
            .is_err());
    }

    #[test]
    fn an_asset_sealed_on_one_device_does_not_open_on_another() {
        // The end-to-end statement of the whole design.
        let mut r = rng(4);
        let honest = material(1, 1, "build-a");
        let wrapped = honest
            .wrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
                &Secret::new([0x43; 32]),
                &mut r,
            )
            .unwrap();

        let thief = material(2, 1, "build-a");
        assert!(thief
            .unwrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
                &wrapped,
            )
            .is_err());
    }

    #[test]
    fn dual_wrapping_lets_one_asset_open_online_or_offline() {
        // The design that keeps sealed assets usable without a network
        // (`crypto-architecture.md §6`).
        let mut r = rng(5);
        let mut m = material(1, 1, "build-a");
        m.set_server_nonce([7; 32]);

        let kek = Secret::new([0x44; 32]);
        let w_on = m
            .wrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Online,
                &kek,
                &mut r,
            )
            .unwrap();
        let w_off = m
            .wrap_kek::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
                &kek,
                &mut r,
            )
            .unwrap();

        let online = m
            .unwrap_kek_any::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                &w_on,
                &w_off,
            )
            .unwrap();
        assert!(online.ct_eq(&kek));

        // A client with no live session still opens the same asset via the offline wrapping.
        let offline_only = material(1, 1, "build-a");
        let offline = offline_only
            .unwrap_kek_any::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                &w_on,
                &w_off,
            )
            .unwrap();
        assert!(offline.ct_eq(&kek));
    }

    #[test]
    fn key_material_debug_reveals_nothing() {
        let m = material(1, 1, "build-a");
        let rendered = alloc::format!("{m:?}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn derivation_is_reproducible() {
        let a = material(1, 1, "build-a");
        let b = material(1, 1, "build-a");
        let ka = a
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        let kb = b
            .feature_key::<ClStd1>(
                LicenseState::Active,
                &entitlements(),
                "export.pdf",
                SessionKind::Offline,
            )
            .unwrap();
        assert!(ka.ct_eq(&kb));
    }
}
