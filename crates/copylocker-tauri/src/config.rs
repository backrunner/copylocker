use core::marker::PhantomData;

use copylocker_client::{Config, ConfigError};
use copylocker_proto::ClientInfo;
use copylocker_suite::{CryptoSuite, EnvEvidence};
use copylocker_suite_std::ClStd1;

/// Build-time application configuration embedded into a Tauri host.
pub struct CopyLockerConfig<S: CryptoSuite = ClStd1> {
    /// Clean HTTPS server origin.
    pub server_url: String,
    /// Stable application storage namespace.
    pub app_id: String,
    /// Product identifier covered by signed artifacts.
    pub product_id: String,
    /// Host application version.
    pub app_version: String,
    /// Registered release identifier.
    pub release_id: String,
    /// Build fingerprint registered for this release.
    pub build_fingerprint: String,
    /// Current Root verifying key bytes.
    pub current_root_key: Vec<u8>,
    /// Pre-positioned successor Root verifying key bytes.
    pub next_root_key: Option<Vec<u8>>,
    /// Per-vendor device-fingerprint salt.
    pub fingerprint_salt: Vec<u8>,
    /// Release variant identifier.
    pub variant_id: u64,
    /// Release variant key-schedule constant.
    pub variant_const: [u8; 32],
    /// Expected executable evidence, used only if local collection is unavailable.
    pub expected_module_digest: [u8; 32],
    /// Additional deterministic evidence registered with the release.
    pub evidence_extra: Vec<Vec<u8>>,
    /// Explicit low-strength opt-in for copyable OLKs.
    pub allow_unbound_olk: bool,
    /// Permit HTTP only for loopback development origins.
    pub allow_insecure_localhost: bool,
    suite: PhantomData<S>,
}

impl<S: CryptoSuite> CopyLockerConfig<S> {
    /// Construct the required embedded configuration.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        server_url: impl Into<String>,
        app_id: impl Into<String>,
        product_id: impl Into<String>,
        app_version: impl Into<String>,
        release_id: impl Into<String>,
        build_fingerprint: impl Into<String>,
        current_root_key: Vec<u8>,
        fingerprint_salt: Vec<u8>,
        variant_id: u64,
        variant_const: [u8; 32],
        expected_module_digest: [u8; 32],
    ) -> Self {
        Self {
            server_url: server_url.into(),
            app_id: app_id.into(),
            product_id: product_id.into(),
            app_version: app_version.into(),
            release_id: release_id.into(),
            build_fingerprint: build_fingerprint.into(),
            current_root_key,
            next_root_key: None,
            fingerprint_salt,
            variant_id,
            variant_const,
            expected_module_digest,
            evidence_extra: Vec::new(),
            allow_unbound_olk: false,
            allow_insecure_localhost: false,
            suite: PhantomData,
        }
    }

    /// Add the successor Root key used during a controlled rotation.
    #[must_use]
    pub fn with_next_root_key(mut self, key: Vec<u8>) -> Self {
        self.next_root_key = Some(key);
        self
    }

    /// Explicitly permit unbound OLKs.
    #[must_use]
    pub const fn with_unbound_olk(mut self, enabled: bool) -> Self {
        self.allow_unbound_olk = enabled;
        self
    }

    /// Permit a loopback HTTP origin for local development.
    #[must_use]
    pub const fn with_insecure_localhost(mut self, enabled: bool) -> Self {
        self.allow_insecure_localhost = enabled;
        self
    }

    pub(crate) fn into_client_config(self, evidence: EnvEvidence) -> Result<Config, ConfigError> {
        let info = ClientInfo {
            app_version: self.app_version,
            sdk_version: env!("CARGO_PKG_VERSION").to_owned(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            build_fingerprint: self.build_fingerprint,
            release_id: self.release_id,
            variant_id: self.variant_id,
            supported_suites: vec![S::SUITE_ID],
            supported_variants: vec![self.variant_id],
        };
        let mut config = Config::new_with_localhost_http(
            &self.server_url,
            self.app_id,
            self.product_id,
            info,
            self.current_root_key,
            self.fingerprint_salt,
            self.variant_const,
            evidence,
            self.allow_insecure_localhost,
        )?;
        if let Some(next) = self.next_root_key {
            config = config.with_next_root_key(next)?;
        }
        config.with_unbound_olk(self.allow_unbound_olk)
    }
}

impl<S: CryptoSuite> core::fmt::Debug for CopyLockerConfig<S> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CopyLockerConfig")
            .field("server_url", &self.server_url)
            .field("app_id", &self.app_id)
            .field("product_id", &self.product_id)
            .field("release_id", &self.release_id)
            .field("variant_id", &self.variant_id)
            .field("root_keys", &"<redacted>")
            .field("fingerprint_salt", &"<redacted>")
            .field("variant_const", &"<redacted>")
            .field("evidence", &"<redacted>")
            .finish()
    }
}
