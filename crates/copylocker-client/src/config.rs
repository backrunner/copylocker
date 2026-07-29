use core::fmt;
use std::net::IpAddr;
use std::time::Duration;

use copylocker_core::CoreConfig;
use copylocker_proto::ClientInfo;
use copylocker_suite::{EnvEvidence, Secret};
use url::Url;

const MAX_IDENTIFIER_LEN: usize = 128;
const MAX_PIN_BYTES: usize = 64 * 1024;
const MAX_FINGERPRINT_SALT_BYTES: usize = 64 * 1024;
const MAX_NETWORK_RECOVERY_POLL: Duration = Duration::from_secs(60);

/// Validation scheduler tuning.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SchedulerConfig {
    /// Initial retry delay after a transient validation failure.
    pub base_retry: Duration,
    /// Maximum exponential-backoff delay.
    pub max_retry: Duration,
    /// Maximum time between scheduler checks while a credential exists.
    pub poll_interval: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            base_retry: Duration::from_secs(30),
            max_retry: Duration::from_secs(6 * 60 * 60),
            poll_interval: Duration::from_secs(30),
        }
    }
}

/// Static client configuration, normally generated into the host at build time.
pub struct Config {
    server_url: Url,
    app_id: String,
    product_id: String,
    client_info: ClientInfo,
    current_root_key: Vec<u8>,
    next_root_key: Option<Vec<u8>>,
    fingerprint_salt: Secret<Vec<u8>>,
    variant_const: Secret<[u8; 32]>,
    evidence: EnvEvidence,
    report_device_attributes: bool,
    privacy_ack: bool,
    allow_unbound_olk: bool,
    allow_insecure_localhost: bool,
    request_timeout: Duration,
    scheduler: SchedulerConfig,
    core: CoreConfig,
}

impl Config {
    /// Construct a configuration with one pinned Root verifying key.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_url: &str,
        app_id: impl Into<String>,
        product_id: impl Into<String>,
        client_info: ClientInfo,
        current_root_key: Vec<u8>,
        fingerprint_salt: Vec<u8>,
        variant_const: [u8; 32],
        evidence: EnvEvidence,
    ) -> Result<Self, ConfigError> {
        Self::new_with_localhost_http(
            server_url,
            app_id,
            product_id,
            client_info,
            current_root_key,
            fingerprint_salt,
            variant_const,
            evidence,
            false,
        )
    }

    /// Construct a configuration with an explicit loopback-HTTP development opt-in.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_localhost_http(
        server_url: &str,
        app_id: impl Into<String>,
        product_id: impl Into<String>,
        client_info: ClientInfo,
        current_root_key: Vec<u8>,
        fingerprint_salt: Vec<u8>,
        variant_const: [u8; 32],
        evidence: EnvEvidence,
        allow_insecure_localhost: bool,
    ) -> Result<Self, ConfigError> {
        let server_url = Url::parse(server_url).map_err(|_| ConfigError::InvalidServerUrl)?;
        let config = Self {
            server_url,
            app_id: app_id.into(),
            product_id: product_id.into(),
            client_info,
            current_root_key,
            next_root_key: None,
            fingerprint_salt: Secret::new(fingerprint_salt),
            variant_const: Secret::new(variant_const),
            evidence,
            report_device_attributes: false,
            privacy_ack: false,
            allow_unbound_olk: false,
            allow_insecure_localhost,
            request_timeout: Duration::from_secs(30),
            scheduler: SchedulerConfig::default(),
            core: CoreConfig::default(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Add the pre-positioned successor Root key used during Root rotation.
    pub fn with_next_root_key(mut self, key: Vec<u8>) -> Result<Self, ConfigError> {
        self.next_root_key = Some(key);
        self.validate()?;
        Ok(self)
    }

    /// Enable raw device-attribute reporting after the host has acknowledged the privacy impact.
    pub fn with_device_attribute_reporting(
        mut self,
        enabled: bool,
        privacy_ack: bool,
    ) -> Result<Self, ConfigError> {
        self.report_device_attributes = enabled;
        self.privacy_ack = privacy_ack;
        self.validate()?;
        Ok(self)
    }

    /// Explicitly permit copyable, non-device-bound Offline License Keys.
    ///
    /// This is disabled by default because an unbound OLK can be installed on unlimited devices.
    pub fn with_unbound_olk(mut self, enabled: bool) -> Result<Self, ConfigError> {
        self.allow_unbound_olk = enabled;
        self.validate()?;
        Ok(self)
    }

    /// Permit plain HTTP only for a loopback development server.
    pub fn with_insecure_localhost(mut self, enabled: bool) -> Result<Self, ConfigError> {
        self.allow_insecure_localhost = enabled;
        self.validate()?;
        Ok(self)
    }

    /// Override the per-request timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Result<Self, ConfigError> {
        self.request_timeout = timeout;
        self.validate()?;
        Ok(self)
    }

    /// Override scheduler tuning.
    pub fn with_scheduler(mut self, scheduler: SchedulerConfig) -> Result<Self, ConfigError> {
        self.scheduler = scheduler;
        self.validate()?;
        Ok(self)
    }

    /// Override deterministic core tuning.
    pub fn with_core_config(mut self, core: CoreConfig) -> Result<Self, ConfigError> {
        self.core = core;
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        validate_server_url(&self.server_url, self.allow_insecure_localhost)?;
        validate_identifier(&self.app_id)?;
        validate_identifier(&self.product_id)?;
        if self.current_root_key.is_empty() || self.current_root_key.len() > MAX_PIN_BYTES {
            return Err(ConfigError::InvalidRootKey);
        }
        if self
            .next_root_key
            .as_ref()
            .is_some_and(|key| key.is_empty() || key.len() > MAX_PIN_BYTES)
        {
            return Err(ConfigError::InvalidRootKey);
        }
        if self.fingerprint_salt.expose().is_empty()
            || self.fingerprint_salt.expose().len() > MAX_FINGERPRINT_SALT_BYTES
        {
            return Err(ConfigError::InvalidFingerprintSalt);
        }
        if self.report_device_attributes && !self.privacy_ack {
            return Err(ConfigError::PrivacyAcknowledgementRequired);
        }
        if self.request_timeout.is_zero()
            || self.scheduler.base_retry.is_zero()
            || self.scheduler.max_retry < self.scheduler.base_retry
            || self.scheduler.poll_interval.is_zero()
            || self.scheduler.poll_interval > MAX_NETWORK_RECOVERY_POLL
            || self.core.min_validation_interval_secs < 0
        {
            return Err(ConfigError::InvalidTiming);
        }
        validate_client_info(&self.client_info, &self.evidence)?;
        Ok(())
    }

    pub(crate) fn endpoint(&self, path: &str) -> Result<Url, ConfigError> {
        if !path.starts_with("v1/") || path.contains('\u{5c}') || path.contains("..") {
            return Err(ConfigError::InvalidEndpoint);
        }
        self.server_url
            .join(path)
            .map_err(|_| ConfigError::InvalidEndpoint)
    }

    pub(crate) fn app_id(&self) -> &str {
        &self.app_id
    }

    pub(crate) fn product_id(&self) -> &str {
        &self.product_id
    }

    pub(crate) fn client_info(&self) -> &ClientInfo {
        &self.client_info
    }

    pub(crate) fn current_root_key(&self) -> &[u8] {
        &self.current_root_key
    }

    pub(crate) fn next_root_key(&self) -> Option<&[u8]> {
        self.next_root_key.as_deref()
    }

    pub(crate) fn fingerprint_salt(&self) -> &[u8] {
        self.fingerprint_salt.expose()
    }

    pub(crate) fn variant_const(&self) -> &[u8; 32] {
        self.variant_const.expose()
    }

    pub(crate) fn evidence(&self) -> &EnvEvidence {
        &self.evidence
    }

    pub(crate) const fn report_device_attributes(&self) -> bool {
        self.report_device_attributes
    }

    pub(crate) const fn allow_unbound_olk(&self) -> bool {
        self.allow_unbound_olk
    }

    pub(crate) const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub(crate) const fn scheduler(&self) -> SchedulerConfig {
        self.scheduler
    }

    pub(crate) const fn core(&self) -> CoreConfig {
        self.core
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("server_url", &self.server_url)
            .field("app_id", &self.app_id)
            .field("product_id", &self.product_id)
            .field("client_info", &self.client_info)
            .field("current_root_key_len", &self.current_root_key.len())
            .field(
                "next_root_key_len",
                &self.next_root_key.as_ref().map(Vec::len),
            )
            .field("fingerprint_salt", &"<redacted>")
            .field("variant_const", &"<redacted>")
            .field("evidence", &"<redacted>")
            .field("report_device_attributes", &self.report_device_attributes)
            .field("allow_unbound_olk", &self.allow_unbound_olk)
            .field("request_timeout", &self.request_timeout)
            .field("scheduler", &self.scheduler)
            .finish_non_exhaustive()
    }
}

/// Invalid static client configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ConfigError {
    /// Server URL is malformed, credential-bearing, or not an allowed HTTPS/loopback origin.
    InvalidServerUrl,
    /// Application or product identifier is unsafe.
    InvalidIdentifier,
    /// A Root verifying key is empty or over the hard bound.
    InvalidRootKey,
    /// Fingerprint salt is empty or over the hard bound.
    InvalidFingerprintSalt,
    /// Raw attributes were enabled without explicit privacy acknowledgement.
    PrivacyAcknowledgementRequired,
    /// Timeout, retry, or polling values are invalid.
    InvalidTiming,
    /// Build metadata is incomplete or disagrees with environment evidence.
    InvalidClientInfo,
    /// Internal endpoint path is unsafe.
    InvalidEndpoint,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidServerUrl => "invalid CopyLocker server URL",
            Self::InvalidIdentifier => "invalid application or product identifier",
            Self::InvalidRootKey => "invalid pinned Root key",
            Self::InvalidFingerprintSalt => "invalid fingerprint salt",
            Self::PrivacyAcknowledgementRequired => {
                "device attribute reporting requires privacy acknowledgement"
            }
            Self::InvalidTiming => "invalid client timing configuration",
            Self::InvalidClientInfo => "invalid client build metadata",
            Self::InvalidEndpoint => "invalid client endpoint",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ConfigError {}

fn validate_identifier(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ConfigError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_server_url(url: &Url, allow_insecure_localhost: bool) -> Result<(), ConfigError> {
    let scheme_allowed = url.scheme() == "https"
        || (url.scheme() == "http" && allow_insecure_localhost && is_loopback(url));
    if !scheme_allowed
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(ConfigError::InvalidServerUrl);
    }
    Ok(())
}

fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

fn validate_client_info(info: &ClientInfo, evidence: &EnvEvidence) -> Result<(), ConfigError> {
    let strings = [
        info.app_version.as_str(),
        info.sdk_version.as_str(),
        info.os.as_str(),
        info.arch.as_str(),
        info.build_fingerprint.as_str(),
        info.release_id.as_str(),
    ];
    if strings
        .iter()
        .any(|value| value.is_empty() || value.len() > 1024 || value.contains('\0'))
        || info.supported_suites.is_empty()
        || !info.supported_variants.contains(&info.variant_id)
        || evidence.build_fingerprint != info.build_fingerprint.as_bytes()
    {
        return Err(ConfigError::InvalidClientInfo);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_types::{Digest, SuiteId};

    fn info() -> ClientInfo {
        ClientInfo {
            app_version: String::from("1.2.3"),
            sdk_version: String::from("0.1.0"),
            os: String::from("macos"),
            arch: String::from("aarch64"),
            build_fingerprint: String::from("build-a"),
            release_id: String::from("release-a"),
            variant_id: 7,
            supported_suites: vec![SuiteId::from_u32(0x0100_0001)],
            supported_variants: vec![7],
        }
    }

    fn evidence() -> EnvEvidence {
        EnvEvidence {
            module_digest: Digest([3; 32]),
            build_fingerprint: b"build-a".to_vec(),
            extra: Vec::new(),
        }
    }

    fn config(url: &str) -> Result<Config, ConfigError> {
        Config::new(
            url,
            "com.example.app",
            "example-product",
            info(),
            vec![1; 32],
            vec![2; 32],
            [4; 32],
            evidence(),
        )
    }

    #[test]
    fn production_urls_must_be_clean_https_origins() {
        assert!(config("https://license.example/").is_ok());
        assert!(config("http://license.example/").is_err());
        assert!(config("https://user@license.example/").is_err());
        assert!(config("https://license.example/base/").is_err());
        assert!(config("https://license.example/?token=x").is_err());
    }

    #[test]
    fn localhost_http_requires_an_explicit_opt_in() {
        let base = config("http://127.0.0.1:8787/");
        assert!(base.is_err());
        let local = Config::new_with_localhost_http(
            "http://127.0.0.1:8787/",
            "com.example.app",
            "example-product",
            info(),
            vec![1; 32],
            vec![2; 32],
            [4; 32],
            evidence(),
            true,
        );
        assert!(local.is_ok());

        let remote = Config::new_with_localhost_http(
            "http://license.example/",
            "com.example.app",
            "example-product",
            info(),
            vec![1; 32],
            vec![2; 32],
            [4; 32],
            evidence(),
            true,
        );
        assert_eq!(remote.err(), Some(ConfigError::InvalidServerUrl));
    }

    #[test]
    fn raw_attribute_reporting_requires_acknowledgement() {
        let cfg = config("https://license.example/").unwrap();
        assert_eq!(
            cfg.with_device_attribute_reporting(true, false).err(),
            Some(ConfigError::PrivacyAcknowledgementRequired)
        );
    }

    #[test]
    fn unbound_olk_is_an_explicit_opt_in() {
        let default = config("https://license.example/").unwrap();
        assert!(!default.allow_unbound_olk());
        let enabled = default.with_unbound_olk(true).unwrap();
        assert!(enabled.allow_unbound_olk());
    }

    #[test]
    fn debug_redacts_build_secrets() {
        let rendered = format!("{:?}", config("https://license.example/").unwrap());
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("[4, 4, 4"));
    }
}
