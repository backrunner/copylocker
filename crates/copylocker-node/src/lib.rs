//! napi-rs binding used exclusively from the Electron main process.

// napi-rs generates the N-API ABI glue. Hand-written unsafe remains denied in this crate.
#![deny(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

mod evidence;

use std::path::PathBuf;

use copylocker_client::{Config, ConfigError, CopyLockerClient, HostErrorCode};
use copylocker_proto::{ClientInfo, MAX_FEATURE_CHALLENGE_BYTES, MAX_SEALED_ASSET_BYTES};
use copylocker_suite::EnvEvidence;
use copylocker_suite_std::ClStd1;
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result, Status};
use napi_derive::napi;

const MAX_KEY_BYTES: usize = 4 * 1024;
const MAX_FEATURE_BYTES: usize = 1024;
const MAX_OFFLINE_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ARMORED_OLK_BYTES: usize = 2 * 1024 * 1024;

/// Paths and fallback bytes used to collect Electron integrity evidence.
#[napi(object)]
pub struct EvidenceOptions {
    /// Absolute path to the loaded `.node` file.
    pub module_path: String,
    /// Absolute path to `app.asar`, when packaged.
    pub asar_path: Option<String>,
    /// Embedded digest used only when local file collection is unavailable.
    pub expected_module_digest: Buffer,
}

impl core::fmt::Debug for EvidenceOptions {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EvidenceOptions")
            .field("module_path", &self.module_path)
            .field("asar_path", &self.asar_path)
            .field("expected_module_digest", &"<redacted>")
            .finish()
    }
}

/// Build-time client configuration passed from the Electron main process.
#[napi(object)]
pub struct NativeConfig {
    pub server_url: String,
    pub app_id: String,
    pub product_id: String,
    pub app_version: String,
    pub release_id: String,
    pub build_fingerprint: String,
    pub current_root_key: Buffer,
    pub next_root_key: Option<Buffer>,
    pub fingerprint_salt: Buffer,
    pub variant_id: u32,
    pub variant_const: Buffer,
    pub evidence: EvidenceOptions,
    pub allow_unbound_olk: Option<bool>,
    pub allow_insecure_localhost: Option<bool>,
}

impl core::fmt::Debug for NativeConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeConfig")
            .field("server_url", &self.server_url)
            .field("app_id", &self.app_id)
            .field("product_id", &self.product_id)
            .field("release_id", &self.release_id)
            .field("variant_id", &self.variant_id)
            .field("root_keys", &"<redacted>")
            .field("fingerprint_salt", &"<redacted>")
            .field("variant_const", &"<redacted>")
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// Advisory UI state. Productive access is available only through byte transformations.
#[derive(Debug)]
#[napi(object)]
pub struct NativeState {
    pub state: String,
}

/// Native CopyLocker client held by the Electron main process.
#[napi]
pub struct CopyLockerNative {
    client: CopyLockerClient<ClStd1>,
}

impl core::fmt::Debug for CopyLockerNative {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CopyLockerNative")
            .field("state", &self.client.state())
            .finish_non_exhaustive()
    }
}

#[napi]
impl CopyLockerNative {
    /// Construct and restore a native client.
    #[napi(factory)]
    pub async fn create(config: NativeConfig) -> Result<Self> {
        let client_config = build_config(config).await?;
        let client = CopyLockerClient::<ClStd1>::new(client_config)
            .await
            .map_err(|error| diagnostic_host_error("client restore", error))?;
        Ok(Self { client })
    }

    /// Activate with a licence key.
    #[napi]
    pub async fn activate(&self, key: String) -> Result<()> {
        require_text(&key, MAX_KEY_BYTES)?;
        self.client.activate(&key).await.map_err(host_error)
    }

    /// Release an online seat or erase a local OLK.
    #[napi]
    pub async fn deactivate(&self) -> Result<()> {
        self.client.deactivate().await.map_err(host_error)
    }

    /// Advisory only; never gate product functionality on this value.
    #[napi]
    pub fn state(&self) -> NativeState {
        NativeState {
            state: self.client.state().as_str().to_owned(),
        }
    }

    /// Authenticate and decrypt a sealed asset off the JavaScript thread.
    #[napi]
    pub async fn unseal(&self, feature: String, data: Buffer) -> Result<Buffer> {
        require_text(&feature, MAX_FEATURE_BYTES)?;
        require_bytes(&data, MAX_SEALED_ASSET_BYTES)?;
        let client = self.client.clone();
        let data = data.to_vec();
        blocking(move || {
            client
                .unseal(&feature, &data)
                .map(Buffer::from)
                .map_err(host_error)
        })
        .await
    }

    /// Answer an opaque feature challenge off the JavaScript thread.
    #[napi]
    pub async fn challenge(&self, input: Buffer) -> Result<Buffer> {
        require_bytes(&input, MAX_FEATURE_CHALLENGE_BYTES)?;
        let client = self.client.clone();
        let input = input.to_vec();
        blocking(move || {
            client
                .challenge(&input)
                .map(Buffer::from)
                .map_err(host_error)
        })
        .await
    }

    /// Create and persist a device-bound offline activation request.
    #[napi]
    pub async fn offline_request(&self, key: String) -> Result<Buffer> {
        require_text(&key, MAX_KEY_BYTES)?;
        let client = self.client.clone();
        blocking(move || {
            client
                .build_offline_request(&key)
                .map(Buffer::from)
                .map_err(host_error)
        })
        .await
    }

    /// Verify and install an offline activation response.
    #[napi]
    pub async fn offline_import(&self, data: Buffer) -> Result<()> {
        require_bytes(&data, MAX_OFFLINE_RESPONSE_BYTES)?;
        let client = self.client.clone();
        let data = data.to_vec();
        blocking(move || client.import_offline_response(&data).map_err(host_error)).await
    }

    /// Verify and install an armored Offline License Key bundle.
    #[napi]
    pub async fn import_olk(&self, data: String) -> Result<()> {
        require_text(&data, MAX_ARMORED_OLK_BYTES)?;
        let client = self.client.clone();
        blocking(move || client.import_olk(&data).map_err(host_error)).await
    }
}

/// Compute the same non-boolean evidence digest used during client construction.
#[napi]
pub async fn collect_evidence(options: EvidenceOptions) -> Result<Buffer> {
    let expected = fixed_32(&options.expected_module_digest)?;
    let module_path = PathBuf::from(options.module_path);
    let asar_path = options.asar_path.map(PathBuf::from);
    blocking(move || {
        let report = evidence::collect(
            &module_path,
            asar_path.as_deref(),
            expected,
            "evidence-only",
        );
        Ok(Buffer::from(
            report.evidence.module_digest.as_bytes().to_vec(),
        ))
    })
    .await
}

async fn build_config(config: NativeConfig) -> Result<Config> {
    require_text(&config.server_url, 4 * 1024)?;
    require_text(&config.app_id, 128)?;
    require_text(&config.product_id, 128)?;
    require_text(&config.build_fingerprint, 1024)?;
    let variant_const = fixed_32(&config.variant_const)?;
    let expected = fixed_32(&config.evidence.expected_module_digest)?;
    let module_path = PathBuf::from(&config.evidence.module_path);
    let asar_path = config.evidence.asar_path.as_ref().map(PathBuf::from);
    let build_fingerprint = config.build_fingerprint.clone();
    let report = blocking(move || {
        Ok(evidence::collect(
            &module_path,
            asar_path.as_deref(),
            expected,
            &build_fingerprint,
        ))
    })
    .await?;
    if matches!(report.source, evidence::EvidenceSource::EmbeddedFallback) {
        log_fallback();
    }
    build_client_config(config, variant_const, report.evidence)
}

fn build_client_config(
    config: NativeConfig,
    variant_const: [u8; 32],
    evidence: EnvEvidence,
) -> Result<Config> {
    let info = ClientInfo {
        app_version: config.app_version,
        sdk_version: env!("CARGO_PKG_VERSION").to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        build_fingerprint: config.build_fingerprint,
        release_id: config.release_id,
        variant_id: u64::from(config.variant_id),
        supported_suites: vec![copylocker_suite_std::CL_STD_1_SUITE_ID],
        supported_variants: vec![u64::from(config.variant_id)],
    };
    let mut client = Config::new_with_localhost_http(
        &config.server_url,
        config.app_id,
        config.product_id,
        info,
        config.current_root_key.to_vec(),
        config.fingerprint_salt.to_vec(),
        variant_const,
        evidence,
        config
            .allow_insecure_localhost
            .is_some_and(|enabled| enabled),
    )
    .map_err(config_error)?;
    if let Some(next) = config.next_root_key {
        client = client
            .with_next_root_key(next.to_vec())
            .map_err(config_error)?;
    }
    client
        .with_unbound_olk(config.allow_unbound_olk.is_some_and(|enabled| enabled))
        .map_err(config_error)
}

async fn blocking<T, F>(operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| host_error(HostErrorCode::UNKNOWN_FATAL))?
}

fn fixed_32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| host_error(HostErrorCode::UNKNOWN_FATAL))
}

fn require_text(value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes || value.as_bytes().contains(&0) {
        return Err(host_error(HostErrorCode::UNKNOWN_FATAL));
    }
    Ok(())
}

fn require_bytes(value: &[u8], max_bytes: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(host_error(HostErrorCode::UNKNOWN_FATAL));
    }
    Ok(())
}

fn host_error<E: Into<HostErrorCode>>(error: E) -> Error {
    let code = error.into().get();
    Error::new(Status::GenericFailure, format!("CL:{code}"))
}

fn config_error(error: ConfigError) -> Error {
    diagnostic("configuration", &error);
    host_error(HostErrorCode::INVALID_ARGUMENT)
}

fn diagnostic_host_error<E>(stage: &str, error: E) -> Error
where
    E: Into<HostErrorCode> + core::fmt::Display,
{
    diagnostic(stage, &error);
    host_error(error)
}

fn diagnostic(stage: &str, error: &dyn core::fmt::Display) {
    if std::env::var_os("COPYLOCKER_DIAGNOSTICS").is_some() {
        eprintln!("CopyLocker {stage} failed: {error}");
    }
}

fn log_fallback() {
    log::warn!("CopyLocker Electron evidence collection degraded to the embedded digest");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_and_input_bounds_reject_locally() {
        assert!(fixed_32(&[0; 31]).is_err());
        assert!(fixed_32(&[0; 32]).is_ok());
        assert!(require_text("", 10).is_err());
        assert!(require_text("ok", 10).is_ok());
        assert!(require_bytes(&[], 10).is_err());
        assert!(require_bytes(&[1], 10).is_ok());
    }

    #[test]
    fn host_errors_contain_only_the_stable_code() {
        let error = host_error(copylocker_core::CoreError::NotEntitled);
        assert_eq!(error.reason, "CL:4100");
    }

    #[test]
    fn invalid_configuration_uses_the_documented_host_code() {
        let error = config_error(ConfigError::InvalidServerUrl);
        assert_eq!(error.reason, "CL:4010");
    }
}
