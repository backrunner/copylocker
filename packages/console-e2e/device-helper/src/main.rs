//! Device fixture for `packages/console-e2e`: performs REAL protocol activations and
//! validations against the local Wrangler backend (no mocks), persisting the client
//! snapshot in a plain file so separate invocations share one device.
//!
//!   device-helper activate --server URL --product P --root-vk-hex HEX \
//!       --license-key CL1-... --state-dir DIR [--release-id dev] \
//!       [--build-fingerprint dev] [--variant-id 0] [--module-digest-hex HEX] \
//!       [--machine-name NAME]
//!   device-helper validate --server URL --product P --root-vk-hex HEX --state-dir DIR \
//!       [same options except --license-key]
//!
//! Exit codes: 0 success; 3 the server rejected the credential (revocation/kill
//! verdict: reactivation required, out of scope, or no credential); 2 any other
//! failure. Prints one JSON line on stdout.
//!
//! Local test fixture only; never used against a real deployment.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use copylocker_client::{Config, CopyLockerClient, ValidationError};
use copylocker_fingerprint::{FingerprintError, FingerprintProvider};
use copylocker_proto::ClientInfo;
use copylocker_store::{KeyStore, StoreError};
use copylocker_suite::{AttrValue, DeviceAttrs, EnvClass, EnvEvidence};
use copylocker_suite_std::ClStd1;
use copylocker_types::{Digest, SuiteId};

const APP_ID: &str = "dev.copylocker.console-e2e";
const APP_VERSION: &str = "0.0.0";
const SDK_VERSION: &str = "0.1.0";
const FINGERPRINT_SALT: &[u8] = b"copylocker-console-e2e-fingerprint-salt";
const VARIANT_CONST: [u8; 32] = [0x43; 32];

struct Options {
    server: String,
    product: String,
    root_vk_hex: String,
    license_key: Option<String>,
    state_dir: PathBuf,
    release_id: String,
    build_fingerprint: String,
    variant_id: u64,
    module_digest_hex: Option<String>,
    machine_name: String,
}

struct FileStore {
    path: PathBuf,
}

impl KeyStore for FileStore {
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(StoreError::ProtectedStorage),
        }
    }

    fn save(&self, blob: &[u8]) -> Result<(), StoreError> {
        fs::write(&self.path, blob).map_err(|_| StoreError::ProtectedStorage)
    }

    fn wipe(&self) -> Result<(), StoreError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StoreError::ProtectedStorage),
        }
    }
}

struct FixedFingerprint {
    machine_name: String,
}

impl FingerprintProvider for FixedFingerprint {
    fn collect(&self) -> Result<DeviceAttrs, FingerprintError> {
        let mut attrs = DeviceAttrs::new();
        attrs.insert("machine_id", AttrValue::text(&self.machine_name));
        attrs.set_env_class(EnvClass::Bare);
        Ok(attrs)
    }
}

fn hex32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex_decode(value)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 64 hex characters, got {}", value.len()))
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex value has an odd length".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "invalid hex".to_owned())?;
            u8::from_str_radix(text, 16).map_err(|_| format!("invalid hex byte {text}"))
        })
        .collect()
}

fn parse_args(args: &[String]) -> Result<(String, Options), String> {
    let command = args.first().map(String::as_str).unwrap_or("");
    if !matches!(command, "activate" | "validate") {
        return Err("usage: device-helper <activate|validate> --flags".to_owned());
    }
    let mut server = None;
    let mut product = None;
    let mut root_vk_hex = None;
    let mut license_key = None;
    let mut state_dir = None;
    let mut release_id = "dev".to_owned();
    let mut build_fingerprint = "dev".to_owned();
    let mut variant_id = 0_u64;
    let mut module_digest_hex = None;
    let mut machine_name = "console-e2e-device".to_owned();
    let mut index = 1;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args.get(index + 1).ok_or_else(|| format!("{flag} needs a value"))?;
        match flag {
            "--server" => server = Some(value.clone()),
            "--product" => product = Some(value.clone()),
            "--root-vk-hex" => root_vk_hex = Some(value.clone()),
            "--license-key" => license_key = Some(value.clone()),
            "--state-dir" => state_dir = Some(PathBuf::from(value)),
            "--release-id" => release_id = value.clone(),
            "--build-fingerprint" => build_fingerprint = value.clone(),
            "--variant-id" => {
                variant_id = value
                    .parse::<u64>()
                    .map_err(|_| "--variant-id must be a non-negative integer".to_owned())?;
            }
            "--module-digest-hex" => module_digest_hex = Some(value.clone()),
            "--machine-name" => machine_name = value.clone(),
            other => return Err(format!("unknown flag {other}")),
        }
        index += 2;
    }
    Ok((
        command.to_owned(),
        Options {
            server: server.ok_or("--server is required")?,
            product: product.ok_or("--product is required")?,
            root_vk_hex: root_vk_hex.ok_or("--root-vk-hex is required")?,
            license_key,
            state_dir: state_dir.ok_or("--state-dir is required")?,
            release_id,
            build_fingerprint,
            variant_id,
            module_digest_hex,
            machine_name,
        },
    ))
}

fn config(options: &Options) -> Result<Config, String> {
    let root_key = hex_decode(&options.root_vk_hex)?;
    let module_digest = match options.module_digest_hex.as_deref() {
        Some(value) => Digest(hex32(value)?),
        None => Digest([0; 32]),
    };
    let client_info = ClientInfo {
        app_version: APP_VERSION.to_owned(),
        sdk_version: SDK_VERSION.to_owned(),
        os: env::consts::OS.to_owned(),
        arch: env::consts::ARCH.to_owned(),
        build_fingerprint: options.build_fingerprint.clone(),
        release_id: options.release_id.clone(),
        variant_id: options.variant_id,
        supported_suites: vec![SuiteId::from_u32(0x0100_0001)],
        supported_variants: vec![options.variant_id],
    };
    let evidence = EnvEvidence {
        module_digest,
        build_fingerprint: options.build_fingerprint.as_bytes().to_vec(),
        extra: Vec::new(),
    };
    Config::new_with_localhost_http(
        &options.server,
        APP_ID,
        options.product.clone(),
        client_info,
        root_key,
        FINGERPRINT_SALT.to_vec(),
        VARIANT_CONST,
        evidence,
        true,
    )
    .map_err(|error| format!("invalid device config: {error}"))
}

fn state_file(dir: &Path) -> PathBuf {
    dir.join("device.state")
}

async fn build_client(options: &Options) -> Result<CopyLockerClient<ClStd1>, String> {
    fs::create_dir_all(&options.state_dir)
        .map_err(|error| format!("state dir unavailable: {error}"))?;
    let transport = Arc::new(
        copylocker_client::ReqwestTransport::new()
            .map_err(|error| format!("transport init failed: {error}"))?,
    );
    let store = Arc::new(FileStore {
        path: state_file(&options.state_dir),
    });
    let fingerprint = FixedFingerprint {
        machine_name: options.machine_name.clone(),
    };
    CopyLockerClient::<ClStd1>::with_components(config(options)?, transport, store, &fingerprint)
        .await
        .map_err(|error| format!("client init failed: {error}"))
}

fn print_json(fields: &[(&str, &str)]) {
    let body = fields
        .iter()
        .map(|(key, value)| format!("\"{key}\":\"{value}\""))
        .collect::<Vec<_>>()
        .join(",");
    println!("{{{body}}}");
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (command, options) = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let client = match build_client(&options).await {
        Ok(client) => client,
        Err(error) => {
            print_json(&[("ok", "false"), ("error", &error)]);
            return ExitCode::from(2);
        }
    };
    match command.as_str() {
        "activate" => {
            let Some(key) = options.license_key.as_deref() else {
                eprintln!("activate requires --license-key");
                return ExitCode::from(2);
            };
            match client.activate(key).await {
                Ok(()) => {
                    print_json(&[("ok", "true"), ("action", "activate")]);
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    let detail = error.to_string();
                    print_json(&[("ok", "false"), ("action", "activate"), ("error", &detail)]);
                    ExitCode::from(2)
                }
            }
        }
        "validate" => match client.validate().await {
            Ok(()) => {
                print_json(&[("ok", "true"), ("verdict", "valid")]);
                ExitCode::SUCCESS
            }
            Err(
                rejection @ (ValidationError::ReactivationRequired
                | ValidationError::VersionOutOfScope
                | ValidationError::NotActivated),
            ) => {
                let kind = format!("{rejection:?}");
                let detail = rejection.to_string();
                print_json(&[
                    ("ok", "false"),
                    ("verdict", "rejected"),
                    ("kind", &kind),
                    ("error", &detail),
                ]);
                ExitCode::from(3)
            }
            Err(error) => {
                let kind = format!("{error:?}");
                print_json(&[("ok", "false"), ("verdict", "error"), ("kind", &kind)]);
                ExitCode::from(2)
            }
        },
        _ => ExitCode::from(2),
    }
}
