//! NFR-PERF-007 harness: resident-memory increment of one initialized desktop client.
//!
//! The budget (`non-functional-requirements.md` NFR-PERF-007, `testing-strategy.md` §7) is an
//! 8 MiB resident-set increment for adding the SDK to a host application, measured as an
//! integration check with a **warning** failure action. This harness initializes one
//! `CopyLockerClient<ClStd1>` with in-memory stub components (transport, store, fingerprint) so
//! the measurement covers the SDK core rather than a platform backend, then repeats the
//! construction to expose per-client growth (a leak would show up as a slope). RSS is sampled
//! through `ps -o rss=` to stay dependency-free and portable across macOS and Linux CI runners.

use std::process::{Command, ExitCode};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::sleep;
use std::time::Duration;

use copylocker_client::{Config, CopyLockerClient, Transport, TransportFuture};
use copylocker_fingerprint::{FingerprintError, FingerprintProvider};
use copylocker_proto::ClientInfo;
use copylocker_store::{KeyStore, StoreError};
use copylocker_suite::{
    AttrValue, CryptoSuite, DeviceAttrs, EnvClass, EnvEvidence, SignatureScheme,
};
use copylocker_suite_std::{ClStd1, HybridSig};
use copylocker_types::Digest;

const BUDGET_KIB: u64 = 8 * 1024;
const REPEAT_CLIENTS: usize = 16;

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(runtime) => runtime,
        Err(error) => return fatal("current-thread runtime build failed", &error),
    };
    runtime.block_on(run())
}

async fn run() -> ExitCode {
    settle();
    let baseline = match rss_kib() {
        Ok(value) => value,
        Err(error) => return fatal("baseline RSS sample failed", &error),
    };

    let client = CopyLockerClient::<ClStd1>::with_components(
        match build_config() {
            Ok(config) => config,
            Err(error) => return fatal("static harness configuration is invalid", &error),
        },
        Arc::new(FailingTransport),
        Arc::new(MemoryStore::default()),
        &FixedFingerprint,
    )
    .await;
    let client = match client {
        Ok(client) => client,
        Err(error) => return fatal("client construction with stub components failed", &error),
    };
    settle();
    let single = match rss_kib() {
        Ok(value) => value,
        Err(error) => return fatal("single-client RSS sample failed", &error),
    };
    let single_delta = single.saturating_sub(baseline);

    let mut clients = vec![client];
    for _ in 1..REPEAT_CLIENTS {
        let config = match build_config() {
            Ok(config) => config,
            Err(error) => return fatal("static harness configuration is invalid", &error),
        };
        let client = CopyLockerClient::<ClStd1>::with_components(
            config,
            Arc::new(FailingTransport),
            Arc::new(MemoryStore::default()),
            &FixedFingerprint,
        )
        .await;
        match client {
            Ok(client) => clients.push(client),
            Err(error) => return fatal("repeated client construction failed", &error),
        }
    }
    settle();
    let repeated = match rss_kib() {
        Ok(value) => value,
        Err(error) => return fatal("repeated-client RSS sample failed", &error),
    };
    let per_extra = repeated
        .saturating_sub(single)
        .checked_div((REPEAT_CLIENTS - 1) as u64)
        .unwrap_or(0);
    drop(clients);

    let verdict = if single_delta < BUDGET_KIB {
        "PASS"
    } else {
        "WARN"
    };
    println!(
        "NFR-PERF-007 memory increment: baseline {baseline} KiB, one client {single} KiB \
         (delta {single_delta} KiB, budget {BUDGET_KIB} KiB) => {verdict}; \
         {REPEAT_CLIENTS} clients {repeated} KiB (per-extra-client {per_extra} KiB)"
    );
    if single_delta >= BUDGET_KIB {
        eprintln!("memory increment exceeds the NFR-PERF-007 budget (warning action)");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn fatal(context: &str, error: &dyn std::fmt::Display) -> ExitCode {
    eprintln!("memory-budget harness error: {context}: {error}");
    ExitCode::from(2)
}

fn build_config() -> Result<Config, copylocker_client::ConfigError> {
    let mut rng = copylocker_suite_std::test_rng(7);
    let (_root_sk, root_vk) = HybridSig::generate(&mut rng);
    let root_vk = HybridSig::encode_vk(&root_vk);
    let info = ClientInfo {
        app_version: String::from("1.0.0"),
        sdk_version: String::from("0.1.0"),
        os: String::from("memory-budget"),
        arch: String::from("memory-budget"),
        build_fingerprint: String::from("memory-budget-build"),
        release_id: String::from("memory-budget-release"),
        variant_id: 1,
        supported_suites: vec![ClStd1::SUITE_ID],
        supported_variants: vec![1],
    };
    Config::new(
        "https://license.memory-budget.invalid/",
        "dev.copylocker.memory-budget",
        "memory-budget-product",
        info,
        root_vk,
        vec![0x77; 32],
        [0x88; 32],
        EnvEvidence {
            module_digest: Digest([0x99; 32]),
            build_fingerprint: b"memory-budget-build".to_vec(),
            extra: Vec::new(),
        },
    )
}

/// Let the allocator and runtime settle so the RSS sample reflects steady state.
fn settle() {
    sleep(Duration::from_millis(200));
}

/// Current resident set in KiB via `ps -o rss=` (dependency-free, macOS and Linux).
fn rss_kib() -> Result<u64, String> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .map_err(|error| format!("ps launch failed: {error}"))?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|error| format!("ps rss output does not parse as KiB: {error}"))
}

struct FailingTransport;

impl Transport for FailingTransport {
    fn send(&self, _request: copylocker_client::TransportRequest) -> TransportFuture<'_> {
        Box::pin(async { Err(copylocker_client::TransportError::Offline) })
    }
}

#[derive(Default)]
struct MemoryStore {
    value: Mutex<Option<Vec<u8>>>,
}

impl MemoryStore {
    fn guard(&self) -> MutexGuard<'_, Option<Vec<u8>>> {
        self.value.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl KeyStore for MemoryStore {
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.guard().clone())
    }

    fn save(&self, blob: &[u8]) -> Result<(), StoreError> {
        *self.guard() = Some(blob.to_vec());
        Ok(())
    }

    fn wipe(&self) -> Result<(), StoreError> {
        *self.guard() = None;
        Ok(())
    }
}

struct FixedFingerprint;

impl FingerprintProvider for FixedFingerprint {
    fn collect(&self) -> Result<DeviceAttrs, FingerprintError> {
        let mut attrs = DeviceAttrs::new();
        attrs.insert("machine_id", AttrValue::text("memory-budget-machine"));
        attrs.set_env_class(EnvClass::Bare);
        Ok(attrs)
    }
}
