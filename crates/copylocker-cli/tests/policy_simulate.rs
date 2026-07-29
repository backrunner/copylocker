use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use copylocker_server_core::simulator::{Scenario, ScenarioStep};
use copylocker_server_core::version::{Release, ReleaseRegistry, ReleaseStatus};
use copylocker_server_core::Preset;
use serde::Serialize;
use serde_json::{json, Value};

const START: i64 = 1_767_225_600;
const MONTH: i64 = 30 * 86_400;

struct FixtureDir {
    root: PathBuf,
}

impl FixtureDir {
    fn new() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "copylocker-policy-simulate-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        Ok(Self { root })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn write_json(&self, name: &str, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
        fs::write(self.path(name), serde_json::to_vec_pretty(value)?)?;
        Ok(())
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run_simulator(root: &Path, json_output: bool) -> Result<Output, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_copylocker"));
    if json_output {
        command.arg("--json");
    }
    command
        .args(["policy", "simulate", "--policy"])
        .arg(root.join("policy.json"))
        .arg("--catalog")
        .arg(root.join("catalog.json"))
        .arg("--releases")
        .arg(root.join("releases.json"))
        .arg("--scenario")
        .arg(root.join("scenario.json"))
        .output()
}

#[test]
fn policy_simulate_reads_files_and_emits_human_and_json_timelines() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureDir::new()?;
    fixture.write_json(
        "policy.json",
        &Preset::SubMonthly.build("policy_cli", "acme", "pro", START),
    )?;
    fixture.write_json(
        "catalog.json",
        &json!({
            "product_id": "acme",
            "version": 1,
            "features": [],
            "groups": [],
            "tiers": [{
                "id": "pro",
                "label": "Pro",
                "rank": 10,
                "groups": [],
                "features": [],
                "limits": {},
                "archived_at": null
            }]
        }),
    )?;
    fixture.write_json(
        "releases.json",
        &ReleaseRegistry {
            releases: vec![Release {
                id: "rel_1".to_string(),
                product_id: "acme".to_string(),
                app_version: "1.0.0".to_string(),
                variant_id: 1,
                build_fingerprint: "build-1".to_string(),
                channel: "stable".to_string(),
                status: ReleaseStatus::Active,
                compromised_action: None,
                published_at: START,
            }],
        },
    )?;
    fixture.write_json(
        "scenario.json",
        &Scenario {
            name: "cli-file-e2e".to_string(),
            steps: vec![
                ScenarioStep::Activate { at: START },
                ScenarioStep::PaymentFails { at: START + MONTH },
            ],
        },
    )?;

    let human = run_simulator(&fixture.root, false)?;
    assert!(
        human.status.success(),
        "human CLI failed: {}",
        String::from_utf8_lossy(&human.stderr)
    );
    let human_stdout = String::from_utf8(human.stdout)?;
    assert!(human_stdout.contains("scenario: cli-file-e2e"));
    assert!(human_stdout.contains("payment_failed"));
    assert!(human_stdout.contains("still usable until"));

    let json_output = run_simulator(&fixture.root, true)?;
    assert!(
        json_output.status.success(),
        "JSON CLI failed: {}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let payload: Value = serde_json::from_slice(&json_output.stdout)?;
    assert_eq!(payload.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        payload.get("command").and_then(Value::as_str),
        Some("policy.simulate")
    );
    assert_eq!(
        payload.get("policy_id").and_then(Value::as_str),
        Some("policy_cli")
    );
    let simulation = payload
        .get("simulation")
        .and_then(Value::as_object)
        .ok_or_else(|| std::io::Error::other("JSON output has no simulation object"))?;
    assert_eq!(
        simulation.get("scenario").and_then(Value::as_str),
        Some("cli-file-e2e")
    );
    assert_eq!(
        simulation
            .get("final_subscription_state")
            .and_then(Value::as_str),
        Some("past_due")
    );
    assert!(simulation
        .get("timeline")
        .and_then(Value::as_array)
        .is_some_and(|entries| entries.iter().any(|entry| {
            entry.get("event").and_then(Value::as_str) == Some("payment_failed")
        })));

    Ok(())
}
