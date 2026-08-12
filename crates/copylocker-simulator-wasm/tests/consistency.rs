//! Three-way simulator consistency (`licensing-model.md §11`, M7 acceptance):
//! the JSON wasm wrapper, a direct `copylocker_server_core::simulator::simulate`
//! call, and the checked-in fixtures must agree byte-for-byte on the same
//! scenario. The console's vitest suite replays the same fixture files
//! through the wasm artifact, and the CLI's `policy simulate` calls the same
//! `simulate` — so equality here transitively pins all three surfaces.
//!
//! Regenerate the fixtures after a deliberate simulator change with:
//! `COPYLOCKER_UPDATE_FIXTURES=1 cargo test -p copylocker-simulator-wasm`

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use copylocker_server_core::catalog::{Catalog, Feature, FeatureGroup, GroupMembers, Tier};
use copylocker_server_core::policy::Preset;
use copylocker_server_core::simulator::{simulate, Scenario, ScenarioStep};
use copylocker_server_core::version::{Release, ReleaseRegistry, ReleaseStatus};
use copylocker_simulator_wasm::{simulate_json, SimulationRequest};

const JAN26: i64 = 1_767_225_600; // 2026-01-01
const YEAR: i64 = 365 * 86_400;

const REQUEST_FIXTURE: &str = "sub_annual_fallback.request.json";
const EXPECTED_FIXTURE: &str = "sub_annual_fallback.expected.json";

fn feature(id: &str) -> Feature {
    Feature {
        id: id.to_owned(),
        label: id.to_owned(),
        description: None,
        deprecated_at: None,
    }
}

/// The example catalog from `licensing-model.md §2.4` (mirrors
/// `catalog::fixtures::sample`, which is test-only inside server-core).
fn sample_catalog() -> Catalog {
    Catalog {
        product_id: "acme".to_owned(),
        version: 1,
        features: vec![
            feature("export.png"),
            feature("export.pdf"),
            feature("export.svg"),
            feature("ai.assist"),
            feature("render.4k"),
            feature("team.share"),
        ],
        groups: vec![
            FeatureGroup {
                id: "export-basic".to_owned(),
                label: "Basic export".to_owned(),
                members: GroupMembers {
                    includes: vec![],
                    features: vec!["export.png".to_owned()],
                },
            },
            FeatureGroup {
                id: "export-pro".to_owned(),
                label: "Pro export".to_owned(),
                members: GroupMembers {
                    includes: vec!["export-basic".to_owned()],
                    features: vec!["export.pdf".to_owned(), "export.svg".to_owned()],
                },
            },
            FeatureGroup {
                id: "pro-suite".to_owned(),
                label: "Pro suite".to_owned(),
                members: GroupMembers {
                    includes: vec!["export-pro".to_owned()],
                    features: vec!["ai.assist".to_owned(), "render.4k".to_owned()],
                },
            },
        ],
        tiers: vec![
            Tier {
                id: "free".to_owned(),
                label: "Free".to_owned(),
                rank: 0,
                groups: vec!["export-basic".to_owned()],
                features: vec![],
                limits: [("max_projects".to_owned(), 3)].into_iter().collect(),
                archived_at: None,
            },
            Tier {
                id: "pro".to_owned(),
                label: "Pro".to_owned(),
                rank: 10,
                groups: vec!["pro-suite".to_owned()],
                features: vec![],
                limits: [("max_projects".to_owned(), 100)].into_iter().collect(),
                archived_at: None,
            },
            Tier {
                id: "team".to_owned(),
                label: "Team".to_owned(),
                rank: 20,
                groups: vec!["pro-suite".to_owned()],
                features: vec!["team.share".to_owned()],
                limits: [
                    ("max_projects".to_owned(), -1),
                    ("max_members".to_owned(), 25),
                ]
                .into_iter()
                .collect(),
                archived_at: None,
            },
        ],
    }
}

fn release(id: &str, app_version: &str, variant_id: u64, published_at: i64) -> Release {
    Release {
        id: id.to_owned(),
        product_id: "acme".to_owned(),
        app_version: app_version.to_owned(),
        variant_id,
        build_fingerprint: format!("bf{variant_id}"),
        channel: "stable".to_owned(),
        status: ReleaseStatus::Active,
        compromised_action: None,
        published_at,
    }
}

fn registry() -> ReleaseRegistry {
    ReleaseRegistry {
        releases: vec![
            release("rel_38", "3.8.0", 38, JAN26),
            release("rel_39", "3.9.0", 39, JAN26 + 350 * 86_400),
            release("rel_42", "4.2.0", 42, JAN26 + 2 * YEAR - 60 * 86_400),
        ],
    }
}

/// The worked example from `licensing-model.md §11`: an annual subscription
/// with a perpetual fallback, cancelled in year two, ending version-capped.
fn request() -> SimulationRequest {
    SimulationRequest {
        policy: Preset::SubAnnualFallback.build("sub-annual-fallback", "acme", "pro", JAN26),
        catalog: sample_catalog(),
        registry: registry(),
        scenario: Scenario {
            name: "sub-annual-fallback, cancel in year two".to_owned(),
            steps: vec![
                ScenarioStep::Activate { at: JAN26 },
                // One completed annual billing cycle earns twelve paid months.
                ScenarioStep::Renew { at: JAN26 + YEAR },
                ScenarioStep::Cancel {
                    at: JAN26 + YEAR + 150 * 86_400,
                },
                ScenarioStep::PeriodEnds {
                    at: JAN26 + 2 * YEAR,
                },
                // 4.2 was published after the fallback vested.
                ScenarioStep::RunRelease {
                    at: JAN26 + 2 * YEAR + 86_400,
                    release_id: "rel_42".to_owned(),
                },
                // 3.9 was published before it, so it still runs.
                ScenarioStep::RunRelease {
                    at: JAN26 + 2 * YEAR + 86_400,
                    release_id: "rel_39".to_owned(),
                },
            ],
        },
    }
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

#[test]
fn the_wrapper_matches_server_core_and_the_checked_in_fixture() {
    let request = request();
    let request_json = serde_json::to_string_pretty(&request).unwrap();

    // The direct call uses the very function the CLI's `policy simulate` calls.
    let direct = simulate(
        &request.policy,
        &request.catalog,
        &request.registry,
        &request.scenario,
    )
    .unwrap();
    let direct_json = serde_json::to_string_pretty(&direct).unwrap();

    // The wrapper (what the wasm shell exposes) must agree on the same inputs.
    let wrapped = simulate_json(&request_json).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&wrapped).unwrap(),
        serde_json::from_str::<serde_json::Value>(&direct_json).unwrap(),
        "the JSON wrapper must not drift from server-core simulate"
    );

    if std::env::var_os("COPYLOCKER_UPDATE_FIXTURES").is_some() {
        fs::write(fixture_path(REQUEST_FIXTURE), format!("{request_json}\n")).unwrap();
        fs::write(fixture_path(EXPECTED_FIXTURE), format!("{direct_json}\n")).unwrap();
        return;
    }

    let request_fixture = fs::read_to_string(fixture_path(REQUEST_FIXTURE)).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&request_fixture).unwrap(),
        serde_json::from_str::<serde_json::Value>(&request_json).unwrap(),
        "the request fixture drifted; regenerate with COPYLOCKER_UPDATE_FIXTURES=1"
    );
    let expected_fixture = fs::read_to_string(fixture_path(EXPECTED_FIXTURE)).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&expected_fixture).unwrap(),
        serde_json::from_str::<serde_json::Value>(&direct_json).unwrap(),
        "the expected fixture drifted from server-core simulate; \
         the console vitest compares the wasm artifact against this file"
    );
    // The wrapper must also accept the fixture as-is (the console sends exactly this).
    let from_fixture = simulate_json(&request_fixture).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&from_fixture).unwrap(),
        serde_json::from_str::<serde_json::Value>(&expected_fixture).unwrap(),
        "the wrapper must reproduce the expected fixture from the request fixture"
    );
}
