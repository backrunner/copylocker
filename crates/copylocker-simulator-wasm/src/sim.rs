//! The platform-independent JSON core: parse, simulate, serialize. Host tests
//! link this directly (rlib), so the wasm artifact and the native build run
//! byte-identical logic.

use copylocker_server_core::catalog::Catalog;
use copylocker_server_core::policy::Policy;
use copylocker_server_core::simulator::{simulate, Scenario};
use copylocker_server_core::version::ReleaseRegistry;
use serde::{Deserialize, Serialize};

/// Bound on one simulation request, matching the Admin API body cap
/// (`admin_resources::MAX_ADMIN_BODY`); parsing is bounded before any work happens.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;

/// One simulation request: the full server-side inputs to [`simulate`].
///
/// Field names mirror the serde JSON of the Rust types exactly — a console
/// builds this object from the Admin API's policy, catalog, and release
/// projections, and the CLI's `policy simulate` consumes the same shapes.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationRequest {
    /// The policy under test.
    pub policy: Policy,
    /// The entitlement catalog the policy resolves against.
    pub catalog: Catalog,
    /// The registered releases the version decisions run against.
    pub registry: ReleaseRegistry,
    /// The scenario to replay.
    pub scenario: Scenario,
}

/// Run one simulation from a JSON [`SimulationRequest`], returning the JSON
/// [`copylocker_server_core::simulator::Simulation`]. Errors are human-readable
/// strings (see the crate docs).
pub fn simulate_json(input: &str) -> Result<String, String> {
    if input.len() > MAX_REQUEST_BYTES {
        return Err(format!(
            "simulation request exceeds the {MAX_REQUEST_BYTES}-byte limit"
        ));
    }
    let request: SimulationRequest = serde_json::from_str(input)
        .map_err(|error| format!("invalid simulation request: {error}"))?;
    let simulation = simulate(
        &request.policy,
        &request.catalog,
        &request.registry,
        &request.scenario,
    )
    .map_err(|error| format!("simulation rejected the inputs: {error}"))?;
    serde_json::to_string(&simulation)
        .map_err(|error| format!("simulation result is not serializable: {error}"))
}
