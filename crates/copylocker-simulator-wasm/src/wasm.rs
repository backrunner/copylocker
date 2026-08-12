//! The `wasm-bindgen` shell — the only symbol the JavaScript side can see.
//! All logic lives in [`crate::sim`]; this file only converts types across
//! the boundary.

use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

/// Run one simulation: a JSON `SimulationRequest` in, a JSON `Simulation`
/// out; the rejection value is the error string.
#[wasm_bindgen]
pub fn simulate_scenario(input: &str) -> Result<String, JsValue> {
    crate::sim::simulate_json(input).map_err(|error| JsValue::from_str(&error))
}
