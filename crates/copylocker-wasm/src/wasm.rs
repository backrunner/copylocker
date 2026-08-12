//! The `wasm-bindgen` shell — the only symbols the JavaScript side can see.
//!
//! Deliberately opaque (`40-web-sdk-wasm-ts.md §3.1`): one constructor taking CBOR config
//! bytes, one `step` method taking and returning CBOR bytes. Errors surface as a bare number
//! (`JsValue` f64), never a string (NFR-SEC-011). All logic lives in [`crate::session`]; this
//! file only converts types across the boundary.

use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use crate::rng::GetrandomRng;
use crate::session::Session;

/// An opaque CopyLocker web session. See [`Session`] for the protocol.
#[wasm_bindgen]
pub struct ClSession {
    core: Session,
}

impl core::fmt::Debug for ClSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClSession").finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl ClSession {
    /// Build a session from CBOR configuration bytes (schema documented on `Session::new`).
    #[wasm_bindgen(constructor)]
    pub fn new(cfg: &[u8]) -> Result<ClSession, JsValue> {
        Session::new(cfg, Box::new(GetrandomRng::new()))
            .map(|core| ClSession { core })
            .map_err(js_error)
    }

    /// The single generic entry point: CBOR op map in, CBOR result out.
    ///
    /// On failure the rejection value is a number — the stable error code from
    /// `copylocker-wasm`'s `codes` module — with no greppable message.
    pub fn step(&mut self, input: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.core.step(input).map_err(js_error)
    }
}

fn js_error(code: u16) -> JsValue {
    JsValue::from_f64(f64::from(code))
}
