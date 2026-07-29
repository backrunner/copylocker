use copylocker_suite::CryptoRng;
use worker::js_sys::{global, Reflect};
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::{Error, Result};

pub(crate) struct WorkerRng {
    crypto: web_sys::Crypto,
    failed: bool,
}

impl WorkerRng {
    pub(crate) fn new() -> Result<Self> {
        let value = Reflect::get(&global(), &JsValue::from_str("crypto"))
            .map_err(|_| rng_error("Workers crypto global is unavailable"))?;
        let crypto = value
            .dyn_into::<web_sys::Crypto>()
            .map_err(|_| rng_error("Workers crypto global has an invalid type"))?;
        Ok(Self {
            crypto,
            failed: false,
        })
    }

    pub(crate) fn random_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut value = [0_u8; N];
        self.fill_bytes(&mut value);
        self.ensure_healthy()?;
        Ok(value)
    }

    pub(crate) fn ensure_healthy(&self) -> Result<()> {
        if self.failed {
            Err(rng_error("Workers CSPRNG failed"))
        } else {
            Ok(())
        }
    }
}

impl CryptoRng for WorkerRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.failed || self.crypto.get_random_values_with_u8_array(dest).is_err() {
            dest.fill(0);
            self.failed = true;
        }
    }
}

fn rng_error(message: &str) -> Error {
    Error::RustError(message.to_owned())
}
