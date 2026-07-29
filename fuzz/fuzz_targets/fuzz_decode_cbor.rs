#![no_main]

use copylocker_suite::cbor::{decode_canonical, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_canonical(data, Limits::default());
});
