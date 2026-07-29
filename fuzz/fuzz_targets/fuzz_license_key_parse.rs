#![no_main]

use copylocker_proto::LicenseKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = core::str::from_utf8(data) {
        let _ = LicenseKey::parse(input);
    }
});
