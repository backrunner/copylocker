#![no_main]

use copylocker_proto::Envelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Envelope::decode(data);
});
