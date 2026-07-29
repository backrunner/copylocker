#![no_main]

use copylocker_proto::{
    ActivationRequest, ActivationResponse, DeactivateRequest, EpochCert, HeartbeatRequest,
    IntegrityManifest, KillOrder, MachineCredential, OfflineLicenseKey, RevocationBatch,
    ValidateRequest, ValidationTicket,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = EpochCert::decode(data);
    let _ = MachineCredential::decode(data);
    let _ = ValidationTicket::decode(data);
    let _ = KillOrder::decode(data);
    let _ = RevocationBatch::decode(data);
    let _ = OfflineLicenseKey::decode(data);
    let _ = IntegrityManifest::decode(data);
    let _ = ActivationResponse::decode(data);
    let _ = ActivationRequest::decode(data);
    let _ = ValidateRequest::decode(data);
    let _ = HeartbeatRequest::decode(data);
    let _ = DeactivateRequest::decode(data);
});
