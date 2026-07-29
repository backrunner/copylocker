#![no_main]

use copylocker_core::{CoreConfig, Deadlines, Event, FatalError, StateMachine, TransientError};
use copylocker_types::KillReason;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(seed) = data.first().copied() else {
        return;
    };
    let mut machine = StateMachine::new(
        CoreConfig {
            rollback_threshold: u32::from(seed % 8),
            min_validation_interval_secs: i64::from(byte(data, 1) as i8),
        },
        i64::from(seed),
    );
    machine.set_deadlines(Deadlines {
        refresh_after: signed_time(data, 2),
        grace_deadline: signed_time(data, 3),
        not_after: if byte(data, 4) & 1 == 0 {
            0
        } else {
            signed_time(data, 4)
        },
    });

    for (index, chunk) in data.chunks(3).take(1_024).enumerate() {
        let tag = chunk.first().copied().unwrap_or_default();
        let detail = chunk.get(1).copied().unwrap_or_default();
        let delta = i64::from(chunk.get(2).copied().unwrap_or_default() as i8);
        let wall_clock = i64::from(seed).saturating_add((index as i64).saturating_mul(delta));
        let event = match tag % 10 {
            0 => Event::Tick,
            1 => Event::NetworkAvailable,
            2 => Event::AppResumed {
                monotonic_gap_ms: u64::from(detail).saturating_mul(1_000),
            },
            3 => Event::CredentialLoaded,
            4 => Event::ActivationVerified,
            5 => Event::TicketVerified,
            6 => Event::KillOrderVerified(kill_reason(detail)),
            7 => Event::NetworkFailed(transient_error(detail)),
            8 => Event::VerificationFailed(fatal_error(detail)),
            _ => Event::UserDeactivate,
        };
        let _ = machine.handle(event, wall_clock);
        let _ = machine.should_opportunistically_validate(wall_clock);
        machine.note_validation_attempt(wall_clock);
        let _ = machine.state();
        let _ = machine.has_credential();
    }
});

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index % data.len()).copied().unwrap_or_default()
}

fn signed_time(data: &[u8], index: usize) -> i64 {
    i64::from(byte(data, index) as i8).saturating_mul(86_400)
}

fn kill_reason(value: u8) -> KillReason {
    KillReason::from_u8(value % 6 + 1).unwrap_or(KillReason::Fraud)
}

fn transient_error(value: u8) -> TransientError {
    match value % 5 {
        0 => TransientError::Offline,
        1 => TransientError::Timeout,
        2 => TransientError::ServerError(u16::from(value)),
        3 => TransientError::RateLimited {
            retry_after: u32::from(value),
        },
        _ => TransientError::TransportFailure,
    }
}

fn fatal_error(value: u8) -> FatalError {
    match value % 10 {
        0 => FatalError::SignatureInvalid,
        1 => FatalError::ChainInvalid,
        2 => FatalError::EpochRevoked,
        3 => FatalError::NonceMismatch,
        4 => FatalError::MachineMismatch,
        5 => FatalError::RevocationRollback,
        6 => FatalError::CredentialCorrupt,
        7 => FatalError::Revoked(kill_reason(value)),
        8 => FatalError::SecurityFloorRegression,
        _ => FatalError::IntegrityFailure,
    }
}
