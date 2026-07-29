use std::time::{SystemTime, UNIX_EPOCH};

use copylocker_suite::CryptoRng;

pub(crate) trait TimeSource: Send + Sync {
    fn unix_seconds(&self) -> i64;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn unix_seconds(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            Err(error) => {
                let seconds = i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX);
                seconds.saturating_neg()
            }
        }
    }
}

pub(crate) trait RandomSource: Send + Sync {
    fn fill(&self, destination: &mut [u8]) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemRandomSource;

impl RandomSource for SystemRandomSource {
    fn fill(&self, destination: &mut [u8]) -> Result<(), ()> {
        getrandom::fill(destination).map_err(|_| ())
    }
}

pub(crate) struct CryptoRngAdapter<'a> {
    source: &'a dyn RandomSource,
    failed: bool,
}

impl<'a> CryptoRngAdapter<'a> {
    pub(crate) fn new(source: &'a dyn RandomSource) -> Self {
        Self {
            source,
            failed: false,
        }
    }

    pub(crate) const fn failed(&self) -> bool {
        self.failed
    }
}

impl CryptoRng for CryptoRngAdapter<'_> {
    fn fill_bytes(&mut self, destination: &mut [u8]) {
        if self.source.fill(destination).is_err() {
            destination.fill(0);
            self.failed = true;
        }
    }
}

pub(crate) fn random_array<const N: usize>(
    source: &dyn RandomSource,
) -> Result<[u8; N], crate::LocalError> {
    let mut value = [0u8; N];
    source
        .fill(&mut value)
        .map_err(|()| crate::LocalError::EntropyUnavailable)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FailingRandom;

    impl RandomSource for FailingRandom {
        fn fill(&self, _: &mut [u8]) -> Result<(), ()> {
            Err(())
        }
    }

    #[test]
    fn fallible_crypto_adapter_records_failure_and_clears_output() {
        let mut adapter = CryptoRngAdapter::new(&FailingRandom);
        let mut output = [0xaa; 32];
        adapter.fill_bytes(&mut output);
        assert!(adapter.failed());
        assert_eq!(output, [0; 32]);
    }

    #[test]
    fn system_time_is_representable() {
        assert!(SystemTimeSource.unix_seconds() > 0);
    }
}
