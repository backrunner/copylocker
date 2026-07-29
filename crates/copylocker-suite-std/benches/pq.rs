use std::env::{self, VarError};
use std::error::Error;
use std::hint::black_box;
use std::io;
use std::time::{Duration, Instant};

use copylocker_suite::{CryptoRng, DomainCtx, KeyEncapsulation, SignatureScheme};
use copylocker_suite_std::{HybridSig, XWingKem, CL_STD_1_SUITE_ID};
use copylocker_types::ArtifactKind;

const REFERENCE_BUDGET: PerformanceBudget = PerformanceBudget {
    profile: "apple-m4-reference",
    sign: Duration::from_millis(3),
    verify: Duration::from_millis(5),
};

const GITHUB_UBUNTU_24_04_BUDGET: PerformanceBudget = PerformanceBudget {
    profile: "github-ubuntu-24.04",
    sign: Duration::from_millis(12),
    verify: Duration::from_millis(8),
};

#[derive(Clone, Copy, Debug)]
struct PerformanceBudget {
    profile: &'static str,
    sign: Duration,
    verify: Duration,
}

struct BenchRng(rand_chacha::ChaCha20Rng);

impl BenchRng {
    fn seeded(seed: u64) -> Self {
        use rand_core::SeedableRng;
        Self(rand_chacha::ChaCha20Rng::seed_from_u64(seed))
    }
}

impl CryptoRng for BenchRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use rand_core::Rng;
        self.0.fill_bytes(dest);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let budget = performance_budget()?;
    let mut rng = BenchRng::seeded(0x5045_5246);
    let (signing_key, verifying_key) = HybridSig::generate(&mut rng);
    let context = DomainCtx::new(
        ArtifactKind::MachineCred,
        CL_STD_1_SUITE_ID,
        "benchmark-product",
    );
    let message = black_box(b"copylocker native performance baseline".as_slice());
    let signature = HybridSig::sign(&signing_key, context, message)
        .map_err(|_| failure("hybrid signature setup failed"))?;

    for _ in 0..5 {
        let warm = HybridSig::sign(&signing_key, context, message)
            .map_err(|_| failure("hybrid signing warmup failed"))?;
        HybridSig::verify(&verifying_key, context, message, black_box(&warm))
            .map_err(|_| failure("hybrid verification warmup failed"))?;
    }

    let sign = average(40, || {
        let output = HybridSig::sign(&signing_key, context, message)
            .map_err(|_| failure("hybrid signing failed"))?;
        black_box(output);
        Ok(())
    })?;
    let verify = average(200, || {
        HybridSig::verify(&verifying_key, context, message, black_box(&signature))
            .map_err(|_| failure("hybrid verification failed"))
    })?;

    let (decapsulation_key, encapsulation_key) = XWingKem::keygen(&mut rng);
    let (ciphertext, _) = XWingKem::encap(&encapsulation_key, &mut rng)
        .map_err(|_| failure("X-Wing setup failed"))?;
    let keygen = average(20, || {
        black_box(XWingKem::keygen(&mut rng));
        Ok(())
    })?;
    let encap = average(40, || {
        let output = XWingKem::encap(&encapsulation_key, &mut rng)
            .map_err(|_| failure("X-Wing encapsulation failed"))?;
        black_box(output);
        Ok(())
    })?;
    let decap = average(100, || {
        let output = XWingKem::decap(&decapsulation_key, black_box(&ciphertext))
            .map_err(|_| failure("X-Wing decapsulation failed"))?;
        black_box(output);
        Ok(())
    })?;

    println!("CL-STD-1 native release baseline (average per operation)");
    println!("hybrid_sign_us={:.2}", micros(sign));
    println!("hybrid_verify_us={:.2}", micros(verify));
    println!("xwing_keygen_us={:.2}", micros(keygen));
    println!("xwing_encap_us={:.2}", micros(encap));
    println!("xwing_decap_us={:.2}", micros(decap));
    println!("performance_profile={}", budget.profile);
    println!("hybrid_sign_budget_us={:.2}", micros(budget.sign));
    println!("hybrid_verify_budget_us={:.2}", micros(budget.verify));

    if sign > budget.sign {
        return Err(failure("hybrid signing exceeds the selected native budget").into());
    }
    if verify > budget.verify {
        return Err(failure("hybrid verification exceeds the selected native budget").into());
    }
    Ok(())
}

fn performance_budget() -> Result<PerformanceBudget, io::Error> {
    match env::var("COPYLOCKER_PERF_PROFILE") {
        Ok(profile) if profile == GITHUB_UBUNTU_24_04_BUDGET.profile => {
            Ok(GITHUB_UBUNTU_24_04_BUDGET)
        }
        Ok(profile) => Err(failure(&format!(
            "unknown COPYLOCKER_PERF_PROFILE: {profile}"
        ))),
        Err(VarError::NotPresent) => Ok(REFERENCE_BUDGET),
        Err(VarError::NotUnicode(_)) => Err(failure(
            "COPYLOCKER_PERF_PROFILE must contain valid Unicode",
        )),
    }
}

fn average(
    iterations: u32,
    mut operation: impl FnMut() -> Result<(), io::Error>,
) -> Result<Duration, io::Error> {
    let started = Instant::now();
    for _ in 0..iterations {
        operation()?;
    }
    Ok(started.elapsed() / iterations)
}

fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

fn failure(message: &str) -> io::Error {
    io::Error::other(message)
}
