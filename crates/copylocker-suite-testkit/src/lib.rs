//! Conformance harness for CopyLocker crypto suites.
//!
//! Every suite — the open CL-STD-1, the compact CL-CMP-1, and any closed-source private suite —
//! must pass this harness unchanged. That is what makes "swap one type alias to change suites"
//! a safe operation rather than a hopeful one (`crypto-architecture.md §9`).
//!
//! The harness deliberately contains more **negative** than positive tests. Confirming that a
//! signature verifies proves very little; confirming that a signature from a different domain,
//! a stripped hybrid component, a wrong AEAD nonce, and tampered AAD all *fail* is what
//! establishes the properties the protocol depends on.
//!
//! # Usage
//!
//! ```ignore
//! #[test]
//! fn my_suite_is_conformant() {
//!     copylocker_suite_testkit::assert_conformant::<MySuite>();
//! }
//! ```

#![forbid(unsafe_code)]
// Test helpers intentionally fail loudly; runtime crates retain the workspace panic-path denies.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod kat;
mod protocol_kat;
pub mod report;

use alloc::vec::Vec;
extern crate alloc;

use copylocker_suite::{
    device::{AttrValue, DeviceAttrs, FingerprintScheme},
    AeadScheme, CryptoError, CryptoRng, CryptoSuite, DeviceBinder, DomainCtx, EnvEvidence,
    HashScheme, KeyDerivation, KeyEncapsulation, SignatureScheme, VendorParams,
};
use copylocker_types::{ArtifactKind, Digest, Fingerprint};

pub use report::{Check, ConformanceReport};

/// A deterministic RNG for conformance runs.
///
/// Seeded on purpose: a failing conformance run must be reproducible. This type lives in a
/// test-only crate and is never linked into a production binary
/// (`crypto-architecture.md §7`).
pub struct TestRng(rand_chacha::ChaCha20Rng);

impl TestRng {
    /// Create a seeded generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        use rand_core::SeedableRng;
        Self(rand_chacha::ChaCha20Rng::seed_from_u64(seed))
    }
}

impl CryptoRng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use rand_core::Rng;
        self.0.fill_bytes(dest);
    }
}

impl core::fmt::Debug for TestRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TestRng")
    }
}

/// Run the full conformance suite, returning a report.
///
/// Prefer [`assert_conformant`] in tests; this form is for tooling that wants the detail.
#[must_use]
pub fn run<S: CryptoSuite>() -> ConformanceReport {
    let mut r = ConformanceReport::new(S::NAME, S::SUITE_ID);
    signature_checks::<S>(&mut r);
    kem_checks::<S>(&mut r);
    aead_checks::<S>(&mut r);
    kdf_checks::<S>(&mut r);
    hash_checks::<S>(&mut r);
    fingerprint_checks::<S>(&mut r);
    binder_checks::<S>(&mut r);
    r
}

/// Run the conformance suite and panic with a readable summary if anything failed.
///
/// # Panics
///
/// Panics when any check fails. This is a test helper; failing loudly is the point.
#[allow(clippy::panic)]
pub fn assert_conformant<S: CryptoSuite>() {
    let report = run::<S>();
    if !report.passed() {
        panic!("{}", report.summary());
    }
}

fn ctx(kind: ArtifactKind, suite: copylocker_types::SuiteId) -> DomainCtx<'static> {
    DomainCtx::new(kind, suite, "conformance-product")
}

fn signature_checks<S: CryptoSuite>(r: &mut ConformanceReport) {
    type Sig<S> = <S as CryptoSuite>::Sig;
    let mut rng = TestRng::new(0xC0FFEE);
    let (sk, vk) = Sig::<S>::generate(&mut rng);
    let msg = b"conformance message";
    let base_ctx = ctx(ArtifactKind::MachineCred, S::SUITE_ID);

    let Ok(sig) = Sig::<S>::sign(&sk, base_ctx, msg) else {
        r.fail("sig.sign", "signing failed outright");
        return;
    };

    r.check(
        "sig.verify",
        "a signature verifies under the key and context that made it",
        Sig::<S>::verify(&vk, base_ctx, msg, &sig).is_ok(),
    );

    r.check(
        "sig.deterministic",
        "signing is deterministic, so KAT vectors are reproducible",
        Sig::<S>::sign(&sk, base_ctx, msg).ok().as_ref() == Some(&sig),
    );

    r.check(
        "sig.length_bound",
        "the produced signature respects the declared SIG_MAX_LEN",
        sig.len() <= Sig::<S>::SIG_MAX_LEN,
    );

    // Cross-domain replay: the central domain-separation property. A signature made for one
    // artifact kind must not verify as any other kind.
    let mut cross_domain_ok = true;
    for kind in ArtifactKind::ALL {
        if kind == ArtifactKind::MachineCred {
            continue;
        }
        if Sig::<S>::verify(&vk, ctx(kind, S::SUITE_ID), msg, &sig).is_ok() {
            cross_domain_ok = false;
        }
    }
    r.check(
        "sig.cross_domain_replay_fails",
        "a signature for one artifact kind verifies under no other kind",
        cross_domain_ok,
    );

    r.check(
        "sig.cross_product_replay_fails",
        "a signature bound to one product does not verify for another",
        Sig::<S>::verify(
            &vk,
            DomainCtx::new(ArtifactKind::MachineCred, S::SUITE_ID, "other-product"),
            msg,
            &sig,
        )
        .is_err(),
    );

    r.check(
        "sig.cross_suite_replay_fails",
        "a signature bound to one suite does not verify under another suite id",
        Sig::<S>::verify(
            &vk,
            DomainCtx::new(
                ArtifactKind::MachineCred,
                copylocker_types::SuiteId::from_u32(0xDEAD_BEEF),
                "conformance-product",
            ),
            msg,
            &sig,
        )
        .is_err(),
    );

    r.check(
        "sig.wrong_message_fails",
        "a signature does not verify over a different message",
        Sig::<S>::verify(&vk, base_ctx, b"other message", &sig).is_err(),
    );

    let (_, other_vk) = Sig::<S>::generate(&mut rng);
    r.check(
        "sig.wrong_key_fails",
        "a signature does not verify under an unrelated key",
        Sig::<S>::verify(&other_vk, base_ctx, msg, &sig).is_err(),
    );

    // Bit-flip resistance across the whole signature blob.
    let mut all_flips_rejected = true;
    for i in 0..sig.len() {
        let mut bad = sig.clone();
        // Both indices are within `sig.len()`.
        #[allow(clippy::indexing_slicing)]
        {
            bad.0[i] ^= 0x01;
        }
        if Sig::<S>::verify(&vk, base_ctx, msg, &bad).is_ok() {
            all_flips_rejected = false;
        }
    }
    r.check(
        "sig.bitflip_rejected",
        "flipping any single bit of a signature invalidates it",
        all_flips_rejected,
    );

    r.check(
        "sig.truncation_rejected",
        "a truncated signature is rejected rather than parsed leniently",
        (0..sig.len()).all(|c| {
            sig.as_bytes().get(..c).is_some_and(|prefix| {
                Sig::<S>::verify(&vk, base_ctx, msg, &prefix.to_vec().into()).is_err()
            })
        }),
    );

    r.check(
        "sig.trailing_bytes_rejected",
        "appending bytes to a signature invalidates it",
        {
            let mut padded = sig.as_bytes().to_vec();
            padded.push(0);
            Sig::<S>::verify(&vk, base_ctx, msg, &padded.into()).is_err()
        },
    );

    // Hybrid schemes must never accept a single component. A suite that reports itself as
    // post-quantum is expected to be hybrid and therefore to expose strip detection.
    if Sig::<S>::is_post_quantum() {
        let mut saw_strip_signal = false;
        let mut any_single_component_accepted = false;
        for i in 0..sig.len() {
            let mut bad = sig.clone();
            #[allow(clippy::indexing_slicing)]
            {
                bad.0[i] ^= 0xff;
            }
            match Sig::<S>::verify(&vk, base_ctx, msg, &bad) {
                Ok(()) => any_single_component_accepted = true,
                Err(CryptoError::HybridStripDetected) => saw_strip_signal = true,
                Err(_) => {}
            }
        }
        r.check(
            "sig.hybrid_no_single_component",
            "no corruption of one hybrid component yields an overall success",
            !any_single_component_accepted,
        );
        r.check(
            "sig.hybrid_strip_detected",
            "corrupting exactly one hybrid component reports HybridStripDetected",
            saw_strip_signal,
        );
    }

    // Key encoding.
    let vk_bytes = Sig::<S>::encode_vk(&vk);
    r.check(
        "sig.vk_len",
        "the encoded verifying key matches the declared VK_LEN",
        vk_bytes.len() == Sig::<S>::VK_LEN,
    );
    r.check(
        "sig.vk_roundtrip",
        "verifying keys survive an encode/decode roundtrip",
        Sig::<S>::decode_vk(&vk_bytes).ok() == Some(vk.clone()),
    );
    r.check(
        "sig.vk_wrong_length_rejected",
        "a verifying key of the wrong length is rejected",
        vk_bytes
            .get(..vk_bytes.len().saturating_sub(1))
            .is_some_and(|short| Sig::<S>::decode_vk(short).is_err()),
    );

    let sk_bytes = Sig::<S>::encode_sk(&sk);
    r.check(
        "sig.sk_len",
        "the encoded signing key matches the declared SK_LEN",
        sk_bytes.len() == Sig::<S>::SK_LEN,
    );
    r.check(
        "sig.sk_roundtrip",
        "a decoded signing key produces the same signatures",
        Sig::<S>::decode_sk(&sk_bytes)
            .ok()
            .and_then(|sk2| Sig::<S>::sign(&sk2, base_ctx, msg).ok())
            .as_ref()
            == Some(&sig),
    );
    r.check(
        "sig.vk_derivation_matches",
        "deriving the verifying key from the signing key reproduces it",
        Sig::<S>::verifying_key(&sk) == vk,
    );
}

fn kem_checks<S: CryptoSuite>(r: &mut ConformanceReport) {
    type Kem<S> = <S as CryptoSuite>::Kem;
    let mut rng = TestRng::new(0xBEEF);
    let (dk, ek) = Kem::<S>::keygen(&mut rng);

    let Ok((ct, ss_sender)) = Kem::<S>::encap(&ek, &mut rng) else {
        r.fail("kem.encap", "encapsulation failed outright");
        return;
    };
    let Ok(ss_receiver) = Kem::<S>::decap(&dk, &ct) else {
        r.fail("kem.decap", "decapsulation failed outright");
        return;
    };

    r.check(
        "kem.agreement",
        "encapsulation and decapsulation agree on the shared secret",
        ss_sender.expose() == ss_receiver.expose(),
    );
    r.check(
        "kem.ct_len",
        "the ciphertext matches the declared CT_LEN",
        ct.as_bytes().len() == Kem::<S>::CT_LEN,
    );
    r.check(
        "kem.ek_len",
        "the encoded encapsulation key matches the declared EK_LEN",
        Kem::<S>::encode_ek(&ek).len() == Kem::<S>::EK_LEN,
    );
    r.check(
        "kem.dk_len",
        "the encoded decapsulation key matches the declared DK_LEN",
        Kem::<S>::encode_dk(&dk).len() == Kem::<S>::DK_LEN,
    );
    r.check(
        "kem.ek_roundtrip",
        "encapsulation keys survive an encode/decode roundtrip",
        Kem::<S>::decode_ek(&Kem::<S>::encode_ek(&ek)).ok() == Some(ek.clone()),
    );
    r.check(
        "kem.dk_roundtrip",
        "a decoded decapsulation key recovers the same secret",
        Kem::<S>::decode_dk(&Kem::<S>::encode_dk(&dk))
            .ok()
            .and_then(|dk2| Kem::<S>::decap(&dk2, &ct).ok())
            .map(|s| *s.expose())
            == Some(*ss_receiver.expose()),
    );
    r.check(
        "kem.encap_key_derivation",
        "deriving the encapsulation key from the private key reproduces it",
        Kem::<S>::encap_key(&dk) == ek,
    );

    // The machine-binding property: another device's key must not recover the secret.
    let (other_dk, _) = Kem::<S>::keygen(&mut rng);
    let other = Kem::<S>::decap(&other_dk, &ct).ok().map(|s| *s.expose());
    r.check(
        "kem.wrong_key_yields_different_secret",
        "a different decapsulation key does not recover the shared secret",
        other != Some(*ss_sender.expose()),
    );

    // ML-KEM-family KEMs reject implicitly, so a tampered ciphertext yields a *different*
    // secret rather than an error. Either behaviour is acceptable; silently returning the
    // *same* secret is not.
    let mut tampered = ct.as_bytes().to_vec();
    if let Some(b) = tampered.first_mut() {
        *b ^= 0x01;
    }
    let tampered_ss = Kem::<S>::decap(&dk, &tampered.into())
        .ok()
        .map(|s| *s.expose());
    r.check(
        "kem.tampered_ciphertext",
        "a tampered ciphertext never yields the original shared secret",
        tampered_ss != Some(*ss_sender.expose()),
    );

    let (ct2, ss2) = match Kem::<S>::encap(&ek, &mut rng) {
        Ok(v) => v,
        Err(_) => {
            r.fail("kem.encap_twice", "second encapsulation failed");
            return;
        }
    };
    r.check(
        "kem.fresh_randomness",
        "two encapsulations to one key differ in both ciphertext and secret",
        ct2.as_bytes() != ct.as_bytes() && ss2.expose() != ss_sender.expose(),
    );

    r.check(
        "kem.short_ciphertext_rejected",
        "a truncated ciphertext is rejected on length",
        Kem::<S>::decap(&dk, &alloc::vec![0u8; 4].into()).is_err(),
    );
}

fn aead_checks<S: CryptoSuite>(r: &mut ConformanceReport) {
    type Aead<S> = <S as CryptoSuite>::Aead;
    let mut rng = TestRng::new(0xFACE);
    let key = alloc::vec![0x11u8; Aead::<S>::KEY_LEN];
    let nonce = alloc::vec![0x22u8; Aead::<S>::NONCE_LEN];
    let pt = b"plaintext payload";

    let Ok(ct) = Aead::<S>::seal(&key, &nonce, b"aad", pt) else {
        r.fail("aead.seal", "sealing failed outright");
        return;
    };

    r.check(
        "aead.roundtrip",
        "sealing then opening recovers the plaintext",
        Aead::<S>::open(&key, &nonce, b"aad", &ct).as_deref() == Ok(pt.as_slice()),
    );
    r.check(
        "aead.tag_overhead",
        "the ciphertext grows by exactly the declared tag length",
        ct.len() == pt.len() + Aead::<S>::TAG_LEN,
    );
    r.check(
        "aead.wrong_aad_fails",
        "opening with different associated data fails",
        Aead::<S>::open(&key, &nonce, b"other", &ct).is_err(),
    );
    r.check(
        "aead.wrong_key_fails",
        "opening with a different key fails",
        Aead::<S>::open(
            &alloc::vec![0x12u8; Aead::<S>::KEY_LEN],
            &nonce,
            b"aad",
            &ct,
        )
        .is_err(),
    );
    r.check(
        "aead.wrong_nonce_fails",
        "opening with a different nonce fails",
        Aead::<S>::open(
            &key,
            &alloc::vec![0x23u8; Aead::<S>::NONCE_LEN],
            b"aad",
            &ct,
        )
        .is_err(),
    );
    r.check(
        "aead.bitflip_rejected",
        "flipping any single bit of the ciphertext or tag fails authentication",
        (0..ct.len()).all(|i| {
            let mut bad = ct.clone();
            #[allow(clippy::indexing_slicing)]
            {
                bad[i] ^= 0x01;
            }
            Aead::<S>::open(&key, &nonce, b"aad", &bad).is_err()
        }),
    );
    r.check(
        "aead.short_input_rejected",
        "input shorter than the tag is rejected on length",
        Aead::<S>::open(&key, &nonce, b"aad", &[0u8; 1]).is_err(),
    );
    r.check(
        "aead.bad_key_length_rejected",
        "a key of the wrong length is rejected rather than padded",
        Aead::<S>::seal(&alloc::vec![0u8; Aead::<S>::KEY_LEN - 1], &nonce, b"", b"").is_err(),
    );

    if Aead::<S>::RANDOM_NONCE_SAFE {
        r.check(
            "aead.random_nonce_width",
            "a scheme claiming random-nonce safety uses at least a 192-bit nonce",
            Aead::<S>::NONCE_LEN >= 24,
        );
        let a = Aead::<S>::seal_with_nonce(&key, b"aad", pt, &mut rng);
        let b = Aead::<S>::seal_with_nonce(&key, b"aad", pt, &mut rng);
        r.check(
            "aead.nonce_freshness",
            "each seal draws a fresh nonce, so identical plaintexts differ",
            matches!((&a, &b), (Ok(x), Ok(y)) if x != y),
        );
        r.check(
            "aead.nonce_prefixed_roundtrip",
            "the nonce-prefixed helper roundtrips",
            a.ok()
                .and_then(|blob| Aead::<S>::open_with_nonce(&key, b"aad", &blob).ok())
                .as_deref()
                == Some(pt.as_slice()),
        );
    }
}

fn kdf_checks<S: CryptoSuite>(r: &mut ConformanceReport) {
    type Kdf<S> = <S as CryptoSuite>::Kdf;

    let base = Kdf::<S>::derive_from(b"salt", b"ikm", &[b"info"]);
    let same = Kdf::<S>::derive_from(b"salt", b"ikm", &[b"info"]);
    let (Ok(base), Ok(same)) = (base, same) else {
        r.fail("kdf.derive", "derivation failed outright");
        return;
    };

    r.check(
        "kdf.deterministic",
        "the same salt, key material, and info derive the same key",
        base.ct_eq(&same),
    );

    let variants = [
        ("salt", Kdf::<S>::derive_from(b"salt2", b"ikm", &[b"info"])),
        ("ikm", Kdf::<S>::derive_from(b"salt", b"ikm2", &[b"info"])),
        ("info", Kdf::<S>::derive_from(b"salt", b"ikm", &[b"info2"])),
    ];
    for (what, other) in variants {
        r.check_named(
            "kdf.input_separation",
            what,
            "changing any input changes the derived key",
            other.map(|o| !base.ct_eq(&o)).unwrap_or(false),
        );
    }

    let prk = Kdf::<S>::extract(b"s", b"i");
    let ab_c = Kdf::<S>::derive_key(&prk, &[b"ab", b"c"]);
    let a_bc = Kdf::<S>::derive_key(&prk, &[b"a", b"bc"]);
    r.check(
        "kdf.multipart_unambiguous",
        "multi-part info is length-prefixed, so ['ab','c'] and ['a','bc'] differ",
        matches!((ab_c, a_bc), (Ok(x), Ok(y)) if !x.ct_eq(&y)),
    );

    let mut oversized = alloc::vec![0u8; 64 * 1024];
    r.check(
        "kdf.output_limit_enforced",
        "an over-long expansion is refused rather than silently truncated",
        Kdf::<S>::expand(&prk, b"", &mut oversized).is_err(),
    );

    let mut s1 = [0u8; 32];
    let mut s2 = [0u8; 32];
    let mut s3 = [0u8; 32];
    let stretch_ok = Kdf::<S>::stretch(b"saltsalt", b"weak", &mut s1).is_ok()
        && Kdf::<S>::stretch(b"saltsalt", b"weak", &mut s2).is_ok()
        && Kdf::<S>::stretch(b"saltsalu", b"weak", &mut s3).is_ok();
    r.check(
        "kdf.stretch_deterministic_and_salted",
        "low-entropy stretching is deterministic and salt-separated",
        stretch_ok && s1 == s2 && s1 != s3,
    );
}

fn hash_checks<S: CryptoSuite>(r: &mut ConformanceReport) {
    type Hash<S> = <S as CryptoSuite>::Hash;
    use copylocker_suite::StreamingHash;

    let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let one_shot = Hash::<S>::hash(&data);

    let mut h = Hash::<S>::hasher();
    for chunk in data.chunks(7) {
        h.update(chunk);
    }
    r.check(
        "hash.streaming_matches_oneshot",
        "streaming and one-shot hashing agree",
        h.finalize() == one_shot,
    );
    r.check(
        "hash.out_len",
        "the digest matches the declared OUT_LEN",
        Hash::<S>::OUT_LEN == 32,
    );
    r.check(
        "hash.distinct_inputs_differ",
        "different inputs hash differently",
        Hash::<S>::hash(b"a") != Hash::<S>::hash(b"b"),
    );
    r.check(
        "hash.parts_unambiguous",
        "length-prefixed parts distinguish ['ab','c'] from ['a','bc']",
        Hash::<S>::hash_parts(&[b"ab", b"c"]) != Hash::<S>::hash_parts(&[b"a", b"bc"]),
    );
}

fn fingerprint_checks<S: CryptoSuite>(r: &mut ConformanceReport) {
    type Fpr<S> = <S as CryptoSuite>::Fpr;

    let mut a = DeviceAttrs::new();
    a.insert("machine_guid", AttrValue::text("A1B2"));
    a.insert("cpu_id", AttrValue::text("CPU-1"));
    a.insert("mac_addrs", AttrValue::set(["aa:bb", "cc:dd"]));

    // Same content, different insertion order, different letter case.
    let mut a_reordered = DeviceAttrs::new();
    a_reordered.insert("mac_addrs", AttrValue::set(["CC:DD", "AA:BB"]));
    a_reordered.insert("cpu_id", AttrValue::text("  cpu-1  "));
    a_reordered.insert("machine_guid", AttrValue::text("a1b2"));

    r.check(
        "fpr.normalisation_canonical",
        "normalisation makes ordering and case irrelevant to the digest",
        Fpr::<S>::compute(b"salt", &a) == Fpr::<S>::compute(b"salt", &a_reordered),
    );
    r.check(
        "fpr.deterministic",
        "the same attributes and salt always produce the same digest",
        Fpr::<S>::compute(b"salt", &a) == Fpr::<S>::compute(b"salt", &a),
    );
    r.check(
        "fpr.salt_separates_vendors",
        "a different vendor salt produces a different digest",
        Fpr::<S>::compute(b"salt", &a) != Fpr::<S>::compute(b"other-salt", &a),
    );

    let mut changed = a.clone();
    changed.insert("cpu_id", AttrValue::text("CPU-2"));
    r.check(
        "fpr.sensitive_to_changes",
        "changing any attribute changes the digest",
        Fpr::<S>::compute(b"salt", &a) != Fpr::<S>::compute(b"salt", &changed),
    );

    let mut with_absent = a.clone();
    with_absent.insert("board_serial", AttrValue::Absent);
    r.check(
        "fpr.absent_is_not_omitted",
        "an explicitly absent attribute differs from an omitted one",
        Fpr::<S>::compute(b"salt", &a) != Fpr::<S>::compute(b"salt", &with_absent),
    );

    r.check(
        "fpr.identical_scores_100",
        "identical attribute sets score 100",
        Fpr::<S>::similarity(&a, &a) == 100,
    );
    r.check(
        "fpr.empty_scores_zero",
        "with nothing comparable the score is 0, so callers fail closed",
        Fpr::<S>::similarity(&DeviceAttrs::new(), &DeviceAttrs::new()) == 0,
    );
    r.check(
        "fpr.tolerates_minor_drift",
        "a single low-weight attribute change stays above the default tolerance of 70",
        {
            let mut drifted = a.clone();
            drifted.insert("mac_addrs", AttrValue::set(["ee:ff"]));
            Fpr::<S>::similarity(&a, &drifted) >= 70
        },
    );
    r.check(
        "fpr.rejects_different_machine",
        "a wholly different machine scores below the default tolerance",
        {
            let mut other = DeviceAttrs::new();
            other.insert("machine_guid", AttrValue::text("ZZZZ"));
            other.insert("cpu_id", AttrValue::text("CPU-9"));
            other.insert("mac_addrs", AttrValue::set(["99:99"]));
            Fpr::<S>::similarity(&a, &other) < 70
        },
    );
    r.check(
        "fpr.weights_published",
        "the weight table is exposed for documentation and audit",
        !Fpr::<S>::weights().is_empty(),
    );
}

fn binder_checks<S: CryptoSuite>(r: &mut ConformanceReport) {
    type Kem<S> = <S as CryptoSuite>::Kem;
    type Binder<S> = <S as CryptoSuite>::Binder;

    let mut rng = TestRng::new(0xB1_4D);
    let (dk, ek) = Kem::<S>::keygen(&mut rng);
    let Ok((ct, _)) = Kem::<S>::encap(&ek, &mut rng) else {
        r.fail("binder.setup", "encapsulation failed");
        return;
    };
    let Ok(ss) = Kem::<S>::decap(&dk, &ct) else {
        r.fail("binder.setup", "decapsulation failed");
        return;
    };

    let fp_a = Fingerprint::from_vec(alloc::vec![1; 32]);
    let fp_b = Fingerprint::from_vec(alloc::vec![2; 32]);
    let env_a = EnvEvidence {
        module_digest: Digest([3; 32]),
        build_fingerprint: b"build-a".to_vec(),
        extra: Vec::new(),
    };
    let env_b = EnvEvidence {
        module_digest: Digest([4; 32]),
        build_fingerprint: b"build-a".to_vec(),
        extra: Vec::new(),
    };

    let (Ok(base), Ok(same)) = (
        Binder::<S>::bind(&ss, &fp_a, &env_a),
        Binder::<S>::bind(&ss, &fp_a, &env_a),
    ) else {
        r.fail("binder.bind", "binding failed outright");
        return;
    };

    r.check(
        "binder.deterministic",
        "binding the same inputs yields the same bound secret",
        base.expose() == same.expose(),
    );
    r.check(
        "binder.fingerprint_bound",
        "a different fingerprint yields a different bound secret",
        Binder::<S>::bind(&ss, &fp_b, &env_a)
            .map(|o| o.expose() != base.expose())
            .unwrap_or(false),
    );
    r.check(
        "binder.environment_bound",
        "a different module digest yields a different bound secret",
        Binder::<S>::bind(&ss, &fp_a, &env_b)
            .map(|o| o.expose() != base.expose())
            .unwrap_or(false),
    );
}

/// Check that a suite declares itself consistently.
///
/// Separate from [`run`] because it needs no cryptographic work and is worth asserting even in
/// a build where the heavier checks are skipped.
#[must_use]
pub fn declaration_report<S: CryptoSuite>() -> ConformanceReport {
    let mut r = ConformanceReport::new(S::NAME, S::SUITE_ID);
    r.check(
        "decl.proto_ver",
        "the suite speaks a protocol version this build understands",
        S::PROTO_VER == copylocker_types::PROTO_VER,
    );
    r.check(
        "decl.name_nonempty",
        "the suite has a human-readable name",
        !S::NAME.is_empty(),
    );
    r.check(
        "decl.suite_id_nonzero",
        "the suite id is not the all-zero placeholder",
        S::SUITE_ID.to_u32() != 0,
    );
    let params = VendorParams::from_salt(alloc::vec![1, 2, 3]);
    let inst = S::with_vendor_params(&params);
    r.check(
        "decl.vendor_params_carried",
        "vendor parameters are retained by the instantiated suite",
        inst.vendor_params().fpr_salt == alloc::vec![1, 2, 3],
    );
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_suite_std::ClStd1;

    #[test]
    fn cl_std_1_is_conformant() {
        assert_conformant::<ClStd1>();
    }

    #[test]
    fn cl_std_1_declares_itself_consistently() {
        let r = declaration_report::<ClStd1>();
        assert!(r.passed(), "{}", r.summary());
    }

    #[test]
    fn the_harness_runs_a_meaningful_number_of_checks() {
        // Guards against a refactor that silently drops whole sections.
        let r = run::<ClStd1>();
        assert!(r.total() >= 45, "only {} checks ran", r.total());
    }
}
