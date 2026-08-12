//! E2E release-material seeder for `packages/web-e2e`.
//!
//! The M1 Admin API has no release-management endpoints (they are post-M1),
//! so the local Wrangler backend used by the Playwright suite needs its
//! `releases.variant_params` and `release_feature_keks.encrypted_kek` blobs
//! produced out of band. This helper encrypts them exactly the way
//! `crates/copylocker-worker/src/bindings/authorization.rs` expects:
//! XChaCha20-Poly1305 (`ClStd1` AEAD slot, `nonce ‖ ciphertext ‖ tag`) with
//! the documented at-rest AAD maps.
//!
//! Output is a JSON object on stdout:
//! `{ "variant_params_hex": "…", "feature_keks": { "<feature>": { "key_version": 1,
//!   "blob_hex": "…", "key_hex": "…" } } }`
//!
//! Local test fixture generator only; never used against a real deployment.

use std::env;
use std::process::ExitCode;

use copylocker_suite::cbor::{CborValue, MapBuilder};
use copylocker_suite::{AeadScheme, CryptoRng, CryptoSuite};
use copylocker_suite_std::ClStd1;

const VARIANT_PARAMS_SCHEMA_VERSION: u64 = 1;
const VARIANT_AT_REST_LABEL: &str = "copylocker/variant-at-rest/v1";
const ASSET_KEK_AT_REST_LABEL: &str = "copylocker/asset-kek-at-rest/v1";

struct OsRng;

impl CryptoRng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("operating system CSPRNG failed");
    }
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid hex value `{value}`"));
    }
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ascii hex"), 16)
                .expect("validated hex digit")
        })
        .collect())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

struct Args {
    product: String,
    release: String,
    variant_id: u64,
    build_fingerprint: String,
    variant_key: Vec<u8>,
    asset_key: Vec<u8>,
    variant_const: Vec<u8>,
    module_digest: Vec<u8>,
    features: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        product: String::new(),
        release: String::new(),
        variant_id: 0,
        build_fingerprint: String::new(),
        variant_key: Vec::new(),
        asset_key: Vec::new(),
        variant_const: vec![0u8; 32],
        module_digest: vec![0u8; 32],
        features: Vec::new(),
    };
    let mut iter = env::args().skip(1);
    let next_value = |flag: &str, iter: &mut dyn Iterator<Item = String>| {
        iter.next().ok_or_else(|| format!("{flag} requires a value"))
    };
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--product" => args.product = next_value("--product", &mut iter)?,
            "--release" => args.release = next_value("--release", &mut iter)?,
            "--variant-id" => {
                args.variant_id = next_value("--variant-id", &mut iter)?
                    .parse()
                    .map_err(|_| "--variant-id must be a non-negative integer".to_owned())?
            }
            "--build-fingerprint" => {
                args.build_fingerprint = next_value("--build-fingerprint", &mut iter)?
            }
            "--variant-key-hex" => {
                args.variant_key = hex_decode(&next_value("--variant-key-hex", &mut iter)?)?
            }
            "--asset-key-hex" => {
                args.asset_key = hex_decode(&next_value("--asset-key-hex", &mut iter)?)?
            }
            "--variant-const-hex" => {
                args.variant_const = hex_decode(&next_value("--variant-const-hex", &mut iter)?)?
            }
            "--module-digest-hex" => {
                args.module_digest = hex_decode(&next_value("--module-digest-hex", &mut iter)?)?
            }
            "--feature" => args.features.push(next_value("--feature", &mut iter)?),
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    if args.product.is_empty()
        || args.release.is_empty()
        || args.build_fingerprint.is_empty()
        || args.features.is_empty()
    {
        return Err(
            "--product, --release, --build-fingerprint and at least one --feature are required"
                .to_owned(),
        );
    }
    for (name, key) in [("--variant-key-hex", &args.variant_key), ("--asset-key-hex", &args.asset_key)] {
        if key.len() != 32 {
            return Err(format!("{name} must decode to exactly 32 bytes"));
        }
    }
    if args.variant_const.len() != 32 || args.module_digest.len() != 32 {
        return Err("variant constant and module digest must be 32 bytes".to_owned());
    }
    Ok(args)
}

fn variant_at_rest_aad(args: &Args) -> Vec<u8> {
    let mut builder = MapBuilder::new();
    builder.put(0, CborValue::Text(VARIANT_AT_REST_LABEL.to_owned()));
    builder.put(1, CborValue::Text(args.release.clone()));
    builder.put(2, CborValue::Text(args.product.clone()));
    builder.put(3, CborValue::Uint(args.variant_id));
    builder.put(4, CborValue::Text(args.build_fingerprint.clone()));
    builder.put(5, CborValue::Bytes(ClStd1::SUITE_ID.as_bytes().to_vec()));
    builder.finish()
}

fn asset_kek_at_rest_aad(args: &Args, feature_id: &str, key_version: u64) -> Vec<u8> {
    let mut builder = MapBuilder::new();
    builder.put(0, CborValue::Text(ASSET_KEK_AT_REST_LABEL.to_owned()));
    builder.put(1, CborValue::Text(args.release.clone()));
    builder.put(2, CborValue::Text(args.product.clone()));
    builder.put(3, CborValue::Text(feature_id.to_owned()));
    builder.put(4, CborValue::Uint(key_version));
    builder.finish()
}

fn run() -> Result<String, String> {
    let args = parse_args()?;
    let mut rng = OsRng;

    // Mirror `parse_variant_params` in the worker: {0: schema, 1: variant_id,
    // 2: variant_const(32), 3: module_digest(32), 4: [binder_extra…]}.
    let mut params = MapBuilder::new();
    params.put(0, CborValue::Uint(VARIANT_PARAMS_SCHEMA_VERSION));
    params.put(1, CborValue::Uint(args.variant_id));
    params.put(2, CborValue::Bytes(args.variant_const.clone()));
    params.put(3, CborValue::Bytes(args.module_digest.clone()));
    params.put(4, CborValue::Array(Vec::new()));
    let params_plaintext = params.finish();

    let variant_blob = <ClStd1 as CryptoSuite>::Aead::seal_with_nonce(
        &args.variant_key,
        &variant_at_rest_aad(&args),
        &params_plaintext,
        &mut rng,
    )
    .map_err(|_| "failed to seal variant parameters".to_owned())?;

    let mut keks_json = String::new();
    for (index, feature) in args.features.iter().enumerate() {
        let mut kek = [0u8; 32];
        rng.fill_bytes(&mut kek);
        let blob = <ClStd1 as CryptoSuite>::Aead::seal_with_nonce(
            &args.asset_key,
            &asset_kek_at_rest_aad(&args, feature, 1),
            &kek,
            &mut rng,
        )
        .map_err(|_| "failed to seal asset KEK".to_owned())?;
        if index > 0 {
            keks_json.push(',');
        }
        keks_json.push_str(&format!(
            "\"{}\":{{\"key_version\":1,\"blob_hex\":\"{}\",\"key_hex\":\"{}\"}}",
            json_escape(feature),
            hex_encode(&blob),
            hex_encode(&kek),
        ));
    }

    Ok(format!(
        "{{\"variant_params_hex\":\"{}\",\"feature_keks\":{{{keks_json}}}}}",
        hex_encode(&variant_blob),
    ))
}

fn main() -> ExitCode {
    match run() {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("seed-helper: {message}");
            ExitCode::FAILURE
        }
    }
}
