use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use copylocker_proto::{Envelope, EpochCert};
use copylocker_suite::{CryptoRng, HashScheme, SignatureScheme};
use copylocker_suite_std::{FastSig, FromRandCore, HybridSig, Sha256Scheme, CL_STD_1_SUITE_ID};
use copylocker_types::{EpochId, PROTO_VER};
use rand_core::SeedableRng as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroize as _;

use crate::{pretty_json_bytes, write_output_file, CliError, Output};

const SUITE_NAME: &str = "CL-STD-1";

#[derive(Debug, Args)]
pub(crate) struct KeygenArgs {
    #[command(subcommand)]
    command: KeygenCommand,
}

#[derive(Debug, Subcommand)]
enum KeygenCommand {
    /// Generate current and next offline root key pairs.
    Root(RootArgs),
    /// Generate an epoch pair, fast key, and root-signed EpochCert.
    Epoch(EpochArgs),
    /// Generate a dedicated build-manifest signing pair.
    Build(BuildArgs),
}

#[derive(Debug, Args)]
struct RootArgs {
    /// Directory receiving two public files and two mode-0600 secret files.
    #[arg(long)]
    out_dir: PathBuf,
    /// Crypto suite. Only CL-STD-1 is available in the public build.
    #[arg(long, default_value = SUITE_NAME)]
    suite: String,
    /// Confirm the host is physically offline and the key ceremony prerequisites are met.
    #[arg(long)]
    offline_confirm: bool,
}

#[derive(Debug, Args)]
struct EpochArgs {
    /// Mode-0600 root secret JSON created by `keygen root`.
    #[arg(long)]
    root_key: PathBuf,
    /// Product scope covered by the certificate.
    #[arg(long)]
    product: String,
    /// Inclusive Unix start timestamp.
    #[arg(long)]
    not_before: i64,
    /// Exclusive Unix end timestamp.
    #[arg(long)]
    not_after: i64,
    /// Optional 8-byte lowercase/uppercase hexadecimal epoch ID. Random by default.
    #[arg(long)]
    epoch_id: Option<String>,
    /// Directory receiving certificate, public metadata, and two mode-0600 Worker secrets.
    #[arg(long)]
    out_dir: PathBuf,
}

#[derive(Debug, Args)]
struct BuildArgs {
    /// Prefix for `<prefix>.public.json` and `<prefix>.secret.json`.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct KeySecretFile {
    schema_version: u8,
    kind: String,
    suite_id: Vec<u8>,
    signing_key: Vec<u8>,
}

#[derive(Serialize)]
struct WorkerSecretFile {
    schema_version: u8,
    epoch_id: Vec<u8>,
    suite_id: Vec<u8>,
    signing_key: Vec<u8>,
}

#[derive(Serialize)]
struct PublicKeyFile<'a> {
    schema_version: u8,
    kind: &'a str,
    suite: &'a str,
    suite_id: Vec<u8>,
    verifying_key_hex: String,
    fingerprint_hex: String,
    created_at: i64,
}

pub(crate) fn run(args: &KeygenArgs) -> Result<Output, CliError> {
    match &args.command {
        KeygenCommand::Root(args) => generate_roots(args),
        KeygenCommand::Epoch(args) => generate_epoch(args),
        KeygenCommand::Build(args) => generate_build(args),
    }
}

fn generate_roots(args: &RootArgs) -> Result<Output, CliError> {
    require_suite(&args.suite)?;
    if !args.offline_confirm {
        return Err(CliError::new(
            "offline_confirmation_required",
            "root generation requires --offline-confirm after physically disconnecting the host and preparing the key ceremony",
        ));
    }
    let outputs = [
        args.out_dir.join("cl-root.public.json"),
        args.out_dir.join("cl-root.secret.json"),
        args.out_dir.join("cl-root-next.public.json"),
        args.out_dir.join("cl-root-next.secret.json"),
    ];
    ensure_outputs_absent(&outputs)?;

    let mut rng = system_rng()?;
    let created_at = now_seconds()?;
    let current = generate_hybrid_pair("root", created_at, &mut rng)?;
    let next = generate_hybrid_pair("root_next", created_at, &mut rng)?;
    write_key_pair(&outputs[0], &outputs[1], current)?;
    write_key_pair(&outputs[2], &outputs[3], next)?;

    Ok(Output {
        human: format!(
            "generated current and next CL-STD-1 roots in {}\nsecret files are mode 0600; move them into the documented offline custody workflow",
            args.out_dir.display()
        ),
        json: json!({
            "ok": true,
            "command": "keygen.root",
            "suite": SUITE_NAME,
            "created_at": created_at,
            "public_files": [&outputs[0], &outputs[2]],
            "secret_files": [&outputs[1], &outputs[3]],
            "secret_file_mode": "0600",
            "offline_confirmed": true
        }),
    })
}

fn generate_epoch(args: &EpochArgs) -> Result<Output, CliError> {
    if args.not_before < 0 || args.not_after <= args.not_before {
        return Err(CliError::new(
            "invalid_epoch_window",
            "epoch timestamps must satisfy 0 <= not_before < not_after",
        ));
    }
    validate_product(&args.product)?;
    let mut root_file = load_root_secret(&args.root_key)?;
    let root_signing_key = HybridSig::decode_sk(&root_file.signing_key).map_err(|_| {
        CliError::new(
            "invalid_root_key",
            format!(
                "{} contains an invalid root signing key",
                args.root_key.display()
            ),
        )
    })?;
    root_file.signing_key.zeroize();

    let mut rng = system_rng()?;
    let (epoch_signing_key, epoch_verifying_key) = HybridSig::generate(&mut rng);
    let (fast_signing_key, fast_verifying_key) = FastSig::generate(&mut rng);
    let epoch_id = match &args.epoch_id {
        Some(value) => parse_epoch_id(value)?,
        None => {
            let mut bytes = [0u8; EpochId::LEN];
            rng.fill_bytes(&mut bytes);
            EpochId(bytes)
        }
    };
    let root_verifying_key = HybridSig::verifying_key(&root_signing_key);
    let root_verifying_bytes = HybridSig::encode_vk(&root_verifying_key);
    let cert = EpochCert {
        proto_ver: PROTO_VER,
        suite_id: CL_STD_1_SUITE_ID,
        epoch_id,
        vk: HybridSig::encode_vk(&epoch_verifying_key),
        vk_fast: FastSig::encode_vk(&fast_verifying_key),
        not_before: args.not_before,
        not_after: args.not_after,
        product_scope: Some(args.product.clone()),
        issuer_vk_digest: Sha256Scheme::hash(&root_verifying_bytes),
    };
    let envelope = Envelope::seal::<HybridSig, _>(
        &cert,
        CL_STD_1_SUITE_ID,
        &args.product,
        None,
        &root_signing_key,
    )
    .map_err(|_| CliError::new("epoch_sign_failed", "failed to sign the epoch certificate"))?;

    let prefix = format!("epoch-{}", epoch_id.to_hex());
    let cert_path = args.out_dir.join(format!("{prefix}.cert.cbor"));
    let public_path = args.out_dir.join(format!("{prefix}.public.json"));
    let signing_path = args.out_dir.join(format!("{prefix}.signing.secret.json"));
    let fast_path = args
        .out_dir
        .join(format!("{prefix}.fast-signing.secret.json"));
    ensure_outputs_absent(&[
        cert_path.clone(),
        public_path.clone(),
        signing_path.clone(),
        fast_path.clone(),
    ])?;

    let public = json!({
        "schema_version": 1,
        "kind": "epoch",
        "suite": SUITE_NAME,
        "suite_id": CL_STD_1_SUITE_ID.as_bytes(),
        "epoch_id": epoch_id.as_bytes(),
        "epoch_id_hex": epoch_id.to_hex(),
        "product_scope": args.product,
        "not_before": args.not_before,
        "not_after": args.not_after,
        "verifying_key_hex": hex::encode(&cert.vk),
        "fast_verifying_key_hex": hex::encode(&cert.vk_fast),
        "issuer_fingerprint_hex": cert.issuer_vk_digest.to_hex()
    });
    write_output_file(&cert_path, &envelope.encode(), false)?;
    write_output_file(&public_path, &pretty_json_bytes(&public)?, false)?;

    let mut signing_secret = WorkerSecretFile {
        schema_version: 1,
        epoch_id: epoch_id.as_bytes().to_vec(),
        suite_id: CL_STD_1_SUITE_ID.as_bytes().to_vec(),
        signing_key: HybridSig::encode_sk(&epoch_signing_key),
    };
    write_serialized_secret(&signing_path, &signing_secret)?;
    signing_secret.signing_key.zeroize();
    let mut fast_secret = WorkerSecretFile {
        schema_version: 1,
        epoch_id: epoch_id.as_bytes().to_vec(),
        suite_id: CL_STD_1_SUITE_ID.as_bytes().to_vec(),
        signing_key: FastSig::encode_sk(&fast_signing_key),
    };
    write_serialized_secret(&fast_path, &fast_secret)?;
    fast_secret.signing_key.zeroize();

    Ok(Output {
        human: format!(
            "generated epoch {} for {} ({}..{})",
            epoch_id, args.product, args.not_before, args.not_after
        ),
        json: json!({
            "ok": true,
            "command": "keygen.epoch",
            "epoch_id": epoch_id.to_hex(),
            "product_id": args.product,
            "not_before": args.not_before,
            "not_after": args.not_after,
            "certificate": cert_path,
            "public_metadata": public_path,
            "epoch_secret": signing_path,
            "fast_secret": fast_path,
            "secret_file_mode": "0600"
        }),
    })
}

fn generate_build(args: &BuildArgs) -> Result<Output, CliError> {
    let public_path = with_suffix(&args.out, ".public.json");
    let secret_path = with_suffix(&args.out, ".secret.json");
    ensure_outputs_absent(&[public_path.clone(), secret_path.clone()])?;
    let mut rng = system_rng()?;
    let created_at = now_seconds()?;
    let pair = generate_hybrid_pair("build", created_at, &mut rng)?;
    let fingerprint = pair.public.fingerprint_hex.clone();
    write_key_pair(&public_path, &secret_path, pair)?;
    Ok(Output {
        human: format!("generated build signing key {}", fingerprint),
        json: json!({
            "ok": true,
            "command": "keygen.build",
            "suite": SUITE_NAME,
            "fingerprint": fingerprint,
            "public_file": public_path,
            "secret_file": secret_path,
            "secret_file_mode": "0600"
        }),
    })
}

struct GeneratedPair {
    public: PublicKeyFile<'static>,
    secret: KeySecretFile,
}

fn generate_hybrid_pair(
    kind: &'static str,
    created_at: i64,
    rng: &mut dyn CryptoRng,
) -> Result<GeneratedPair, CliError> {
    let (signing_key, verifying_key) = HybridSig::generate(rng);
    let verifying_bytes = HybridSig::encode_vk(&verifying_key);
    let fingerprint = Sha256Scheme::hash(&verifying_bytes);
    Ok(GeneratedPair {
        public: PublicKeyFile {
            schema_version: 1,
            kind,
            suite: SUITE_NAME,
            suite_id: CL_STD_1_SUITE_ID.as_bytes().to_vec(),
            verifying_key_hex: hex::encode(verifying_bytes),
            fingerprint_hex: fingerprint.to_hex(),
            created_at,
        },
        secret: KeySecretFile {
            schema_version: 1,
            kind: kind.to_owned(),
            suite_id: CL_STD_1_SUITE_ID.as_bytes().to_vec(),
            signing_key: HybridSig::encode_sk(&signing_key),
        },
    })
}

fn write_key_pair(
    public_path: &Path,
    secret_path: &Path,
    mut pair: GeneratedPair,
) -> Result<(), CliError> {
    write_output_file(public_path, &pretty_json_bytes(&pair.public)?, false)?;
    let result = write_serialized_secret(secret_path, &pair.secret);
    pair.secret.signing_key.zeroize();
    result
}

pub(crate) fn write_serialized_secret<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), CliError> {
    let mut bytes = pretty_json_bytes(value)?;
    let result = write_secret_file(path, &bytes);
    bytes.zeroize();
    result
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| CliError::io("create directory", parent, &error))?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        CliError::new(
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "file_exists"
            } else {
                "io_error"
            },
            format!("failed to create secret {}: {error}", path.display()),
        )
    })?;
    file.write_all(bytes)
        .map_err(|error| CliError::io("write secret", path, &error))?;
    file.sync_all()
        .map_err(|error| CliError::io("sync secret", path, &error))?;
    Ok(())
}

fn load_root_secret(path: &Path) -> Result<KeySecretFile, CliError> {
    let mut bytes = fs::read(path).map_err(|error| CliError::io("read root key", path, &error))?;
    let parsed = serde_json::from_slice::<KeySecretFile>(&bytes);
    bytes.zeroize();
    let mut parsed = parsed.map_err(|_| {
        CliError::new(
            "invalid_root_key",
            format!("{} is not a CopyLocker root secret", path.display()),
        )
    })?;
    let valid = parsed.schema_version == 1
        && matches!(parsed.kind.as_str(), "root" | "root_next")
        && parsed.suite_id == CL_STD_1_SUITE_ID.as_bytes();
    if valid {
        Ok(parsed)
    } else {
        parsed.signing_key.zeroize();
        Err(CliError::new(
            "invalid_root_key",
            format!("{} has incompatible root key metadata", path.display()),
        ))
    }
}

fn system_rng() -> Result<FromRandCore<rand_chacha::ChaCha20Rng>, CliError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| {
        CliError::new(
            "secure_random_unavailable",
            "the operating system CSPRNG is unavailable; no key material was generated",
        )
    })?;
    let rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    Ok(FromRandCore(rng))
}

fn now_seconds() -> Result<i64, CliError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::new("clock_error", "system clock is before the Unix epoch"))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| CliError::new("clock_error", "system clock cannot fit in Unix seconds"))
}

fn parse_epoch_id(value: &str) -> Result<EpochId, CliError> {
    let bytes = hex::decode(value).map_err(|_| {
        CliError::new(
            "invalid_epoch_id",
            "epoch id must contain exactly 16 hexadecimal characters",
        )
    })?;
    EpochId::from_slice(&bytes).ok_or_else(|| {
        CliError::new(
            "invalid_epoch_id",
            "epoch id must contain exactly 16 hexadecimal characters",
        )
    })
}

fn require_suite(value: &str) -> Result<(), CliError> {
    if value.eq_ignore_ascii_case(SUITE_NAME) {
        Ok(())
    } else {
        Err(CliError::new(
            "unsupported_suite",
            format!("public key generation supports only {SUITE_NAME}"),
        ))
    }
}

fn validate_product(value: &str) -> Result<(), CliError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_product_id",
            "product id must be 1-128 ASCII letters, digits, hyphens, underscores, or dots",
        ))
    }
}

fn ensure_outputs_absent<const N: usize>(paths: &[PathBuf; N]) -> Result<(), CliError> {
    if let Some(existing) = paths.iter().find(|path| path.exists()) {
        Err(CliError::new(
            "file_exists",
            format!(
                "{} already exists; key generation never overwrites key material",
                existing.display()
            ),
        ))
    } else {
        Ok(())
    }
}

fn with_suffix(prefix: &Path, suffix: &str) -> PathBuf {
    let mut value = prefix.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_ids_have_an_exact_width() {
        assert_eq!(
            parse_epoch_id("0011223344556677")
                .expect("valid epoch id")
                .to_hex(),
            "0011223344556677"
        );
        assert!(parse_epoch_id("0011").is_err());
        assert!(parse_epoch_id("not-hex-not-hex!").is_err());
    }

    #[test]
    fn output_suffixes_do_not_discard_existing_extensions() {
        assert_eq!(
            with_suffix(Path::new("keys/build-v1"), ".public.json"),
            PathBuf::from("keys/build-v1.public.json")
        );
    }
}
