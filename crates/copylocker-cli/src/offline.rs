//! Air-gapped offline activation and offline license key utilities
//! (ADR-0005 §5.3, ADR-0015, FR-SRV-016).
//!
//! The air-gapped loop:
//!
//! ```text
//! offline device:  copylocker offline request --out request.cbor --keys-out device.secret.json
//! relay:           copylocker offline redeem --request request.cbor --out response.cbor
//! offline device:  copylocker offline import --response response.cbor --keys device.secret.json \
//!                    --root-public cl-root.public.json --out credential.cbor
//! ```
//!
//! `offline issue` is the vendor-side OLK minting command (Admin API), and `offline qr`
//! renders a `CLK1` armored bundle as a QR code for camera-based transfer.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use copylocker_proto::{
    ActivationRequest, ActivationResponse, ClientInfo, Credential, Envelope, MachineCredential,
    OfflineLicenseBundle, PinnedRoots, VerifiedChain, MAX_OLK_BUNDLE_BYTES,
};
use copylocker_suite::{CryptoRng, DomainCtx, KeyEncapsulation, SignatureScheme};
use copylocker_suite_std::{FastSig, FromRandCore, HybridSig, Sha256Scheme, XWingKem};
use copylocker_types::{ArtifactKind, Digest, Fingerprint, PROTO_VER};
use rand_core::SeedableRng as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroize as _;

use crate::keys::write_serialized_secret;
use crate::remote::{self, AdminClient, ConnectionArgs};
use crate::{project, write_output_file, CliError, Output};
use copylocker_suite_std::CL_STD_1_SUITE_ID;

const MAX_OFFLINE_REQUEST_BYTES: u64 = copylocker_types::MAX_BODY_BYTES as u64;
const MAX_OFFLINE_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const QR_MODULE: &str = "\u{2588}"; // full block
const QR_UPPER: &str = "\u{2580}"; // upper half block
const QR_LOWER: &str = "\u{2584}"; // lower half block
const QR_QUIET: usize = 2;

#[derive(Debug, Args)]
pub(crate) struct OfflineArgs {
    #[command(subcommand)]
    command: OfflineCommand,
}

#[derive(Debug, Subcommand)]
enum OfflineCommand {
    /// Generate an offline activation request and the matching device key file.
    Request(OfflineRequestArgs),
    /// Upload an activation request to /v1/offline/request and store the signed response.
    Redeem(OfflineRedeemArgs),
    /// Verify a signed activation response and export the machine credential.
    Import(OfflineImportArgs),
    /// Render an offline bundle's `CLK1` armor or an activation request's `CLR1` armor as a QR code.
    Qr(OfflineQrArgs),
    /// Issue an offline license key (OLK) for a license through the Admin API.
    Issue(OfflineIssueArgs),
}

#[derive(Debug, Args)]
struct OfflineRequestArgs {
    /// Directory in or below an initialized CopyLocker project (for defaults).
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// License key presented by the end user.
    #[arg(long)]
    license_key: String,
    /// Registered release identifier.
    #[arg(long)]
    release_id: String,
    /// Build fingerprint injected into the build.
    #[arg(long)]
    build_fingerprint: String,
    /// Application version, for example 1.4.2.
    #[arg(long)]
    app_version: String,
    /// Variant the build derives keys for.
    #[arg(long)]
    variant_id: u64,
    /// 32-byte device fingerprint digest as 64 hexadecimal characters.
    #[arg(long)]
    fingerprint_hex: String,
    /// Destination for the canonical-CBOR activation request.
    #[arg(long)]
    out: PathBuf,
    /// Optional destination for the `CLR1` armor text of the request.
    #[arg(long)]
    armor_out: Option<PathBuf>,
    /// Destination for the mode-0600 device key file needed later by `offline import`.
    #[arg(long)]
    keys_out: PathBuf,
}

#[derive(Debug, Args)]
struct OfflineRedeemArgs {
    /// Override the API origin from copylocker.json or COPYLOCKER_API_URL.
    #[arg(long)]
    api_url: Option<String>,
    /// Directory in or below an initialized CopyLocker project (for defaults).
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Activation request file produced by `offline request`.
    #[arg(long)]
    request: PathBuf,
    /// Destination for the signed activation response envelope.
    #[arg(long)]
    out: PathBuf,
    /// Idempotency key for the activation.
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct OfflineImportArgs {
    /// Signed activation response from `offline redeem`.
    #[arg(long)]
    response: PathBuf,
    /// Mode-0600 device key file produced by `offline request`.
    #[arg(long)]
    keys: PathBuf,
    /// Root public metadata file produced by `keygen root`.
    #[arg(long)]
    root_public: PathBuf,
    /// Destination for the verified machine credential envelope.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct OfflineQrArgs {
    /// `.clk` binary bundle, `CLK1` armor, activation-request CBOR, or `CLR1` armor text.
    #[arg(long)]
    input: PathBuf,
    /// Output format: ascii (terminal blocks) or svg.
    #[arg(long, default_value = "ascii")]
    format: String,
    /// Destination file. ASCII output defaults to stdout; SVG requires --out.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct OfflineIssueArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// License identifier as 32 hexadecimal characters.
    #[arg(long)]
    license: String,
    /// Registered release identifier the OLK opens.
    #[arg(long)]
    release_id: String,
    /// Optional 32-byte bound device fingerprint as 64 hexadecimal characters.
    #[arg(long)]
    bound_fingerprint_hex: Option<String>,
    /// Declared seat count (advisory only; nothing enforces it offline).
    #[arg(long)]
    max_seats: Option<u32>,
    /// Idempotency key for the issuance.
    #[arg(long)]
    idempotency_key: String,
    /// Destination for the binary `.clk` bundle.
    #[arg(long)]
    out: PathBuf,
    /// Optional destination for the `CLK1` armor text.
    #[arg(long)]
    armor_out: Option<PathBuf>,
}

pub(crate) fn run(args: &OfflineArgs) -> Result<Output, CliError> {
    match &args.command {
        OfflineCommand::Request(args) => request(args),
        OfflineCommand::Redeem(args) => redeem(args),
        OfflineCommand::Import(args) => import(args),
        OfflineCommand::Qr(args) => qr(args),
        OfflineCommand::Issue(args) => issue(args),
    }
}

fn request(args: &OfflineRequestArgs) -> Result<Output, CliError> {
    let product = args.product.clone().map(Ok).unwrap_or_else(|| {
        project::find_project_config(&args.project)
            .and_then(|path| project::load_project_config(&path).ok())
            .map(|config| config.product_id)
            .ok_or_else(|| {
                CliError::new(
                    "product_id_missing",
                    "pass --product or run the command in an initialized CopyLocker project",
                )
            })
    })?;
    remote::validate_identifier("product id", &product, 128)?;
    remote::validate_identifier("release id", &args.release_id, 128)?;
    copylocker_proto::LicenseKey::parse(&args.license_key).map_err(|_| {
        CliError::new(
            "invalid_license_key",
            "the license key is not a valid CL1 license key",
        )
    })?;
    remote::validate_hex_id("fingerprint-hex", &args.fingerprint_hex, 32)?;
    let fingerprint = Fingerprint::from_vec(hex::decode(&args.fingerprint_hex).map_err(|_| {
        CliError::new(
            "invalid_identifier",
            "fingerprint-hex must be lowercase hexadecimal",
        )
    })?);

    let mut rng = system_rng()?;
    let (kem_dk, kem_ek) = XWingKem::keygen(&mut rng);
    let (sig_sk, sig_vk) = FastSig::generate(&mut rng);
    let mut nonce = [0_u8; 32];
    rng.fill_bytes(&mut nonce);

    let mut activation = ActivationRequest {
        proto_ver: PROTO_VER,
        suite_id: CL_STD_1_SUITE_ID,
        product_id: product.clone(),
        credential: Credential::LicenseKey(args.license_key.clone()),
        fingerprint,
        device_attrs: None,
        device_kem_ek: XWingKem::encode_ek(&kem_ek),
        device_sig_vk: FastSig::encode_vk(&sig_vk),
        nonce_c: nonce,
        client_time: now_seconds()?,
        client_info: ClientInfo {
            app_version: args.app_version.clone(),
            sdk_version: env!("CARGO_PKG_VERSION").to_owned(),
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            build_fingerprint: args.build_fingerprint.clone(),
            release_id: args.release_id.clone(),
            variant_id: args.variant_id,
            supported_suites: vec![CL_STD_1_SUITE_ID],
            supported_variants: vec![args.variant_id],
        },
        attestation: None,
        proof: Vec::new(),
    };
    let context = DomainCtx::new(ArtifactKind::ActivationRequest, CL_STD_1_SUITE_ID, &product);
    let proof = FastSig::sign(&sig_sk, context, &activation.proof_input())
        .map_err(|_| CliError::new("proof_failed", "failed to self-sign the request"))?;
    activation.proof = proof.0;

    let encoded = activation.encode();
    write_output_file(&args.out, &encoded, false)?;
    let armor_chars = if let Some(armor_path) = &args.armor_out {
        let armor = copylocker_proto::armor_activation_request(&encoded);
        write_output_file(armor_path, format!("{armor}\n").as_bytes(), false)?;
        Some(armor.len())
    } else {
        None
    };
    let keys = DeviceKeyFile {
        schema_version: 1,
        kind: "offline-device".to_owned(),
        product_id: product.clone(),
        fingerprint_hex: args.fingerprint_hex.to_lowercase(),
        nonce_hex: hex::encode(nonce),
        device_kem_dk_hex: hex::encode(XWingKem::encode_dk(&kem_dk)),
        device_sig_sk_hex: hex::encode(FastSig::encode_sk(&sig_sk)),
    };
    write_serialized_secret(&args.keys_out, &keys)?;

    Ok(Output {
        human: format!(
            "wrote the activation request to {}\ndevice keys (mode 0600) at {}; keep them for `offline import`{}",
            args.out.display(),
            args.keys_out.display(),
            args.armor_out
                .as_ref()
                .map(|path| format!("\narmor: {}", path.display()))
                .unwrap_or_default(),
        ),
        json: json!({
            "ok": true,
            "command": "offline.request",
            "product_id": product,
            "release_id": args.release_id,
            "request": args.out,
            "request_bytes": encoded.len(),
            "armor_file": args.armor_out,
            "armor_chars": armor_chars,
            "device_keys": args.keys_out,
        }),
    })
}

fn redeem(args: &OfflineRedeemArgs) -> Result<Output, CliError> {
    remote::validate_idempotency_key(&args.idempotency_key)?;
    let body = read_activation_request(&args.request)?;
    ActivationRequest::decode(&body).map_err(|_| {
        CliError::new(
            "invalid_activation_request",
            format!(
                "{} is not a canonical CopyLocker activation request",
                args.request.display()
            ),
        )
    })?;
    let api_url = args
        .api_url
        .clone()
        .or_else(|| std::env::var("COPYLOCKER_API_URL").ok())
        .or_else(|| {
            project::find_project_config(&args.project)
                .and_then(|path| project::load_project_config(&path).ok())
                .and_then(|config| config.api_url)
        })
        .ok_or_else(|| {
            CliError::new(
                "api_url_missing",
                "set --api-url, COPYLOCKER_API_URL, or api_url in an initialized copylocker.json",
            )
        })?;

    let bytes = post_offline_request(&api_url, &body, &args.idempotency_key)?;
    let envelope = Envelope::decode(&bytes).map_err(|_| {
        CliError::new(
            "invalid_activation_response",
            "the server response is not a signed CopyLocker envelope",
        )
    })?;
    if envelope.kind != ArtifactKind::ActivationResponse {
        return Err(CliError::new(
            "invalid_activation_response",
            "the server response is not an activation response",
        ));
    }
    write_output_file(&args.out, &bytes, false)?;

    Ok(Output {
        human: format!(
            "stored the signed activation response at {}\nverify it with `offline import` on the offline device",
            args.out.display()
        ),
        json: json!({
            "ok": true,
            "command": "offline.redeem",
            "response": args.out,
            "response_bytes": bytes.len(),
        }),
    })
}

fn import(args: &OfflineImportArgs) -> Result<Output, CliError> {
    let response_bytes = read_bounded(
        &args.response,
        MAX_OFFLINE_RESPONSE_BYTES,
        "activation response",
    )?;
    let keys: DeviceKeyFile = read_secret_json(&args.keys)?;
    if keys.schema_version != 1 || keys.kind != "offline-device" {
        return Err(CliError::new(
            "invalid_device_keys",
            format!(
                "{} is not a CopyLocker offline device key file",
                args.keys.display()
            ),
        ));
    }
    let root: RootPublicFile = crate::load_config_json(
        &args.root_public,
        "invalid_root_public",
        "root public metadata",
    )?;
    let root_vk_bytes = hex::decode(&root.verifying_key_hex).map_err(|_| {
        CliError::new(
            "invalid_root_public",
            "root verifying key is not hexadecimal",
        )
    })?;
    let root_vk = HybridSig::decode_vk(&root_vk_bytes)
        .map_err(|_| CliError::new("invalid_root_public", "root verifying key is invalid"))?;
    let root_digest_bytes = hex::decode(&root.fingerprint_hex)
        .map_err(|_| CliError::new("invalid_root_public", "root fingerprint is not hexadecimal"))?;
    let root_digest = Digest::from_slice(&root_digest_bytes)
        .ok_or_else(|| CliError::new("invalid_root_public", "root fingerprint must be 32 bytes"))?;

    let envelope = Envelope::decode(&response_bytes).map_err(|_| {
        CliError::new(
            "invalid_activation_response",
            format!(
                "{} is not a signed CopyLocker envelope",
                args.response.display()
            ),
        )
    })?;
    let now = now_seconds()?;
    let unverified = envelope
        .peek_unverified::<ActivationResponse>()
        .map_err(|_| invalid_response())?;
    let mut chain = VerifiedChain::<HybridSig>::new(PinnedRoots::single(root_digest));
    for certificate in &unverified.chain {
        let certificate_envelope = Envelope::decode(certificate).map_err(|_| invalid_response())?;
        chain
            .add_epoch::<Sha256Scheme>(&certificate_envelope, &keys.product_id, &root_vk, now)
            .map_err(|_| {
                CliError::new(
                    "chain_verification_failed",
                    "an epoch certificate in the response failed root verification",
                )
            })?;
    }
    let activation_response = chain
        .verify_artifact::<ActivationResponse>(&envelope, &keys.product_id, now)
        .map_err(|_| {
            CliError::new(
                "signature_verification_failed",
                "the activation response signature does not verify against the pinned root",
            )
        })?;
    let nonce = hex::decode(&keys.nonce_hex)
        .ok()
        .and_then(|value| <[u8; 32]>::try_from(value.as_slice()).ok());
    if Some(activation_response.nonce_c_echo) != nonce {
        return Err(CliError::new(
            "nonce_mismatch",
            "the response answers a different request; refusing to import",
        ));
    }
    if activation_response.valid_until <= now {
        return Err(CliError::new(
            "response_expired",
            "the activation response is past its valid_until deadline; redeem the request again",
        ));
    }
    let credential_envelope =
        Envelope::decode(&activation_response.credential).map_err(|_| invalid_response())?;
    // A product mismatch fails here: the product id is part of every signature domain.
    let credential = chain
        .verify_artifact::<MachineCredential>(&credential_envelope, &keys.product_id, now)
        .map_err(|_| {
            CliError::new(
                "signature_verification_failed",
                "the machine credential signature does not verify against the pinned root",
            )
        })?;
    if credential.fingerprint.as_bytes().to_vec()
        != hex::decode(&keys.fingerprint_hex).unwrap_or_default()
    {
        return Err(CliError::new(
            "fingerprint_mismatch",
            "the credential is bound to a different device fingerprint",
        ));
    }
    write_output_file(&args.out, &activation_response.credential, false)?;

    Ok(Output {
        human: format!(
            "verified and exported the machine credential to {}\nlicense {} machine {} (mode {:?})",
            args.out.display(),
            credential.license_id.to_hex(),
            credential.machine_id.to_hex(),
            credential.mode,
        ),
        json: json!({
            "ok": true,
            "command": "offline.import",
            "verified": true,
            "credential": args.out,
            "product_id": credential.product_id,
            "license_id": credential.license_id.to_hex(),
            "machine_id": credential.machine_id.to_hex(),
            "not_after": credential.not_after,
            "refresh_after": credential.refresh_after,
            "valid_until": activation_response.valid_until,
        }),
    })
}

fn qr(args: &OfflineQrArgs) -> Result<Output, CliError> {
    let armor = read_armor(&args.input)?;
    let code = qrcode::QrCode::with_error_correction_level(armor.as_bytes(), qrcode::EcLevel::M)
        .map_err(|_| {
            CliError::new(
            "offline_bundle_too_large_for_qr",
            "the armored bundle does not fit in a QR code (version 40-M); transfer it as a file",
        )
        })?;
    let (text, extension) = match args.format.as_str() {
        "ascii" => (render_qr_ascii(&code), "txt"),
        "svg" => (render_qr_svg(&code), "svg"),
        _ => {
            return Err(CliError::new(
                "invalid_format",
                "--format must be ascii or svg",
            ));
        }
    };
    match &args.out {
        Some(path) => {
            write_output_file(path, text.as_bytes(), false)?;
            Ok(Output {
                human: format!("wrote the {extension} QR code to {}", path.display()),
                json: json!({
                    "ok": true,
                    "command": "offline.qr",
                    "format": args.format,
                    "out": path,
                    "armor_chars": armor.len(),
                    "modules": code.width(),
                }),
            })
        }
        None if args.format == "ascii" => Ok(Output {
            human: text,
            json: json!({
                "ok": true,
                "command": "offline.qr",
                "format": "ascii",
                "armor_chars": armor.len(),
                "modules": code.width(),
            }),
        }),
        None => Err(CliError::new(
            "output_required",
            "SVG output requires --out",
        )),
    }
}

fn issue(args: &OfflineIssueArgs) -> Result<Output, CliError> {
    remote::validate_hex_id("license", &args.license, 16)?;
    remote::validate_identifier("release id", &args.release_id, 128)?;
    if let Some(value) = &args.bound_fingerprint_hex {
        remote::validate_hex_id("bound-fingerprint-hex", value, 32)?;
    }
    remote::validate_idempotency_key(&args.idempotency_key)?;
    let client = AdminClient::connect(&args.connection)?;
    let body = json!({
        "release_id": args.release_id,
        "bound_fingerprint_hex": args.bound_fingerprint_hex.as_deref().map(str::to_lowercase),
        "max_seats": args.max_seats,
    });
    let response = client.post(
        &format!(
            "/v1/admin/licenses/{}/offline-key",
            args.license.to_lowercase()
        ),
        &[],
        &body,
        Some(&args.idempotency_key),
    )?;
    let mut output = remote::output("offline.issue", response);
    let armor = output
        .json
        .get("armor")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::new(
                "invalid_api_response",
                "the Admin API response did not contain the OLK armor",
            )
        })?
        .to_owned();
    let bundle = OfflineLicenseBundle::from_armored(&armor).map_err(|_| {
        CliError::new(
            "invalid_api_response",
            "the Admin API returned armor that does not decode",
        )
    })?;
    write_output_file(&args.out, &bundle.encode(), false)?;
    if let Some(armor_path) = &args.armor_out {
        write_output_file(armor_path, format!("{armor}\n").as_bytes(), false)?;
    }
    if let Some(object) = output.json.as_object_mut() {
        object.insert("bundle".to_owned(), json!(args.out));
        if let Some(armor_path) = &args.armor_out {
            object.insert("armor_file".to_owned(), json!(armor_path));
        }
    }
    output.human = format!(
        "issued the offline license key ({} armor characters)\nbundle: {}\n{}{}",
        armor.len(),
        args.out.display(),
        args.armor_out
            .as_ref()
            .map(|path| format!("armor: {}\n", path.display()))
            .unwrap_or_default(),
        "the bundle is a bearer credential: distribute it only through the documented offline channel",
    );
    Ok(output)
}

fn post_offline_request(
    api_url: &str,
    body: &[u8],
    idempotency_key: &str,
) -> Result<Vec<u8>, CliError> {
    let mut url = reqwest::Url::parse(api_url).map_err(|_| {
        CliError::new(
            "invalid_api_url",
            "API URL must be an absolute HTTP(S) origin",
        )
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(CliError::new(
            "invalid_api_url",
            "API URL must be an HTTP(S) origin without credentials, path, query, or fragment",
        ));
    }
    url.set_path("/v1/offline/request");
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("copylocker-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| {
            CliError::new(
                "http_client_failed",
                format!("failed to initialize the HTTP client: {error}"),
            )
        })?;
    let response = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .header(reqwest::header::ACCEPT, "application/cbor")
        .header("X-CL-Proto", "1")
        .header("Idempotency-Key", idempotency_key)
        .body(body.to_vec())
        .send()
        .map_err(|error| {
            CliError::new(
                "network_error",
                format!("offline activation request failed: {error}"),
            )
        })?;
    let status = response.status();
    let mut bytes = Vec::new();
    response
        .take(MAX_OFFLINE_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliError::new(
                "response_read_failed",
                format!("failed to read the activation response: {error}"),
            )
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_OFFLINE_RESPONSE_BYTES {
        return Err(CliError::new(
            "response_too_large",
            "the activation response exceeds the 2 MiB CLI limit",
        ));
    }
    if !status.is_success() {
        let detail = copylocker_proto::ProtocolErrorResponse::decode(&bytes)
            .ok()
            .and_then(|error| error.message)
            .unwrap_or_else(|| "the server rejected the activation request".to_owned());
        return Err(CliError::new(
            "activation_rejected",
            format!("HTTP {}: {detail}", status.as_u16()),
        ));
    }
    Ok(bytes)
}

/// Read an activation request file in either carrier: raw canonical CBOR, or the `CLR1`
/// Base32 armor (`.clar`, compact or PEM-bounded). The armor is decoded back to the identical
/// CBOR bytes, so the wire request is unchanged either way.
fn read_activation_request(path: &Path) -> Result<Vec<u8>, CliError> {
    let bytes = read_bounded(path, MAX_OFFLINE_REQUEST_BYTES * 2, "activation request")?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if text
            .trim_start()
            .starts_with(copylocker_proto::AR_ARMOR_PREFIX)
            || text.contains("BEGIN COPYLOCKER ACTIVATION REQUEST")
        {
            return copylocker_proto::unarmor_activation_request(text).map_err(|_| {
                CliError::new(
                    "invalid_activation_request",
                    format!("{} is not valid CLR1 armor", path.display()),
                )
            });
        }
    }
    Ok(bytes)
}

fn read_armor(path: &Path) -> Result<String, CliError> {
    let bytes = read_bounded(path, MAX_OLK_BUNDLE_BYTES as u64 * 2, "offline bundle")?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if text
            .trim_start()
            .starts_with(copylocker_proto::AR_ARMOR_PREFIX)
            || text.contains("BEGIN COPYLOCKER ACTIVATION REQUEST")
        {
            let decoded = copylocker_proto::unarmor_activation_request(text).map_err(|_| {
                CliError::new(
                    "invalid_activation_request",
                    format!("{} is not valid CLR1 armor", path.display()),
                )
            })?;
            // The QR carries only well-formed requests.
            ActivationRequest::decode(&decoded).map_err(|_| {
                CliError::new(
                    "invalid_activation_request",
                    format!("{} does not contain an activation request", path.display()),
                )
            })?;
            return Ok(copylocker_proto::armor_activation_request(&decoded));
        }
        if text.trim_start().starts_with("CLK1:") || text.contains("BEGIN COPYLOCKER") {
            let bundle = OfflineLicenseBundle::from_armored(text).map_err(|_| {
                CliError::new(
                    "invalid_offline_bundle",
                    format!("{} is not valid CLK1 armor", path.display()),
                )
            })?;
            return Ok(bundle.to_armored());
        }
    }
    if let Ok(bundle) = OfflineLicenseBundle::decode(&bytes) {
        return Ok(bundle.to_armored());
    }
    if let Ok(request) = ActivationRequest::decode(&bytes) {
        return Ok(copylocker_proto::armor_activation_request(
            &request.encode(),
        ));
    }
    Err(CliError::new(
        "invalid_offline_bundle",
        format!(
            "{} is neither a .clk bundle, CLK1 armor, nor an activation request",
            path.display()
        ),
    ))
}

fn render_qr_ascii(code: &qrcode::QrCode) -> String {
    let width = code.width();
    let colors = code.to_colors();
    let is_dark = |x: usize, y: usize| -> bool {
        colors
            .get(y.saturating_mul(width).saturating_add(x))
            .is_some_and(|color| *color == qrcode::Color::Dark)
    };
    let total = width + 2 * QR_QUIET;
    let mut output = String::new();
    let mut row = 0_usize;
    while row < total {
        let upper = row;
        let lower = row + 1;
        for column in 0..total {
            let up = module_is_dark(&is_dark, column, upper, width);
            let low = module_is_dark(&is_dark, column, lower, width);
            output.push_str(match (up, low) {
                (true, true) => QR_MODULE,
                (true, false) => QR_UPPER,
                (false, true) => QR_LOWER,
                (false, false) => " ",
            });
        }
        output.push('\n');
        row += 2;
    }
    output
}

fn module_is_dark(
    is_dark: &dyn Fn(usize, usize) -> bool,
    column: usize,
    row: usize,
    width: usize,
) -> bool {
    if column < QR_QUIET || row < QR_QUIET {
        return false;
    }
    let x = column - QR_QUIET;
    let y = row - QR_QUIET;
    if x >= width || y >= width {
        return false;
    }
    is_dark(x, y)
}

fn render_qr_svg(code: &qrcode::QrCode) -> String {
    let width = code.width();
    let colors = code.to_colors();
    let total = width + 2 * QR_QUIET;
    let mut output = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total} {total}\" shape-rendering=\"crispEdges\">\n<rect width=\"{total}\" height=\"{total}\" fill=\"#ffffff\"/>\n<path fill=\"#000000\" d=\""
    );
    let mut path = String::new();
    for (index, color) in colors.iter().enumerate() {
        if *color == qrcode::Color::Dark {
            let x = index % width + QR_QUIET;
            let y = index / width + QR_QUIET;
            path.push_str(&format!("M{x} {y}h1v1h-1z"));
        }
    }
    output.push_str(&path);
    output.push_str("\"/>\n</svg>\n");
    output
}

fn read_bounded(path: &Path, limit: u64, kind: &str) -> Result<Vec<u8>, CliError> {
    let metadata = fs::metadata(path).map_err(|error| CliError::io("inspect", path, &error))?;
    if metadata.len() > limit {
        return Err(CliError::new(
            "file_too_large",
            format!("{} exceeds the {}-byte {kind} limit", path.display(), limit),
        ));
    }
    fs::read(path).map_err(|error| CliError::io("read", path, &error))
}

fn read_secret_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let bytes = fs::read(path).map_err(|error| CliError::io("read", path, &error))?;
    serde_json::from_slice(&bytes).map_err(|_| {
        CliError::new(
            "invalid_device_keys",
            format!("{} is not valid JSON", path.display()),
        )
    })
}

fn invalid_response() -> CliError {
    CliError::new(
        "invalid_activation_response",
        "the activation response is malformed",
    )
}

fn now_seconds() -> Result<i64, CliError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::new("clock_error", "system clock is before the Unix epoch"))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| CliError::new("clock_error", "system clock cannot fit in Unix seconds"))
}

fn system_rng() -> Result<FromRandCore<rand_chacha::ChaCha20Rng>, CliError> {
    let mut seed = [0_u8; 32];
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

#[derive(Debug, Deserialize, Serialize)]
struct DeviceKeyFile {
    schema_version: u8,
    kind: String,
    product_id: String,
    fingerprint_hex: String,
    nonce_hex: String,
    device_kem_dk_hex: String,
    device_sig_sk_hex: String,
}

impl Drop for DeviceKeyFile {
    fn drop(&mut self) {
        self.device_kem_dk_hex.zeroize();
        self.device_sig_sk_hex.zeroize();
    }
}

#[derive(Debug, Deserialize)]
struct RootPublicFile {
    verifying_key_hex: String,
    fingerprint_hex: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> OfflineLicenseBundle {
        OfflineLicenseBundle::new(vec![1, 2, 3, 4], vec![vec![5, 6, 7]])
    }

    #[test]
    fn ascii_qr_renders_a_framed_square() {
        let code = qrcode::QrCode::new(bundle().to_armored().as_bytes()).unwrap();
        let rendered = render_qr_ascii(&code);
        let lines = rendered.lines().count();
        let width = code.width() + 2 * QR_QUIET;
        assert_eq!(lines, width.div_ceil(2));
        assert!(rendered.contains(QR_MODULE));
    }

    #[test]
    fn svg_qr_renders_modules_inside_a_quiet_zone() {
        let code = qrcode::QrCode::new(bundle().to_armored().as_bytes()).unwrap();
        let svg = render_qr_svg(&code);
        let total = code.width() + 2 * QR_QUIET;
        assert!(svg.contains(&format!("viewBox=\"0 0 {total} {total}\"")));
        assert!(svg.contains("<path"));
        assert!(svg.trim_end().ends_with("</svg>"));
    }

    #[test]
    fn armor_input_accepts_pem_boundaries_and_binary() {
        let dir =
            std::env::temp_dir().join(format!("copylocker-offline-qr-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let armor_path = dir.join("bundle.clk.txt");
        let binary_path = dir.join("bundle.clk");
        let pem = format!(
            "-----BEGIN COPYLOCKER OFFLINE LICENSE-----\n{}\n-----END COPYLOCKER OFFLINE LICENSE-----\n",
            bundle().to_armored()
        );
        fs::write(&armor_path, pem).unwrap();
        fs::write(&binary_path, bundle().encode()).unwrap();
        assert_eq!(read_armor(&armor_path).unwrap(), bundle().to_armored());
        assert_eq!(read_armor(&binary_path).unwrap(), bundle().to_armored());
        fs::remove_dir_all(&dir).unwrap();
    }
}
