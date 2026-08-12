//! Asset KEK administration through the remote Admin API (M4-B).
//!
//! `asset-kek register` uploads the 32-byte KEK that `@copylocker/seal` used to seal a
//! release's feature assets. The Worker stores only the AEAD-encrypted KEK; the plaintext is
//! shown exactly once here and must be kept in the local seal KEK registry. `list` returns
//! fingerprints only, so the local registry can be reconciled against the server without
//! exposing key material.

use clap::{Args, Subcommand};
use serde_json::json;
use zeroize::Zeroize as _;

use crate::remote::{self, AdminClient};
use crate::{CliError, Output};

const KEK_HEX_LEN: usize = 64;

#[derive(Debug, Args)]
pub(crate) struct AssetKekArgs {
    #[command(subcommand)]
    command: AssetKekCommand,
}

#[derive(Debug, Subcommand)]
enum AssetKekCommand {
    /// Register a 32-byte asset KEK for a release feature. Generates one unless --kek-hex is given.
    Register(AssetKekRegisterArgs),
    /// List registered asset KEKs (fingerprints only, never plaintext).
    List(AssetKekListArgs),
    /// Delete a registered asset KEK. Without --confirm this only sends a dry-run request.
    Delete(AssetKekDeleteArgs),
}

#[derive(Debug, Args)]
struct AssetKekRegisterArgs {
    #[command(flatten)]
    connection: remote::ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Release identifier the KEK belongs to.
    #[arg(long)]
    release: String,
    /// Feature identifier whose assets the KEK seals.
    #[arg(long)]
    feature: String,
    /// Existing 32-byte KEK as 64 hexadecimal characters. Generated when omitted.
    #[arg(long)]
    kek_hex: Option<String>,
    /// Idempotency key for the registration.
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct AssetKekListArgs {
    #[command(flatten)]
    connection: remote::ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Restrict the list to one release.
    #[arg(long)]
    release: Option<String>,
}

#[derive(Debug, Args)]
struct AssetKekDeleteArgs {
    #[command(flatten)]
    connection: remote::ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Release identifier the KEK belongs to.
    #[arg(long)]
    release: String,
    /// Feature identifier whose KEK is deleted.
    #[arg(long)]
    feature: String,
    /// Apply the deletion after reviewing the default dry-run.
    #[arg(long)]
    confirm: bool,
    /// Idempotency key required only for a confirmed deletion.
    #[arg(long, required_if_eq("confirm", "true"))]
    idempotency_key: Option<String>,
}

pub(crate) fn run(args: &AssetKekArgs) -> Result<Output, CliError> {
    match &args.command {
        AssetKekCommand::Register(args) => register(args),
        AssetKekCommand::List(args) => list(args),
        AssetKekCommand::Delete(args) => delete(args),
    }
}

fn register(args: &AssetKekRegisterArgs) -> Result<Output, CliError> {
    remote::validate_identifier("release id", &args.release, 128)?;
    remote::validate_identifier("feature id", &args.feature, 128)?;
    remote::validate_idempotency_key(&args.idempotency_key)?;
    let (kek_hex, generated) = match &args.kek_hex {
        Some(value) => {
            let normalized = value.to_lowercase();
            if normalized.len() != KEK_HEX_LEN
                || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(CliError::new(
                    "invalid_kek",
                    "--kek-hex must contain exactly 64 hexadecimal characters (32 bytes)",
                ));
            }
            (normalized, false)
        }
        None => {
            let mut kek = [0_u8; 32];
            getrandom::fill(&mut kek).map_err(|_| {
                CliError::new(
                    "secure_random_unavailable",
                    "the operating system CSPRNG is unavailable; no KEK was generated",
                )
            })?;
            let encoded = hex_encode(&kek);
            kek.zeroize();
            (encoded, true)
        }
    };
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    let body = json!({
        "product_id": product,
        "release_id": args.release,
        "feature_id": args.feature,
        "kek_hex": kek_hex,
    });
    let response = client.post(
        "/v1/admin/asset-keks",
        &[],
        &body,
        Some(&args.idempotency_key),
    )?;
    let mut output = remote::output("asset-kek.register", response);
    if let Some(object) = output.json.as_object_mut() {
        object.insert("kek_hex".to_owned(), json!(kek_hex));
        object.insert("kek_shown_once".to_owned(), json!(true));
        object.insert("kek_generated".to_owned(), json!(generated));
    }
    output.human = format!(
        "registered asset KEK for {}/{}\n\
         kek (shown once, store it in the seal KEK registry): {}\n\
         response: {}",
        args.release, args.feature, kek_hex, output.human
    );
    Ok(output)
}

fn list(args: &AssetKekListArgs) -> Result<Output, CliError> {
    if let Some(release) = &args.release {
        remote::validate_identifier("release id", release, 128)?;
    }
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    let mut query = vec![("product_id", product)];
    if let Some(release) = &args.release {
        query.push(("release_id", release.clone()));
    }
    remote::output_result("asset-kek.list", client.get("/v1/admin/asset-keks", &query))
}

fn delete(args: &AssetKekDeleteArgs) -> Result<Output, CliError> {
    remote::validate_identifier("release id", &args.release, 128)?;
    remote::validate_identifier("feature id", &args.feature, 128)?;
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    let path = format!("/v1/admin/asset-keks/{}/{}", args.release, args.feature);
    let query = [
        ("product_id", product),
        ("dry_run", (!args.confirm).to_string()),
    ];
    remote::output_result(
        "asset-kek.delete",
        client.delete(&path, &query, args.idempotency_key.as_deref()),
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let low = HEX.get(usize::from(byte & 0x0f)).copied().unwrap_or(b'0');
        encoded.push(char::from(high));
        encoded.push(char::from(low));
    }
    encoded
}
