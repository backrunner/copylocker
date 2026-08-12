//! Release registration and version-level revocation through the Admin API (M5-A,
//! `versioning-and-variants.md` §2 and §4).
//!
//! `release register` is the CI gate every published build must pass: the server assigns the
//! `release_id` and `variant_id`, and the CLI-side CSPRNG generates the public-suite variant
//! seed (§2.2), which is shown exactly once for the build pipeline to embed. Lifecycle actions
//! are dry-run by default and print the impacted device counts before `--confirm` applies them;
//! `revoke` additionally requires `--ack-revoke`.

use clap::{Args, Subcommand};
use serde_json::{json, Value};
use zeroize::Zeroize as _;

use crate::remote::{self, AdminClient};
use crate::{CliError, Output};

const HEX_32_BYTES: usize = 64;

#[derive(Debug, Args)]
pub(crate) struct ReleaseArgs {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Debug, Subcommand)]
enum ReleaseCommand {
    /// Register a published build. The server assigns release_id and variant_id.
    Register(ReleaseRegisterArgs),
    /// List the registered releases of a product.
    List(ReleaseListArgs),
    /// Show one registered release.
    Show(ReleaseShowArgs),
    /// Deprecate a release. Without --confirm this only reports the impact.
    Deprecate(ReleaseDeprecateArgs),
    /// Mark a release compromised. Without --confirm this only reports the impact.
    MarkCompromised(ReleaseCompromisedArgs),
}

#[derive(Debug, Args)]
struct ReleaseRegisterArgs {
    #[command(flatten)]
    connection: remote::ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Semantic version of the build, for example 1.4.2.
    #[arg(long)]
    app_version: String,
    /// Unique build fingerprint injected into the build.
    #[arg(long)]
    build_fingerprint: String,
    /// Release channel.
    #[arg(long, default_value = "stable")]
    channel: String,
    /// Optional 32-byte manifest root digest as 64 hexadecimal characters.
    #[arg(long)]
    manifest_root_hex: Option<String>,
    /// Optional 32-byte module digest as 64 hexadecimal characters. Defaults to zeroes.
    #[arg(long)]
    module_digest_hex: Option<String>,
    /// Existing 32-byte variant seed as 64 hexadecimal characters. Generated when omitted.
    #[arg(long)]
    variant_seed_hex: Option<String>,
    /// Idempotency key for the registration.
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct ReleaseListArgs {
    #[command(flatten)]
    connection: remote::ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
}

#[derive(Debug, Args)]
struct ReleaseShowArgs {
    #[command(flatten)]
    connection: remote::ConnectionArgs,
    /// Release identifier.
    release_id: String,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
}

#[derive(Debug, Args)]
struct ReleaseDeprecateArgs {
    #[command(flatten)]
    connection: remote::ConnectionArgs,
    /// Release identifier.
    release_id: String,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Apply the deprecation after reviewing the default dry-run.
    #[arg(long)]
    confirm: bool,
    /// Idempotency key required only for a confirmed deprecation.
    #[arg(long, required_if_eq("confirm", "true"))]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args)]
struct ReleaseCompromisedArgs {
    #[command(flatten)]
    connection: remote::ConnectionArgs,
    /// Release identifier.
    release_id: String,
    /// What devices on this release should experience: warn, force_upgrade, or revoke.
    #[arg(long)]
    action: String,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Also bump the global security floor so downgrades to this release fail closed.
    #[arg(long)]
    bump_security_floor: bool,
    /// Apply the action after reviewing the default dry-run.
    #[arg(long)]
    confirm: bool,
    /// Second acknowledgement required to confirm --action revoke.
    #[arg(long)]
    ack_revoke: bool,
    /// Idempotency key required only for a confirmed action.
    #[arg(long, required_if_eq("confirm", "true"))]
    idempotency_key: Option<String>,
}

pub(crate) fn run(args: &ReleaseArgs) -> Result<Output, CliError> {
    match &args.command {
        ReleaseCommand::Register(args) => register(args),
        ReleaseCommand::List(args) => list(args),
        ReleaseCommand::Show(args) => show(args),
        ReleaseCommand::Deprecate(args) => deprecate(args),
        ReleaseCommand::MarkCompromised(args) => mark_compromised(args),
    }
}

fn register(args: &ReleaseRegisterArgs) -> Result<Output, CliError> {
    validate_app_version(&args.app_version)?;
    validate_build_fingerprint(&args.build_fingerprint)?;
    remote::validate_identifier("channel", &args.channel, 128)?;
    remote::validate_idempotency_key(&args.idempotency_key)?;
    for (field, value) in [
        ("manifest-root-hex", &args.manifest_root_hex),
        ("module-digest-hex", &args.module_digest_hex),
    ] {
        if let Some(value) = value {
            remote::validate_hex_id(field, value, 32)?;
        }
    }
    let (variant_seed_hex, generated) = match &args.variant_seed_hex {
        Some(value) => {
            remote::validate_hex_id("variant-seed-hex", value, 32)?;
            (value.to_lowercase(), false)
        }
        None => {
            let mut seed = [0_u8; 32];
            getrandom::fill(&mut seed).map_err(|_| {
                CliError::new(
                    "secure_random_unavailable",
                    "the operating system CSPRNG is unavailable; no variant seed was generated",
                )
            })?;
            let encoded = hex_encode(&seed);
            seed.zeroize();
            (encoded, true)
        }
    };
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    let body = json!({
        "product_id": product,
        "app_version": args.app_version,
        "build_fingerprint": args.build_fingerprint,
        "channel": args.channel,
        "manifest_root_hex": args.manifest_root_hex,
        "module_digest_hex": args.module_digest_hex,
        "variant_seed_hex": variant_seed_hex,
    });
    let response = client.post(
        "/v1/admin/releases",
        &[],
        &body,
        Some(&args.idempotency_key),
    )?;
    let mut output = remote::output("release.register", response);
    if let Some(object) = output.json.as_object_mut() {
        object.insert("variant_seed_hex".to_owned(), json!(variant_seed_hex));
        object.insert("variant_seed_shown_once".to_owned(), json!(true));
        object.insert("variant_seed_generated".to_owned(), json!(generated));
    }
    let release = output.json.get("release").cloned().unwrap_or(Value::Null);
    let release_id = release
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    let variant_id = release
        .get("variant_id")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut human = format!(
        "registered release {release_id} ({} {}, channel {})\nvariant_id: {variant_id}",
        product, args.app_version, args.channel
    );
    if output.json.get("variant_reused").and_then(Value::as_bool) == Some(true) {
        human.push_str("\nvariant reused from the product's first active release (variant_stable)");
    } else {
        human.push_str(&format!(
            "\nvariant seed (shown once, embed it in the build as variant_const): {variant_seed_hex}"
        ));
    }
    if output
        .json
        .get("already_registered")
        .and_then(Value::as_bool)
        == Some(true)
    {
        human.push_str("\nthis build was already registered; returning the existing release");
    }
    human.push_str(&warnings_text(&output.json));
    output.human = human;
    Ok(output)
}

fn list(args: &ReleaseListArgs) -> Result<Output, CliError> {
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    remote::output_result(
        "release.list",
        client.get("/v1/admin/releases", &[("product_id", product)]),
    )
}

fn show(args: &ReleaseShowArgs) -> Result<Output, CliError> {
    remote::validate_identifier("release id", &args.release_id, 128)?;
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    remote::output_result(
        "release.show",
        client.get(
            &format!("/v1/admin/releases/{}", args.release_id),
            &[("product_id", product)],
        ),
    )
}

fn deprecate(args: &ReleaseDeprecateArgs) -> Result<Output, CliError> {
    remote::validate_identifier("release id", &args.release_id, 128)?;
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    let query = [
        ("product_id", product),
        ("dry_run", (!args.confirm).to_string()),
    ];
    let response = client.post(
        &format!("/v1/admin/releases/{}/deprecate", args.release_id),
        &query,
        &json!({}),
        args.idempotency_key.as_deref(),
    )?;
    Ok(lifecycle_output("release.deprecate", response))
}

fn mark_compromised(args: &ReleaseCompromisedArgs) -> Result<Output, CliError> {
    remote::validate_identifier("release id", &args.release_id, 128)?;
    if !matches!(args.action.as_str(), "warn" | "force_upgrade" | "revoke") {
        return Err(CliError::new(
            "invalid_action",
            "--action must be warn, force_upgrade, or revoke",
        ));
    }
    if args.confirm && args.action == "revoke" && !args.ack_revoke {
        return Err(CliError::new(
            "acknowledgement_required",
            "confirming --action revoke also requires --ack-revoke (immediate device kill)",
        ));
    }
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    let query = [
        ("product_id", product),
        ("dry_run", (!args.confirm).to_string()),
    ];
    let body = json!({
        "action": args.action,
        "bump_security_floor": args.bump_security_floor,
        "acknowledge_revoke": args.action == "revoke" && args.ack_revoke,
    });
    let response = client.post(
        &format!("/v1/admin/releases/{}/mark-compromised", args.release_id),
        &query,
        &body,
        args.idempotency_key.as_deref(),
    )?;
    Ok(lifecycle_output("release.mark-compromised", response))
}

/// Human rendering of a lifecycle response, following `versioning-and-variants.md` §4.2:
/// the dry-run leads with the impact, and the confirm hint comes last.
fn lifecycle_output(command: &str, response: remote::ApiResponse) -> Output {
    let mut output = remote::output(command, response);
    let json = &output.json;
    let Some(release) = json.get("release") else {
        return output;
    };
    let release_id = release.get("id").and_then(Value::as_str).unwrap_or("?");
    let product_id = release
        .get("product_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let app_version = release
        .get("app_version")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let variant_id = release
        .get("variant_id")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let published_at = release
        .get("published_at")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let action = json.get("action").and_then(Value::as_str).unwrap_or("?");
    let devices = json
        .pointer("/impact/devices")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let recent = json
        .pointer("/impact/checkins_last_7d")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    if json.get("dry_run").and_then(Value::as_bool) == Some(true) {
        let mut human = format!(
            "[DRY RUN] impact of {action} on {release_id}:\n\
             \x20 release:  {release_id} ({product_id} {app_version}, variant {variant_id}, published at {published_at})\n\
             \x20 devices:  {devices} ({recent} checked in during the last 7 days)\n\
             \x20 action:   {action}"
        );
        if let Some(effects) = json.get("effects").and_then(Value::as_array) {
            for effect in effects.iter().filter_map(Value::as_str) {
                human.push_str(&format!("\n  - {effect}"));
            }
        }
        if let Some(next) = json.pointer("/security_floor/next").and_then(Value::as_i64) {
            let current = json
                .pointer("/security_floor/current")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            human.push_str(&format!("\n  security floor: {current} -> {next}"));
        }
        if json
            .get("requires_acknowledgement")
            .and_then(Value::as_bool)
            == Some(true)
        {
            human.push_str(
                "\n  revoke disables devices immediately; confirming requires --ack-revoke",
            );
        }
        human.push_str("\nre-run with --confirm to apply");
        output.human = human;
    } else {
        output.human = format!(
            "{action} applied to {release_id} ({product_id} {app_version}); \
             {devices} devices affected ({recent} checked in during the last 7 days)"
        );
    }
    output
}

fn warnings_text(json: &Value) -> String {
    let mut text = String::new();
    if let Some(warnings) = json.get("warnings").and_then(Value::as_array) {
        for warning in warnings.iter().filter_map(|warning| warning.get("message")) {
            if let Some(message) = warning.as_str() {
                text.push_str(&format!("\nwarning: {message}"));
            }
        }
    }
    text
}

fn validate_app_version(value: &str) -> Result<(), CliError> {
    if !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_identifier",
            "app version must be 1-64 ASCII letters, digits, dots, hyphens, or plus signs",
        ))
    }
}

fn validate_build_fingerprint(value: &str) -> Result<(), CliError> {
    if !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'+')
        })
    {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_identifier",
            "build fingerprint must be 1-128 ASCII letters, digits, or . _ - : +",
        ))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(HEX_32_BYTES);
    for byte in bytes {
        let high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let low = HEX.get(usize::from(byte & 0x0f)).copied().unwrap_or(b'0');
        encoded.push(char::from(high));
        encoded.push(char::from(low));
    }
    encoded
}
