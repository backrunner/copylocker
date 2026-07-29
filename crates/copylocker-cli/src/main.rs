//! CopyLocker administration and development CLI.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod admin_cli;
mod bootstrap;
mod catalog_cli;
mod inspect;
mod keys;
mod project;
mod remote;

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use copylocker_server_core::simulator::{simulate, Scenario};
use copylocker_server_core::version::ReleaseRegistry;
use copylocker_server_core::{resolve, Catalog, Policy, Preset};
use copylocker_suite_std::ClStd1;
use copylocker_suite_testkit::kat::{generate, replay, VectorFile};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

const DEFAULT_VECTOR_PATH: &str = "vectors/CL-STD-1/kat.json";

#[derive(Debug, Parser)]
#[command(
    name = "copylocker",
    version,
    about = "Administer CopyLocker and verify its protocol artifacts",
    arg_required_else_help = true
)]
struct Cli {
    /// Emit a stable JSON object on stdout.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a deployable CopyLocker server project from the embedded template.
    Init(project::InitArgs),
    /// Validate or deploy an initialized CopyLocker server project.
    Deploy(project::DeployArgs),
    /// Create the first vendor, product, and Admin credential safely.
    Bootstrap(bootstrap::BootstrapArgs),
    /// Report local readiness and optionally probe the configured Admin API.
    Doctor(DoctorArgs),
    /// Generate root, epoch, and build signing key material.
    Keygen(keys::KeygenArgs),
    /// Create and evolve a versioned entitlement catalog.
    Catalog(catalog_cli::CatalogArgs),
    /// Generate and verify known-answer test vectors.
    Kat(KatArgs),
    /// Create, validate, and simulate five-axis licensing policies.
    Policy(PolicyArgs),
    /// Issue and administer licenses through the remote Admin API.
    License(admin_cli::LicenseArgs),
    /// Upload, inspect, rotate, and revoke signing epochs.
    Epoch(admin_cli::EpochArgs),
    /// Decode a canonical CBOR artifact or signed envelope without trusting it.
    Inspect(inspect::InspectArgs),
    /// Send a narrow authenticated request to the configured Admin API.
    Request(remote::RequestArgs),
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// KAT file to inspect.
    #[arg(long, default_value = DEFAULT_VECTOR_PATH)]
    vectors: PathBuf,
    #[command(flatten)]
    connection: remote::ConnectionArgs,
    /// Make one authenticated, read-only Admin API request.
    #[arg(long)]
    check_api: bool,
}

#[derive(Debug, Args)]
struct KatArgs {
    #[command(subcommand)]
    command: KatCommand,
}

#[derive(Debug, Subcommand)]
enum KatCommand {
    /// Generate the deterministic CL-STD-1 vector file.
    Generate(KatGenerateArgs),
    /// Replay a committed vector file against the current suite.
    Verify(KatFileArgs),
    /// Fail if a committed vector file differs from current deterministic output.
    Check(KatFileArgs),
}

#[derive(Debug, Args)]
struct KatGenerateArgs {
    /// Destination JSON file.
    #[arg(long)]
    out: PathBuf,

    /// Replace an existing file. Without this flag, generation is create-only.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct KatFileArgs {
    /// Vector JSON file.
    #[arg(long)]
    file: PathBuf,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// List the built-in policy presets.
    Presets,
    /// Create a JSON policy from a named preset.
    Create(PolicyCreateArgs),
    /// Validate a policy against its entitlement catalog.
    Validate(PolicyValidateArgs),
    /// Run a scenario through the same logic used by the live server.
    Simulate(PolicySimulateArgs),
    /// List remote policies for a product.
    List(admin_cli::PolicyListArgs),
    /// Show one remote policy.
    Show(admin_cli::PolicyShowArgs),
    /// Create a remote policy from a JSON file.
    Push(admin_cli::PolicyWriteArgs),
    /// Replace a remote policy from a JSON file.
    Update(admin_cli::PolicyWriteArgs),
}

#[derive(Debug, Args)]
struct PolicyCreateArgs {
    /// One of the names printed by `policy presets`.
    #[arg(long)]
    preset: String,
    /// Policy identifier.
    #[arg(long)]
    id: String,
    /// Product identifier.
    #[arg(long)]
    product: String,
    /// Initial tier identifier.
    #[arg(long)]
    tier: String,
    /// Unix timestamp used for date-derived preset fields.
    #[arg(long)]
    at: i64,
    /// Destination JSON file.
    #[arg(long)]
    out: PathBuf,
    /// Replace an existing file.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct PolicyValidateArgs {
    /// Policy JSON file.
    #[arg(long)]
    policy: PathBuf,
    /// Catalog JSON file for the same product.
    #[arg(long)]
    catalog: PathBuf,
    /// Unix timestamp used to resolve time-limited grants.
    #[arg(long)]
    at: i64,
}

#[derive(Debug, Args)]
struct PolicySimulateArgs {
    /// Policy JSON file.
    #[arg(long)]
    policy: PathBuf,
    /// Catalog JSON file for the same product.
    #[arg(long)]
    catalog: PathBuf,
    /// Release registry JSON file.
    #[arg(long)]
    releases: PathBuf,
    /// Scenario JSON file.
    #[arg(long)]
    scenario: PathBuf,
}

#[derive(Debug)]
pub(crate) struct CliError {
    pub(crate) code: String,
    pub(crate) message: String,
}

impl CliError {
    pub(crate) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub(crate) fn io(action: &'static str, path: &Path, error: &std::io::Error) -> Self {
        Self::new(
            "io_error",
            format!("failed to {action} {}: {error}", path.display()),
        )
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let json_requested = args.iter().any(|arg| arg == "--json");
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let exit_code = u8::try_from(error.exit_code()).unwrap_or(2);
            if json_requested {
                emit_json(&json!({
                    "ok": false,
                    "error": {
                        "code": "invalid_arguments",
                        "message": error.to_string()
                    }
                }));
            } else if let Err(print_error) = error.print() {
                eprintln!("copylocker: failed to print argument error: {print_error}");
            }
            return ExitCode::from(exit_code);
        }
    };

    match run(&cli) {
        Ok(output) => {
            if cli.json {
                emit_json(&output.json);
            } else {
                println!("{}", output.human);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            if cli.json {
                emit_json(&json!({
                    "ok": false,
                    "error": { "code": error.code, "message": error.message }
                }));
            } else {
                eprintln!("copylocker: {error}");
            }
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug)]
pub(crate) struct Output {
    pub(crate) human: String,
    pub(crate) json: Value,
}

fn run(cli: &Cli) -> Result<Output, CliError> {
    match &cli.command {
        Command::Init(args) => project::init(args),
        Command::Deploy(args) => project::deploy(args),
        Command::Bootstrap(args) => bootstrap::run(args),
        Command::Doctor(args) => doctor(args),
        Command::Keygen(args) => keys::run(args),
        Command::Catalog(args) => catalog_cli::run(args),
        Command::Kat(args) => match &args.command {
            KatCommand::Generate(args) => generate_vectors(&args.out, args.force),
            KatCommand::Verify(args) => verify_vectors(&args.file),
            KatCommand::Check(args) => check_vectors(&args.file),
        },
        Command::Policy(args) => match &args.command {
            PolicyCommand::Presets => list_policy_presets(),
            PolicyCommand::Create(args) => create_policy(args),
            PolicyCommand::Validate(args) => validate_policy(args),
            PolicyCommand::Simulate(args) => simulate_policy(args),
            PolicyCommand::List(args) => admin_cli::policy_list(args),
            PolicyCommand::Show(args) => admin_cli::policy_show(args),
            PolicyCommand::Push(args) => admin_cli::policy_push(args),
            PolicyCommand::Update(args) => admin_cli::policy_update(args),
        },
        Command::License(args) => admin_cli::run_license(args),
        Command::Epoch(args) => admin_cli::run_epoch(args),
        Command::Inspect(args) => inspect::run(args),
        Command::Request(args) => remote::run_request(args),
    }
}

fn doctor(args: &DoctorArgs) -> Result<Output, CliError> {
    let path = &args.vectors;
    let vector_status = if path.is_file() {
        match load_vectors(path).and_then(|file| replay_vectors(path, &file)) {
            Ok(count) => json!({ "status": "ok", "vectors": count }),
            Err(error) => json!({
                "status": "invalid",
                "error": { "code": error.code, "message": error.message }
            }),
        }
    } else {
        json!({
            "status": "missing",
            "next": format!(
                "copylocker kat generate --out {}",
                path.display()
            )
        })
    };
    let ready = vector_status.get("status").and_then(Value::as_str) == Some("ok");
    let config_path = project::find_project_config(&args.connection.project);
    let (project_status, token_env) = match config_path.as_deref() {
        Some(config_path) => match project::load_project_config(config_path) {
            Ok(config) => {
                let project_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
                let wrangler =
                    project_dir
                        .join("node_modules")
                        .join(".bin")
                        .join(if cfg!(windows) {
                            "wrangler.cmd"
                        } else {
                            "wrangler"
                        });
                let token_env = config.admin_token_env.clone();
                (
                    json!({
                        "status": "ok",
                        "path": config_path,
                        "project_name": config.project_name,
                        "product_id": config.product_id,
                        "api_url": config.api_url,
                        "wrangler_installed": wrangler.is_file()
                    }),
                    token_env,
                )
            }
            Err(error) => (
                json!({
                    "status": "invalid",
                    "path": config_path,
                    "error": { "code": error.code, "message": error.message }
                }),
                args.connection
                    .admin_token_env
                    .clone()
                    .unwrap_or_else(|| String::from("COPYLOCKER_ADMIN_TOKEN")),
            ),
        },
        None => (
            json!({
                "status": "missing",
                "searched_from": args.connection.project,
                "next": "copylocker init --help"
            }),
            args.connection
                .admin_token_env
                .clone()
                .unwrap_or_else(|| String::from("COPYLOCKER_ADMIN_TOKEN")),
        ),
    };
    let token_env = args.connection.admin_token_env.clone().unwrap_or(token_env);
    let auth_available = std::env::var_os(&token_env).is_some();
    let api_url = args
        .connection
        .api_url
        .clone()
        .or_else(|| std::env::var("COPYLOCKER_API_URL").ok())
        .or_else(|| {
            config_path
                .as_deref()
                .and_then(|path| project::load_project_config(path).ok())
                .and_then(|config| config.api_url)
        });
    let api_source = if args.connection.api_url.is_some() {
        "argument"
    } else if std::env::var_os("COPYLOCKER_API_URL").is_some() {
        "env"
    } else if api_url.is_some() {
        "project"
    } else {
        "missing"
    };
    let reachability = if args.check_api {
        match remote::AdminClient::connect(&args.connection).and_then(|client| {
            let product = client.product_id(None)?;
            let token_env = client.token_env().to_owned();
            client
                .get(
                    "/v1/admin/catalog/features",
                    &[("product_id", product.clone())],
                )
                .map(|response| {
                    json!({
                        "status": "ok",
                        "http_status": response.status,
                        "product_id": product,
                        "auth_env": token_env
                    })
                })
        }) {
            Ok(result) => result,
            Err(error) => json!({
                "status": "failed",
                "error": { "code": error.code, "message": error.message }
            }),
        }
    } else {
        json!({"status": "not_checked"})
    };
    let api_ready =
        !args.check_api || reachability.get("status").and_then(Value::as_str) == Some("ok");
    let ready = ready && api_ready;
    Ok(Output {
        human: if ready {
            format!("ready: {} is valid", path.display())
        } else {
            format!("not ready: inspect {}", path.display())
        },
        json: json!({
            "ok": true,
            "command": "doctor",
            "offline": !args.check_api,
            "auth_required": args.check_api,
            "version": env!("CARGO_PKG_VERSION"),
            "ready": ready,
            "kat": { "path": path, "result": vector_status },
            "project": project_status,
            "api": {
                "configured": api_url.is_some(),
                "url": api_url,
                "source": api_source,
                "reachability": reachability
            },
            "auth": {
                "available": auth_available,
                "source": if auth_available { "environment_variable" } else { "missing" },
                "env": token_env
            }
        }),
    })
}

fn generate_vectors(path: &Path, force: bool) -> Result<Output, CliError> {
    let file = generate::<ClStd1>();
    let bytes = vector_bytes(&file)?;
    write_output_file(path, &bytes, force)?;

    let count = vector_count(&file);
    Ok(Output {
        human: format!("wrote {count} CL-STD-1 vectors to {}", path.display()),
        json: json!({
            "ok": true,
            "command": "kat.generate",
            "suite_id": file.suite_id,
            "suite_name": file.suite_name,
            "vectors": count,
            "bytes": bytes.len(),
            "path": path
        }),
    })
}

pub(crate) fn write_output_file(path: &Path, bytes: &[u8], force: bool) -> Result<(), CliError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| CliError::io("create directory", parent, &error))?;
    }

    let mut options = fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut destination = options.open(path).map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::AlreadyExists {
            "file_exists"
        } else {
            "io_error"
        };
        CliError::new(
            code,
            if code == "file_exists" {
                format!(
                    "{} already exists; pass --force to replace it",
                    path.display()
                )
            } else {
                format!("failed to create {}: {error}", path.display())
            },
        )
    })?;
    destination
        .write_all(bytes)
        .map_err(|error| CliError::io("write", path, &error))?;
    destination
        .sync_all()
        .map_err(|error| CliError::io("sync", path, &error))?;
    Ok(())
}

fn verify_vectors(path: &Path) -> Result<Output, CliError> {
    let file = load_vectors(path)?;
    let count = replay_vectors(path, &file)?;
    Ok(Output {
        human: format!("verified {count} vectors from {}", path.display()),
        json: json!({
            "ok": true,
            "command": "kat.verify",
            "suite_id": file.suite_id,
            "suite_name": file.suite_name,
            "vectors": count,
            "path": path
        }),
    })
}

fn check_vectors(path: &Path) -> Result<Output, CliError> {
    let actual = fs::read(path).map_err(|error| CliError::io("read", path, &error))?;
    let generated = generate::<ClStd1>();
    let expected = vector_bytes(&generated)?;
    if actual != expected {
        return Err(CliError::new(
            "kat_drift",
            format!(
                "{} differs from current deterministic output; review the protocol change and regenerate explicitly",
                path.display()
            ),
        ));
    }
    let count = replay_vectors(path, &generated)?;
    Ok(Output {
        human: format!("{} is current ({count} vectors)", path.display()),
        json: json!({
            "ok": true,
            "command": "kat.check",
            "suite_id": generated.suite_id,
            "suite_name": generated.suite_name,
            "vectors": count,
            "path": path
        }),
    })
}

fn list_policy_presets() -> Result<Output, CliError> {
    let presets: Vec<&str> = Preset::ALL.into_iter().map(Preset::as_str).collect();
    Ok(Output {
        human: format!("available policy presets:\n{}", presets.join("\n")),
        json: json!({
            "ok": true,
            "command": "policy.presets",
            "presets": presets
        }),
    })
}

fn create_policy(args: &PolicyCreateArgs) -> Result<Output, CliError> {
    let preset = Preset::parse(&args.preset).ok_or_else(|| {
        CliError::new(
            "invalid_preset",
            format!(
                "unknown preset `{}`; run `copylocker policy presets` to list valid names",
                args.preset
            ),
        )
    })?;
    let policy = preset.build(&args.id, &args.product, &args.tier, args.at);
    policy.validate().map_err(|error| {
        CliError::new(
            "invalid_policy",
            format!(
                "preset `{}` produced an invalid policy: {error}",
                args.preset
            ),
        )
    })?;
    let warnings = policy_warning_values(&policy);
    let bytes = pretty_json_bytes(&policy)?;
    write_output_file(&args.out, &bytes, args.force)?;

    Ok(Output {
        human: format!(
            "created policy {} from {} at {}",
            policy.id,
            preset.as_str(),
            args.out.display()
        ),
        json: json!({
            "ok": true,
            "command": "policy.create",
            "path": args.out,
            "bytes": bytes.len(),
            "policy": &policy,
            "warnings": warnings
        }),
    })
}

fn validate_policy(args: &PolicyValidateArgs) -> Result<Output, CliError> {
    let policy: Policy = load_config_json(&args.policy, "invalid_policy_json", "policy")?;
    let catalog: Catalog = load_config_json(&args.catalog, "invalid_catalog_json", "catalog")?;
    validate_policy_pair(&policy, &catalog)?;
    let resolved = resolve(&catalog, &policy.entitlement, args.at).map_err(|error| {
        CliError::new(
            "invalid_policy",
            format!(
                "policy {} cannot resolve against {}: {error}",
                args.policy.display(),
                args.catalog.display()
            ),
        )
    })?;
    let warnings = policy_warning_values(&policy);

    Ok(Output {
        human: format!(
            "policy {} is valid: tier={}, features={}, limits={}, warnings={}",
            policy.id,
            resolved.tier_id,
            resolved.features.len(),
            resolved.limits.len(),
            warnings.len()
        ),
        json: json!({
            "ok": true,
            "command": "policy.validate",
            "policy_id": policy.id,
            "product_id": policy.product_id,
            "catalog_version": resolved.catalog_version,
            "resolved": {
                "tier_id": resolved.tier_id,
                "tier_label": resolved.tier_label,
                "features": resolved.features,
                "limits": resolved.limits
            },
            "warnings": warnings
        }),
    })
}

fn simulate_policy(args: &PolicySimulateArgs) -> Result<Output, CliError> {
    let policy: Policy = load_config_json(&args.policy, "invalid_policy_json", "policy")?;
    let catalog: Catalog = load_config_json(&args.catalog, "invalid_catalog_json", "catalog")?;
    let registry: ReleaseRegistry =
        load_config_json(&args.releases, "invalid_releases_json", "release registry")?;
    let scenario: Scenario = load_config_json(&args.scenario, "invalid_scenario_json", "scenario")?;

    validate_policy_pair(&policy, &catalog)?;
    if let Some(release) = registry
        .releases
        .iter()
        .find(|release| release.product_id != policy.product_id)
    {
        return Err(CliError::new(
            "invalid_releases",
            format!(
                "release `{}` belongs to product `{}`, not `{}`",
                release.id, release.product_id, policy.product_id
            ),
        ));
    }
    validate_scenario_order(&scenario)?;

    let simulation = simulate(&policy, &catalog, &registry, &scenario).map_err(|error| {
        CliError::new(
            "simulation_failed",
            format!("scenario `{}` failed: {error}", scenario.name),
        )
    })?;
    let human = simulation.render().trim_end().to_string();
    Ok(Output {
        human,
        json: json!({
            "ok": true,
            "command": "policy.simulate",
            "policy_id": policy.id,
            "product_id": policy.product_id,
            "simulation": simulation
        }),
    })
}

fn validate_scenario_order(scenario: &Scenario) -> Result<(), CliError> {
    if !scenario.steps.is_sorted_by_key(|step| step.at()) {
        return Err(CliError::new(
            "invalid_scenario",
            format!(
                "scenario `{}` is not ordered by ascending `at` timestamps",
                scenario.name
            ),
        ));
    }
    Ok(())
}

fn validate_policy_pair(policy: &Policy, catalog: &Catalog) -> Result<(), CliError> {
    policy.validate().map_err(|error| {
        CliError::new(
            "invalid_policy",
            format!("policy `{}` is invalid: {error}", policy.id),
        )
    })?;
    catalog.validate().map_err(|error| {
        CliError::new(
            "invalid_catalog",
            format!("catalog `{}` is invalid: {error}", catalog.product_id),
        )
    })?;
    if policy.product_id != catalog.product_id {
        return Err(CliError::new(
            "product_mismatch",
            format!(
                "policy `{}` belongs to product `{}`, but catalog belongs to `{}`",
                policy.id, policy.product_id, catalog.product_id
            ),
        ));
    }
    Ok(())
}

fn policy_warning_values(policy: &Policy) -> Vec<Value> {
    policy
        .warnings()
        .into_iter()
        .map(|warning| json!({ "id": warning.id, "message": warning.message }))
        .collect()
}

pub(crate) fn load_config_json<T: DeserializeOwned>(
    path: &Path,
    code: &'static str,
    kind: &str,
) -> Result<T, CliError> {
    let bytes = fs::read(path).map_err(|error| CliError::io("read", path, &error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        CliError::new(
            code,
            format!("failed to parse {kind} {}: {error}", path.display()),
        )
    })
}

pub(crate) fn pretty_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CliError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        CliError::new(
            "json_encode_failed",
            format!("failed to encode JSON output: {error}"),
        )
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn load_vectors(path: &Path) -> Result<VectorFile, CliError> {
    let bytes = fs::read(path).map_err(|error| CliError::io("read", path, &error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        CliError::new(
            "invalid_vector_json",
            format!("failed to parse {}: {error}", path.display()),
        )
    })
}

fn replay_vectors(path: &Path, file: &VectorFile) -> Result<usize, CliError> {
    replay::<ClStd1>(file).map_err(|error| {
        CliError::new(
            "kat_failed",
            format!("{} failed verification: {error}", path.display()),
        )
    })
}

fn vector_bytes(file: &VectorFile) -> Result<Vec<u8>, CliError> {
    let mut bytes = serde_json::to_vec_pretty(file).map_err(|error| {
        CliError::new(
            "json_encode_failed",
            format!("failed to encode deterministic vectors: {error}"),
        )
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn vector_count(file: &VectorFile) -> usize {
    file.signatures.len()
        + file.kem.len()
        + file.aead.len()
        + file.kdf.len()
        + file.fingerprints.len()
        + file.artifacts.len()
        + file.chains.len()
}

fn emit_json(value: &Value) {
    println!("{value}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_server_core::simulator::ScenarioStep;

    #[test]
    fn generated_vectors_are_stable_and_replay() {
        let a = generate::<ClStd1>();
        let b = generate::<ClStd1>();
        assert_eq!(vector_bytes(&a).unwrap(), vector_bytes(&b).unwrap());
        assert_eq!(replay::<ClStd1>(&a).unwrap(), vector_count(&a));
    }

    #[test]
    fn help_names_the_offline_workflow() {
        use clap::CommandFactory as _;
        let mut command = Cli::command();
        let mut help = Vec::new();
        command.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(help.contains("doctor"));
        assert!(help.contains("kat"));
        assert!(help.contains("--json"));
    }

    #[test]
    fn policy_presets_lists_all_eleven_presets() {
        let output = list_policy_presets().unwrap();
        let presets = output
            .json
            .get("presets")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(presets.len(), Preset::ALL.len());
        assert_eq!(presets.len(), 11);
        for preset in Preset::ALL {
            assert!(presets.iter().any(|value| value == preset.as_str()));
        }
    }

    #[test]
    fn every_policy_preset_round_trips_through_json() {
        for preset in Preset::ALL {
            let policy = preset.build("policy", "product", "pro", 1_767_225_600);
            let bytes = pretty_json_bytes(&policy).unwrap();
            let decoded: Policy = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(decoded, policy, "{} did not round-trip", preset.as_str());
        }
    }

    #[test]
    fn malformed_policy_json_has_a_stable_error_code() {
        let path = temporary_path("malformed-policy.json");
        fs::write(&path, b"{").unwrap();

        let error = load_config_json::<Policy>(&path, "invalid_policy_json", "policy")
            .expect_err("malformed JSON must be rejected");

        assert_eq!(error.code, "invalid_policy_json");
        assert!(error.message.contains(&path.display().to_string()));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn policy_and_catalog_products_must_match() {
        let policy = Preset::Perpetual.build("policy", "desktop", "pro", 1_767_225_600);
        let catalog: Catalog = serde_json::from_value(json!({
            "product_id": "web",
            "version": 1,
            "tiers": [{
                "id": "pro",
                "label": "Pro",
                "rank": 1,
                "groups": [],
                "features": [],
                "limits": {}
            }]
        }))
        .unwrap();

        let error = validate_policy_pair(&policy, &catalog)
            .expect_err("cross-product policy resolution must be rejected");

        assert_eq!(error.code, "product_mismatch");
        assert!(error.message.contains("desktop"));
        assert!(error.message.contains("web"));
    }

    #[test]
    fn scenario_steps_must_be_chronological() {
        let scenario = Scenario {
            name: "out of order".to_string(),
            steps: vec![
                ScenarioStep::Activate { at: 20 },
                ScenarioStep::RunRelease {
                    at: 10,
                    release_id: "release".to_string(),
                },
            ],
        };

        let error =
            validate_scenario_order(&scenario).expect_err("descending timestamps must be rejected");

        assert_eq!(error.code, "invalid_scenario");
        assert!(error.message.contains("out of order"));
    }

    fn temporary_path(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "copylocker-cli-{}-{}-{name}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }
}
