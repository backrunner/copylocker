use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use clap::{Args, Subcommand};
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{keys, project, remote, CliError, Output};

const DEFAULT_TOKEN_LIFETIME: i64 = 90 * 24 * 60 * 60;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const ADMIN_SCOPES: &[&str] = &[
    "products:rw",
    "catalog:rw",
    "policies:rw",
    "licenses:rw",
    "machines:rw",
    "revoke",
    "releases:rw",
    "epochs:rw",
    "audit:r",
    "analytics:r",
    "sign:manifest",
];

#[derive(Debug, Args)]
pub(crate) struct BootstrapArgs {
    #[command(subcommand)]
    command: BootstrapCommand,
}

#[derive(Debug, Subcommand)]
enum BootstrapCommand {
    /// Generate a recoverable mode-0600 bootstrap credential bundle.
    Prepare(PrepareArgs),
    /// Apply a prepared bundle to Secrets Store and D1.
    Apply(ApplyArgs),
}

#[derive(Debug, Args)]
struct PrepareArgs {
    /// Initialized CopyLocker project directory.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Initial vendor identifier.
    #[arg(long)]
    vendor: String,
    /// Human or service actor recorded for the initial Admin token.
    #[arg(long)]
    actor: String,
    /// Optional exclusive Unix expiry timestamp. Defaults to 90 days.
    #[arg(long)]
    expires_at: Option<i64>,
    /// New mode-0600 file that receives the token and pepper.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    /// Initialized CopyLocker project directory.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Bootstrap bundle created by `bootstrap prepare`.
    #[arg(long)]
    bundle: PathBuf,
    /// Apply remote Secrets Store and D1 changes.
    #[arg(long)]
    confirm: bool,
    /// Assert that ADMIN_TOKEN_PEPPER was already uploaded from this exact bundle.
    #[arg(long, requires = "confirm")]
    skip_secret_upload: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapBundle {
    schema_version: u8,
    project_name: String,
    product_id: String,
    secret_store_id: String,
    vendor_id: String,
    actor: String,
    token_id: String,
    admin_token: String,
    admin_token_pepper: Vec<u8>,
    scopes: Vec<String>,
    created_at: i64,
    expires_at: i64,
}

impl Drop for BootstrapBundle {
    fn drop(&mut self) {
        self.admin_token.zeroize();
        self.admin_token_pepper.zeroize();
    }
}

pub(crate) fn run(args: &BootstrapArgs) -> Result<Output, CliError> {
    match &args.command {
        BootstrapCommand::Prepare(args) => prepare(args),
        BootstrapCommand::Apply(args) => apply(args),
    }
}

fn prepare(args: &PrepareArgs) -> Result<Output, CliError> {
    remote::validate_identifier("vendor id", &args.vendor, 128)?;
    remote::validate_identifier("actor", &args.actor, 128)?;
    let project_dir = project::canonical_project_dir(&args.project)?;
    let config = project::load_project_config(&project_dir)?;
    let secret_store_id = config.secret_store_id.clone().ok_or_else(|| {
        CliError::new(
            "secret_store_id_missing",
            "copylocker.json has no secret_store_id; regenerate the project or add its 32-character Secrets Store ID",
        )
    })?;
    let created_at = now_seconds()?;
    let expires_at = args
        .expires_at
        .unwrap_or_else(|| created_at.saturating_add(DEFAULT_TOKEN_LIFETIME));
    if expires_at <= created_at || expires_at > MAX_SAFE_INTEGER {
        return Err(CliError::new(
            "invalid_token_expiry",
            "bootstrap token expiry must be a future JavaScript-safe Unix timestamp",
        ));
    }

    let mut token_bytes = [0_u8; 32];
    let mut pepper = vec![0_u8; 32];
    getrandom::fill(&mut token_bytes).map_err(|_| secure_random_error())?;
    if let Err(error) = getrandom::fill(&mut pepper) {
        token_bytes.zeroize();
        pepper.zeroize();
        return Err(CliError::new(
            "secure_random_unavailable",
            format!("the operating system CSPRNG failed: {error}"),
        ));
    }
    let admin_token = format!("clat_{}", URL_SAFE_NO_PAD.encode(token_bytes));
    let token_id = format!("bootstrap-{}", hex::encode(&token_bytes[..8]));
    token_bytes.zeroize();
    if !remote::valid_token_format(&admin_token) {
        pepper.zeroize();
        return Err(CliError::new(
            "token_generation_failed",
            "generated Admin token did not satisfy the canonical wire format",
        ));
    }
    let bundle = BootstrapBundle {
        schema_version: 1,
        project_name: config.project_name.clone(),
        product_id: config.product_id.clone(),
        secret_store_id,
        vendor_id: args.vendor.clone(),
        actor: args.actor.clone(),
        token_id: token_id.clone(),
        admin_token,
        admin_token_pepper: pepper,
        scopes: ADMIN_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
        created_at,
        expires_at,
    };
    keys::write_serialized_secret(&args.out, &bundle)?;
    Ok(Output {
        human: format!(
            "prepared bootstrap credentials at {}\nkeep this mode-0600 file outside source control; apply it with `copylocker bootstrap apply --bundle {} --confirm`",
            args.out.display(),
            args.out.display()
        ),
        json: json!({
            "ok": true,
            "command": "bootstrap.prepare",
            "project_name": config.project_name,
            "product_id": config.product_id,
            "vendor_id": args.vendor,
            "actor": args.actor,
            "token_id": token_id,
            "expires_at": expires_at,
            "bundle": args.out,
            "contains_secrets": true
        }),
    })
}

fn apply(args: &ApplyArgs) -> Result<Output, CliError> {
    let project_dir = project::canonical_project_dir(&args.project)?;
    let config = project::load_project_config(&project_dir)?;
    let bundle = load_bundle(&args.bundle)?;
    validate_bundle(&bundle, &config)?;
    let planned_steps = if args.skip_secret_upload {
        vec!["migrate", "seed"]
    } else {
        vec!["upload_admin_token_pepper", "migrate", "seed"]
    };
    if !args.confirm {
        return Ok(Output {
            human: format!(
                "[DRY RUN] bootstrap {} for vendor {} using {}\nconfirm remote changes with --confirm",
                bundle.product_id,
                bundle.vendor_id,
                args.bundle.display()
            ),
            json: json!({
                "ok": true,
                "command": "bootstrap.apply",
                "dry_run": true,
                "project_name": bundle.project_name,
                "product_id": bundle.product_id,
                "vendor_id": bundle.vendor_id,
                "token_id": bundle.token_id,
                "steps": planned_steps
            }),
        });
    }

    let wrangler = project::wrangler_command(&project_dir)?;
    let mut steps = Vec::new();
    if !args.skip_secret_upload {
        steps.push(upload_admin_pepper(
            &wrangler,
            &project_dir,
            &bundle.secret_store_id,
            &bundle.admin_token_pepper,
        )?);
    }
    steps.push(run_wrangler_redacted(
        &wrangler,
        &project_dir,
        &[
            "d1".to_owned(),
            "migrations".to_owned(),
            "apply".to_owned(),
            config.project_name.clone(),
            "--remote".to_owned(),
        ],
        "bootstrap.migrate",
        None,
    )?);
    let sql = bootstrap_sql(&bundle)?;
    steps.push(run_wrangler_redacted(
        &wrangler,
        &project_dir,
        &[
            "d1".to_owned(),
            "execute".to_owned(),
            config.project_name.clone(),
            "--remote".to_owned(),
            "--yes".to_owned(),
            "--command".to_owned(),
            sql,
        ],
        "bootstrap.seed",
        None,
    )?);

    Ok(Output {
        human: format!(
            "bootstrapped product {} for vendor {}\nmove `admin_token` from {} into {} and then destroy or escrow the bundle",
            bundle.product_id,
            bundle.vendor_id,
            args.bundle.display(),
            config.admin_token_env
        ),
        json: json!({
            "ok": true,
            "command": "bootstrap.apply",
            "dry_run": false,
            "project_name": bundle.project_name,
            "product_id": bundle.product_id,
            "vendor_id": bundle.vendor_id,
            "token_id": bundle.token_id,
            "token_env": config.admin_token_env,
            "bundle": args.bundle,
            "steps": steps
        }),
    })
}

fn load_bundle(path: &Path) -> Result<BootstrapBundle, CliError> {
    ensure_private_file(path)?;
    let mut bytes = fs::read(path).map_err(|error| CliError::io("read", path, &error))?;
    let parsed = serde_json::from_slice(&bytes);
    bytes.zeroize();
    parsed.map_err(|_| {
        CliError::new(
            "invalid_bootstrap_bundle",
            format!("{} is not a CopyLocker bootstrap bundle", path.display()),
        )
    })
}

fn validate_bundle(
    bundle: &BootstrapBundle,
    config: &project::ProjectConfig,
) -> Result<(), CliError> {
    let now = now_seconds()?;
    let valid_scopes = !bundle.scopes.is_empty()
        && bundle.scopes.iter().all(|scope| {
            ADMIN_SCOPES.contains(&scope.as_str())
                && bundle.scopes.iter().filter(|item| *item == scope).count() == 1
        });
    if bundle.schema_version != 1
        || bundle.project_name != config.project_name
        || bundle.product_id != config.product_id
        || config.secret_store_id.as_deref() != Some(bundle.secret_store_id.as_str())
        || remote::validate_identifier("vendor id", &bundle.vendor_id, 128).is_err()
        || remote::validate_identifier("actor", &bundle.actor, 128).is_err()
        || remote::validate_identifier("token id", &bundle.token_id, 128).is_err()
        || !remote::valid_token_format(&bundle.admin_token)
        || bundle.admin_token_pepper.len() != 32
        || !valid_scopes
        || bundle.created_at < 0
        || bundle.expires_at <= now
        || bundle.expires_at > MAX_SAFE_INTEGER
    {
        return Err(CliError::new(
            "invalid_bootstrap_bundle",
            "bootstrap bundle is malformed, expired, or belongs to another project",
        ));
    }
    Ok(())
}

fn bootstrap_sql(bundle: &BootstrapBundle) -> Result<String, CliError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&bundle.admin_token_pepper).map_err(|_| {
        CliError::new(
            "invalid_bootstrap_bundle",
            "bootstrap pepper has an invalid HMAC key shape",
        )
    })?;
    mac.update(bundle.admin_token.as_bytes());
    let token_hmac = hex::encode(mac.finalize().into_bytes());
    let scopes = serde_json::to_string(&bundle.scopes).map_err(|error| {
        CliError::new(
            "json_encode_failed",
            format!("failed to encode bootstrap scopes: {error}"),
        )
    })?;
    let suite_id = hex::encode(copylocker_suite_std::CL_STD_1_SUITE_ID.as_bytes());
    Ok(format!(
        "INSERT INTO vendors(id,name,fpr_salt_ref,created_at) VALUES ({vendor},{vendor_name},'FPR_SALT',{created}) ON CONFLICT(id) DO NOTHING;\n\
         INSERT INTO products(id,vendor_id,name,min_suite_id,min_proto_ver,min_sdk_version,created_at) VALUES ({product},{vendor},{product_name},X'{suite}',1,'0.0.0',{created}) ON CONFLICT(id) DO UPDATE SET vendor_id=CASE WHEN products.vendor_id=excluded.vendor_id THEN products.vendor_id ELSE NULL END;\n\
         INSERT INTO admin_tokens(id,vendor_id,token_hmac,actor,scopes_json,not_before,expires_at,created_at) VALUES ({token_id},{vendor},X'{token_hmac}',{actor},{scopes},{created},{expires},{created}) ON CONFLICT(id) DO UPDATE SET token_hmac=CASE WHEN admin_tokens.vendor_id=excluded.vendor_id AND admin_tokens.token_hmac=excluded.token_hmac AND admin_tokens.actor=excluded.actor AND admin_tokens.scopes_json=excluded.scopes_json AND admin_tokens.not_before=excluded.not_before AND admin_tokens.expires_at=excluded.expires_at AND admin_tokens.revoked_at IS NULL THEN admin_tokens.token_hmac ELSE NULL END;",
        vendor = sql_text(&bundle.vendor_id),
        vendor_name = sql_text(&bundle.vendor_id),
        product = sql_text(&bundle.product_id),
        product_name = sql_text(&bundle.product_id),
        suite = suite_id,
        created = bundle.created_at,
        token_id = sql_text(&bundle.token_id),
        token_hmac = token_hmac,
        actor = sql_text(&bundle.actor),
        scopes = sql_text(&scopes),
        expires = bundle.expires_at,
    ))
}

fn upload_admin_pepper(
    wrangler: &Path,
    project_dir: &Path,
    store_id: &str,
    pepper: &[u8],
) -> Result<Value, CliError> {
    let mut payload = Zeroizing::new(
        serde_json::to_string(&json!({"schema_version": 1, "key": pepper})).map_err(|error| {
            CliError::new(
                "json_encode_failed",
                format!("failed to encode Admin token pepper: {error}"),
            )
        })?,
    );
    payload.push('\n');
    run_wrangler_redacted(
        wrangler,
        project_dir,
        &[
            "secrets-store".to_owned(),
            "secret".to_owned(),
            "create".to_owned(),
            store_id.to_owned(),
            "--name".to_owned(),
            "ADMIN_TOKEN_PEPPER".to_owned(),
            "--scopes".to_owned(),
            "workers".to_owned(),
            "--comment".to_owned(),
            "CopyLocker Admin token HMAC pepper".to_owned(),
            "--remote".to_owned(),
        ],
        "bootstrap.secret",
        Some(payload.as_bytes()),
    )
}

fn run_wrangler_redacted(
    executable: &Path,
    project_dir: &Path,
    args: &[String],
    step: &'static str,
    stdin: Option<&[u8]>,
) -> Result<Value, CliError> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .current_dir(project_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command
        .spawn()
        .map_err(|error| CliError::io("run Wrangler", executable, &error))?;
    if let Some(input) = stdin {
        let mut child_stdin = child.stdin.take().ok_or_else(|| {
            CliError::new(
                "wrangler_failed",
                format!("Wrangler step `{step}` did not open secure stdin"),
            )
        })?;
        child_stdin
            .write_all(input)
            .map_err(|error| CliError::io("write Wrangler stdin", executable, &error))?;
    }
    let result = child
        .wait_with_output()
        .map_err(|error| CliError::io("wait for Wrangler", executable, &error))?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let message = stderr.lines().last().unwrap_or("Wrangler failed").trim();
        return Err(CliError::new(
            "wrangler_failed",
            format!(
                "Wrangler step `{step}` failed with {}: {message}",
                result.status
            ),
        ));
    }
    Ok(json!({"step": step, "status": result.status.code()}))
}

fn ensure_private_file(path: &Path) -> Result<(), CliError> {
    if !path.is_file() {
        return Err(CliError::new(
            "bootstrap_bundle_missing",
            format!("{} is not a bootstrap bundle file", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(path)
            .map_err(|error| CliError::io("read metadata", path, &error))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(CliError::new(
                "insecure_bootstrap_bundle",
                format!(
                    "{} must not be accessible by group or other users",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn sql_text(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn now_seconds() -> Result<i64, CliError> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::new("clock_error", "system clock is before the Unix epoch"))?
        .as_secs();
    i64::try_from(value)
        .map_err(|_| CliError::new("clock_error", "system time does not fit in Unix seconds"))
}

fn secure_random_error() -> CliError {
    CliError::new(
        "secure_random_unavailable",
        "the operating system CSPRNG is unavailable; no bootstrap material was generated",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_strings_escape_single_quotes() {
        assert_eq!(sql_text("owner's"), "'owner''s'");
    }
}
