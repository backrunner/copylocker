use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Args;
use copylocker_server_core::Catalog;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{pretty_json_bytes, write_output_file, CliError, Output};

const PACKAGE_TEMPLATE: &str = include_str!("../../../server-template/package.json");
const WRANGLER_TEMPLATE: &str = include_str!("../../../server-template/wrangler.jsonc");
const CONFIG_TEMPLATE: &str = include_str!("../../../server-template/copylocker.json");
const README_TEMPLATE: &str = include_str!("../../../server-template/README.md");
const GITIGNORE_TEMPLATE: &str = include_str!("../../../server-template/.gitignore");
const ENTRYPOINT_TEMPLATE: &str = include_str!("../../../server-template/src/index.js");

const MIGRATIONS: &[(&str, &[u8])] = &[
    (
        "migrations/0001_initial.sql",
        include_bytes!("../../../server-template/migrations/0001_initial.sql"),
    ),
    (
        "migrations/0002_release_feature_keks.sql",
        include_bytes!("../../../server-template/migrations/0002_release_feature_keks.sql"),
    ),
    (
        "migrations/0003_admin_revocations.sql",
        include_bytes!("../../../server-template/migrations/0003_admin_revocations.sql"),
    ),
    (
        "migrations/0004_admin_audit.sql",
        include_bytes!("../../../server-template/migrations/0004_admin_audit.sql"),
    ),
    (
        "migrations/0005_billing_webhooks.sql",
        include_bytes!("../../../server-template/migrations/0005_billing_webhooks.sql"),
    ),
    (
        "migrations/0006_unified_admin_audit.sql",
        include_bytes!("../../../server-template/migrations/0006_unified_admin_audit.sql"),
    ),
    (
        "migrations/0007_admin_operations.sql",
        include_bytes!("../../../server-template/migrations/0007_admin_operations.sql"),
    ),
    (
        "migrations/0008_epoch_approvals.sql",
        include_bytes!("../../../server-template/migrations/0008_epoch_approvals.sql"),
    ),
    (
        "migrations/0009_integrity_signer_keys.sql",
        include_bytes!("../../../server-template/migrations/0009_integrity_signer_keys.sql"),
    ),
    (
        "migrations/0010_release_admin.sql",
        include_bytes!("../../../server-template/migrations/0010_release_admin.sql"),
    ),
];

#[derive(Debug, Args)]
pub(crate) struct InitArgs {
    /// Directory to create. It must not contain existing files.
    pub(crate) path: PathBuf,
    /// Cloudflare Worker and resource name. Defaults to the directory name.
    #[arg(long)]
    pub(crate) name: Option<String>,
    /// Product identifier used by the first catalog and API configuration.
    #[arg(long)]
    pub(crate) product: String,
    /// Public base URL for the deployed API, if already known.
    #[arg(long)]
    pub(crate) api_url: Option<String>,
    /// Existing D1 database UUID.
    #[arg(long)]
    pub(crate) d1_database_id: String,
    /// Existing KV namespace identifier.
    #[arg(long)]
    pub(crate) kv_namespace_id: String,
    /// Existing Secrets Store identifier.
    #[arg(long)]
    pub(crate) secret_store_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct DeployArgs {
    /// Initialized CopyLocker server project.
    #[arg(long, default_value = ".")]
    pub(crate) project: PathBuf,
    /// Apply D1 migrations and deploy remotely. Without this flag only a local dry-run is built.
    #[arg(long)]
    pub(crate) confirm: bool,
    /// Do not apply remote D1 migrations before a confirmed deploy.
    #[arg(long, requires = "confirm")]
    pub(crate) skip_migrations: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ProjectConfig {
    pub(crate) schema_version: u8,
    pub(crate) project_name: String,
    pub(crate) product_id: String,
    #[serde(default)]
    pub(crate) secret_store_id: Option<String>,
    pub(crate) api_url: Option<String>,
    pub(crate) admin_token_env: String,
}

pub(crate) fn init(args: &InitArgs) -> Result<Output, CliError> {
    let name = args
        .name
        .clone()
        .or_else(|| {
            args.path
                .file_name()
                .and_then(|value| value.to_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| {
            CliError::new(
                "invalid_project_name",
                "--name is required when the destination has no final path component",
            )
        })?;
    validate_worker_name(&name)?;
    validate_product_id(&args.product)?;
    validate_uuid("D1 database", &args.d1_database_id)?;
    validate_hex_id("KV namespace", &args.kv_namespace_id)?;
    validate_hex_id("Secrets Store", &args.secret_store_id)?;
    if let Some(url) = &args.api_url {
        validate_api_url(url)?;
    }
    ensure_empty_destination(&args.path)?;

    let api_url_json = serde_json::to_string(&args.api_url).map_err(|error| {
        CliError::new(
            "json_encode_failed",
            format!("failed to encode project API URL: {error}"),
        )
    })?;
    let replacements = [
        ("__COPYLOCKER_PROJECT_NAME__", name.as_str()),
        ("__COPYLOCKER_PRODUCT_ID__", args.product.as_str()),
        ("__COPYLOCKER_API_URL_JSON__", api_url_json.as_str()),
        (
            "__COPYLOCKER_D1_DATABASE_ID__",
            args.d1_database_id.as_str(),
        ),
        (
            "__COPYLOCKER_KV_NAMESPACE_ID__",
            args.kv_namespace_id.as_str(),
        ),
        (
            "__COPYLOCKER_SECRET_STORE_ID__",
            args.secret_store_id.as_str(),
        ),
    ];

    let text_files = [
        ("package.json", PACKAGE_TEMPLATE),
        ("wrangler.jsonc", WRANGLER_TEMPLATE),
        ("copylocker.json", CONFIG_TEMPLATE),
        ("README.md", README_TEMPLATE),
        (".gitignore", GITIGNORE_TEMPLATE),
        ("src/index.js", ENTRYPOINT_TEMPLATE),
    ];
    let mut written = Vec::new();
    for (relative, template) in text_files {
        let rendered = render(template, &replacements)?;
        let path = args.path.join(relative);
        write_output_file(&path, rendered.as_bytes(), false)?;
        written.push(relative);
    }
    for (relative, bytes) in MIGRATIONS {
        let path = args.path.join(relative);
        write_output_file(&path, bytes, false)?;
        written.push(*relative);
    }

    let catalog = Catalog {
        product_id: args.product.clone(),
        version: 1,
        ..Catalog::default()
    };
    let catalog_path = args.path.join("catalog.json");
    write_output_file(&catalog_path, &pretty_json_bytes(&catalog)?, false)?;
    written.push("catalog.json");

    Ok(Output {
        human: format!(
            "initialized {} at {}\nnext: cd {} && npm install && copylocker deploy",
            name,
            args.path.display(),
            args.path.display()
        ),
        json: json!({
            "ok": true,
            "command": "init",
            "project_name": name,
            "product_id": args.product,
            "path": args.path,
            "files": written,
            "next": ["npm install", "copylocker deploy"]
        }),
    })
}

pub(crate) fn deploy(args: &DeployArgs) -> Result<Output, CliError> {
    let project = canonical_project_dir(&args.project)?;
    let config = load_project_config(&project)?;
    ensure_rendered(&project.join("wrangler.jsonc"))?;
    ensure_rendered(&project.join("package.json"))?;

    let wrapper = wrangler_command(&project)?;
    fs::create_dir_all(project.join(".copylocker"))
        .map_err(|error| CliError::io("create deployment output directory", &project, &error))?;

    let mut steps = Vec::new();
    if args.confirm {
        if !args.skip_migrations {
            steps.push(run_wrangler(
                &wrapper,
                &project,
                &[
                    "d1",
                    "migrations",
                    "apply",
                    &config.project_name,
                    "--remote",
                ],
                "deploy.migrate",
            )?);
        }
        steps.push(run_wrangler(
            &wrapper,
            &project,
            &["deploy"],
            "deploy.apply",
        )?);
    } else {
        steps.push(run_wrangler(
            &wrapper,
            &project,
            &["deploy", "--dry-run", "--outfile", ".copylocker/dry-run.js"],
            "deploy.plan",
        )?);
    }

    Ok(Output {
        human: if args.confirm {
            format!(
                "deployed {} from {}",
                config.project_name,
                project.display()
            )
        } else {
            format!(
                "[DRY RUN] {} bundles successfully\nconfirm remote migration and deployment with --confirm",
                config.project_name
            )
        },
        json: json!({
            "ok": true,
            "command": "deploy",
            "dry_run": !args.confirm,
            "project": config,
            "path": project,
            "steps": steps
        }),
    })
}

pub(crate) fn find_project_config(start: &Path) -> Option<PathBuf> {
    let mut current = if start.is_file() {
        start.parent()?.to_path_buf()
    } else {
        start.to_path_buf()
    };
    loop {
        let candidate = current.join("copylocker.json");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

pub(crate) fn load_project_config(project: &Path) -> Result<ProjectConfig, CliError> {
    let path = if project.ends_with("copylocker.json") {
        project.to_path_buf()
    } else {
        project.join("copylocker.json")
    };
    let bytes = fs::read(&path).map_err(|error| CliError::io("read", &path, &error))?;
    let config: ProjectConfig = serde_json::from_slice(&bytes).map_err(|error| {
        CliError::new(
            "invalid_project_config",
            format!("failed to parse {}: {error}", path.display()),
        )
    })?;
    if config.schema_version != 1
        || !valid_worker_name(&config.project_name)
        || !valid_product_id(&config.product_id)
        || config.admin_token_env.is_empty()
        || config
            .secret_store_id
            .as_deref()
            .is_some_and(|value| validate_hex_id("Secrets Store", value).is_err())
    {
        return Err(CliError::new(
            "invalid_project_config",
            format!("{} contains invalid project metadata", path.display()),
        ));
    }
    if let Some(url) = &config.api_url {
        validate_api_url(url)?;
    }
    Ok(config)
}

fn ensure_empty_destination(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::new(
                "destination_not_directory",
                format!("{} exists and is not a directory", path.display()),
            ));
        }
        let mut entries =
            fs::read_dir(path).map_err(|error| CliError::io("read directory", path, &error))?;
        if entries.next().is_some() {
            return Err(CliError::new(
                "destination_not_empty",
                format!("{} is not empty", path.display()),
            ));
        }
    } else {
        fs::create_dir_all(path).map_err(|error| CliError::io("create directory", path, &error))?;
    }
    Ok(())
}

fn render(template: &str, replacements: &[(&str, &str)]) -> Result<String, CliError> {
    let mut rendered = template.to_owned();
    for (token, value) in replacements {
        rendered = rendered.replace(token, value);
    }
    if rendered.contains("__COPYLOCKER_") {
        return Err(CliError::new(
            "template_incomplete",
            "the embedded server template contains an unresolved placeholder",
        ));
    }
    Ok(rendered)
}

fn validate_worker_name(value: &str) -> Result<(), CliError> {
    if valid_worker_name(value) {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_project_name",
            "project name must be 1-63 lowercase letters, digits, or hyphens and start/end with a letter or digit",
        ))
    }
}

fn valid_worker_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn validate_product_id(value: &str) -> Result<(), CliError> {
    if valid_product_id(value) {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_product_id",
            "product id must be 1-128 ASCII letters, digits, hyphens, underscores, or dots",
        ))
    }
}

fn valid_product_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_uuid(kind: &str, value: &str) -> Result<(), CliError> {
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if valid {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_resource_id",
            format!("{kind} id must be a UUID"),
        ))
    }
}

fn validate_hex_id(kind: &str, value: &str) -> Result<(), CliError> {
    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_resource_id",
            format!("{kind} id must contain exactly 32 hexadecimal characters"),
        ))
    }
}

fn validate_api_url(value: &str) -> Result<(), CliError> {
    let valid = (value.starts_with("https://") || value.starts_with("http://"))
        && !value.bytes().any(|byte| byte.is_ascii_whitespace());
    if valid {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_api_url",
            "API URL must be an absolute HTTP(S) URL without whitespace",
        ))
    }
}

pub(crate) fn canonical_project_dir(path: &Path) -> Result<PathBuf, CliError> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| CliError::io("resolve project directory", path, &error))?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        Err(CliError::new(
            "invalid_project_directory",
            format!("{} is not a directory", path.display()),
        ))
    }
}

fn ensure_rendered(path: &Path) -> Result<(), CliError> {
    let content = fs::read_to_string(path).map_err(|error| CliError::io("read", path, &error))?;
    if content.contains("__COPYLOCKER_") {
        Err(CliError::new(
            "unresolved_template",
            format!("{} still contains template placeholders", path.display()),
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn wrangler_command(project: &Path) -> Result<PathBuf, CliError> {
    let executable = if cfg!(windows) {
        "wrangler.cmd"
    } else {
        "wrangler"
    };
    let path = project.join("node_modules").join(".bin").join(executable);
    if path.is_file() {
        Ok(path)
    } else {
        Err(CliError::new(
            "wrangler_missing",
            format!(
                "Wrangler is not installed at {}; run `npm install` in the project first",
                path.display()
            ),
        ))
    }
}

fn run_wrangler(
    executable: &Path,
    project: &Path,
    args: &[&str],
    step: &'static str,
) -> Result<Value, CliError> {
    let result = Command::new(executable)
        .args(args)
        .current_dir(project)
        .output()
        .map_err(|error| CliError::io("run Wrangler", executable, &error))?;
    let stdout = String::from_utf8_lossy(&result.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&result.stderr).trim().to_owned();
    if !result.status.success() {
        return Err(CliError::new(
            "wrangler_failed",
            format!(
                "Wrangler step `{step}` failed with {}: {}",
                result.status,
                if stderr.is_empty() { &stdout } else { &stderr }
            ),
        ));
    }
    Ok(json!({
        "step": step,
        "status": result.status.code(),
        "stdout": stdout,
        "stderr": stderr
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_and_product_identifiers_are_bounded() {
        assert!(valid_worker_name("copylocker-acme"));
        assert!(!valid_worker_name("CopyLocker"));
        assert!(!valid_worker_name("-copylocker"));
        assert!(valid_product_id("desktop.pro_1"));
        assert!(!valid_product_id("desktop/pro"));
    }

    #[test]
    fn rendering_rejects_new_unknown_placeholders() {
        let error = render("__COPYLOCKER_UNKNOWN__", &[])
            .expect_err("unresolved placeholders must fail initialization");
        assert_eq!(error.code, "template_incomplete");
    }
}
