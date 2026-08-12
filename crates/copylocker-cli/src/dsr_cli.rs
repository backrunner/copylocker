//! Data-subject-rights (DSR) and telemetry retention commands against the Admin API
//! (`data-model.md §14`, `90-analytics-telemetry.md §11`).
//!
//! Both destructive commands (`dsr delete`, `telemetry purge`) mirror the license
//! revocation discipline: without `--confirm` they only send the server's default
//! dry-run; a confirmed run requires an Idempotency-Key.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde_json::json;

use crate::remote::{self, AdminClient, ConnectionArgs};
use crate::{pretty_json_bytes, write_output_file, CliError, Output};

#[derive(Debug, Args)]
pub(crate) struct DsrArgs {
    #[command(subcommand)]
    command: DsrCommand,
}

#[derive(Debug, Subcommand)]
enum DsrCommand {
    /// Export everything held about one machine or license as a JSON bundle.
    Export(DsrExportArgs),
    /// Delete one machine's or license's personal data. Without --confirm this only
    /// sends a dry-run request.
    Delete(DsrDeleteArgs),
}

#[derive(Debug, Args)]
struct DsrExportArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// 16-byte hexadecimal machine identifier.
    #[arg(long, group = "subject")]
    machine: Option<String>,
    /// 16-byte hexadecimal license identifier.
    #[arg(long, group = "subject")]
    license: Option<String>,
    /// Write the export bundle to this file instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Replace an existing --out file.
    #[arg(long, requires = "out")]
    force: bool,
}

#[derive(Debug, Args)]
struct DsrDeleteArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// 16-byte hexadecimal machine identifier.
    #[arg(long, group = "subject")]
    machine: Option<String>,
    /// 16-byte hexadecimal license identifier.
    #[arg(long, group = "subject")]
    license: Option<String>,
    /// Apply the deletion after reviewing the default dry-run.
    #[arg(long)]
    confirm: bool,
    /// Idempotency key required only for a confirmed deletion.
    #[arg(long, required_if_eq("confirm", "true"))]
    idempotency_key: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct TelemetryArgs {
    #[command(subcommand)]
    command: TelemetryCommand,
}

#[derive(Debug, Subcommand)]
enum TelemetryCommand {
    /// Purge T1 raw detail (and, with --before, rollup rows) for a product. Without
    /// --confirm this only sends a dry-run request.
    Purge(TelemetryPurgeArgs),
}

#[derive(Debug, Args)]
struct TelemetryPurgeArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Purge records before this YYYY-MM-DD date. Defaults to the 30-day T1 raw
    /// retention horizon and also removes older telemetry_rollup rows.
    #[arg(long)]
    before: Option<String>,
    /// Apply the purge after reviewing the default dry-run.
    #[arg(long)]
    confirm: bool,
    /// Idempotency key required only for a confirmed purge.
    #[arg(long, required_if_eq("confirm", "true"))]
    idempotency_key: Option<String>,
}

pub(crate) fn run_dsr(args: &DsrArgs) -> Result<Output, CliError> {
    match &args.command {
        DsrCommand::Export(args) => dsr_export(args),
        DsrCommand::Delete(args) => dsr_delete(args),
    }
}

pub(crate) fn run_telemetry(args: &TelemetryArgs) -> Result<Output, CliError> {
    match &args.command {
        TelemetryCommand::Purge(args) => telemetry_purge(args),
    }
}

fn dsr_export(args: &DsrExportArgs) -> Result<Output, CliError> {
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    let body = dsr_body(&product, args.machine.as_deref(), args.license.as_deref())?;
    let response = client.post("/v1/admin/dsr/export", &[], &body, None)?;
    if let Some(path) = &args.out {
        let bytes = pretty_json_bytes(&response.value)?;
        write_output_file(path, &bytes, args.force)?;
        return Ok(Output {
            human: format!(
                "wrote DSR export for {} to {}",
                subject_label(&body),
                path.display()
            ),
            json: json!({
                "ok": true,
                "command": "dsr.export",
                "http_status": response.status,
                "path": path,
                "bytes": bytes.len()
            }),
        });
    }
    Ok(remote::output("dsr.export", response))
}

fn dsr_delete(args: &DsrDeleteArgs) -> Result<Output, CliError> {
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    let body = dsr_body(&product, args.machine.as_deref(), args.license.as_deref())?;
    remote::output_result(
        "dsr.delete",
        client.post(
            "/v1/admin/dsr/delete",
            &[("dry_run", (!args.confirm).to_string())],
            &body,
            args.idempotency_key.as_deref(),
        ),
    )
}

fn telemetry_purge(args: &TelemetryPurgeArgs) -> Result<Output, CliError> {
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    if let Some(before) = &args.before {
        validate_date(before)?;
    }
    let body = json!({
        "product_id": product,
        "before": args.before,
    });
    remote::output_result(
        "telemetry.purge",
        client.post(
            "/v1/admin/telemetry/purge",
            &[("dry_run", (!args.confirm).to_string())],
            &body,
            args.idempotency_key.as_deref(),
        ),
    )
}

fn dsr_body(
    product: &str,
    machine: Option<&str>,
    license: Option<&str>,
) -> Result<serde_json::Value, CliError> {
    match (machine, license) {
        (Some(machine), None) => {
            remote::validate_hex_id("machine id", machine, 16)?;
            Ok(json!({"product_id": product, "machine_id": machine}))
        }
        (None, Some(license)) => {
            remote::validate_hex_id("license id", license, 16)?;
            Ok(json!({"product_id": product, "license_id": license}))
        }
        _ => Err(CliError::new(
            "invalid_subject",
            "exactly one of --machine or --license is required",
        )),
    }
}

fn subject_label(body: &serde_json::Value) -> String {
    if let Some(machine) = body.get("machine_id").and_then(|value| value.as_str()) {
        format!("machine {machine}")
    } else if let Some(license) = body.get("license_id").and_then(|value| value.as_str()) {
        format!("license {license}")
    } else {
        "subject".to_owned()
    }
}

fn validate_date(value: &str) -> Result<(), CliError> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 10
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit());
    if valid {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_date",
            "--before must be a YYYY-MM-DD date",
        ))
    }
}
