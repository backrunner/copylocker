use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use copylocker_server_core::{
    resolve, Catalog, EntitlementSpec, Feature, FeatureGroup, GroupMembers, Tier,
};
use serde_json::json;

use crate::{load_config_json, pretty_json_bytes, write_output_file, CliError, Output};

#[derive(Debug, Args)]
pub(crate) struct CatalogArgs {
    /// Version-controlled catalog JSON file.
    #[arg(long, global = true, default_value = "catalog.json")]
    pub(crate) file: PathBuf,
    #[command(subcommand)]
    command: CatalogCommand,
}

#[derive(Debug, Subcommand)]
enum CatalogCommand {
    /// Add, list, or deprecate immutable feature identifiers.
    Feature(FeatureArgs),
    /// Add, replace, or list feature groups.
    Group(GroupArgs),
    /// Add, replace, or list purchasable tiers.
    Tier(TierArgs),
    /// Resolve one tier to its deterministic feature and limit snapshot.
    Resolve(ResolveArgs),
    /// Export a normalized catalog snapshot.
    Export(ExportArgs),
    /// Import a newer catalog after enforcing immutable identifiers.
    Import(ImportArgs),
    /// Pull the current remote catalog into the version-controlled file.
    Pull(crate::admin_cli::CatalogPullArgs),
    /// Push local catalog changes through the authenticated Admin API.
    Push(crate::admin_cli::CatalogPushArgs),
}

#[derive(Debug, Args)]
struct FeatureArgs {
    #[command(subcommand)]
    command: FeatureCommand,
}

#[derive(Debug, Subcommand)]
enum FeatureCommand {
    /// Add a new immutable feature identifier.
    Add(FeatureAddArgs),
    /// List every feature, including deprecated entries.
    List,
    /// Mark a feature deprecated while retaining its identifier.
    Deprecate(FeatureDeprecateArgs),
}

#[derive(Debug, Args)]
struct FeatureAddArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    label: String,
    #[arg(long)]
    description: Option<String>,
}

#[derive(Debug, Args)]
struct FeatureDeprecateArgs {
    #[arg(long)]
    id: String,
    /// Unix timestamp recorded as `deprecated_at`.
    #[arg(long)]
    at: i64,
}

#[derive(Debug, Args)]
struct GroupArgs {
    #[command(subcommand)]
    command: GroupCommand,
}

#[derive(Debug, Subcommand)]
enum GroupCommand {
    /// Add a group. Repeated includes and features form the complete membership.
    Add(GroupDefinitionArgs),
    /// Replace a group's label and complete membership.
    Edit(GroupDefinitionArgs),
    /// List every group.
    List,
}

#[derive(Debug, Args)]
struct GroupDefinitionArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    label: String,
    #[arg(long = "include")]
    includes: Vec<String>,
    #[arg(long = "feature")]
    features: Vec<String>,
}

#[derive(Debug, Args)]
struct TierArgs {
    #[command(subcommand)]
    command: TierCommand,
}

#[derive(Debug, Subcommand)]
enum TierCommand {
    /// Add a tier. Repeated groups, features, and limits form the complete definition.
    Add(TierDefinitionArgs),
    /// Replace a tier's complete definition.
    Edit(TierDefinitionArgs),
    /// List every tier.
    List,
}

#[derive(Debug, Args)]
struct TierDefinitionArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    label: String,
    #[arg(long)]
    rank: i32,
    #[arg(long = "group")]
    groups: Vec<String>,
    #[arg(long = "feature")]
    features: Vec<String>,
    /// Numeric limit in KEY=VALUE form. Use -1 for unlimited.
    #[arg(long = "limit", value_parser = parse_limit)]
    limits: Vec<(String, i64)>,
}

#[derive(Debug, Args)]
struct ResolveArgs {
    #[arg(long)]
    tier: String,
    /// Unix timestamp used for time-limited grants. A plain tier has none, but the value is explicit.
    #[arg(long, default_value_t = 0)]
    at: i64,
}

#[derive(Debug, Args)]
struct ExportArgs {
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct ImportArgs {
    /// Newer catalog snapshot to validate and install.
    #[arg(long)]
    from: PathBuf,
}

pub(crate) fn run(args: &CatalogArgs) -> Result<Output, CliError> {
    match &args.command {
        CatalogCommand::Feature(command) => match &command.command {
            FeatureCommand::Add(add) => feature_add(&args.file, add),
            FeatureCommand::List => list_features(&args.file),
            FeatureCommand::Deprecate(deprecate) => feature_deprecate(&args.file, deprecate),
        },
        CatalogCommand::Group(command) => match &command.command {
            GroupCommand::Add(definition) => group_put(&args.file, definition, false),
            GroupCommand::Edit(definition) => group_put(&args.file, definition, true),
            GroupCommand::List => list_groups(&args.file),
        },
        CatalogCommand::Tier(command) => match &command.command {
            TierCommand::Add(definition) => tier_put(&args.file, definition, false),
            TierCommand::Edit(definition) => tier_put(&args.file, definition, true),
            TierCommand::List => list_tiers(&args.file),
        },
        CatalogCommand::Resolve(resolve_args) => resolve_tier(&args.file, resolve_args),
        CatalogCommand::Export(export) => export_catalog(&args.file, export),
        CatalogCommand::Import(import) => import_catalog(&args.file, import),
        CatalogCommand::Pull(remote) => crate::admin_cli::catalog_pull(&args.file, remote),
        CatalogCommand::Push(remote) => crate::admin_cli::catalog_push(&args.file, remote),
    }
}

fn feature_add(path: &Path, args: &FeatureAddArgs) -> Result<Output, CliError> {
    validate_identifier("feature", &args.id, false)?;
    if args.label.trim().is_empty() {
        return Err(CliError::new(
            "invalid_feature",
            "feature label must not be empty",
        ));
    }
    mutate(path, "catalog.feature.add", |catalog| {
        if catalog.feature(&args.id).is_some() {
            return Err(CliError::new(
                "feature_exists",
                format!(
                    "feature `{}` already exists; feature identifiers cannot be renamed or reused",
                    args.id
                ),
            ));
        }
        catalog.features.push(Feature {
            id: args.id.clone(),
            label: args.label.clone(),
            description: args.description.clone(),
            deprecated_at: None,
        });
        Ok(json!({ "feature_id": args.id }))
    })
}

fn feature_deprecate(path: &Path, args: &FeatureDeprecateArgs) -> Result<Output, CliError> {
    mutate(path, "catalog.feature.deprecate", |catalog| {
        let feature = catalog
            .features
            .iter_mut()
            .find(|feature| feature.id == args.id)
            .ok_or_else(|| {
                CliError::new(
                    "feature_not_found",
                    format!("feature `{}` does not exist", args.id),
                )
            })?;
        feature.deprecated_at = Some(args.at);
        Ok(json!({ "feature_id": args.id, "deprecated_at": args.at }))
    })
}

fn group_put(path: &Path, args: &GroupDefinitionArgs, editing: bool) -> Result<Output, CliError> {
    validate_identifier("group", &args.id, false)?;
    for include in &args.includes {
        validate_identifier("included group", include, false)?;
    }
    for feature in &args.features {
        validate_identifier("group feature", feature, true)?;
    }
    let command = if editing {
        "catalog.group.edit"
    } else {
        "catalog.group.add"
    };
    mutate(path, command, |catalog| {
        let position = catalog.groups.iter().position(|group| group.id == args.id);
        match (editing, position) {
            (false, Some(_)) => {
                return Err(CliError::new(
                    "group_exists",
                    format!("group `{}` already exists", args.id),
                ));
            }
            (true, None) => {
                return Err(CliError::new(
                    "group_not_found",
                    format!("group `{}` does not exist", args.id),
                ));
            }
            _ => {}
        }
        let group = FeatureGroup {
            id: args.id.clone(),
            label: args.label.clone(),
            members: GroupMembers {
                includes: args.includes.clone(),
                features: args.features.clone(),
            },
        };
        if let Some(position) = position {
            let slot = catalog.groups.get_mut(position).ok_or_else(|| {
                CliError::new("catalog_changed", "group disappeared during the update")
            })?;
            *slot = group;
        } else {
            catalog.groups.push(group);
        }
        Ok(json!({ "group_id": args.id }))
    })
}

fn tier_put(path: &Path, args: &TierDefinitionArgs, editing: bool) -> Result<Output, CliError> {
    validate_identifier("tier", &args.id, false)?;
    for group in &args.groups {
        validate_identifier("tier group", group, false)?;
    }
    for feature in &args.features {
        validate_identifier("tier feature", feature, true)?;
    }
    let limits: BTreeMap<String, i64> = args.limits.iter().cloned().collect();
    if limits.len() != args.limits.len() {
        return Err(CliError::new(
            "duplicate_limit",
            "each tier limit key may be specified only once",
        ));
    }
    let command = if editing {
        "catalog.tier.edit"
    } else {
        "catalog.tier.add"
    };
    mutate(path, command, |catalog| {
        let position = catalog.tiers.iter().position(|tier| tier.id == args.id);
        match (editing, position) {
            (false, Some(_)) => {
                return Err(CliError::new(
                    "tier_exists",
                    format!("tier `{}` already exists", args.id),
                ));
            }
            (true, None) => {
                return Err(CliError::new(
                    "tier_not_found",
                    format!("tier `{}` does not exist", args.id),
                ));
            }
            _ => {}
        }
        let tier = Tier {
            id: args.id.clone(),
            label: args.label.clone(),
            rank: args.rank,
            groups: args.groups.clone(),
            features: args.features.clone(),
            limits: limits.clone(),
            archived_at: None,
        };
        if let Some(position) = position {
            let slot = catalog.tiers.get_mut(position).ok_or_else(|| {
                CliError::new("catalog_changed", "tier disappeared during the update")
            })?;
            *slot = tier;
        } else {
            catalog.tiers.push(tier);
        }
        Ok(json!({ "tier_id": args.id }))
    })
}

fn list_features(path: &Path) -> Result<Output, CliError> {
    let catalog = load_catalog(path)?;
    Ok(Output {
        human: serde_json::to_string_pretty(&catalog.features).map_err(json_error)?,
        json: json!({
            "ok": true,
            "command": "catalog.feature.list",
            "product_id": catalog.product_id,
            "catalog_version": catalog.version,
            "features": catalog.features
        }),
    })
}

fn list_groups(path: &Path) -> Result<Output, CliError> {
    let catalog = load_catalog(path)?;
    Ok(Output {
        human: serde_json::to_string_pretty(&catalog.groups).map_err(json_error)?,
        json: json!({
            "ok": true,
            "command": "catalog.group.list",
            "product_id": catalog.product_id,
            "catalog_version": catalog.version,
            "groups": catalog.groups
        }),
    })
}

fn list_tiers(path: &Path) -> Result<Output, CliError> {
    let catalog = load_catalog(path)?;
    Ok(Output {
        human: serde_json::to_string_pretty(&catalog.tiers).map_err(json_error)?,
        json: json!({
            "ok": true,
            "command": "catalog.tier.list",
            "product_id": catalog.product_id,
            "catalog_version": catalog.version,
            "tiers": catalog.tiers
        }),
    })
}

fn resolve_tier(path: &Path, args: &ResolveArgs) -> Result<Output, CliError> {
    let catalog = load_catalog(path)?;
    let resolved = resolve(
        &catalog,
        &EntitlementSpec {
            tier: args.tier.clone(),
            ..EntitlementSpec::default()
        },
        args.at,
    )
    .map_err(|error| {
        CliError::new(
            "catalog_resolution_failed",
            format!("failed to resolve tier `{}`: {error}", args.tier),
        )
    })?;
    let human = format!(
        "tier {} ({})\nfeatures:\n{}\nlimits:\n{}",
        resolved.tier_id,
        resolved.tier_label,
        resolved
            .features
            .iter()
            .map(|feature| format!("  {feature}"))
            .collect::<Vec<_>>()
            .join("\n"),
        resolved
            .limits
            .iter()
            .map(|(key, value)| format!("  {key}={value}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    Ok(Output {
        human,
        json: json!({
            "ok": true,
            "command": "catalog.resolve",
            "product_id": catalog.product_id,
            "catalog_version": resolved.catalog_version,
            "tier_id": resolved.tier_id,
            "tier_label": resolved.tier_label,
            "features": resolved.features,
            "limits": resolved.limits
        }),
    })
}

fn export_catalog(path: &Path, args: &ExportArgs) -> Result<Output, CliError> {
    let mut catalog = load_catalog(path)?;
    sort_catalog(&mut catalog);
    let bytes = pretty_json_bytes(&catalog)?;
    write_output_file(&args.out, &bytes, args.force)?;
    Ok(Output {
        human: format!(
            "exported {} catalog version {} to {}",
            catalog.product_id,
            catalog.version,
            args.out.display()
        ),
        json: json!({
            "ok": true,
            "command": "catalog.export",
            "product_id": catalog.product_id,
            "catalog_version": catalog.version,
            "path": args.out,
            "bytes": bytes.len()
        }),
    })
}

fn import_catalog(path: &Path, args: &ImportArgs) -> Result<Output, CliError> {
    let mut proposed: Catalog = load_config_json(&args.from, "invalid_catalog_json", "catalog")?;
    sort_catalog(&mut proposed);
    if path.exists() {
        let current = load_catalog(path)?;
        current.validate_evolution(&proposed).map_err(|error| {
            CliError::new(
                "invalid_catalog_evolution",
                format!("catalog import rejected: {error}"),
            )
        })?;
        write_output_file(path, &pretty_json_bytes(&proposed)?, true)?;
    } else {
        proposed.validate().map_err(|error| {
            CliError::new(
                "invalid_catalog",
                format!("catalog import rejected: {error}"),
            )
        })?;
        write_output_file(path, &pretty_json_bytes(&proposed)?, false)?;
    }
    Ok(Output {
        human: format!(
            "imported {} catalog version {} into {}",
            proposed.product_id,
            proposed.version,
            path.display()
        ),
        json: json!({
            "ok": true,
            "command": "catalog.import",
            "product_id": proposed.product_id,
            "catalog_version": proposed.version,
            "path": path
        }),
    })
}

fn mutate<F>(path: &Path, command: &'static str, change: F) -> Result<Output, CliError>
where
    F: FnOnce(&mut Catalog) -> Result<serde_json::Value, CliError>,
{
    let current = load_catalog(path)?;
    let mut proposed = current.clone();
    let detail = change(&mut proposed)?;
    proposed.version = current.version.checked_add(1).ok_or_else(|| {
        CliError::new(
            "catalog_version_exhausted",
            "catalog version cannot be incremented beyond u32::MAX",
        )
    })?;
    sort_catalog(&mut proposed);
    current.validate_evolution(&proposed).map_err(|error| {
        CliError::new(
            "invalid_catalog_evolution",
            format!("catalog update rejected: {error}"),
        )
    })?;
    write_output_file(path, &pretty_json_bytes(&proposed)?, true)?;
    Ok(Output {
        human: format!(
            "updated {} catalog to version {}",
            proposed.product_id, proposed.version
        ),
        json: json!({
            "ok": true,
            "command": command,
            "product_id": proposed.product_id,
            "catalog_version": proposed.version,
            "change": detail
        }),
    })
}

fn load_catalog(path: &Path) -> Result<Catalog, CliError> {
    let catalog: Catalog = load_config_json(path, "invalid_catalog_json", "catalog")?;
    catalog.validate().map_err(|error| {
        CliError::new(
            "invalid_catalog",
            format!("catalog {} is invalid: {error}", path.display()),
        )
    })?;
    Ok(catalog)
}

fn sort_catalog(catalog: &mut Catalog) {
    catalog
        .features
        .sort_by(|left, right| left.id.cmp(&right.id));
    catalog.groups.sort_by(|left, right| left.id.cmp(&right.id));
    catalog.tiers.sort_by(|left, right| left.id.cmp(&right.id));
    for group in &mut catalog.groups {
        group.members.includes.sort();
        group.members.features.sort();
    }
    for tier in &mut catalog.tiers {
        tier.groups.sort();
        tier.features.sort();
    }
}

fn validate_identifier(kind: &str, value: &str, trailing_glob: bool) -> Result<(), CliError> {
    let base = value.strip_suffix('*').unwrap_or(value);
    let glob_is_valid = !value.contains('*') || (trailing_glob && value.ends_with('*'));
    let valid = !base.is_empty()
        && base.len() <= 128
        && glob_is_valid
        && base
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_catalog_identifier",
            format!("{kind} identifier `{value}` is invalid"),
        ))
    }
}

fn parse_limit(value: &str) -> Result<(String, i64), String> {
    let (key, raw) = value
        .split_once('=')
        .ok_or_else(|| String::from("limits use KEY=VALUE form"))?;
    validate_identifier("limit", key, false).map_err(|error| error.message)?;
    let parsed = raw
        .parse::<i64>()
        .map_err(|_| format!("limit `{key}` has a non-integer value"))?;
    if parsed < -1 {
        return Err(format!(
            "limit `{key}` must be -1 or a non-negative integer"
        ));
    }
    Ok((key.to_owned(), parsed))
}

fn json_error(error: serde_json::Error) -> CliError {
    CliError::new(
        "json_encode_failed",
        format!("failed to encode catalog output: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_parser_accepts_unlimited_and_rejects_negative_values() {
        assert_eq!(parse_limit("projects=-1"), Ok(("projects".into(), -1)));
        assert_eq!(parse_limit("projects=10"), Ok(("projects".into(), 10)));
        assert!(parse_limit("projects=-2").is_err());
        assert!(parse_limit("projects").is_err());
    }

    #[test]
    fn feature_globs_are_only_allowed_at_the_end() {
        assert!(validate_identifier("feature", "export.*", true).is_ok());
        assert!(validate_identifier("feature", "*.pdf", true).is_err());
        assert!(validate_identifier("feature", "export.*.pdf", true).is_err());
    }
}
