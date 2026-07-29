use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use copylocker_server_core::{Catalog, Feature, FeatureGroup, Policy, Tier};
use copylocker_suite::SignatureScheme;
use copylocker_suite_std::HybridSig;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::remote::{self, AdminClient, ApiResponse, ConnectionArgs};
use crate::{load_config_json, pretty_json_bytes, write_output_file, CliError, Output};

#[derive(Debug, Args)]
pub(crate) struct CatalogPullArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Replace an existing catalog file.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
pub(crate) struct CatalogPushArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Stable prefix used to derive one Idempotency-Key per changed item.
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct PolicyListArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct PolicyShowArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Policy identifier.
    id: String,
}

#[derive(Debug, Args)]
pub(crate) struct PolicyWriteArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Policy JSON file.
    #[arg(long)]
    file: PathBuf,
    /// Idempotency key for the policy mutation.
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct LicenseArgs {
    #[command(subcommand)]
    command: LicenseCommand,
}

#[derive(Debug, Subcommand)]
enum LicenseCommand {
    /// Issue one or more licenses. Plaintext keys are returned only by this call.
    Issue(LicenseIssueArgs),
    /// List licenses for a product.
    List(LicenseListArgs),
    /// Show one license.
    Show(LicenseTargetArgs),
    /// Suspend a license.
    Suspend(LicenseMutationArgs),
    /// Resume a suspended license.
    Resume(LicenseMutationArgs),
    /// Extend an expiring license.
    Extend(LicenseExtendArgs),
    /// Change a license's entitlement tier.
    ChangeTier(LicenseChangeTierArgs),
    /// Preview the fallback retained when a subscription ends.
    PreviewFallback(LicenseTargetArgs),
    /// List machines associated with a license.
    Machines(LicenseTargetArgs),
    /// Revoke a license. Without --confirm this only sends a dry-run request.
    Revoke(LicenseRevokeArgs),
}

#[derive(Debug, Args)]
struct LicenseIssueArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Policy used to issue the licenses.
    #[arg(long)]
    policy: String,
    /// Number of licenses to issue in this batch.
    #[arg(long, default_value_t = 1)]
    count: u32,
    /// Optional account identifier associated with every issued license.
    #[arg(long)]
    account: Option<String>,
    /// Optional seat-count override.
    #[arg(long)]
    seats: Option<u32>,
    /// Optional exclusive Unix expiry timestamp.
    #[arg(long)]
    expires_at: Option<i64>,
    /// Optional JSON object included as license metadata.
    #[arg(long)]
    metadata: Option<PathBuf>,
    /// Idempotency key for the license batch.
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct LicenseListArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
    /// Optional status filter.
    #[arg(long, value_parser = ["active", "suspended", "expired", "revoked"])]
    status: Option<String>,
    /// Maximum number of licenses to return.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=100))]
    limit: u32,
}

#[derive(Debug, Args)]
struct LicenseTargetArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// 16-byte hexadecimal license identifier.
    id: String,
}

#[derive(Debug, Args)]
struct LicenseMutationArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// 16-byte hexadecimal license identifier.
    id: String,
    /// Idempotency key for the license mutation.
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct LicenseExtendArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// 16-byte hexadecimal license identifier.
    id: String,
    /// Positive extension in seconds.
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
    by_seconds: i64,
    /// Idempotency key for the license mutation.
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct LicenseChangeTierArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// 16-byte hexadecimal license identifier.
    id: String,
    /// Target tier identifier.
    #[arg(long)]
    to: String,
    /// Idempotency key for the tier change.
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct LicenseRevokeArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// 16-byte hexadecimal license identifier.
    id: String,
    /// Apply the revocation after reviewing the default dry-run.
    #[arg(long)]
    confirm: bool,
    /// Idempotency key required only for a confirmed revocation.
    #[arg(long, required_if_eq("confirm", "true"))]
    idempotency_key: Option<String>,
    /// Optional numeric KillReason value.
    #[arg(long)]
    reason: Option<u8>,
}

#[derive(Debug, Args)]
pub(crate) struct EpochArgs {
    #[command(subcommand)]
    command: EpochCommand,
}

#[derive(Debug, Subcommand)]
enum EpochCommand {
    /// List epochs for a product.
    List(EpochListArgs),
    /// Show one epoch and its replacement readiness.
    Show(EpochTargetArgs),
    /// Upload a Root-signed epoch certificate.
    Upload(EpochUploadArgs),
    /// Upload a new epoch certificate for a rotation.
    Rotate(EpochUploadArgs),
    /// Revoke an epoch. Requires two distinct Admin actors to complete.
    Revoke(EpochRevokeArgs),
}

#[derive(Debug, Args)]
struct EpochListArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Product identifier. Defaults to the initialized project's product.
    #[arg(long)]
    product: Option<String>,
}

#[derive(Debug, Args)]
struct EpochTargetArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// 8-byte hexadecimal epoch identifier.
    id: String,
}

#[derive(Debug, Args)]
struct EpochUploadArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Root-signed `.cert.cbor` file.
    certificate: PathBuf,
    /// Root public-key JSON emitted by `copylocker keygen root`.
    #[arg(long)]
    root_public: PathBuf,
    /// Idempotency key for the epoch upload.
    #[arg(long)]
    idempotency_key: String,
}

#[derive(Debug, Args)]
struct EpochRevokeArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// 8-byte hexadecimal epoch identifier.
    id: String,
    /// Submit an approval after reviewing the default dry-run.
    #[arg(long)]
    confirm: bool,
    /// Typed confirmation; must exactly match the target epoch ID.
    #[arg(long, requires = "confirm")]
    confirm_epoch_id: Option<String>,
    /// Idempotency key required for each actor's confirmed approval.
    #[arg(long, required_if_eq("confirm", "true"))]
    idempotency_key: Option<String>,
}

pub(crate) fn catalog_pull(path: &Path, args: &CatalogPullArgs) -> Result<Output, CliError> {
    let client = AdminClient::connect(&args.connection)?;
    let product_id = client.product_id(args.product.as_deref())?;
    let (catalog, version) = fetch_catalog(&client, &product_id)?;
    let bytes = pretty_json_bytes(&catalog)?;
    write_output_file(path, &bytes, args.force)?;
    Ok(Output {
        human: format!(
            "pulled catalog version {version} for {product_id} to {}",
            path.display()
        ),
        json: json!({
            "ok": true,
            "command": "catalog.pull",
            "product_id": product_id,
            "catalog_version": version,
            "path": path,
            "bytes": bytes.len()
        }),
    })
}

pub(crate) fn catalog_push(path: &Path, args: &CatalogPushArgs) -> Result<Output, CliError> {
    remote::validate_idempotency_key(&args.idempotency_key)?;
    let mut local: Catalog = load_config_json(path, "invalid_catalog_json", "catalog")?;
    local.validate().map_err(|error| {
        CliError::new(
            "invalid_catalog",
            format!("catalog {} is invalid: {error}", path.display()),
        )
    })?;
    sort_catalog(&mut local);
    validate_catalog_idempotency_keys(&local, &args.idempotency_key)?;
    let group_order = ordered_groups(&local)?;

    let client = AdminClient::connect(&args.connection)?;
    let product_id = client.product_id(args.product.as_deref())?;
    if local.product_id != product_id {
        return Err(CliError::new(
            "product_mismatch",
            format!(
                "catalog product {} does not match requested product {product_id}",
                local.product_id
            ),
        ));
    }
    let (remote_catalog, initial_version) = fetch_catalog(&client, &product_id)?;
    ensure_catalog_items_retained(&remote_catalog, &local)?;
    validate_catalog_evolution(&remote_catalog, &local)?;

    let mut created = 0_u64;
    let mut updated = 0_u64;
    let mut bridge_updates = 0_u64;
    let mut unchanged = 0_u64;
    let mut last_version = initial_version;

    for feature in &local.features {
        let current = remote_catalog
            .features
            .iter()
            .find(|item| item.id == feature.id);
        mutate_catalog_item(
            &client,
            "features",
            &product_id,
            feature,
            current,
            &args.idempotency_key,
            None,
            &mut created,
            &mut updated,
            &mut unchanged,
            &mut last_version,
        )?;
    }
    for group in group_order {
        let current = remote_catalog
            .groups
            .iter()
            .find(|item| item.id == group.id);
        mutate_catalog_item(
            &client,
            "groups",
            &product_id,
            group,
            current,
            &args.idempotency_key,
            None,
            &mut created,
            &mut updated,
            &mut unchanged,
            &mut last_version,
        )?;
    }
    mutate_catalog_tiers(
        &client,
        &product_id,
        &local,
        &remote_catalog,
        &args.idempotency_key,
        &mut created,
        &mut updated,
        &mut bridge_updates,
        &mut unchanged,
        &mut last_version,
    )?;

    Ok(Output {
        human: format!(
            "pushed catalog for {product_id}: created={created}, updated={updated}, unchanged={unchanged}, remote version={last_version}"
        ),
        json: json!({
            "ok": true,
            "command": "catalog.push",
            "product_id": product_id,
            "catalog_version_before": initial_version,
            "catalog_version_after": last_version,
            "created": created,
            "updated": updated,
            "bridge_updates": bridge_updates,
            "unchanged": unchanged
        }),
    })
}

pub(crate) fn policy_list(args: &PolicyListArgs) -> Result<Output, CliError> {
    let client = AdminClient::connect(&args.connection)?;
    let product = client.product_id(args.product.as_deref())?;
    respond(
        "policy.list",
        client.get("/v1/admin/policies", &[("product_id", product)])?,
    )
}

pub(crate) fn policy_show(args: &PolicyShowArgs) -> Result<Output, CliError> {
    remote::validate_identifier("policy id", &args.id, 128)?;
    let client = AdminClient::connect(&args.connection)?;
    respond(
        "policy.show",
        client.get(&format!("/v1/admin/policies/{}", args.id), &[])?,
    )
}

pub(crate) fn policy_push(args: &PolicyWriteArgs) -> Result<Output, CliError> {
    write_policy(args, true)
}

pub(crate) fn policy_update(args: &PolicyWriteArgs) -> Result<Output, CliError> {
    write_policy(args, false)
}

pub(crate) fn run_license(args: &LicenseArgs) -> Result<Output, CliError> {
    match &args.command {
        LicenseCommand::Issue(args) => {
            remote::validate_identifier("policy id", &args.policy, 128)?;
            if !(1..=100).contains(&args.count) {
                return Err(CliError::new(
                    "invalid_count",
                    "license count must be between 1 and 100",
                ));
            }
            if let Some(account) = &args.account {
                remote::validate_identifier("account id", account, 128)?;
            }
            if args
                .seats
                .is_some_and(|value| !(1..=100_000).contains(&value))
            {
                return Err(CliError::new(
                    "invalid_seats",
                    "seat override must be between 1 and 100000",
                ));
            }
            let metadata = args
                .metadata
                .as_deref()
                .map(|path| read_json_value(path, "invalid_metadata_json"))
                .transpose()?;
            let client = AdminClient::connect(&args.connection)?;
            let product = client.product_id(args.product.as_deref())?;
            let body = json!({
                "product_id": product,
                "policy_id": args.policy,
                "count": args.count,
                "account_id": args.account,
                "seats_override": args.seats,
                "expires_at": args.expires_at,
                "metadata": metadata
            });
            respond(
                "license.issue",
                client.post(
                    "/v1/admin/licenses",
                    &[],
                    &body,
                    Some(&args.idempotency_key),
                )?,
            )
        }
        LicenseCommand::List(args) => {
            let client = AdminClient::connect(&args.connection)?;
            let product = client.product_id(args.product.as_deref())?;
            let mut query = vec![("product_id", product), ("limit", args.limit.to_string())];
            if let Some(status) = &args.status {
                query.push(("status", status.clone()));
            }
            respond("license.list", client.get("/v1/admin/licenses", &query)?)
        }
        LicenseCommand::Show(args) => license_get(args, "", "license.show"),
        LicenseCommand::Suspend(args) => {
            license_patch(args, json!({"status": "suspended"}), "license.suspend")
        }
        LicenseCommand::Resume(args) => {
            license_patch(args, json!({"status": "active"}), "license.resume")
        }
        LicenseCommand::Extend(args) => {
            validate_license_id(&args.id)?;
            let client = AdminClient::connect(&args.connection)?;
            respond(
                "license.extend",
                client.patch(
                    &format!("/v1/admin/licenses/{}", args.id),
                    &json!({"extend_by_seconds": args.by_seconds}),
                    &args.idempotency_key,
                )?,
            )
        }
        LicenseCommand::ChangeTier(args) => {
            validate_license_id(&args.id)?;
            remote::validate_identifier("tier id", &args.to, 128)?;
            let client = AdminClient::connect(&args.connection)?;
            respond(
                "license.change-tier",
                client.post(
                    &format!("/v1/admin/licenses/{}/change-tier", args.id),
                    &[],
                    &json!({"tier": args.to}),
                    Some(&args.idempotency_key),
                )?,
            )
        }
        LicenseCommand::PreviewFallback(args) => {
            license_get(args, "/preview-fallback", "license.preview-fallback")
        }
        LicenseCommand::Machines(args) => license_get(args, "/machines", "license.machines"),
        LicenseCommand::Revoke(args) => {
            validate_license_id(&args.id)?;
            let client = AdminClient::connect(&args.connection)?;
            let body = match args.reason {
                Some(reason) => json!({"reason": reason}),
                None => json!({}),
            };
            respond(
                "license.revoke",
                client.post(
                    &format!("/v1/admin/licenses/{}/revoke", args.id),
                    &[("dry_run", (!args.confirm).to_string())],
                    &body,
                    args.idempotency_key.as_deref(),
                )?,
            )
        }
    }
}

pub(crate) fn run_epoch(args: &EpochArgs) -> Result<Output, CliError> {
    match &args.command {
        EpochCommand::List(args) => {
            let client = AdminClient::connect(&args.connection)?;
            let product = client.product_id(args.product.as_deref())?;
            respond(
                "epoch.list",
                client.get("/v1/admin/epochs", &[("product_id", product)])?,
            )
        }
        EpochCommand::Show(args) => {
            validate_epoch_id(&args.id)?;
            let client = AdminClient::connect(&args.connection)?;
            respond(
                "epoch.show",
                client.get(&format!("/v1/admin/epochs/{}", args.id), &[])?,
            )
        }
        EpochCommand::Upload(args) => upload_epoch(args, "epoch.upload"),
        EpochCommand::Rotate(args) => upload_epoch(args, "epoch.rotate"),
        EpochCommand::Revoke(args) => {
            validate_epoch_id(&args.id)?;
            if args.confirm {
                let confirmed = args.confirm_epoch_id.as_deref().ok_or_else(|| {
                    CliError::new(
                        "epoch_confirmation_required",
                        "confirmed epoch revocation requires --confirm-epoch-id",
                    )
                })?;
                validate_epoch_id(confirmed)?;
                if confirmed != args.id {
                    return Err(CliError::new(
                        "confirmation_mismatch",
                        "--confirm-epoch-id must exactly match the target epoch ID",
                    ));
                }
            }
            let client = AdminClient::connect(&args.connection)?;
            let body = json!({
                "confirm_epoch_id": args.confirm.then(|| args.id.clone())
            });
            respond(
                "epoch.revoke",
                client.post(
                    &format!("/v1/admin/epochs/{}/revoke", args.id),
                    &[("dry_run", (!args.confirm).to_string())],
                    &body,
                    args.idempotency_key.as_deref(),
                )?,
            )
        }
    }
}

fn fetch_catalog(client: &AdminClient, product_id: &str) -> Result<(Catalog, u32), CliError> {
    let query = [("product_id", product_id.to_owned())];
    let features: CollectionResponse<Feature> = response_as(
        client.get("/v1/admin/catalog/features", &query)?,
        "catalog features",
    )?;
    let groups: CollectionResponse<FeatureGroup> = response_as(
        client.get("/v1/admin/catalog/groups", &query)?,
        "catalog groups",
    )?;
    let tiers: CollectionResponse<Tier> = response_as(
        client.get("/v1/admin/catalog/tiers", &query)?,
        "catalog tiers",
    )?;
    if features.product_id != product_id
        || groups.product_id != product_id
        || tiers.product_id != product_id
        || features.catalog_version != groups.catalog_version
        || features.catalog_version != tiers.catalog_version
    {
        return Err(CliError::new(
            "inconsistent_catalog_response",
            "Admin API catalog collections disagree on product or catalog version; retry the pull",
        ));
    }
    let version = features.catalog_version;
    let mut catalog = Catalog {
        product_id: product_id.to_owned(),
        version,
        features: features.items,
        groups: groups.items,
        tiers: tiers.items,
    };
    sort_catalog(&mut catalog);
    catalog.validate().map_err(|error| {
        CliError::new(
            "invalid_remote_catalog",
            format!("Admin API returned an invalid catalog: {error}"),
        )
    })?;
    Ok((catalog, version))
}

fn ensure_catalog_items_retained(current: &Catalog, proposed: &Catalog) -> Result<(), CliError> {
    for feature in &current.features {
        if !proposed.features.iter().any(|item| item.id == feature.id) {
            return Err(CliError::new(
                "remote_item_removed",
                format!(
                    "remote feature `{}` is absent locally; catalog push never deletes published identifiers",
                    feature.id
                ),
            ));
        }
    }
    for group in &current.groups {
        if !proposed.groups.iter().any(|item| item.id == group.id) {
            return Err(CliError::new(
                "remote_item_removed",
                format!(
                    "remote group `{}` is absent locally; catalog push does not delete remote items",
                    group.id
                ),
            ));
        }
    }
    for tier in &current.tiers {
        if !proposed.tiers.iter().any(|item| item.id == tier.id) {
            return Err(CliError::new(
                "remote_item_removed",
                format!(
                    "remote tier `{}` is absent locally; archive it instead of deleting it",
                    tier.id
                ),
            ));
        }
    }
    Ok(())
}

fn validate_catalog_evolution(current: &Catalog, proposed: &Catalog) -> Result<(), CliError> {
    let mut final_catalog = proposed.clone();
    final_catalog.version = current.version.checked_add(1).ok_or_else(|| {
        CliError::new(
            "catalog_version_exhausted",
            "remote catalog version cannot be advanced",
        )
    })?;
    current.validate_evolution(&final_catalog).map_err(|error| {
        CliError::new(
            "invalid_catalog_evolution",
            format!("local catalog cannot replace the remote catalog: {error}"),
        )
    })
}

fn validate_catalog_idempotency_keys(catalog: &Catalog, prefix: &str) -> Result<(), CliError> {
    remote::validate_idempotency_key(prefix)?;
    for (collection, id) in catalog
        .features
        .iter()
        .map(|item| ("features", item.id.as_str()))
        .chain(
            catalog
                .groups
                .iter()
                .map(|item| ("groups", item.id.as_str())),
        )
        .chain(catalog.tiers.iter().map(|item| ("tiers", item.id.as_str())))
    {
        remote::validate_idempotency_key(&format!("{prefix}:{collection}:{id}"))?;
        if collection == "tiers" {
            remote::validate_idempotency_key(&format!("{prefix}:{collection}:{id}:bridge"))?;
            remote::validate_idempotency_key(&format!("{prefix}:{collection}:{id}:final"))?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn mutate_catalog_tiers(
    client: &AdminClient,
    product_id: &str,
    local: &Catalog,
    remote_catalog: &Catalog,
    key_prefix: &str,
    created: &mut u64,
    updated: &mut u64,
    bridge_updates: &mut u64,
    unchanged: &mut u64,
    last_version: &mut u32,
) -> Result<(), CliError> {
    for tier in &local.tiers {
        let current = remote_catalog.tiers.iter().find(|item| item.id == tier.id);
        match current {
            None => mutate_catalog_item(
                client,
                "tiers",
                product_id,
                tier,
                None,
                key_prefix,
                None,
                created,
                updated,
                unchanged,
                last_version,
            )?,
            Some(current) if current == tier => {
                *unchanged = unchanged.saturating_add(1);
            }
            Some(current) => {
                let bridge = tier_bridge(current, tier);
                if bridge != *current && bridge != *tier {
                    mutate_catalog_item(
                        client,
                        "tiers",
                        product_id,
                        &bridge,
                        Some(current),
                        key_prefix,
                        Some("bridge"),
                        created,
                        updated,
                        unchanged,
                        last_version,
                    )?;
                    *bridge_updates = bridge_updates.saturating_add(1);
                } else if bridge == *tier {
                    mutate_catalog_item(
                        client,
                        "tiers",
                        product_id,
                        tier,
                        Some(current),
                        key_prefix,
                        None,
                        created,
                        updated,
                        unchanged,
                        last_version,
                    )?;
                }
            }
        }
    }

    for tier in &local.tiers {
        let Some(current) = remote_catalog.tiers.iter().find(|item| item.id == tier.id) else {
            continue;
        };
        if current == tier {
            continue;
        }
        let bridge = tier_bridge(current, tier);
        if bridge == *tier {
            continue;
        }
        let phase = (bridge != *current).then_some("final");
        mutate_catalog_item(
            client,
            "tiers",
            product_id,
            tier,
            Some(current),
            key_prefix,
            phase,
            created,
            updated,
            unchanged,
            last_version,
        )?;
    }
    Ok(())
}

fn tier_bridge(current: &Tier, proposed: &Tier) -> Tier {
    let mut bridge = proposed.clone();
    for (key, value) in &current.limits {
        bridge.limits.entry(key.clone()).or_insert(*value);
    }
    bridge
}

#[allow(clippy::too_many_arguments)]
fn mutate_catalog_item<T>(
    client: &AdminClient,
    collection: &str,
    product_id: &str,
    local: &T,
    remote_item: Option<&T>,
    key_prefix: &str,
    key_phase: Option<&str>,
    created: &mut u64,
    updated: &mut u64,
    unchanged: &mut u64,
    last_version: &mut u32,
) -> Result<(), CliError>
where
    T: serde::Serialize + PartialEq + ItemId,
{
    if remote_item == Some(local) {
        *unchanged = unchanged.saturating_add(1);
        return Ok(());
    }
    let mut body = serde_json::to_value(local).map_err(|error| {
        CliError::new(
            "json_encode_failed",
            format!("failed to encode catalog item: {error}"),
        )
    })?;
    let object = body.as_object_mut().ok_or_else(|| {
        CliError::new(
            "json_encode_failed",
            "catalog item did not encode as a JSON object",
        )
    })?;
    object.insert(
        "product_id".to_owned(),
        Value::String(product_id.to_owned()),
    );
    let mut key = format!("{key_prefix}:{collection}:{}", local.item_id());
    if let Some(phase) = key_phase {
        key.push(':');
        key.push_str(phase);
    }
    remote::validate_idempotency_key(&key)?;
    let response = if remote_item.is_some() {
        *updated = updated.saturating_add(1);
        client.patch(&format!("/v1/admin/catalog/{collection}"), &body, &key)?
    } else {
        *created = created.saturating_add(1);
        client.post(
            &format!("/v1/admin/catalog/{collection}"),
            &[],
            &body,
            Some(&key),
        )?
    };
    *last_version = response
        .value
        .get("catalog_version")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            CliError::new(
                "invalid_api_response",
                "catalog mutation response omitted a valid catalog_version",
            )
        })?;
    Ok(())
}

fn ordered_groups(catalog: &Catalog) -> Result<Vec<&FeatureGroup>, CliError> {
    fn visit<'a>(
        id: &str,
        groups: &BTreeMap<&'a str, &'a FeatureGroup>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
        ordered: &mut Vec<&'a FeatureGroup>,
    ) -> Result<(), CliError> {
        let group = groups.get(id).copied().ok_or_else(|| {
            CliError::new(
                "invalid_catalog",
                format!("group `{id}` is referenced but not defined"),
            )
        })?;
        if visited.contains(group.id.as_str()) {
            return Ok(());
        }
        if !visiting.insert(group.id.as_str()) {
            return Err(CliError::new(
                "invalid_catalog",
                format!("group `{id}` participates in a cycle"),
            ));
        }
        for include in &group.members.includes {
            visit(include, groups, visiting, visited, ordered)?;
        }
        visiting.remove(group.id.as_str());
        visited.insert(group.id.as_str());
        ordered.push(group);
        Ok(())
    }

    let groups = catalog
        .groups
        .iter()
        .map(|group| (group.id.as_str(), group))
        .collect::<BTreeMap<_, _>>();
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut ordered = Vec::with_capacity(catalog.groups.len());
    for id in groups.keys() {
        visit(id, &groups, &mut visiting, &mut visited, &mut ordered)?;
    }
    Ok(ordered)
}

fn write_policy(args: &PolicyWriteArgs, create: bool) -> Result<Output, CliError> {
    let policy: Policy = load_config_json(&args.file, "invalid_policy_json", "policy")?;
    policy.validate().map_err(|error| {
        CliError::new(
            "invalid_policy",
            format!("policy {} is invalid: {error}", args.file.display()),
        )
    })?;
    remote::validate_identifier("policy id", &policy.id, 128)?;
    let body = serde_json::to_value(&policy).map_err(|error| {
        CliError::new(
            "json_encode_failed",
            format!("failed to encode policy: {error}"),
        )
    })?;
    let client = AdminClient::connect(&args.connection)?;
    let response = if create {
        client.post(
            "/v1/admin/policies",
            &[],
            &body,
            Some(&args.idempotency_key),
        )?
    } else {
        client.patch(
            &format!("/v1/admin/policies/{}", policy.id),
            &body,
            &args.idempotency_key,
        )?
    };
    respond(
        if create {
            "policy.push"
        } else {
            "policy.update"
        },
        response,
    )
}

fn license_get(args: &LicenseTargetArgs, suffix: &str, command: &str) -> Result<Output, CliError> {
    validate_license_id(&args.id)?;
    let client = AdminClient::connect(&args.connection)?;
    respond(
        command,
        client.get(&format!("/v1/admin/licenses/{}{suffix}", args.id), &[])?,
    )
}

fn license_patch(
    args: &LicenseMutationArgs,
    body: Value,
    command: &str,
) -> Result<Output, CliError> {
    validate_license_id(&args.id)?;
    let client = AdminClient::connect(&args.connection)?;
    respond(
        command,
        client.patch(
            &format!("/v1/admin/licenses/{}", args.id),
            &body,
            &args.idempotency_key,
        )?,
    )
}

fn upload_epoch(args: &EpochUploadArgs, command: &str) -> Result<Output, CliError> {
    let certificate = fs::read(&args.certificate)
        .map_err(|error| CliError::io("read", &args.certificate, &error))?;
    if certificate.is_empty() || certificate.len() > 64 * 1024 {
        return Err(CliError::new(
            "invalid_epoch_certificate",
            "epoch certificate must contain between 1 byte and 64 KiB",
        ));
    }
    let root: RootPublicFile = load_config_json(
        &args.root_public,
        "invalid_root_public_json",
        "root public key",
    )?;
    let root_key = hex::decode(&root.verifying_key_hex).ok();
    if root.schema_version != 1
        || !matches!(root.kind.as_str(), "root" | "root_next")
        || root_key.as_ref().map(Vec::len) != Some(HybridSig::VK_LEN)
    {
        return Err(CliError::new(
            "invalid_root_public_key",
            format!(
                "{} is not a valid Root public-key file",
                args.root_public.display()
            ),
        ));
    }
    let body = json!({
        "certificate_hex": hex::encode(certificate),
        "root_verifying_key_hex": root.verifying_key_hex
    });
    let client = AdminClient::connect(&args.connection)?;
    respond(
        command,
        client.post("/v1/admin/epochs", &[], &body, Some(&args.idempotency_key))?,
    )
}

fn validate_license_id(value: &str) -> Result<(), CliError> {
    remote::validate_hex_id("license id", value, 16)
}

fn validate_epoch_id(value: &str) -> Result<(), CliError> {
    remote::validate_hex_id("epoch id", value, 8)
}

fn response_as<T: DeserializeOwned>(response: ApiResponse, label: &str) -> Result<T, CliError> {
    serde_json::from_value(response.value).map_err(|error| {
        CliError::new(
            "invalid_api_response",
            format!("Admin API returned an invalid {label} response: {error}"),
        )
    })
}

fn respond(command: &str, response: ApiResponse) -> Result<Output, CliError> {
    Ok(remote::output(command, response))
}

fn read_json_value(path: &Path, code: &str) -> Result<Value, CliError> {
    let bytes = fs::read(path).map_err(|error| CliError::io("read", path, &error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        CliError::new(code, format!("failed to parse {}: {error}", path.display()))
    })
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

trait ItemId {
    fn item_id(&self) -> &str;
}

impl ItemId for Feature {
    fn item_id(&self) -> &str {
        &self.id
    }
}

impl ItemId for FeatureGroup {
    fn item_id(&self) -> &str {
        &self.id
    }
}

impl ItemId for Tier {
    fn item_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
struct CollectionResponse<T> {
    product_id: String,
    catalog_version: u32,
    items: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct RootPublicFile {
    schema_version: u8,
    kind: String,
    verifying_key_hex: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use copylocker_server_core::GroupMembers;

    fn group(id: &str, includes: &[&str]) -> FeatureGroup {
        FeatureGroup {
            id: id.to_owned(),
            label: id.to_owned(),
            members: GroupMembers {
                includes: includes.iter().map(|value| (*value).to_owned()).collect(),
                features: Vec::new(),
            },
        }
    }

    #[test]
    fn groups_are_pushed_after_their_includes() {
        let catalog = Catalog {
            product_id: "acme".to_owned(),
            version: 1,
            groups: vec![group("outer", &["inner"]), group("inner", &[])],
            ..Catalog::default()
        };
        let ids = ordered_groups(&catalog)
            .expect("valid graph")
            .into_iter()
            .map(|value| value.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["inner", "outer"]);
    }
}
