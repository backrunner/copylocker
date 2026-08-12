/**
 * Wire types for the CopyLocker Admin API (`/v1/admin/*`).
 *
 * These types are hand-written to mirror the request/response bodies in
 * `crates/copylocker-worker/src/admin.rs` and
 * `crates/copylocker-worker/src/admin_resources/` (`releases.rs`,
 * `licenses.rs`, `accounts.rs`, `asset_keks.rs`, `integrity.rs`,
 * `offline_key.rs`, `analytics_api.rs`, `dsr.rs`, `epochs.rs`,
 * `products.rs`, and the catalog/policy routes in `admin_resources.rs`).
 * Field names follow the JSON wire format exactly (snake_case, `Option<T>` →
 * `T | null` in responses).
 *
 * Drift-check boundary (`scripts/check-admin-sdk-bindings.mjs`, wired in
 * `.github/workflows/ci.yml`): a subset of these types maps 1:1 onto Rust
 * types that carry `#[derive(TS)]` and export bindings under
 * `packages/admin-sdk/bindings/`. The CI job regenerates those bindings and
 * fails on any diff, and a type-level test asserts the hand-written shapes
 * below stay assignable to the generated ones. The drift-checked subset is:
 *
 * - `EntitlementSpec`, `Grant`, `GrantTarget`, `LimitMergePolicy`,
 *   `VersionScope` (copylocker-server-core `entitlement.rs`,
 *   copylocker-types `entitlements.rs`)
 * - `Policy`, `Validity`, `TrialScope`, `PerpetualFallback`,
 *   `FallbackScopeAt`, `SeatSpec`, `RuntimeSpec`, `VtSignature`,
 *   `OfflineUpgradePolicy`, `Mode` (copylocker-server-core `policy.rs`,
 *   copylocker-types `state.rs`)
 * - `Feature`, `GroupMembers`, `FeatureGroup`, `Tier`
 *   (copylocker-server-core `catalog.rs`)
 * - `Entitlements`, `SubscriptionHint`, `SubscriptionState`
 *   (copylocker-types `entitlements.rs`)
 * - `QueryMeta`, `Source`, `MetricDefinition`, `MetricTier`
 *   (copylocker-server-core `analytics/`)
 *
 * Everything else in this file mirrors worker-local structs (`json!`
 * bodies, D1 row projections, journaled operation results) that have no
 * shared Rust type to derive from; keep those in sync manually.
 *
 * Covered endpoint groups:
 *
 * - releases:      `GET/POST /v1/admin/releases`,
 *                  `GET /v1/admin/releases/:id`,
 *                  `POST /v1/admin/releases/:id/deprecate`,
 *                  `POST /v1/admin/releases/:id/mark-compromised`
 * - licenses:      `GET/POST /v1/admin/licenses`,
 *                  `GET/PATCH /v1/admin/licenses/:id`,
 *                  `POST /v1/admin/licenses/:id/change-tier`,
 *                  `GET /v1/admin/licenses/:id/preview-fallback`,
 *                  `GET /v1/admin/licenses/:id/machines`
 * - offline-key:   `POST /v1/admin/licenses/:id/offline-key`
 * - accounts:      `GET/POST /v1/admin/accounts`
 * - asset-keks:    `GET/POST /v1/admin/asset-keks`,
 *                  `DELETE /v1/admin/asset-keks/:release_id/:feature_id`
 * - integrity:     `GET/POST /v1/admin/integrity/keys`,
 *                  `POST /v1/admin/integrity/keys/:fingerprint/revoke`,
 *                  `POST /v1/admin/integrity/sign`
 * - catalog:       `GET/POST/PATCH /v1/admin/catalog/:collection`,
 *                  `POST /v1/admin/catalog/resolve`
 * - policies:      `GET/POST /v1/admin/policies`,
 *                  `GET/PATCH /v1/admin/policies/:id`
 * - epochs:        `GET/POST /v1/admin/epochs`, `GET /v1/admin/epochs/:id`,
 *                  `POST /v1/admin/epochs/:id/revoke`
 * - revoke:        `POST /v1/admin/licenses/:id/revoke`,
 *                  `POST /v1/admin/machines/:id/revoke`
 * - products:      `GET/PATCH /v1/admin/products/:id/alert-webhook`
 * - analytics:     `GET /v1/admin/analytics/definitions`,
 *                  `GET /v1/admin/analytics/metrics`,
 *                  `GET /v1/admin/analytics/export`,
 *                  `GET/POST /v1/admin/analytics/subscriptions`
 * - dsr:           `POST /v1/admin/dsr/export`,
 *                  `POST /v1/admin/dsr/delete`
 * - telemetry:     `POST /v1/admin/telemetry/purge`
 * - machines:      `GET /v1/admin/machines`,
 *                  `DELETE /v1/admin/machines/:id`
 * - audit:         `GET /v1/admin/audit`,
 *                  `POST /v1/admin/audit/verify`
 */

// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------

/** Success marker present on every JSON Admin response body. */
export interface OkResponse {
  ok: true
}

/** A non-fatal advisory attached to some Admin responses. */
export interface ApiWarning {
  id: string
  message: string
}

/**
 * The worker's error envelope (`response::api_error_no_store` in
 * `crates/copylocker-worker/src/response.rs`): every non-2xx JSON response
 * is `{ ok: false, error: { code, message } }`.
 */
export interface ErrorEnvelope {
  ok: false
  error: {
    code: string
    message: string
  }
}

// ---------------------------------------------------------------------------
// Entitlement / version-scope shapes (copylocker-server-core
// `entitlement.rs`, copylocker-types `entitlements.rs`)
// ---------------------------------------------------------------------------

/** A numeric limit; `-1` is the agreed encoding for "unlimited". */
export type LimitValue = number

/** How a numeric limit combines when several sources set it. */
export type LimitMergePolicy = 'max' | 'sum' | 'override'

/** What a grant confers (serde `tag = "kind"`, snake_case). */
export type GrantTarget = { kind: 'feature'; id: string } | { kind: 'group'; id: string }

/** An add-on grant (`EntitlementSpec.grants` item). */
export interface Grant {
  target: GrantTarget
  /** Start of the grant, inclusive; `null`/absent means "already started". */
  valid_from?: number | null
  /** End of the grant, exclusive; `null`/absent means "follows the license". */
  valid_until?: number | null
  /** Order number or promotion code, for audit. */
  source?: string
  /** Limit overrides carried by this grant. */
  limits?: Record<string, LimitValue>
}

/** The input to entitlement resolution (`licensing-model.md` §2.1). */
export interface EntitlementSpec {
  /** Base tier. */
  tier: string
  /** Groups included on top of the tier. */
  extra_groups?: string[]
  /** Add-on grants. */
  grants?: Grant[]
  /** Features explicitly removed. */
  excluded_features?: string[]
  /** Final limit overrides, applied last. */
  limit_overrides?: Record<string, LimitValue>
  /** Per-key merge policies; keys absent here use `max`. */
  limit_merge?: Record<string, LimitMergePolicy>
}

/**
 * Which application versions a license covers (serde `tag = "kind"`,
 * `content = "value"`, snake_case).
 */
export type VersionScope =
  | { kind: 'unlimited' }
  | { kind: 'semver_range'; value: string }
  | { kind: 'released_before'; value: number }
  | { kind: 'pinned'; value: string[] }

// ---------------------------------------------------------------------------
// Releases (`admin_resources/releases.rs`)
// ---------------------------------------------------------------------------

/**
 * The release projection returned by every release endpoint
 * (`release_value` in releases.rs). `variant_params` never leaves the
 * server.
 */
export interface Release {
  id: string
  product_id: string
  app_version: string
  variant_id: number
  build_fingerprint: string
  manifest_root_hex: string | null
  channel: string
  /** `active`, `deprecated`, or `compromised`. */
  status: string
  /** `warn`, `force_upgrade`, `revoke`, or `null`. */
  compromised_action: string | null
  published_at: number
  deprecated_at: number | null
  created_at: number
}

/** `POST /v1/admin/releases` request body (`RegisterBody`). */
export interface RegisterReleaseBody {
  product_id: string
  app_version: string
  build_fingerprint: string
  channel: string
  /** Exactly 64 hex characters when present. */
  manifest_root_hex?: string
  /** Exactly 64 hex characters when present. */
  module_digest_hex?: string
  /**
   * Exactly 64 hex characters when present. Required unless a
   * `variant_stable` product reuses an existing variant. Never journaled
   * or returned; only its SHA-256 fingerprint reaches the journal.
   */
  variant_seed_hex?: string
}

/** `GET /v1/admin/releases?product_id=` response. */
export interface ListReleasesResponse extends OkResponse {
  product_id: string
  items: Release[]
}

/** `GET /v1/admin/releases/:id?product_id=` response. */
export interface ShowReleaseResponse extends OkResponse {
  release: Release
}

/**
 * `POST /v1/admin/releases` response. On an exact re-register the server
 * returns only `{ ok, already_registered: true, release }`; the other
 * fields are present on a fresh registration.
 */
export interface RegisterReleaseResponse extends OkResponse {
  already_registered: boolean
  variant_reused?: boolean
  release: Release
  warnings?: ApiWarning[]
}

/** Release transition impact preview (`load_impact`). */
export interface ReleaseImpact {
  devices: number
  checkins_last_7d: number
}

/** `POST /v1/admin/releases/:id/deprecate` dry-run response. */
export interface DeprecateReleaseDryRunResponse extends OkResponse {
  dry_run: true
  action: 'deprecate'
  release: Release
  impact: ReleaseImpact
  effects: string[]
}

/** `POST /v1/admin/releases/:id/deprecate` confirmed response. */
export interface DeprecateReleaseResponse extends OkResponse {
  dry_run: false
  action: 'deprecate'
  release: {
    id: string
    status: string
    deprecated_at: number
  }
  impact: ReleaseImpact
}

/** `POST /v1/admin/releases/:id/mark-compromised` request body (`CompromiseBody`). */
export interface MarkCompromisedBody {
  action: 'warn' | 'force_upgrade' | 'revoke'
  bump_security_floor?: boolean
  /** Required (`true`) for a confirmed `revoke`. */
  acknowledge_revoke?: boolean
}

/** `POST /v1/admin/releases/:id/mark-compromised` dry-run response. */
export interface MarkCompromisedDryRunResponse extends OkResponse {
  dry_run: true
  action: string
  release: Release
  impact: ReleaseImpact
  effects: string[]
  requires_acknowledgement: boolean
  security_floor: {
    current: number
    next: number | null
  }
}

/** `POST /v1/admin/releases/:id/mark-compromised` confirmed response. */
export interface MarkCompromisedResponse extends OkResponse {
  dry_run: false
  action: string
  release: {
    id: string
    status: string
    compromised_action: string
  }
  impact: ReleaseImpact
  security_floor: number | null
}

// ---------------------------------------------------------------------------
// Licenses (`admin_resources/licenses.rs`)
// ---------------------------------------------------------------------------

/**
 * The license record returned by the license endpoints (`LicenseRecord`).
 */
export interface License {
  /** 16-byte id, hex-encoded (32 characters). */
  license_id: string
  product_id: string
  policy_id: string
  account_id: string | null
  /** `active`, `suspended`, `expired`, or `revoked`. */
  status: string
  seats_override: number | null
  entitlement_override: EntitlementSpec | null
  version_scope_override: VersionScope | null
  expires_at: number | null
  catalog_version: number
  metadata: unknown
  created_at: number
  updated_at: number
  seats_used: number
  last_seen_at: number | null
}

/** `POST /v1/admin/licenses` request body (`IssueBody`). */
export interface IssueLicenseBody {
  product_id: string
  policy_id: string
  /** 1..=100; defaults to 1 server-side. */
  count?: number
  account_id?: string
  seats_override?: number
  entitlement_override?: EntitlementSpec
  version_scope_override?: VersionScope
  expires_at?: number
  metadata?: unknown
}

/** One issued license id/key pair (`issued_response`). */
export interface IssuedLicense {
  license_id: string
  license_key: string
}

/** `POST /v1/admin/licenses` response. */
export interface IssueLicenseResponse extends OkResponse {
  product_id: string
  policy_id: string
  catalog_version: number
  count: number
  license_ids: string[]
  licenses: IssuedLicense[]
}

/** `GET /v1/admin/licenses?product_id=` response. */
export interface ListLicensesResponse extends OkResponse {
  product_id: string
  items: License[]
}

/** `GET /v1/admin/licenses/:id` response. */
export interface ShowLicenseResponse extends OkResponse {
  license: License
}

/**
 * `PATCH /v1/admin/licenses/:id` request body (`LicensePatch`). At most one
 * of `extend_by_seconds` / `expires_at` / `clear_expires_at` may be set, and
 * a `clear_*` flag may not accompany its corresponding value field.
 */
export interface LicensePatch {
  /** `active`, `suspended`, or `expired`. */
  status?: string
  extend_by_seconds?: number
  expires_at?: number
  clear_expires_at?: boolean
  seats_override?: number
  clear_seats_override?: boolean
  entitlement_override?: EntitlementSpec
  clear_entitlement_override?: boolean
  version_scope_override?: VersionScope
  clear_version_scope_override?: boolean
  metadata?: unknown
  clear_metadata?: boolean
}

/**
 * `PATCH /v1/admin/licenses/:id` and
 * `POST /v1/admin/licenses/:id/change-tier` response (`persist_update`).
 */
export interface UpdateLicenseResponse extends OkResponse {
  license: License
  version: number
}

/** Subscription lifecycle state mirrored in the fallback preview. */
export type SubscriptionState =
  | 'active'
  | 'past_due'
  | 'canceling'
  | 'suspended'
  | 'ended'
  | 'expired'
  | 'perpetual_fallback'

/** `GET /v1/admin/licenses/:id/preview-fallback` response. */
export interface PreviewFallbackResponse extends OkResponse {
  license_id: string
  current_state: SubscriptionState
  end_state: SubscriptionState
  version_cutoff: number | null
  fallback_earned_at: number | null
  continuous_paid_months: number
}

/** One machine row (`MachineView`). */
export interface Machine {
  /** 16-byte id, hex-encoded (32 characters). */
  machine_id: string
  status: string
  activation_path: string
  first_seen_at: number
  last_seen_at: number | null
  os: string | null
  arch: string | null
  app_version: string | null
  sdk_version: string | null
  release_id: string | null
  variant_id: number | null
  build_fingerprint: string | null
  geo_country: string | null
  suspicion: number
}

/** `GET /v1/admin/licenses/:id/machines` response. */
export interface ListMachinesResponse extends OkResponse {
  license_id: string
  items: Machine[]
}

// ---------------------------------------------------------------------------
// Offline license key (`admin_resources/offline_key.rs`, ADR-0015)
// ---------------------------------------------------------------------------

/** `POST /v1/admin/licenses/:id/offline-key` request body (`OfflineKeyBody`). */
export interface IssueOfflineKeyBody {
  release_id: string
  /** 64 hex characters (32 bytes) when present. */
  bound_fingerprint_hex?: string
  /** 1..=100000; advisory only. */
  max_seats?: number
}

/**
 * `POST /v1/admin/licenses/:id/offline-key` response. The `armor` (CLK1) is
 * returned exactly once per idempotency key.
 */
export interface IssueOfflineKeyResponse extends OkResponse {
  license_id: string
  product_id: string
  release_id: string
  variant_id: number
  bound: boolean
  bound_fingerprint_hex: string | null
  /** `0` is the documented permanent OLK. */
  not_after: number
  max_seats: number
  revocation_epoch: number
  security_floor: number
  /** CLK1-armored `.clk` bundle. */
  armor: string
  armor_chars: number
  max_seats_advisory: boolean
}

// ---------------------------------------------------------------------------
// Accounts (`admin_resources/accounts.rs`, Mode E)
// ---------------------------------------------------------------------------

/** One account row (list projection). */
export interface Account {
  id: string
  email: string
  status: string
  max_devices: number | null
  created_at: number
}

/** The account object returned by account creation (adds `product_id`). */
export interface CreatedAccount extends Account {
  product_id: string
}

/** `GET /v1/admin/accounts?product_id=` response. */
export interface ListAccountsResponse extends OkResponse {
  product_id: string
  items: Account[]
}

/**
 * `POST /v1/admin/accounts` request body (`CreateAccountBody`). The
 * password is hashed (Argon2id) server-side and never journaled; the
 * client must treat it as a secret and never log it either.
 */
export interface CreateAccountBody {
  product_id: string
  email: string
  /** Minimum 12 characters, maximum 72 bytes, no NUL. */
  password: string
  /** 1..=1000 when present. */
  max_devices?: number
}

/** `POST /v1/admin/accounts` response. */
export interface CreateAccountResponse extends OkResponse {
  account: CreatedAccount
}

// ---------------------------------------------------------------------------
// Asset KEKs (`admin_resources/asset_keks.rs`)
// ---------------------------------------------------------------------------

/** `POST /v1/admin/asset-keks` request body (`RegisterBody`). */
export interface RegisterAssetKekBody {
  product_id: string
  release_id: string
  feature_id: string
  /** Exactly 64 hex characters (32-byte KEK). */
  kek_hex: string
}

/**
 * One asset KEK list item: fingerprint-only projection, plaintext KEKs
 * never appear in responses.
 */
export interface AssetKek {
  product_id: string
  release_id: string
  feature_id: string
  key_version: number
  /** SHA-256 of the plaintext KEK, hex-encoded. */
  kek_fingerprint: string
  created_at: number
  updated_at: number
}

/** `GET /v1/admin/asset-keks?product_id=[&release_id=]` response. */
export interface ListAssetKeksResponse extends OkResponse {
  product_id: string
  items: AssetKek[]
}

/** `POST /v1/admin/asset-keks` response. */
export interface RegisterAssetKekResponse extends OkResponse {
  product_id: string
  release_id: string
  feature_id: string
  key_version: number
  kek_fingerprint: string
}

/** `DELETE /v1/admin/asset-keks/:release_id/:feature_id` dry-run response. */
export interface DeleteAssetKekDryRunResponse extends OkResponse {
  dry_run: true
  product_id: string
  release_id: string
  feature_id: string
  key_version: number
}

/** `DELETE /v1/admin/asset-keks/:release_id/:feature_id` confirmed response. */
export interface DeleteAssetKekResponse extends OkResponse {
  dry_run: false
  product_id: string
  release_id: string
  feature_id: string
  deleted: true
}

// ---------------------------------------------------------------------------
// Integrity signer keys and remote signing (`admin_resources/integrity.rs`)
// ---------------------------------------------------------------------------

/** One integrity signer key (list projection). */
export interface IntegritySignerKey {
  product_id: string
  /** SHA-256 of the Ed25519 public key, hex-encoded (64 characters). */
  fingerprint: string
  /** Ed25519 public key, hex-encoded (64 characters). */
  public_key_hex: string
  /** `active` or `revoked`. */
  status: string
  created_by: string
  created_at: number
  revoked_at: number | null
}

/** `GET /v1/admin/integrity/keys?product_id=` response. */
export interface ListIntegrityKeysResponse extends OkResponse {
  product_id: string
  items: IntegritySignerKey[]
}

/** `POST /v1/admin/integrity/keys` request body (`RegisterKeyBody`). */
export interface RegisterIntegrityKeyBody {
  product_id: string
  /** Ed25519 public key, exactly 64 hex characters. */
  public_key_hex: string
}

/** `POST /v1/admin/integrity/keys` response. */
export interface RegisterIntegrityKeyResponse extends OkResponse {
  product_id: string
  fingerprint: string
  public_key_hex: string
  status: string
}

/** `POST /v1/admin/integrity/keys/:fingerprint/revoke` dry-run response. */
export interface RevokeIntegrityKeyDryRunResponse extends OkResponse {
  dry_run: true
  product_id: string
  fingerprint: string
  status: string
  already_revoked: boolean
}

/** `POST /v1/admin/integrity/keys/:fingerprint/revoke` confirmed response. */
export interface RevokeIntegrityKeyResponse extends OkResponse {
  dry_run: false
  product_id: string
  fingerprint: string
  status: string
}

/**
 * Result of `POST /v1/admin/integrity/sign`: the raw 64-byte Ed25519
 * signature over `"copylocker/im-sig/v1" ‖ tbs`, plus the signer key
 * fingerprint from the `X-CL-Signer-Key` response header.
 */
export interface IntegritySignature {
  signature: Uint8Array
  signerKeyFingerprint: string | null
}

// ---------------------------------------------------------------------------
// Catalog (`admin_resources.rs` catalog routes; item types mirror
// copylocker-server-core `catalog.rs`)
// ---------------------------------------------------------------------------

/** One atomic capability (`catalog.rs` `Feature`). */
export interface Feature {
  /** Immutable once published: it feeds `FeatureKey` derivation. */
  id: string
  label: string
  description?: string | null
  deprecated_at?: number | null
}

/** What a group contains (`catalog.rs` `GroupMembers`). */
export interface GroupMembers {
  includes?: string[]
  /** Feature identifiers, optionally with a trailing `*` glob. */
  features?: string[]
}

/** A named, reusable set of features (`catalog.rs` `FeatureGroup`). */
export interface FeatureGroup {
  id: string
  label: string
  members: GroupMembers
}

/** A purchasable tier (`catalog.rs` `Tier`). */
export interface Tier {
  id: string
  label: string
  rank: number
  groups?: string[]
  features?: string[]
  limits?: Record<string, LimitValue>
  archived_at?: number | null
}

/** The catalog collections the admin routes serve. */
export type CatalogCollection = 'features' | 'groups' | 'tiers'

/** Item type of a catalog collection. */
export type CatalogItemOf<C extends CatalogCollection> = C extends 'features'
  ? Feature
  : C extends 'groups'
    ? FeatureGroup
    : Tier

/** `GET /v1/admin/catalog/:collection?product_id=` response. */
export interface CatalogListResponse<Item> extends OkResponse {
  product_id: string
  catalog_version: number
  items: Item[]
}

/**
 * `POST`/`PATCH /v1/admin/catalog/:collection` request bodies. Each mirrors
 * the corresponding `*Body` struct in `admin_resources.rs` plus the
 * `product_id` the server uses for ownership and journaling.
 */
export type CatalogBodyOf<C extends CatalogCollection> = CatalogItemOf<C> & {
  product_id: string
}

/** `POST`/`PATCH /v1/admin/catalog/:collection` response. */
export interface CatalogMutationResponse extends OkResponse {
  product_id: string
  catalog_version: number
  item: Feature | FeatureGroup | Tier
}

/** `POST /v1/admin/catalog/resolve` request body (`ResolveBody`). */
export interface CatalogResolveBody {
  product_id: string
  /** Resolves against the current catalog version when absent. */
  catalog_version?: number
  entitlement: EntitlementSpec
  /** Unix seconds; defaults to "now" server-side. */
  at?: number
}

/**
 * Subscription hints mirrored to clients for in-app messaging
 * (copylocker-types `SubscriptionHint`). Not a security decision.
 */
export interface SubscriptionHint {
  /**
   * Current lifecycle state. The wire enum
   * (copylocker-types `SubscriptionState`) only ever produces the four
   * states listed in {@link SubscriptionState}; the wider union is reused
   * here because the preview-fallback endpoint reports the extended set.
   */
  state: SubscriptionState
  current_period_end: number
  fallback_progress_months: number | null
  fallback_required_months: number | null
}

/**
 * The resolved entitlement set (copylocker-types `Entitlements`). Features
 * are fully expanded (no globs), sorted, and deduplicated.
 */
export interface Entitlements {
  features: string[]
  limits: Record<string, LimitValue>
  tier_id: string
  tier_label: string
  catalog_version: number
  version_scope: VersionScope | null
  subscription_hint: SubscriptionHint | null
}

/** `POST /v1/admin/catalog/resolve` response. */
export interface CatalogResolveResponse extends OkResponse {
  product_id: string
  catalog_version: number
  at: number
  entitlements: Entitlements
}

// ---------------------------------------------------------------------------
// Policies (`admin_resources.rs` policy routes; the `Policy` shape mirrors
// copylocker-server-core `policy.rs`)
// ---------------------------------------------------------------------------

/** What a trial is deduplicated against (`policy.rs` `TrialScope`). */
export type TrialScope = 'fingerprint' | 'account' | 'email'

/** Where the perpetual fallback's version cap is anchored (`FallbackScopeAt`). */
export type FallbackScopeAt = 'earned_at' | 'subscription_start'

/** Terms under which a subscription converts to perpetual (`PerpetualFallback`). */
export interface PerpetualFallback {
  after_months: number
  scope_at: FallbackScopeAt
}

/** Axis two: how long the license lasts (`policy.rs` `Validity`, serde tag `kind`). */
export type Validity =
  | { kind: 'perpetual' }
  | { kind: 'fixed_term'; duration_secs: number }
  | {
      kind: 'subscription'
      period_secs: number
      dunning_grace_secs: number
      fallback?: PerpetualFallback | null
    }
  | {
      kind: 'trial'
      duration_secs: number
      once_per: TrialScope
      extendable_by_secs?: number | null
    }

/** Axis four: seats and transfers (`policy.rs` `SeatSpec`). */
export interface SeatSpec {
  seats: number
  max_transfers?: number | null
  transfer_window_secs?: number | null
  heartbeat_secs?: number | null
}

/** Which signature protects a validation ticket (`policy.rs` `VtSignature`). */
export type VtSignature = 'fast' | 'pq'

/** What an offline client does when its variant is superseded (`OfflineUpgradePolicy`). */
export type OfflineUpgradePolicy = 'require_online' | 'preload_n' | 'variant_stable'

/** Runtime tuning that ends up in every credential (`policy.rs` `RuntimeSpec`). */
export interface RuntimeSpec {
  refresh_after_secs: number
  grace_secs: number
  /** Minimum fingerprint similarity, 0..=100. */
  fpr_tolerance: number
  allow_vm: boolean
  allow_olk: boolean
  allow_unbound_olk: boolean
  vt_signature: VtSignature
  offline_upgrade_policy: OfflineUpgradePolicy
  preload_variants_n: number
  report_attrs: boolean
}

/** Enforcement mode (copylocker-types `Mode`, snake_case). */
export type Mode = 'offline_hybrid' | 'enforced_online'

/** A complete policy: one point in the five-axis space (`policy.rs` `Policy`). */
export interface Policy {
  id: string
  product_id: string
  name: string
  preset?: string | null
  entitlement: EntitlementSpec
  validity: Validity
  version_scope: VersionScope
  seats: SeatSpec
  mode: Mode
  runtime: RuntimeSpec
}

/** A legal-but-risky configuration surfaced by the server (`PolicyWarning`). */
export interface PolicyWarning {
  id: string
  message: string
}

/** `GET /v1/admin/policies?product_id=` response. */
export interface ListPoliciesResponse extends OkResponse {
  product_id: string
  items: Policy[]
}

/**
 * `GET /v1/admin/policies/:id`, `POST /v1/admin/policies`, and
 * `PATCH /v1/admin/policies/:id` response (`policy_response`).
 */
export interface PolicyResponse extends OkResponse {
  policy: Policy
  version: number | null
  warnings: PolicyWarning[]
}

// ---------------------------------------------------------------------------
// Epochs (`admin_resources/epochs.rs`)
// ---------------------------------------------------------------------------

/** The epoch projection returned by every epoch endpoint (`EpochView`). */
export interface Epoch {
  /** 8-byte id, hex-encoded (16 characters). */
  epoch_id: string
  product_id: string
  /** Suite id, hex-encoded. */
  suite_id: string
  not_before: number
  not_after: number
  revoked_at: number | null
  created_at: number
  /** `upcoming`, `active`, `expired`, or `revoked`. */
  status: string
  affected_machines_upper_bound: number
}

/** `GET /v1/admin/epochs?product_id=` response. */
export interface ListEpochsResponse extends OkResponse {
  product_id: string
  items: Epoch[]
}

/** `GET /v1/admin/epochs/:id` response. */
export interface ShowEpochResponse extends OkResponse {
  epoch: Epoch
  replacement_ready: boolean
  replacement_epoch_ids: string[]
}

/** `POST /v1/admin/epochs` request body (`UploadBody`). */
export interface UploadEpochBody {
  /** Canonical CBOR epoch-certificate envelope, hex-encoded. */
  certificate_hex: string
  /** Root hybrid verifying key, hex-encoded. */
  root_verifying_key_hex: string
}

/** `POST /v1/admin/epochs` response. */
export interface UploadEpochResponse extends OkResponse {
  epoch: Epoch
  version: number
}

/** `POST /v1/admin/epochs/:id/revoke` request body (`RevokeBody`). */
export interface RevokeEpochBody {
  /** Required on a confirmed revoke; must repeat the target epoch id. */
  confirm_epoch_id?: string
}

/** `POST /v1/admin/epochs/:id/revoke` dry-run response. */
export interface RevokeEpochDryRunResponse extends OkResponse {
  dry_run: true
  epoch: Epoch
  affected_machines_upper_bound: number
  replacement_ready: boolean
  replacement_epoch_ids: string[]
  already_revoked: boolean
  requires_distinct_actors: number
}

/**
 * `POST /v1/admin/epochs/:id/revoke` confirmed response. The first of the
 * two required actor confirmations answers 202 with
 * `approval_pending: true`; the second answers 200 with the assigned
 * `revocation_epoch`.
 */
export interface RevokeEpochResponse extends OkResponse {
  dry_run: false
  approval_pending: boolean
  epoch_id: string
  first_actor: string
  /** Present on the pending (first) confirmation. */
  approval_expires_at?: number
  /** Present on the final (second) confirmation. */
  second_actor?: string
  /** Present on the final (second) confirmation. */
  revocation_epoch?: number
  required_confirmations: number
  received_confirmations: number
}

// ---------------------------------------------------------------------------
// License/machine revocation (`admin.rs` revoke route, `revoke` scope)
// ---------------------------------------------------------------------------

/** The revoke route's target kinds (`parse_revoke_path`). */
export type RevokeTargetKind = 'licenses' | 'machines'

/** `POST /v1/admin/:kind/:id/revoke` request body (`RevokeBody`). */
export interface RevokeBody {
  /**
   * A `KillReason` code (1 license, 2 activation, 3 seat reclaim, 4 fraud,
   * 5 refund, 6 epoch). Defaults to the kind's default reason server-side.
   */
  reason?: number
}

/** `POST /v1/admin/:kind/:id/revoke` dry-run response. */
export interface RevokeDryRunResponse extends OkResponse {
  dry_run: true
  kind: string
  /** 16-byte target id, hex-encoded. */
  target: string
  affected_machines: number
  already_revoked: boolean
}

/** `POST /v1/admin/:kind/:id/revoke` confirmed response. */
export interface RevokeResponse extends OkResponse {
  dry_run: false
  kind: string
  target: string
  revocation_epoch: number
}

// ---------------------------------------------------------------------------
// Products (`admin_resources/products.rs`, `products:rw` scope)
// ---------------------------------------------------------------------------

/** `GET`/`PATCH /v1/admin/products/:id/alert-webhook` response. */
export interface AlertWebhookResponse extends OkResponse {
  product_id: string
  /** `null` means "record only": crossings are logged, nothing delivered. */
  alert_webhook_url: string | null
  /** `null` means the server default (70). */
  alert_suspicion_threshold: number | null
}

/** `PATCH /v1/admin/products/:id/alert-webhook` request body (`AlertWebhookBody`). */
export interface AlertWebhookBody {
  /** HTTPS URL without credentials, query, or fragment; `null` clears. */
  url?: string | null
  /** 1..=100; `null` clears back to the server default. */
  threshold?: number | null
}

// ---------------------------------------------------------------------------
// Analytics (`admin_resources/analytics_api.rs`, `analytics:r` scope)
// ---------------------------------------------------------------------------

/** Collection tier of a metric (`analytics/catalog.rs` `MetricTier`). */
export type MetricTier = 'T0' | 'T1'

/** One metric's precise definition (`analytics/catalog.rs` `MetricDefinition`). */
export interface MetricDefinition {
  id: string
  name: string
  definition: string
  tier: MetricTier
  trusted: boolean
}

/** `GET /v1/admin/analytics/definitions` response. */
export interface AnalyticsDefinitionsResponse extends OkResponse {
  items: MetricDefinition[]
}

/** The metrics/export granularity. */
export type AnalyticsGranularity = 'day' | 'week' | 'month'

/** Which computation path produced a distinct-count series (`Source`). */
export type AnalyticsSource = 'exact' | 'hll'

/** The fixed cube set available as `group_by` (`parse_group_by`). */
export type AnalyticsGroupBy =
  | 'app_version'
  | 'os_arch'
  | 'country'
  | 'activation_path'
  | 'mode'
  | 'release_id'
  | 'policy_id'
  | 'sdk_version'

/** Query options for `analytics.metrics` and `analytics.export`. */
export interface AnalyticsMetricsQuery {
  product: string
  /** 1..=8 metric ids from the definitions catalog. */
  ids: string[]
  /** Window start, `YYYY-MM-DD`. */
  from: string
  /** Window end, `YYYY-MM-DD`; at most 366 days after `from`. */
  to: string
  granularity?: AnalyticsGranularity
  groupBy?: AnalyticsGroupBy
  /** Defaults to `auto` (exact below 1M machine rows). */
  source?: 'auto' | 'exact' | 'hll'
}

/** One series point: bucket start date, group-by dimensions, and value. */
export interface AnalyticsPoint {
  /** Bucket start, `YYYY-MM-DD`. */
  bucket: string
  dims: Record<string, unknown>
  value: number
}

/** One metric's series. */
export interface AnalyticsSeries {
  metric_id: string
  points: AnalyticsPoint[]
}

/**
 * Query-result metadata (`analytics/source.rs` `QueryMeta`, plus the
 * optional day-granularity resolution warning the worker inserts).
 */
export interface QueryMeta {
  source: AnalyticsSource
  /** Worst-case relative error in percent: 0 for exact, ~0.81 for HLL. */
  error_pct: number
  /** Buckets suppressed by k-anonymity (k=5). */
  suppressed_buckets: number
  warning?: string
}

/** `GET /v1/admin/analytics/metrics` response. */
export interface AnalyticsMetricsResponse extends OkResponse {
  product_id: string
  from: string
  to: string
  granularity: AnalyticsGranularity
  series: AnalyticsSeries[]
  meta: QueryMeta
}

/**
 * Result of `GET /v1/admin/analytics/export`: the raw CSV/NDJSON body plus
 * the content type and the `Content-Disposition` filename.
 */
export interface AnalyticsExport {
  contentType: string
  filename: string | null
  body: string
}

/** `POST /v1/admin/analytics/subscriptions` request body (`SubscriptionBody`). */
export interface CreateSubscriptionBody {
  product_id: string
  /** 1..=8 unique metric ids from the definitions catalog. */
  metric_ids: string[]
  /** 1..=90. */
  window_days: number
  granularity: AnalyticsGranularity
  /** HTTPS URL without credentials in the authority. */
  webhook_url: string
}

/** A stored periodic-report config (`SubscriptionRecord`). */
export interface AnalyticsSubscription {
  schema_version: number
  /** `sub_<32 hex>`, derived from the vendor and the Idempotency-Key. */
  id: string
  product_id: string
  metric_ids: string[]
  window_days: number
  granularity: string
  webhook_url: string
  created_by: string
  created_at: number
  /** `pending` until subscription delivery ships (documented deviation). */
  delivery: string
}

/** `POST /v1/admin/analytics/subscriptions` response. */
export interface CreateSubscriptionResponse extends OkResponse {
  subscription: AnalyticsSubscription
}

/** `GET /v1/admin/analytics/subscriptions` response. */
export interface ListSubscriptionsResponse extends OkResponse {
  items: AnalyticsSubscription[]
}

// ---------------------------------------------------------------------------
// DSR and telemetry retention (`admin_resources/dsr.rs`, `dsr:rw` scope)
// ---------------------------------------------------------------------------

/**
 * `POST /v1/admin/dsr/export` and `POST /v1/admin/dsr/delete` request body
 * (`DsrBody`): exactly one of `machine_id`/`license_id` (16-byte hex).
 */
export interface DsrSubjectBody {
  product_id: string
  machine_id?: string
  license_id?: string
}

/** Which subject a DSR request resolved to (`subject_json`). */
export interface DsrSubject {
  machine_id?: string
  license_id?: string
}

/** The full machine projection in a DSR export (`load_machine_view`). */
export interface DsrMachineView {
  id: string
  license_id: string
  fingerprint: string
  status: string
  activation_path: string
  first_seen_at: number
  last_seen_at: number | null
  os: string | null
  arch: string | null
  app_version: string | null
  sdk_version: string | null
  release_id: string | null
  variant_id: number | null
  build_fp: string | null
  geo_country: string | null
  suspicion: number
}

/** The full license projection in a DSR export (`load_license_view`). */
export interface DsrLicenseView {
  id: string
  product_id: string
  policy_id: string
  account_id: string | null
  status: string
  seats_override: number | null
  expires_at: number | null
  catalog_version: number
  metadata: unknown
  created_at: number
  updated_at: number
  seats_used: number
  last_seen_at: number | null
}

/** One audit-chain reference to the subject. */
export interface DsrAuditReference {
  seq: number
  ts: number
  actor: string
  action: string
  target: string | null
  r2_key: string
}

/** `POST /v1/admin/dsr/export` response. */
export interface DsrExportResponse extends OkResponse {
  product_id: string
  subject: DsrSubject
  generated_at: number
  machines: DsrMachineView[]
  licenses: DsrLicenseView[]
  audit_references: DsrAuditReference[]
  audit_truncated: boolean
}

/** The journal-shaped machine summary carried by DSR delete responses. */
export interface DsrMachineSummary {
  id: string
  license_id: string
  status: string
}

/** `POST /v1/admin/dsr/delete` dry-run response (the default). */
export interface DsrDeleteDryRunResponse extends OkResponse {
  dry_run: true
  product_id: string
  subject: DsrSubject
  machines: DsrMachineSummary[]
  raw_records: number
  audit_tombstone: false
}

/** `POST /v1/admin/dsr/delete` confirmed response. */
export interface DsrDeleteResponse extends OkResponse {
  dry_run: false
  product_id: string
  subject: DsrSubject
  deleted_machines: number
  deleted_raw_records: number
  audit_tombstone: false
  audit_note: string
}

/** `POST /v1/admin/telemetry/purge` request body (`PurgeBody`). */
export interface TelemetryPurgeBody {
  product_id: string
  /**
   * `YYYY-MM-DD` cutoff. Absent means the 30-day T1 raw retention default
   * and leaves the rollup tables untouched.
   */
  before?: string
}

/** `POST /v1/admin/telemetry/purge` dry-run response (the default). */
export interface TelemetryPurgeDryRunResponse extends OkResponse {
  dry_run: true
  product_id: string
  cutoff: string
  raw_records: number
  rollup_rows: number
}

/** `POST /v1/admin/telemetry/purge` confirmed response. */
export interface TelemetryPurgeResponse extends OkResponse {
  dry_run: false
  product_id: string
  cutoff: string
  deleted_raw_records: number
  deleted_rollup_rows: number
  /** `false` when nothing matched and no journal entry was written. */
  journaled: boolean
}

// ---------------------------------------------------------------------------
// Cross-license machines (`admin_resources/machines.rs`, `machines:r` read
// scope satisfied by `machines:rw`; `machines:rw` for the GDPR delete)
// ---------------------------------------------------------------------------

/** One row of `GET /v1/admin/machines` (the cross-license list projection). */
export interface AdminMachine {
  machine_id: string
  license_id: string
  status: 'active' | 'pending' | 'released' | 'revoked'
  activation_path: string
  first_seen_at: number
  last_seen_at: number | null
  os: string | null
  arch: string | null
  app_version: string | null
  sdk_version: string | null
  release_id: string | null
  variant_id: number | null
  build_fingerprint: string | null
  geo_country: string | null
  suspicion: number
}

/** `GET /v1/admin/machines` response; `next_cursor` pages keyset-style. */
export interface ListAdminMachinesResponse extends OkResponse {
  product_id: string
  items: AdminMachine[]
  /** Pass verbatim as `cursor` for the next page; `null` on the last page. */
  next_cursor: string | null
}

/**
 * `DELETE /v1/admin/machines/:id` responses: the endpoint is a journaled alias
 * over the `dsr:delete` cascade, so the wire shapes are the DSR delete ones.
 */
export type MachineDeleteDryRunResponse = DsrDeleteDryRunResponse
export type MachineDeleteResponse = DsrDeleteResponse

// ---------------------------------------------------------------------------
// Admin audit chain (`admin_resources/audit_admin.rs`, `audit:r` scope)
// ---------------------------------------------------------------------------

/**
 * One row of `GET /v1/admin/audit`: the summary projection of a stored Admin
 * audit event (never the before/after snapshots).
 */
export interface AdminAuditEventSummary {
  seq: number
  occurred_at: number
  actor: string
  action: string
  target: string
  reason: number | null
  request_id: string
  source_kind: string
  r2_key: string
}

/** `GET /v1/admin/audit` response, newest first; `next_cursor` pages on seq. */
export interface ListAdminAuditResponse extends OkResponse {
  items: AdminAuditEventSummary[]
  /** Pass verbatim as `cursor` for the next page; `null` on the last page. */
  next_cursor: string | null
}

/** The verified Admin audit chain head (hash hex-encoded). */
export interface AdminAuditChainHead {
  seq: number
  hash: string
}

/** The first broken chain link reported by `POST /v1/admin/audit/verify`. */
export interface AdminAuditChainBreak {
  seq: number
  reason:
    | 'event_json_corrupt'
    | 'seq_mismatch'
    | 'seq_gap'
    | 'column_mismatch'
    | 'prev_hash_link'
    | 'hash_mismatch'
}

/** `POST /v1/admin/audit/verify` response (read-only, always HTTP 200). */
export interface VerifyAdminAuditResponse extends OkResponse {
  verified: boolean
  /** Events examined before stopping (the whole chain when `verified`). */
  event_count: number
  first_seq: number | null
  last_seq: number | null
  head: AdminAuditChainHead | null
  first_broken: AdminAuditChainBreak | null
}
