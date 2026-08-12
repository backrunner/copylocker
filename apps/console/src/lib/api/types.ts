/**
 * Admin REST API 的 TypeScript 类型（页面侧形状）。
 *
 * M7-B 起传输层由 @copylocker/admin-sdk 承担（client.ts 是它的适配层）；
 * 本文件保留页面使用的响应包装形状（{ ok, product_id, items } 等），
 * 条目类型与 packages/admin-sdk/src/types.ts 结构一致，后者经
 * packages/admin-sdk/bindings + bindings-check.ts 与 Rust 线格式做漂移检查。
 * 手写时遵守的 serde 约定：
 * - 带 #[serde(default)] 的 Option 字段：请求可省略，响应总是输出 null。
 * - 仅 Feature.description / Feature.deprecated_at / Tier.archived_at 在
 *   None 时真正省略（skip_serializing_if）。
 * - 时间戳均为 Unix 秒（i64），实际值远小于 2^53，用 number 安全。
 * - LimitValue = i64，-1 表示 unlimited。
 */

// ---------------------------------------------------------------------------
// 通用信封
// ---------------------------------------------------------------------------

/** 所有 Admin 响应都带 ok 字段；错误统一为 { ok:false, error:{code,message} }。 */
export interface ErrorEnvelope {
	ok: false;
	error: { code: string; message: string };
}

// ---------------------------------------------------------------------------
// Catalog（/v1/admin/catalog/*）
// ---------------------------------------------------------------------------

export type LimitValue = number;

export interface Feature {
	/** 发布后不可变（FeatureKey 派生依赖它）。 */
	id: string;
	label: string;
	description?: string;
	deprecated_at?: number | null;
}

export interface GroupMembers {
	/** 嵌套引用的其他 group id。 */
	includes?: string[];
	/** 直接包含的 feature id，允许尾部 `*` glob（如 `export.*`）。 */
	features?: string[];
}

export interface FeatureGroup {
	id: string;
	label: string;
	members: GroupMembers;
}

export interface Tier {
	id: string;
	label: string;
	rank: number;
	groups?: string[];
	features?: string[];
	limits?: Record<string, LimitValue>;
	archived_at?: number | null;
}

export interface Catalog {
	product_id: string;
	version: number;
	features?: Feature[];
	groups?: FeatureGroup[];
	tiers?: Tier[];
}

export type CatalogCollection = 'features' | 'groups' | 'tiers';

/** POST/PATCH /catalog/features 请求体（deny_unknown_fields）。 */
export interface FeatureBody {
	product_id: string;
	id: string;
	label: string;
	description?: string;
	deprecated_at?: number | null;
}

export interface GroupBody {
	product_id: string;
	id: string;
	label: string;
	members: GroupMembers;
}

export interface TierBody {
	product_id: string;
	id: string;
	label: string;
	rank: number;
	groups?: string[];
	features?: string[];
	limits?: Record<string, LimitValue>;
	archived_at?: number | null;
}

export interface CatalogListResponse<T> {
	ok: true;
	product_id: string;
	catalog_version: number;
	items: T[];
}

export interface CatalogMutationResponse {
	ok: true;
	product_id: string;
	catalog_version: number;
	item: Feature | FeatureGroup | Tier;
}

// ---------------------------------------------------------------------------
// Entitlement（EntitlementSpec / resolve 输出 Entitlements）
// ---------------------------------------------------------------------------

export type GrantTarget =
	| { kind: 'feature'; id: string }
	| { kind: 'group'; id: string };

export type LimitMergePolicy = 'max' | 'sum' | 'override';

export interface Grant {
	target: GrantTarget;
	valid_from?: number | null;
	valid_until?: number | null;
	source?: string;
	limits?: Record<string, LimitValue>;
}

export interface EntitlementSpec {
	tier: string;
	extra_groups?: string[];
	grants?: Grant[];
	excluded_features?: string[];
	limit_overrides?: Record<string, LimitValue>;
	limit_merge?: Record<string, LimitMergePolicy>;
}

export type VersionScope =
	| { kind: 'unlimited' }
	| { kind: 'semver_range'; value: string }
	| { kind: 'released_before'; value: number }
	| { kind: 'pinned'; value: string[] };

export type SubscriptionHintState = 'active' | 'past_due' | 'canceling' | 'suspended';

export interface SubscriptionHint {
	state: SubscriptionHintState;
	current_period_end: number;
	fallback_progress_months: number | null;
	fallback_required_months: number | null;
}

/** POST /catalog/resolve 的 `entitlements` 字段（copylocker-types Entitlements）。 */
export interface ResolvedEntitlements {
	features: string[];
	limits: Record<string, LimitValue>;
	tier_id: string;
	tier_label: string;
	catalog_version: number;
	version_scope: VersionScope | null;
	subscription_hint: SubscriptionHint | null;
}

export interface ResolveRequest {
	product_id: string;
	catalog_version?: number;
	entitlement: EntitlementSpec;
	at?: number;
}

export interface ResolveResponse {
	ok: true;
	product_id: string;
	catalog_version: number;
	at: number;
	entitlements: ResolvedEntitlements;
}

// ---------------------------------------------------------------------------
// Policy（/v1/admin/policies）
// ---------------------------------------------------------------------------

export type TrialScope = 'fingerprint' | 'account' | 'email';

export interface PerpetualFallback {
	after_months: number;
	scope_at: 'earned_at' | 'subscription_start';
}

export type Validity =
	| { kind: 'perpetual' }
	| { kind: 'fixed_term'; duration_secs: number }
	| {
			kind: 'subscription';
			period_secs: number;
			dunning_grace_secs: number;
			fallback?: PerpetualFallback | null;
	  }
	| {
			kind: 'trial';
			duration_secs: number;
			once_per: TrialScope;
			extendable_by_secs?: number | null;
	  };

export interface SeatSpec {
	seats: number;
	max_transfers?: number | null;
	transfer_window_secs?: number | null;
	heartbeat_secs?: number | null;
}

export type Mode = 'offline_hybrid' | 'enforced_online';
export type VtSignature = 'fast' | 'pq';
export type OfflineUpgradePolicy = 'require_online' | 'preload_n' | 'variant_stable';

export interface RuntimeSpec {
	refresh_after_secs: number;
	grace_secs: number;
	/** 0..=100 */
	fpr_tolerance: number;
	allow_vm: boolean;
	allow_olk: boolean;
	allow_unbound_olk: boolean;
	vt_signature: VtSignature;
	offline_upgrade_policy: OfflineUpgradePolicy;
	preload_variants_n: number;
	report_attrs: boolean;
}

export interface Policy {
	id: string;
	product_id: string;
	name: string;
	preset?: string | null;
	entitlement: EntitlementSpec;
	validity: Validity;
	version_scope: VersionScope;
	seats: SeatSpec;
	mode: Mode;
	runtime: RuntimeSpec;
}

export interface PolicyWarning {
	id: string;
	message: string;
}

export interface PolicyListResponse {
	ok: true;
	product_id: string;
	items: Policy[];
}

export interface PolicyResponse {
	ok: true;
	policy: Policy;
	version: number | null;
	warnings: PolicyWarning[];
}

// ---------------------------------------------------------------------------
// License（/v1/admin/licenses）
// ---------------------------------------------------------------------------

export type LicenseStatus = 'active' | 'suspended' | 'expired' | 'revoked';

export interface LicenseRecord {
	license_id: string;
	product_id: string;
	policy_id: string;
	account_id: string | null;
	status: LicenseStatus;
	seats_override: number | null;
	entitlement_override: EntitlementSpec | null;
	version_scope_override: VersionScope | null;
	expires_at: number | null;
	catalog_version: number;
	metadata: unknown;
	created_at: number;
	updated_at: number;
	seats_used: number;
	last_seen_at: number | null;
}

export interface LicenseListResponse {
	ok: true;
	product_id: string;
	items: LicenseRecord[];
}

export interface LicenseResponse {
	ok: true;
	license: LicenseRecord;
	version?: number;
}

export interface IssueLicenseBody {
	product_id: string;
	policy_id: string;
	/** 1..=100，默认 1。 */
	count?: number;
	account_id?: string;
	seats_override?: number;
	entitlement_override?: EntitlementSpec;
	version_scope_override?: VersionScope;
	expires_at?: number;
	metadata?: unknown;
}

export interface IssuedLicense {
	license_id: string;
	/** 明文 License Key，仅此一次可见，展示后必须从内存清除。 */
	license_key: string;
}

export interface IssueLicenseResponse {
	ok: true;
	product_id: string;
	policy_id: string;
	catalog_version: number;
	count: number;
	license_ids: string[];
	licenses: IssuedLicense[];
}

export interface LicensePatch {
	status?: 'active' | 'suspended' | 'expired';
	extend_by_seconds?: number;
	expires_at?: number;
	clear_expires_at?: boolean;
	seats_override?: number;
	clear_seats_override?: boolean;
	entitlement_override?: EntitlementSpec;
	clear_entitlement_override?: boolean;
	version_scope_override?: VersionScope;
	clear_version_scope_override?: boolean;
	metadata?: unknown;
	clear_metadata?: boolean;
}

export interface MachineView {
	machine_id: string;
	status: string;
	activation_path: string;
	first_seen_at: number;
	last_seen_at: number | null;
	os: string | null;
	arch: string | null;
	app_version: string | null;
	sdk_version: string | null;
	release_id: string | null;
	variant_id: number | null;
	build_fingerprint: string | null;
	geo_country: string | null;
	suspicion: number;
}

export interface MachineListResponse {
	ok: true;
	license_id: string;
	items: MachineView[];
}

export type SubscriptionState =
	| 'active'
	| 'past_due'
	| 'canceling'
	| 'suspended'
	| 'ended'
	| 'expired'
	| 'perpetual_fallback';

export interface PreviewFallbackResponse {
	ok: true;
	license_id: string;
	current_state: SubscriptionState;
	end_state: SubscriptionState;
	version_cutoff: number | null;
	fallback_earned_at: number | null;
	continuous_paid_months: number;
}

// ---------------------------------------------------------------------------
// 吊销（/v1/admin/{licenses,machines}/:id/revoke?dry_run=...）
// ---------------------------------------------------------------------------

/** copylocker-types KillReason 的 u8 判别值（不走 serde，按数值传递）。 */
export const KILL_REASONS = {
	RevokedLicense: 1,
	RevokedActivation: 2,
	SeatReclaimed: 3,
	Fraud: 4,
	Refund: 5,
	EpochRevoked: 6
} as const;

export type RevokeKind = 'licenses' | 'machines';

export interface RevokeDryRunResponse {
	ok: true;
	dry_run: true;
	kind: 'license' | 'machine';
	target: string;
	affected_machines: number;
	already_revoked: boolean;
}

export interface RevokeConfirmedResponse {
	ok: true;
	dry_run: false;
	kind: 'license' | 'machine';
	target: string;
	revocation_epoch: number;
}

export type RevokeResponse = RevokeDryRunResponse | RevokeConfirmedResponse;

// ---------------------------------------------------------------------------
// Epoch（/v1/admin/epochs）
// ---------------------------------------------------------------------------

export type EpochStatus = 'active' | 'upcoming' | 'expired' | 'revoked';

export interface EpochView {
	epoch_id: string;
	product_id: string;
	suite_id: string;
	not_before: number;
	not_after: number;
	revoked_at: number | null;
	created_at: number;
	status: EpochStatus;
	affected_machines_upper_bound: number;
}

export interface EpochListResponse {
	ok: true;
	product_id: string;
	items: EpochView[];
}

export interface EpochResponse {
	ok: true;
	epoch: EpochView;
	replacement_ready: boolean;
	replacement_epoch_ids: string[];
}

export interface EpochUploadBody {
	certificate_hex: string;
	root_verifying_key_hex: string;
}

export interface EpochUploadResponse {
	ok: true;
	epoch: EpochView;
	version: number;
}

export interface EpochRevokeDryRunResponse {
	ok: true;
	dry_run: true;
	epoch: EpochView;
	affected_machines_upper_bound: number;
	replacement_ready: boolean;
	replacement_epoch_ids: string[];
	already_revoked: boolean;
	requires_distinct_actors: number;
}

/** 第一次批准：202，approval_pending=true；第二次批准：200，含 revocation_epoch。 */
export interface EpochRevokeConfirmedResponse {
	ok: true;
	dry_run: false;
	approval_pending: boolean;
	epoch_id: string;
	revocation_epoch?: number;
	first_actor: string;
	second_actor?: string;
	approval_expires_at?: number;
	required_confirmations: number;
	received_confirmations: number;
}

export type EpochRevokeResponse = EpochRevokeDryRunResponse | EpochRevokeConfirmedResponse;

// ---------------------------------------------------------------------------
// Releases（admin_resources/releases.rs 的 list 投影；Simulator 的版本决策输入）
// ---------------------------------------------------------------------------

/** 一个已注册 release（`release_value` 投影；variant_params 永不离开服务端）。 */
export interface ReleaseRecord {
	id: string;
	product_id: string;
	app_version: string;
	variant_id: number;
	build_fingerprint: string;
	manifest_root_hex: string | null;
	channel: string;
	/** `active`、`deprecated` 或 `compromised`。 */
	status: string;
	compromised_action: 'warn' | 'force_upgrade' | 'revoke' | null;
	published_at: number;
	deprecated_at: number | null;
	created_at: number;
}

/** `GET /v1/admin/releases?product_id=` 响应。 */
export interface ReleaseListResponse {
	ok: true;
	product_id: string;
	items: ReleaseRecord[];
}

// ---------------------------------------------------------------------------
// Release 操作（register / deprecate / mark-compromised，M5-A wire shapes）
// ---------------------------------------------------------------------------

export interface RegisterReleaseBody {
	product_id: string;
	app_version: string;
	build_fingerprint: string;
	channel: string;
	manifest_root_hex?: string;
	module_digest_hex?: string;
	/** 64 hex chars；只用于服务端派生 variant params，永不回显。 */
	variant_seed_hex?: string;
}

export interface RegisterReleaseResponse {
	ok: true;
	already_registered: boolean;
	variant_reused?: boolean;
	release: ReleaseRecord;
	warnings?: { id: string; message: string }[];
}

export interface ReleaseImpact {
	devices: number;
	checkins_last_7d: number;
}

export interface DeprecateReleaseDryRunResponse {
	ok: true;
	dry_run: true;
	action: 'deprecate';
	release: ReleaseRecord;
	impact: ReleaseImpact;
	effects: string[];
}

export interface DeprecateReleaseConfirmedResponse {
	ok: true;
	dry_run: false;
	action: 'deprecate';
	release: { id: string; status: string; deprecated_at: number };
	impact: ReleaseImpact;
}

export type DeprecateReleaseResponse =
	| DeprecateReleaseDryRunResponse
	| DeprecateReleaseConfirmedResponse;

export type CompromiseAction = 'warn' | 'force_upgrade' | 'revoke';

export interface MarkCompromisedBody {
	action: CompromiseAction;
	bump_security_floor?: boolean;
	acknowledge_revoke?: boolean;
}

export interface MarkCompromisedDryRunResponse {
	ok: true;
	dry_run: true;
	action: string;
	release: ReleaseRecord;
	impact: ReleaseImpact;
	effects: string[];
	requires_acknowledgement: boolean;
	security_floor: { current: number; next: number | null };
}

export interface MarkCompromisedConfirmedResponse {
	ok: true;
	dry_run: false;
	action: string;
	release: { id: string; status: string; compromised_action: string };
	impact: ReleaseImpact;
	security_floor: number | null;
}

export type MarkCompromisedResponse =
	| MarkCompromisedDryRunResponse
	| MarkCompromisedConfirmedResponse;

// ---------------------------------------------------------------------------
// 跨许可设备列表与 GDPR 删除（/v1/admin/machines，M7-C）
// ---------------------------------------------------------------------------

export type MachineStatus = 'active' | 'pending' | 'released' | 'revoked';

export interface AdminMachine {
	machine_id: string;
	license_id: string;
	status: MachineStatus;
	activation_path: string;
	first_seen_at: number;
	last_seen_at: number | null;
	os: string | null;
	arch: string | null;
	app_version: string | null;
	sdk_version: string | null;
	release_id: string | null;
	variant_id: number | null;
	build_fingerprint: string | null;
	geo_country: string | null;
	suspicion: number;
}

export interface AdminMachineListResponse {
	ok: true;
	product_id: string;
	items: AdminMachine[];
	next_cursor: string | null;
}

// ---------------------------------------------------------------------------
// Admin 审计链（/v1/admin/audit，M7-C）
// ---------------------------------------------------------------------------

export interface AdminAuditEventSummary {
	seq: number;
	occurred_at: number;
	actor: string;
	action: string;
	target: string;
	reason: number | null;
	request_id: string;
	source_kind: string;
	r2_key: string;
}

export interface AdminAuditListResponse {
	ok: true;
	items: AdminAuditEventSummary[];
	next_cursor: string | null;
}

export interface AdminAuditChainHead {
	seq: number;
	hash: string;
}

export interface AdminAuditChainBreak {
	seq: number;
	reason: string;
}

export interface VerifyAdminAuditResponse {
	ok: true;
	verified: boolean;
	event_count: number;
	first_seq: number | null;
	last_seq: number | null;
	head: AdminAuditChainHead | null;
	first_broken: AdminAuditChainBreak | null;
}

// ---------------------------------------------------------------------------
// Analytics（/v1/admin/analytics/*，M6 wire shapes）
// ---------------------------------------------------------------------------

export interface AnalyticsMetricDefinition {
	id: string;
	name: string;
	definition: string;
	tier: string;
	/** T0（签名计量）或 T1（设备自报）；两类不得同图混绘。 */
	trusted: boolean;
}

export interface AnalyticsPoint {
	bucket: string;
	dims: Record<string, unknown>;
	value: number;
}

export interface AnalyticsSeries {
	metric_id: string;
	points: AnalyticsPoint[];
}

export interface AnalyticsQueryMeta {
	source: 'exact' | 'hll';
	/** 最坏相对误差（%）：exact 为 0，HLL 约 0.81。 */
	error_pct: number;
	/** k-匿名抑制的 bucket 数。 */
	suppressed_buckets: number;
	warning?: string;
}

export type AnalyticsGroupBy =
	| 'app_version'
	| 'os_arch'
	| 'country'
	| 'activation_path'
	| 'mode'
	| 'release_id'
	| 'policy_id'
	| 'sdk_version';

export interface AnalyticsMetricsQuery {
	product: string;
	ids: string[];
	from: string;
	to: string;
	granularity?: 'day' | 'week' | 'month';
	groupBy?: AnalyticsGroupBy;
	source?: 'auto' | 'exact' | 'hll';
}

export interface AnalyticsMetricsResponse {
	ok: true;
	product_id: string;
	from: string;
	to: string;
	granularity: string;
	series: AnalyticsSeries[];
	meta: AnalyticsQueryMeta;
}

// ---------------------------------------------------------------------------
// DSR 与 telemetry 保留（/v1/admin/dsr/*、/v1/admin/telemetry/purge，M6）
// ---------------------------------------------------------------------------

export interface DsrSubjectBody {
	product_id: string;
	machine_id?: string;
	license_id?: string;
}

export interface DsrSubject {
	machine_id?: string;
	license_id?: string;
}

export interface DsrMachineSummary {
	id: string;
	license_id: string;
	status: string;
}

export interface DsrExportResponse {
	ok: true;
	product_id: string;
	subject: DsrSubject;
	generated_at: number;
	machines: unknown[];
	licenses: unknown[];
	audit_references: unknown[];
	audit_truncated: boolean;
}

export interface DsrDeleteDryRunResponse {
	ok: true;
	dry_run: true;
	product_id: string;
	subject: DsrSubject;
	machines: DsrMachineSummary[];
	raw_records: number;
	audit_tombstone: false;
}

export interface DsrDeleteConfirmedResponse {
	ok: true;
	dry_run: false;
	product_id: string;
	subject: DsrSubject;
	deleted_machines: number;
	deleted_raw_records: number;
	audit_tombstone: false;
	audit_note: string;
}

export type DsrDeleteResponse = DsrDeleteDryRunResponse | DsrDeleteConfirmedResponse;

export interface TelemetryPurgeBody {
	product_id: string;
	/** YYYY-MM-DD；缺省 = 30 天 T1 raw 保留策略（不动 rollup 表）。 */
	before?: string;
}

export interface TelemetryPurgeDryRunResponse {
	ok: true;
	dry_run: true;
	product_id: string;
	cutoff: string;
	raw_records: number;
	rollup_rows: number;
}

export interface TelemetryPurgeConfirmedResponse {
	ok: true;
	dry_run: false;
	product_id: string;
	cutoff: string;
	deleted_raw_records: number;
	deleted_rollup_rows: number;
	journaled: boolean;
}

export type TelemetryPurgeResponse =
	| TelemetryPurgeDryRunResponse
	| TelemetryPurgeConfirmedResponse;
