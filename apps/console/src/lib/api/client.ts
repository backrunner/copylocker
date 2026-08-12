/**
 * Admin REST API 的类型化客户端（@copylocker/admin-sdk 的适配层）。
 *
 * M7-B 起传输层由 @copylocker/admin-sdk 承担（同一套类型在
 * packages/admin-sdk/bindings + bindings-check.ts 下与 Rust 线格式做漂移检查）；
 * 本类只保留控制台自己的调用约定，页面无感知：
 *
 * - 方法名/返回形状与原手写客户端一致（list 响应包回 { ok, product_id, items }）；
 * - mutation 自动携带 Idempotency-Key（crypto.randomUUID()），可显式覆盖；
 * - 响应上限 4 MiB（SDK 的 maxResponseBytes，Content-Length 预检 + 流式上限）；
 * - token 只出现在 Authorization header，绝不进 URL；
 * - 只允许 /v1/admin/* 路径（SDK 只暴露 admin 路由）；
 * - 错误按 { ok:false, error:{code,message} } 信封解析并分类（ApiError）。
 */

import {
	AdminApiError,
	createAdminClient,
	type AdminClient as SdkAdminClient,
	type FetchLike
} from '@copylocker/admin-sdk';
import { ApiError, classifyError } from './errors';
import type {
	AdminAuditListResponse,
	AdminMachineListResponse,
	AnalyticsMetricDefinition,
	AnalyticsMetricsQuery,
	AnalyticsMetricsResponse,
	CatalogCollection,
	CatalogListResponse,
	CatalogMutationResponse,
	DeprecateReleaseResponse,
	DsrDeleteResponse,
	DsrExportResponse,
	DsrSubjectBody,
	EpochListResponse,
	EpochResponse,
	EpochRevokeResponse,
	EpochUploadBody,
	EpochUploadResponse,
	Feature,
	FeatureBody,
	FeatureGroup,
	GroupBody,
	IssueLicenseBody,
	IssueLicenseResponse,
	LicenseListResponse,
	LicensePatch,
	LicenseRecord,
	LicenseResponse,
	LicenseStatus,
	MachineListResponse,
	MachineStatus,
	MachineView,
	MarkCompromisedBody,
	MarkCompromisedResponse,
	Policy,
	PolicyListResponse,
	PolicyResponse,
	PreviewFallbackResponse,
	RegisterReleaseBody,
	RegisterReleaseResponse,
	ReleaseListResponse,
	ResolveRequest,
	ResolveResponse,
	RevokeKind,
	RevokeResponse,
	TelemetryPurgeBody,
	TelemetryPurgeResponse,
	Tier,
	TierBody,
	VerifyAdminAuditResponse
} from './types';

/** 与 CLI 一致：4 MiB 响应上限。 */
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export const ADMIN_TOKEN_PATTERN = /^clat_[A-Za-z0-9_-]{43}$/;

export interface AdminClientOptions {
	/** 例如 '/admin-api'（经 Service Binding 代理）或 'http://localhost:8788'（dev mock）。 */
	baseUrl: string;
	/** 每次请求时取 token；返回 null 表示未登录。 */
	getToken: () => string | null;
	/** 测试注入 mock fetch。 */
	fetcher?: typeof fetch;
}

type CatalogBodyOf<C extends CatalogCollection> = C extends 'features'
	? FeatureBody
	: C extends 'groups'
		? GroupBody
		: TierBody;

type CatalogItemOf<C extends CatalogCollection> = C extends 'features'
	? Feature
	: C extends 'groups'
		? FeatureGroup
		: Tier;

export class AdminClient {
	private readonly baseUrl: string;
	private readonly getToken: () => string | null;
	private readonly fetcher: typeof fetch;

	constructor(options: AdminClientOptions) {
		// 拒绝带凭据的 origin（与 CLI 一致），避免 token 被转发到第三方。
		if (/^https?:\/\/[^/@]+@/.test(options.baseUrl)) {
			throw new Error('API base URL must not embed credentials');
		}
		this.baseUrl = options.baseUrl.replace(/\/+$/, '');
		this.getToken = options.getToken;
		this.fetcher = options.fetcher ?? fetch;
	}

	private sdk(): SdkAdminClient {
		const fetcher = this.fetcher;
		const wrapped: FetchLike = async (input, init) => {
			// SDK 传 plain-object headers；控制台约定（含测试断言）是 Headers 实例。
			const headers = new Headers(init?.headers as Record<string, string>);
			if (headers.get('Authorization') === 'Bearer ') {
				// 未登录：与原客户端一致，完全不发送 Authorization 头。
				headers.delete('Authorization');
			}
			try {
				return await fetcher(input, { ...init, headers, redirect: 'error' });
			} catch {
				throw new ApiError(0, 'network_error', '无法连接 Admin API', 'network');
			}
		};
		return createAdminClient({
			baseUrl: this.baseUrl,
			token: this.getToken() ?? '',
			fetch: wrapped,
			maxResponseBytes: MAX_RESPONSE_BYTES
		});
	}

	private async call<T>(run: (sdk: SdkAdminClient) => Promise<T>): Promise<T> {
		try {
			return await run(this.sdk());
		} catch (error) {
			if (error instanceof ApiError) throw error;
			if (error instanceof AdminApiError) {
				// response_too_large 是传输层失败（status 0），归入 network 类。
				throw new ApiError(error.status, error.code, error.message, classifyError(error.status, ''));
			}
			throw error;
		}
	}

	private mutationKey(idempotencyKey?: string): { idempotencyKey: string } {
		return { idempotencyKey: idempotencyKey ?? crypto.randomUUID() };
	}

	// ------------------------------------------------------------- licenses

	listLicenses(query: { product_id: string; status?: LicenseStatus; limit?: number }) {
		return this.call(async (sdk): Promise<LicenseListResponse> => {
			const items = (await sdk.licenses.list({
				productId: query.product_id,
				status: query.status,
				limit: query.limit
			})) as LicenseRecord[];
			return { ok: true, product_id: query.product_id, items };
		});
	}

	getLicense(licenseId: string) {
		return this.call(async (sdk): Promise<LicenseResponse> => {
			const license = (await sdk.licenses.get(licenseId)) as LicenseRecord;
			return { ok: true, license };
		});
	}

	issueLicenses(body: IssueLicenseBody, idempotencyKey?: string) {
		return this.call(
			(sdk): Promise<IssueLicenseResponse> =>
				sdk.licenses.issue(body, this.mutationKey(idempotencyKey))
		);
	}

	patchLicense(licenseId: string, patch: LicensePatch, idempotencyKey?: string) {
		return this.call(async (sdk): Promise<LicenseResponse> => {
			const response = await sdk.licenses.update(licenseId, patch, this.mutationKey(idempotencyKey));
			return { ok: true, license: response.license as LicenseRecord, version: response.version };
		});
	}

	changeLicenseTier(licenseId: string, tier: string, idempotencyKey?: string) {
		return this.call(async (sdk): Promise<LicenseResponse> => {
			const response = await sdk.licenses.changeTier(
				licenseId,
				tier,
				this.mutationKey(idempotencyKey)
			);
			return { ok: true, license: response.license as LicenseRecord, version: response.version };
		});
	}

	previewLicenseFallback(licenseId: string) {
		return this.call(
			(sdk): Promise<PreviewFallbackResponse> => sdk.licenses.previewFallback(licenseId)
		);
	}

	listLicenseMachines(licenseId: string) {
		return this.call(async (sdk): Promise<MachineListResponse> => {
			const items = (await sdk.licenses.listMachines(licenseId)) as MachineView[];
			return { ok: true, license_id: licenseId, items };
		});
	}

	// ------------------------------------------------------------- revoke

	revoke(
		kind: RevokeKind,
		targetId: string,
		options: { dryRun: boolean; reason?: number; idempotencyKey?: string }
	) {
		return this.call(async (sdk): Promise<RevokeResponse> => {
			const revokeOptions = {
				dryRun: options.dryRun,
				reason: options.reason,
				// dry-run 不需要幂等键；确认请求必须携带（服务端强制）。
				...(options.dryRun ? {} : this.mutationKey(options.idempotencyKey))
			};
			const response =
				kind === 'licenses'
					? await sdk.revoke.license(targetId, revokeOptions)
					: await sdk.revoke.machine(targetId, revokeOptions);
			return response as RevokeResponse;
		});
	}

	// ------------------------------------------------------------- catalog

	listCatalog<C extends CatalogCollection>(collection: C, productId: string) {
		return this.call(async (sdk): Promise<CatalogListResponse<CatalogItemOf<C>>> => {
			const response = await sdk.catalog.list(collection, productId);
			return {
				ok: true,
				product_id: productId,
				catalog_version: response.catalogVersion,
				items: response.items as CatalogItemOf<C>[]
			};
		});
	}

	createCatalogItem<C extends CatalogCollection>(
		collection: C,
		body: CatalogBodyOf<C>,
		idempotencyKey?: string
	) {
		return this.call(
			(sdk): Promise<CatalogMutationResponse> =>
				sdk.catalog
					.create(collection, body, this.mutationKey(idempotencyKey))
					.then((response) => response as CatalogMutationResponse)
		);
	}

	updateCatalogItem<C extends CatalogCollection>(
		collection: C,
		body: CatalogBodyOf<C>,
		idempotencyKey?: string
	) {
		return this.call(
			(sdk): Promise<CatalogMutationResponse> =>
				sdk.catalog
					.update(collection, body, this.mutationKey(idempotencyKey))
					.then((response) => response as CatalogMutationResponse)
		);
	}

	resolveCatalog(body: ResolveRequest) {
		return this.call((sdk): Promise<ResolveResponse> =>
			sdk.catalog.resolve(body).then((response) => response as unknown as ResolveResponse)
		);
	}

	// ------------------------------------------------------------- policies

	listPolicies(productId: string) {
		return this.call(async (sdk): Promise<PolicyListResponse> => {
			const items = (await sdk.policies.list(productId)) as Policy[];
			return { ok: true, product_id: productId, items };
		});
	}

	getPolicy(policyId: string) {
		return this.call((sdk): Promise<PolicyResponse> => sdk.policies.get(policyId));
	}

	createPolicy(policy: Policy, idempotencyKey?: string) {
		return this.call(
			(sdk): Promise<PolicyResponse> => sdk.policies.create(policy, this.mutationKey(idempotencyKey))
		);
	}

	updatePolicy(policy: Policy, idempotencyKey?: string) {
		return this.call(
			(sdk): Promise<PolicyResponse> => sdk.policies.update(policy, this.mutationKey(idempotencyKey))
		);
	}

	// ------------------------------------------------------------- epochs

	listEpochs(productId: string) {
		return this.call(async (sdk): Promise<EpochListResponse> => {
			const items = (await sdk.epochs.list(productId)) as EpochListResponse['items'];
			return { ok: true, product_id: productId, items };
		});
	}

	getEpoch(epochId: string) {
		return this.call((sdk): Promise<EpochResponse> =>
			sdk.epochs.get(epochId).then((response) => response as EpochResponse)
		);
	}

	uploadEpoch(body: EpochUploadBody, idempotencyKey?: string) {
		return this.call((sdk): Promise<EpochUploadResponse> =>
			sdk.epochs
				.upload(body, this.mutationKey(idempotencyKey))
				.then((response) => response as EpochUploadResponse)
		);
	}

	revokeEpoch(
		epochId: string,
		options: { dryRun: boolean; confirmEpochId?: string; idempotencyKey?: string }
	) {
		return this.call(async (sdk): Promise<EpochRevokeResponse> => {
			const response = await sdk.epochs.revoke(epochId, {
				dryRun: options.dryRun,
				confirmEpochId: options.confirmEpochId,
				...(options.dryRun ? {} : this.mutationKey(options.idempotencyKey))
			});
			return response as EpochRevokeResponse;
		});
	}

	// ------------------------------------------------------------- releases

	listReleases(productId: string) {
		return this.call(async (sdk): Promise<ReleaseListResponse> => {
			const items = (await sdk.releases.list(productId)) as ReleaseListResponse['items'];
			return { ok: true, product_id: productId, items };
		});
	}

	registerRelease(body: RegisterReleaseBody, idempotencyKey?: string) {
		return this.call(
			(sdk): Promise<RegisterReleaseResponse> =>
				sdk.releases
					.register(body, this.mutationKey(idempotencyKey))
					.then((response) => response as RegisterReleaseResponse)
		);
	}

	deprecateRelease(
		releaseId: string,
		options: { productId: string; dryRun: boolean; idempotencyKey?: string }
	) {
		return this.call(async (sdk): Promise<DeprecateReleaseResponse> => {
			const response = await sdk.releases.deprecate(releaseId, {
				productId: options.productId,
				dryRun: options.dryRun,
				...(options.dryRun ? {} : this.mutationKey(options.idempotencyKey))
			});
			return response as DeprecateReleaseResponse;
		});
	}

	markReleaseCompromised(
		releaseId: string,
		body: MarkCompromisedBody,
		options: { productId: string; dryRun: boolean; idempotencyKey?: string }
	) {
		return this.call(async (sdk): Promise<MarkCompromisedResponse> => {
			const response = await sdk.releases.markCompromised(releaseId, body, {
				productId: options.productId,
				dryRun: options.dryRun,
				...(options.dryRun ? {} : this.mutationKey(options.idempotencyKey))
			});
			return response as MarkCompromisedResponse;
		});
	}

	// ------------------------------------------------------------- machines

	listMachines(query: {
		product_id: string;
		license_id?: string;
		status?: MachineStatus;
		limit?: number;
		cursor?: string;
	}) {
		return this.call((sdk): Promise<AdminMachineListResponse> =>
			sdk.machines.list({
				productId: query.product_id,
				licenseId: query.license_id,
				status: query.status,
				limit: query.limit,
				cursor: query.cursor
			})
		);
	}

	deleteMachine(machineId: string, options: { dryRun: boolean; idempotencyKey?: string }) {
		return this.call(async (sdk): Promise<DsrDeleteResponse> => {
			const response = await sdk.machines.delete(machineId, {
				dryRun: options.dryRun,
				...(options.dryRun ? {} : this.mutationKey(options.idempotencyKey))
			});
			return response as DsrDeleteResponse;
		});
	}

	// ------------------------------------------------------------- audit

	listAuditEvents(query: { target?: string; kind?: string; limit?: number; cursor?: string }) {
		return this.call((sdk): Promise<AdminAuditListResponse> =>
			sdk.audit.list({
				target: query.target,
				kind: query.kind,
				limit: query.limit,
				cursor: query.cursor
			})
		);
	}

	verifyAuditChain() {
		return this.call((sdk): Promise<VerifyAdminAuditResponse> => sdk.audit.verify());
	}

	// ------------------------------------------------------------- analytics

	analyticsDefinitions() {
		return this.call(async (sdk): Promise<AnalyticsMetricDefinition[]> => {
			const items = await sdk.analytics.definitions();
			return items as AnalyticsMetricDefinition[];
		});
	}

	analyticsMetrics(query: AnalyticsMetricsQuery) {
		return this.call((sdk): Promise<AnalyticsMetricsResponse> =>
			sdk.analytics.metrics(query) as Promise<AnalyticsMetricsResponse>
		);
	}

	// ------------------------------------------------------------- dsr + telemetry

	dsrExport(body: DsrSubjectBody) {
		return this.call((sdk): Promise<DsrExportResponse> =>
			sdk.dsr.export(body) as Promise<DsrExportResponse>
		);
	}

	dsrDelete(body: DsrSubjectBody, options: { dryRun: boolean; idempotencyKey?: string }) {
		return this.call(async (sdk): Promise<DsrDeleteResponse> => {
			const response = await sdk.dsr.delete(body, {
				dryRun: options.dryRun,
				...(options.dryRun ? {} : this.mutationKey(options.idempotencyKey))
			});
			return response as DsrDeleteResponse;
		});
	}

	telemetryPurge(body: TelemetryPurgeBody, options: { dryRun: boolean; idempotencyKey?: string }) {
		return this.call(async (sdk): Promise<TelemetryPurgeResponse> => {
			const response = await sdk.telemetry.purge(body, {
				dryRun: options.dryRun,
				...(options.dryRun ? {} : this.mutationKey(options.idempotencyKey))
			});
			return response as TelemetryPurgeResponse;
		});
	}
}
