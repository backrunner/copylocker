import { AdminApiError } from './errors.js'
import type {
  Account,
  AlertWebhookBody,
  AlertWebhookResponse,
  AnalyticsDefinitionsResponse,
  AnalyticsExport,
  AnalyticsMetricsQuery,
  AnalyticsMetricsResponse,
  AnalyticsSubscription,
  AssetKek,
  CatalogBodyOf,
  CatalogCollection,
  CatalogItemOf,
  CatalogListResponse,
  CatalogMutationResponse,
  CatalogResolveBody,
  CatalogResolveResponse,
  CreateAccountBody,
  CreateAccountResponse,
  CreateSubscriptionBody,
  CreateSubscriptionResponse,
  DeleteAssetKekDryRunResponse,
  DeleteAssetKekResponse,
  DeprecateReleaseDryRunResponse,
  DeprecateReleaseResponse,
  DsrDeleteDryRunResponse,
  DsrDeleteResponse,
  DsrExportResponse,
  DsrSubjectBody,
  Epoch,
  IntegritySignature,
  IssueLicenseBody,
  IssueLicenseResponse,
  IssueOfflineKeyBody,
  IssueOfflineKeyResponse,
  License,
  LicensePatch,
  ListAccountsResponse,
  ListAdminAuditResponse,
  ListAdminMachinesResponse,
  ListAssetKeksResponse,
  ListEpochsResponse,
  ListIntegrityKeysResponse,
  ListLicensesResponse,
  ListMachinesResponse,
  ListPoliciesResponse,
  ListReleasesResponse,
  ListSubscriptionsResponse,
  Machine,
  MachineDeleteDryRunResponse,
  MachineDeleteResponse,
  MarkCompromisedBody,
  MarkCompromisedDryRunResponse,
  MarkCompromisedResponse,
  Policy,
  PolicyResponse,
  PreviewFallbackResponse,
  RegisterAssetKekBody,
  RegisterAssetKekResponse,
  RegisterIntegrityKeyBody,
  RegisterIntegrityKeyResponse,
  RegisterReleaseBody,
  RegisterReleaseResponse,
  Release,
  RevokeBody,
  RevokeDryRunResponse,
  RevokeEpochBody,
  RevokeEpochDryRunResponse,
  RevokeEpochResponse,
  RevokeIntegrityKeyDryRunResponse,
  RevokeIntegrityKeyResponse,
  RevokeResponse,
  ShowEpochResponse,
  ShowLicenseResponse,
  ShowReleaseResponse,
  TelemetryPurgeBody,
  TelemetryPurgeDryRunResponse,
  TelemetryPurgeResponse,
  UpdateLicenseResponse,
  UploadEpochBody,
  UploadEpochResponse,
  VerifyAdminAuditResponse,
} from './types.js'

/** A `fetch`-compatible function (global `fetch` is used by default). */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

/** Options for {@link createAdminClient}. */
export interface AdminClientOptions {
  /**
   * Base URL of the CopyLocker Worker, e.g. `https://licenses.example.com`.
   * A trailing slash is ignored. A relative base (e.g. `/admin-api` behind a
   * same-origin server proxy) is allowed: requests then go to relative URLs.
   */
  baseUrl: string
  /**
   * Admin bearer token (`clat_…`). Sent as `Authorization: Bearer <token>`
   * on every request. Never logged or included in URLs.
   */
  token: string
  /** Custom fetch implementation (defaults to the global `fetch`). */
  fetch?: FetchLike
  /**
   * Response body cap in bytes. Responses whose declared Content-Length or
   * actual body exceeds it are rejected with an `AdminApiError` carrying the
   * `response_too_large` code and status 0 (a transport-level failure, like
   * a network error). Defaults to 4 MiB, matching the CLI.
   */
  maxResponseBytes?: number
}

/**
 * Options for confirmed mutations. Every confirmed Admin mutation requires
 * an `Idempotency-Key` header; the key must be unique per logical operation
 * and reused verbatim on retries.
 */
export interface MutationOptions {
  idempotencyKey?: string
}

/**
 * Options for destructive transitions that follow the Admin dry-run
 * discipline. `dryRun` defaults to `true` server-side; pass `false`
 * together with an `idempotencyKey` to confirm.
 */
export interface TransitionOptions extends MutationOptions {
  dryRun?: boolean
}

/** Query options for `licenses.list`. */
export interface ListLicensesQuery {
  productId: string
  status?: 'active' | 'suspended' | 'expired' | 'revoked'
  /** 1..=100, defaults to 50 server-side. */
  limit?: number
}

/** Query options for `assetKeks.list`. */
export interface ListAssetKeksQuery {
  productId: string
  releaseId?: string
}

/** Query options for `machines.list`. */
export interface ListAdminMachinesQuery {
  productId: string
  /** 16-byte hex; restricts to one license's machines. */
  licenseId?: string
  status?: 'active' | 'pending' | 'released' | 'revoked'
  /** 1..=100, defaults to 50 server-side. */
  limit?: number
  /** Opaque cursor from a previous page's `next_cursor`. */
  cursor?: string
}

/** Query options for `audit.list`. */
export interface ListAdminAuditQuery {
  /** Exact event target (e.g. a 16-byte hex machine/license id). */
  target?: string
  /** `source_kind` filter (e.g. `revocation`, `dsr`, `catalog`). */
  kind?: string
  /** 1..=100, defaults to 50 server-side. */
  limit?: number
  /** Opaque cursor from a previous page's `next_cursor`. */
  cursor?: string
}

/** Options for the epoch revocation two-actor flow. */
export interface RevokeEpochOptions extends TransitionOptions {
  /** Required when confirming (`dryRun: false`); must repeat the target id. */
  confirmEpochId?: string
}

/** Options for license/machine revocation. */
export interface RevokeOptions extends TransitionOptions {
  /** A `KillReason` code; the kind's default applies when omitted. */
  reason?: number
}

interface RequestOptions {
  method: string
  path: string
  query?: Record<string, string | number | boolean | undefined>
  body?: unknown
  idempotencyKey?: string
}

/** The typed Admin API client returned by {@link createAdminClient}. */
export interface AdminClient {
  releases: {
    list(productId: string): Promise<Release[]>
    get(releaseId: string, productId: string): Promise<Release>
    register(body: RegisterReleaseBody, options?: MutationOptions): Promise<RegisterReleaseResponse>
    deprecate(
      releaseId: string,
      options: TransitionOptions & { productId: string },
    ): Promise<DeprecateReleaseDryRunResponse | DeprecateReleaseResponse>
    markCompromised(
      releaseId: string,
      body: MarkCompromisedBody,
      options: TransitionOptions & { productId: string },
    ): Promise<MarkCompromisedDryRunResponse | MarkCompromisedResponse>
  }
  licenses: {
    list(query: ListLicensesQuery): Promise<License[]>
    get(licenseId: string): Promise<License>
    issue(body: IssueLicenseBody, options?: MutationOptions): Promise<IssueLicenseResponse>
    update(
      licenseId: string,
      patch: LicensePatch,
      options?: MutationOptions,
    ): Promise<UpdateLicenseResponse>
    changeTier(
      licenseId: string,
      tier: string,
      options?: MutationOptions,
    ): Promise<UpdateLicenseResponse>
    previewFallback(licenseId: string): Promise<PreviewFallbackResponse>
    listMachines(licenseId: string): Promise<Machine[]>
  }
  accounts: {
    list(productId: string): Promise<Account[]>
    create(body: CreateAccountBody, options?: MutationOptions): Promise<CreateAccountResponse>
  }
  assetKeks: {
    list(query: ListAssetKeksQuery): Promise<AssetKek[]>
    register(body: RegisterAssetKekBody, options?: MutationOptions): Promise<RegisterAssetKekResponse>
    delete(
      releaseId: string,
      featureId: string,
      options: TransitionOptions & { productId: string },
    ): Promise<DeleteAssetKekDryRunResponse | DeleteAssetKekResponse>
  }
  integrity: {
    listKeys(productId: string): Promise<ListIntegrityKeysResponse['items']>
    registerKey(
      body: RegisterIntegrityKeyBody,
      options?: MutationOptions,
    ): Promise<RegisterIntegrityKeyResponse>
    revokeKey(
      fingerprint: string,
      options: TransitionOptions & { productId: string },
    ): Promise<RevokeIntegrityKeyDryRunResponse | RevokeIntegrityKeyResponse>
    sign(tbs: Uint8Array): Promise<IntegritySignature>
  }
  offlineKey: {
    issue(
      licenseId: string,
      body: IssueOfflineKeyBody,
      options?: MutationOptions,
    ): Promise<IssueOfflineKeyResponse>
  }
  catalog: {
    list<C extends CatalogCollection>(
      collection: C,
      productId: string,
    ): Promise<{ catalogVersion: number; items: CatalogItemOf<C>[] }>
    create<C extends CatalogCollection>(
      collection: C,
      body: CatalogBodyOf<C>,
      options?: MutationOptions,
    ): Promise<CatalogMutationResponse>
    update<C extends CatalogCollection>(
      collection: C,
      body: CatalogBodyOf<C>,
      options?: MutationOptions,
    ): Promise<CatalogMutationResponse>
    resolve(body: CatalogResolveBody): Promise<CatalogResolveResponse>
  }
  policies: {
    list(productId: string): Promise<Policy[]>
    get(policyId: string): Promise<PolicyResponse>
    create(policy: Policy, options?: MutationOptions): Promise<PolicyResponse>
    update(policy: Policy, options?: MutationOptions): Promise<PolicyResponse>
  }
  epochs: {
    list(productId: string): Promise<Epoch[]>
    get(epochId: string): Promise<ShowEpochResponse>
    upload(body: UploadEpochBody, options?: MutationOptions): Promise<UploadEpochResponse>
    revoke(
      epochId: string,
      options?: RevokeEpochOptions,
    ): Promise<RevokeEpochDryRunResponse | RevokeEpochResponse>
  }
  revoke: {
    license(
      licenseId: string,
      options?: RevokeOptions,
    ): Promise<RevokeDryRunResponse | RevokeResponse>
    machine(
      machineId: string,
      options?: RevokeOptions,
    ): Promise<RevokeDryRunResponse | RevokeResponse>
  }
  products: {
    getAlertWebhook(productId: string): Promise<AlertWebhookResponse>
    updateAlertWebhook(
      productId: string,
      body: AlertWebhookBody,
      options?: MutationOptions,
    ): Promise<AlertWebhookResponse>
  }
  analytics: {
    definitions(): Promise<AnalyticsDefinitionsResponse['items']>
    metrics(query: AnalyticsMetricsQuery): Promise<AnalyticsMetricsResponse>
    export(query: AnalyticsMetricsQuery & { format: 'csv' | 'ndjson' }): Promise<AnalyticsExport>
    listSubscriptions(productId?: string): Promise<AnalyticsSubscription[]>
    createSubscription(
      body: CreateSubscriptionBody,
      options?: MutationOptions,
    ): Promise<CreateSubscriptionResponse>
  }
  dsr: {
    export(body: DsrSubjectBody): Promise<DsrExportResponse>
    delete(
      body: DsrSubjectBody,
      options?: TransitionOptions,
    ): Promise<DsrDeleteDryRunResponse | DsrDeleteResponse>
  }
  machines: {
    list(query: ListAdminMachinesQuery): Promise<ListAdminMachinesResponse>
    /**
     * GDPR machine deletion (prd.md §209): a journaled alias over the DSR
     * delete cascade. Dry-run by default; confirm with `dryRun: false` plus
     * an `idempotencyKey`.
     */
    delete(
      machineId: string,
      options?: TransitionOptions,
    ): Promise<MachineDeleteDryRunResponse | MachineDeleteResponse>
  }
  audit: {
    list(query?: ListAdminAuditQuery): Promise<ListAdminAuditResponse>
    /** Read-only full hash-chain verification over `admin_audit_events`. */
    verify(): Promise<VerifyAdminAuditResponse>
  }
  telemetry: {
    purge(
      body: TelemetryPurgeBody,
      options?: TransitionOptions,
    ): Promise<TelemetryPurgeDryRunResponse | TelemetryPurgeResponse>
  }
}

/**
 * Create a typed client for the CopyLocker Admin API (`/v1/admin/*`).
 *
 * Covers every admin route: releases, licenses, accounts, asset-keks,
 * integrity, offline-key issuance, catalog, policies, epochs, license and
 * machine revocation, the product alert webhook, analytics
 * (definitions/metrics/export/subscriptions), DSR export/delete, the
 * telemetry retention purge, cross-license machine listing, the GDPR machine
 * delete, and the Admin audit chain query/verify.
 */
export function createAdminClient(options: AdminClientOptions): AdminClient {
  const base = options.baseUrl.replace(/\/+$/, '')
  const absolute = /^https?:\/\//i.test(base)
  const maxResponseBytes = options.maxResponseBytes ?? 4 * 1024 * 1024
  const fetchFn: FetchLike = options.fetch ?? ((input, init) => fetch(input, init))

  /** Resolve an API path to a fetchable URL (relative bases stay relative). */
  function buildUrl(path: string, query?: RequestOptions['query']): string {
    const url = new URL(`${base}${path}`, absolute ? undefined : 'http://admin-api.invalid')
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value !== undefined) {
        url.searchParams.set(key, String(value))
      }
    }
    return absolute ? url.toString() : `${url.pathname}${url.search}`
  }

  function tooLarge(): AdminApiError {
    return new AdminApiError(
      0,
      'response_too_large',
      `Admin API response exceeds the ${maxResponseBytes}-byte limit`,
    )
  }

  /** Read a JSON response body with the size cap enforced. */
  async function readJson(response: Response): Promise<unknown> {
    const declared = Number(response.headers.get('content-length') ?? 0)
    if (declared > maxResponseBytes) {
      throw tooLarge()
    }
    const text = await response.text()
    if (text.length > maxResponseBytes) {
      throw tooLarge()
    }
    // A non-JSON body (allowed only on error responses) becomes `undefined`.
    try {
      return JSON.parse(text) as unknown
    } catch {
      return undefined
    }
  }

  async function request<T>(opts: RequestOptions): Promise<T> {
    const url = buildUrl(opts.path, opts.query)
    const headers: Record<string, string> = {
      Authorization: `Bearer ${options.token}`,
    }
    if (opts.idempotencyKey !== undefined) {
      headers['Idempotency-Key'] = opts.idempotencyKey
    }
    let body: string | undefined
    if (opts.body !== undefined) {
      headers['Content-Type'] = 'application/json'
      body = JSON.stringify(opts.body)
    }
    const response = await fetchFn(url, {
      method: opts.method,
      headers,
      body,
    })
    const parsed: unknown = await readJson(response)
    if (!response.ok) {
      throw AdminApiError.fromBody(response.status, parsed)
    }
    return parsed as T
  }

  function transitionQuery(productId: string, dryRun: boolean | undefined) {
    return {
      product_id: productId,
      // Only send dry_run when explicitly confirming; the server default is
      // true, so omitting it preserves the dry-run-first discipline.
      ...(dryRun === undefined ? {} : { dry_run: dryRun }),
    }
  }

  /** The `dry_run`-only query contract of the revoke/DSR/purge endpoints. */
  function dryRunQuery(dryRun: boolean | undefined) {
    return dryRun === undefined ? {} : { dry_run: dryRun }
  }

  function analyticsParams(query: AnalyticsMetricsQuery) {
    return {
      product: query.product,
      ids: query.ids.join(','),
      from: query.from,
      to: query.to,
      granularity: query.granularity,
      group_by: query.groupBy,
      source: query.source,
    }
  }

  async function revokeTarget(
    kind: 'licenses' | 'machines',
    targetId: string,
    { dryRun, reason, idempotencyKey }: RevokeOptions = {},
  ) {
    const body: RevokeBody = reason === undefined ? {} : { reason }
    return request<RevokeDryRunResponse | RevokeResponse>({
      method: 'POST',
      path: `/v1/admin/${kind}/${encodeURIComponent(targetId)}/revoke`,
      query: dryRunQuery(dryRun),
      body,
      idempotencyKey,
    })
  }

  return {
    releases: {
      async list(productId) {
        const response = await request<ListReleasesResponse>({
          method: 'GET',
          path: '/v1/admin/releases',
          query: { product_id: productId },
        })
        return response.items
      },
      async get(releaseId, productId) {
        const response = await request<ShowReleaseResponse>({
          method: 'GET',
          path: `/v1/admin/releases/${encodeURIComponent(releaseId)}`,
          query: { product_id: productId },
        })
        return response.release
      },
      async register(body, mutation) {
        return request<RegisterReleaseResponse>({
          method: 'POST',
          path: '/v1/admin/releases',
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
      async deprecate(releaseId, { productId, dryRun, idempotencyKey }) {
        return request<DeprecateReleaseDryRunResponse | DeprecateReleaseResponse>({
          method: 'POST',
          path: `/v1/admin/releases/${encodeURIComponent(releaseId)}/deprecate`,
          query: transitionQuery(productId, dryRun),
          body: {},
          idempotencyKey,
        })
      },
      async markCompromised(releaseId, body, { productId, dryRun, idempotencyKey }) {
        return request<MarkCompromisedDryRunResponse | MarkCompromisedResponse>({
          method: 'POST',
          path: `/v1/admin/releases/${encodeURIComponent(releaseId)}/mark-compromised`,
          query: transitionQuery(productId, dryRun),
          body,
          idempotencyKey,
        })
      },
    },

    licenses: {
      async list({ productId, status, limit }) {
        const response = await request<ListLicensesResponse>({
          method: 'GET',
          path: '/v1/admin/licenses',
          query: { product_id: productId, status, limit },
        })
        return response.items
      },
      async get(licenseId) {
        const response = await request<ShowLicenseResponse>({
          method: 'GET',
          path: `/v1/admin/licenses/${encodeURIComponent(licenseId)}`,
        })
        return response.license
      },
      async issue(body, mutation) {
        return request<IssueLicenseResponse>({
          method: 'POST',
          path: '/v1/admin/licenses',
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
      async update(licenseId, patch, mutation) {
        return request<UpdateLicenseResponse>({
          method: 'PATCH',
          path: `/v1/admin/licenses/${encodeURIComponent(licenseId)}`,
          body: patch,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
      async changeTier(licenseId, tier, mutation) {
        return request<UpdateLicenseResponse>({
          method: 'POST',
          path: `/v1/admin/licenses/${encodeURIComponent(licenseId)}/change-tier`,
          body: { tier },
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
      async previewFallback(licenseId) {
        return request<PreviewFallbackResponse>({
          method: 'GET',
          path: `/v1/admin/licenses/${encodeURIComponent(licenseId)}/preview-fallback`,
        })
      },
      async listMachines(licenseId) {
        const response = await request<ListMachinesResponse>({
          method: 'GET',
          path: `/v1/admin/licenses/${encodeURIComponent(licenseId)}/machines`,
        })
        return response.items
      },
    },

    accounts: {
      async list(productId) {
        const response = await request<ListAccountsResponse>({
          method: 'GET',
          path: '/v1/admin/accounts',
          query: { product_id: productId },
        })
        return response.items
      },
      async create(body, mutation) {
        return request<CreateAccountResponse>({
          method: 'POST',
          path: '/v1/admin/accounts',
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
    },

    assetKeks: {
      async list({ productId, releaseId }) {
        const response = await request<ListAssetKeksResponse>({
          method: 'GET',
          path: '/v1/admin/asset-keks',
          query: { product_id: productId, release_id: releaseId },
        })
        return response.items
      },
      async register(body, mutation) {
        return request<RegisterAssetKekResponse>({
          method: 'POST',
          path: '/v1/admin/asset-keks',
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
      async delete(releaseId, featureId, { productId, dryRun, idempotencyKey }) {
        return request<DeleteAssetKekDryRunResponse | DeleteAssetKekResponse>({
          method: 'DELETE',
          path: `/v1/admin/asset-keks/${encodeURIComponent(releaseId)}/${encodeURIComponent(featureId)}`,
          query: transitionQuery(productId, dryRun),
          idempotencyKey,
        })
      },
    },

    integrity: {
      async listKeys(productId) {
        const response = await request<ListIntegrityKeysResponse>({
          method: 'GET',
          path: '/v1/admin/integrity/keys',
          query: { product_id: productId },
        })
        return response.items
      },
      async registerKey(body, mutation) {
        return request<RegisterIntegrityKeyResponse>({
          method: 'POST',
          path: '/v1/admin/integrity/keys',
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
      async revokeKey(fingerprint, { productId, dryRun, idempotencyKey }) {
        return request<RevokeIntegrityKeyDryRunResponse | RevokeIntegrityKeyResponse>({
          method: 'POST',
          path: `/v1/admin/integrity/keys/${encodeURIComponent(fingerprint)}/revoke`,
          query: transitionQuery(productId, dryRun),
          idempotencyKey,
        })
      },
      async sign(tbs) {
        const response = await fetchFn(buildUrl('/v1/admin/integrity/sign'), {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${options.token}`,
            'Content-Type': 'application/octet-stream',
          },
          body: tbs as BodyInit,
        })
        if (!response.ok) {
          const parsed: unknown = await response.json().catch(() => undefined)
          throw AdminApiError.fromBody(response.status, parsed)
        }
        const signature = new Uint8Array(await response.arrayBuffer())
        return {
          signature,
          signerKeyFingerprint: response.headers.get('X-CL-Signer-Key'),
        }
      },
    },

    offlineKey: {
      async issue(licenseId, body, mutation) {
        return request<IssueOfflineKeyResponse>({
          method: 'POST',
          path: `/v1/admin/licenses/${encodeURIComponent(licenseId)}/offline-key`,
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
    },

    catalog: {
      async list(collection, productId) {
        const response = await request<CatalogListResponse<CatalogItemOf<typeof collection>>>({
          method: 'GET',
          path: `/v1/admin/catalog/${collection}`,
          query: { product_id: productId },
        })
        return { catalogVersion: response.catalog_version, items: response.items }
      },
      async create(collection, body, mutation) {
        return request<CatalogMutationResponse>({
          method: 'POST',
          path: `/v1/admin/catalog/${collection}`,
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
      async update(collection, body, mutation) {
        return request<CatalogMutationResponse>({
          method: 'PATCH',
          path: `/v1/admin/catalog/${collection}`,
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
      async resolve(body) {
        return request<CatalogResolveResponse>({
          method: 'POST',
          path: '/v1/admin/catalog/resolve',
          body,
        })
      },
    },

    policies: {
      async list(productId) {
        const response = await request<ListPoliciesResponse>({
          method: 'GET',
          path: '/v1/admin/policies',
          query: { product_id: productId },
        })
        return response.items
      },
      async get(policyId) {
        return request<PolicyResponse>({
          method: 'GET',
          path: `/v1/admin/policies/${encodeURIComponent(policyId)}`,
        })
      },
      async create(policy, mutation) {
        return request<PolicyResponse>({
          method: 'POST',
          path: '/v1/admin/policies',
          body: policy,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
      async update(policy, mutation) {
        return request<PolicyResponse>({
          method: 'PATCH',
          path: `/v1/admin/policies/${encodeURIComponent(policy.id)}`,
          body: policy,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
    },

    epochs: {
      async list(productId) {
        const response = await request<ListEpochsResponse>({
          method: 'GET',
          path: '/v1/admin/epochs',
          query: { product_id: productId },
        })
        return response.items
      },
      async get(epochId) {
        return request<ShowEpochResponse>({
          method: 'GET',
          path: `/v1/admin/epochs/${encodeURIComponent(epochId)}`,
        })
      },
      async upload(body, mutation) {
        return request<UploadEpochResponse>({
          method: 'POST',
          path: '/v1/admin/epochs',
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
      async revoke(epochId, { dryRun, confirmEpochId, idempotencyKey } = {}) {
        const body: RevokeEpochBody =
          confirmEpochId === undefined ? {} : { confirm_epoch_id: confirmEpochId }
        return request<RevokeEpochDryRunResponse | RevokeEpochResponse>({
          method: 'POST',
          path: `/v1/admin/epochs/${encodeURIComponent(epochId)}/revoke`,
          query: dryRunQuery(dryRun),
          body,
          idempotencyKey,
        })
      },
    },

    revoke: {
      license(licenseId, options) {
        return revokeTarget('licenses', licenseId, options)
      },
      machine(machineId, options) {
        return revokeTarget('machines', machineId, options)
      },
    },

    products: {
      async getAlertWebhook(productId) {
        return request<AlertWebhookResponse>({
          method: 'GET',
          path: `/v1/admin/products/${encodeURIComponent(productId)}/alert-webhook`,
        })
      },
      async updateAlertWebhook(productId, body, mutation) {
        return request<AlertWebhookResponse>({
          method: 'PATCH',
          path: `/v1/admin/products/${encodeURIComponent(productId)}/alert-webhook`,
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
    },

    analytics: {
      async definitions() {
        const response = await request<AnalyticsDefinitionsResponse>({
          method: 'GET',
          path: '/v1/admin/analytics/definitions',
        })
        return response.items
      },
      async metrics(query) {
        return request<AnalyticsMetricsResponse>({
          method: 'GET',
          path: '/v1/admin/analytics/metrics',
          query: analyticsParams(query),
        })
      },
      async export(query) {
        const url = buildUrl('/v1/admin/analytics/export', {
          ...analyticsParams(query),
          format: query.format,
        })
        const response = await fetchFn(url, {
          method: 'GET',
          headers: { Authorization: `Bearer ${options.token}` },
        })
        if (!response.ok) {
          const parsed: unknown = await response.json().catch(() => undefined)
          throw AdminApiError.fromBody(response.status, parsed)
        }
        const disposition = response.headers.get('Content-Disposition')
        const filename = disposition?.match(/filename="([^"]+)"/)?.[1] ?? null
        return {
          contentType: response.headers.get('Content-Type') ?? 'application/octet-stream',
          filename,
          body: await response.text(),
        }
      },
      async listSubscriptions(productId) {
        const response = await request<ListSubscriptionsResponse>({
          method: 'GET',
          path: '/v1/admin/analytics/subscriptions',
          query: { product_id: productId },
        })
        return response.items
      },
      async createSubscription(body, mutation) {
        return request<CreateSubscriptionResponse>({
          method: 'POST',
          path: '/v1/admin/analytics/subscriptions',
          body,
          idempotencyKey: mutation?.idempotencyKey,
        })
      },
    },

    dsr: {
      async export(body) {
        return request<DsrExportResponse>({
          method: 'POST',
          path: '/v1/admin/dsr/export',
          body,
        })
      },
      async delete(body, { dryRun, idempotencyKey } = {}) {
        return request<DsrDeleteDryRunResponse | DsrDeleteResponse>({
          method: 'POST',
          path: '/v1/admin/dsr/delete',
          query: dryRunQuery(dryRun),
          body,
          idempotencyKey,
        })
      },
    },

    machines: {
      async list(query) {
        return request<ListAdminMachinesResponse>({
          method: 'GET',
          path: '/v1/admin/machines',
          query: {
            product_id: query.productId,
            license_id: query.licenseId,
            status: query.status,
            limit: query.limit,
            cursor: query.cursor,
          },
        })
      },
      async delete(machineId, { dryRun, idempotencyKey } = {}) {
        return request<MachineDeleteDryRunResponse | MachineDeleteResponse>({
          method: 'DELETE',
          path: `/v1/admin/machines/${encodeURIComponent(machineId)}`,
          query: dryRunQuery(dryRun),
          idempotencyKey,
        })
      },
    },

    audit: {
      async list(query = {}) {
        return request<ListAdminAuditResponse>({
          method: 'GET',
          path: '/v1/admin/audit',
          query: {
            target: query.target,
            kind: query.kind,
            limit: query.limit,
            cursor: query.cursor,
          },
        })
      },
      async verify() {
        return request<VerifyAdminAuditResponse>({
          method: 'POST',
          path: '/v1/admin/audit/verify',
        })
      },
    },

    telemetry: {
      async purge(body, { dryRun, idempotencyKey } = {}) {
        return request<TelemetryPurgeDryRunResponse | TelemetryPurgeResponse>({
          method: 'POST',
          path: '/v1/admin/telemetry/purge',
          query: dryRunQuery(dryRun),
          body,
          idempotencyKey,
        })
      },
    },
  }
}
