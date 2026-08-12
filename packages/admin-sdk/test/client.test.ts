import { describe, expect, it, vi } from 'vitest'
import { AdminApiError, createAdminClient, type FetchLike } from '../src/index.js'

interface RecordedCall {
  url: string
  method: string
  headers: Record<string, string>
  body: unknown
}

function jsonResponse(status: number, body: unknown, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

function mockFetch(...responses: Response[]): { fetchFn: FetchLike; calls: RecordedCall[] } {
  const calls: RecordedCall[] = []
  const queue = [...responses]
  const fetchFn: FetchLike = async (input, init) => {
    calls.push({
      url: input,
      method: init?.method ?? 'GET',
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : init?.body,
    })
    const response = queue.shift()
    if (!response) {
      throw new Error('mock fetch exhausted')
    }
    return response
  }
  return { fetchFn, calls }
}

const TOKEN = 'clat_testtoken'
const client = (fetchFn: FetchLike) =>
  createAdminClient({ baseUrl: 'https://admin.example.com/', token: TOKEN, fetch: fetchFn })

describe('releases', () => {
  it('lists releases with the product_id query', async () => {
    const release = { id: 'rel_1', status: 'active' }
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', items: [release] }),
    )
    const items = await client(fetchFn).releases.list('prod')
    expect(items).toEqual([release])
    expect(calls[0].method).toBe('GET')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/releases?product_id=prod')
  })

  it('gets one release by id', async () => {
    const { fetchFn, calls } = mockFetch(jsonResponse(200, { ok: true, release: { id: 'rel_9' } }))
    const release = await client(fetchFn).releases.get('rel_9', 'prod')
    expect(release.id).toBe('rel_9')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/releases/rel_9?product_id=prod')
  })

  it('registers a release with the idempotency key header', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(201, { ok: true, already_registered: false, release: { id: 'rel_1' } }),
    )
    const body = {
      product_id: 'prod',
      app_version: '1.2.3',
      build_fingerprint: 'fp',
      channel: 'stable',
      variant_seed_hex: 'ab'.repeat(32),
    }
    await client(fetchFn).releases.register(body, { idempotencyKey: 'req-1' })
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/releases')
    expect(calls[0].body).toEqual(body)
    expect(calls[0].headers['Idempotency-Key']).toBe('req-1')
  })

  it('deprecate is a dry run by default (no dry_run param sent)', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, dry_run: true, action: 'deprecate' }),
    )
    const response = await client(fetchFn).releases.deprecate('rel_1', { productId: 'prod' })
    expect(response.dry_run).toBe(true)
    expect(calls[0].url).toBe(
      'https://admin.example.com/v1/admin/releases/rel_1/deprecate?product_id=prod',
    )
    expect(calls[0].headers['Idempotency-Key']).toBeUndefined()
  })

  it('deprecate confirmed sends dry_run=false and the idempotency key', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, dry_run: false, action: 'deprecate' }),
    )
    await client(fetchFn).releases.deprecate('rel_1', {
      productId: 'prod',
      dryRun: false,
      idempotencyKey: 'req-2',
    })
    expect(calls[0].url).toBe(
      'https://admin.example.com/v1/admin/releases/rel_1/deprecate?product_id=prod&dry_run=false',
    )
    expect(calls[0].headers['Idempotency-Key']).toBe('req-2')
  })

  it('marks a release compromised with the action body', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, dry_run: true, action: 'revoke' }),
    )
    await client(fetchFn).releases.markCompromised(
      'rel_1',
      { action: 'revoke', bump_security_floor: true, acknowledge_revoke: true },
      { productId: 'prod' },
    )
    expect(calls[0].url).toBe(
      'https://admin.example.com/v1/admin/releases/rel_1/mark-compromised?product_id=prod',
    )
    expect(calls[0].body).toEqual({
      action: 'revoke',
      bump_security_floor: true,
      acknowledge_revoke: true,
    })
  })
})

describe('licenses', () => {
  it('lists licenses with status and limit filters', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', items: [] }),
    )
    await client(fetchFn).licenses.list({ productId: 'prod', status: 'active', limit: 25 })
    expect(calls[0].url).toBe(
      'https://admin.example.com/v1/admin/licenses?product_id=prod&status=active&limit=25',
    )
  })

  it('omits absent list filters from the query', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', items: [] }),
    )
    await client(fetchFn).licenses.list({ productId: 'prod' })
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/licenses?product_id=prod')
  })

  it('gets one license by hex id', async () => {
    const { fetchFn, calls } = mockFetch(jsonResponse(200, { ok: true, license: { license_id: 'aa' } }))
    const license = await client(fetchFn).licenses.get('aa')
    expect(license.license_id).toBe('aa')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/licenses/aa')
  })

  it('issues licenses', async () => {
    const issued = {
      ok: true,
      product_id: 'prod',
      policy_id: 'pol',
      catalog_version: 3,
      count: 1,
      license_ids: ['aa'],
      licenses: [{ license_id: 'aa', license_key: 'XXXX-XXXX' }],
    }
    const { fetchFn, calls } = mockFetch(jsonResponse(201, issued))
    const response = await client(fetchFn).licenses.issue(
      { product_id: 'prod', policy_id: 'pol', count: 1 },
      { idempotencyKey: 'req-3' },
    )
    expect(response).toEqual(issued)
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/licenses')
    expect(calls[0].body).toEqual({ product_id: 'prod', policy_id: 'pol', count: 1 })
  })

  it('patches a license', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, license: { license_id: 'aa', status: 'suspended' }, version: 2 }),
    )
    await client(fetchFn).licenses.update('aa', { status: 'suspended' }, { idempotencyKey: 'req-4' })
    expect(calls[0].method).toBe('PATCH')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/licenses/aa')
    expect(calls[0].body).toEqual({ status: 'suspended' })
  })

  it('changes the license tier', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, license: { license_id: 'aa' }, version: 3 }),
    )
    await client(fetchFn).licenses.changeTier('aa', 'pro', { idempotencyKey: 'req-5' })
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/licenses/aa/change-tier')
    expect(calls[0].body).toEqual({ tier: 'pro' })
  })

  it('previews the subscription fallback', async () => {
    const preview = {
      ok: true,
      license_id: 'aa',
      current_state: 'active',
      end_state: 'perpetual_fallback',
      version_cutoff: 1_800_000_000,
      fallback_earned_at: 1_700_000_000,
      continuous_paid_months: 14,
    }
    const { fetchFn, calls } = mockFetch(jsonResponse(200, preview))
    const response = await client(fetchFn).licenses.previewFallback('aa')
    expect(response).toEqual(preview)
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/licenses/aa/preview-fallback')
  })

  it('lists machines for a license', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, license_id: 'aa', items: [{ machine_id: 'bb' }] }),
    )
    const items = await client(fetchFn).licenses.listMachines('aa')
    expect(items).toEqual([{ machine_id: 'bb' }])
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/licenses/aa/machines')
  })
})

describe('offline key', () => {
  it('issues an offline key for a license', async () => {
    const olk = {
      ok: true,
      license_id: 'aa',
      product_id: 'prod',
      release_id: 'rel_1',
      variant_id: 1,
      bound: false,
      bound_fingerprint_hex: null,
      not_after: 0,
      max_seats: 5,
      revocation_epoch: 2,
      security_floor: 0,
      armor: 'CLK1…',
      armor_chars: 100,
      max_seats_advisory: true,
    }
    const { fetchFn, calls } = mockFetch(jsonResponse(201, olk))
    const response = await client(fetchFn).offlineKey.issue(
      'aa',
      { release_id: 'rel_1', max_seats: 5 },
      { idempotencyKey: 'req-6' },
    )
    expect(response.armor).toBe('CLK1…')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/licenses/aa/offline-key')
    expect(calls[0].body).toEqual({ release_id: 'rel_1', max_seats: 5 })
  })
})

describe('accounts', () => {
  it('lists accounts for a product', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', items: [{ id: 'acc_1' }] }),
    )
    const items = await client(fetchFn).accounts.list('prod')
    expect(items).toEqual([{ id: 'acc_1' }])
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/accounts?product_id=prod')
  })

  it('creates an account', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(201, { ok: true, account: { id: 'acc_1', email: 'a@b.c' } }),
    )
    await client(fetchFn).accounts.create(
      { product_id: 'prod', email: 'a@b.c', password: 'correct horse', max_devices: 3 },
      { idempotencyKey: 'req-7' },
    )
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/accounts')
    expect(calls[0].body).toEqual({
      product_id: 'prod',
      email: 'a@b.c',
      password: 'correct horse',
      max_devices: 3,
    })
  })
})

describe('asset KEKs', () => {
  it('lists asset KEKs with an optional release filter', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', items: [] }),
    )
    await client(fetchFn).assetKeks.list({ productId: 'prod', releaseId: 'rel_1' })
    expect(calls[0].url).toBe(
      'https://admin.example.com/v1/admin/asset-keks?product_id=prod&release_id=rel_1',
    )
  })

  it('registers an asset KEK', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(201, { ok: true, key_version: 1, kek_fingerprint: 'ff' }),
    )
    const body = { product_id: 'prod', release_id: 'rel_1', feature_id: 'feat', kek_hex: 'cd'.repeat(32) }
    await client(fetchFn).assetKeks.register(body, { idempotencyKey: 'req-8' })
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/asset-keks')
    expect(calls[0].body).toEqual(body)
  })

  it('deletes an asset KEK as a dry run by default', async () => {
    const { fetchFn, calls } = mockFetch(jsonResponse(200, { ok: true, dry_run: true }))
    await client(fetchFn).assetKeks.delete('rel_1', 'feat', { productId: 'prod' })
    expect(calls[0].method).toBe('DELETE')
    expect(calls[0].url).toBe(
      'https://admin.example.com/v1/admin/asset-keks/rel_1/feat?product_id=prod',
    )
    expect(calls[0].body).toBeUndefined()
  })

  it('confirms an asset KEK deletion', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, dry_run: false, deleted: true }),
    )
    await client(fetchFn).assetKeks.delete('rel_1', 'feat', {
      productId: 'prod',
      dryRun: false,
      idempotencyKey: 'req-9',
    })
    expect(calls[0].url).toBe(
      'https://admin.example.com/v1/admin/asset-keks/rel_1/feat?product_id=prod&dry_run=false',
    )
    expect(calls[0].headers['Idempotency-Key']).toBe('req-9')
  })
})

describe('integrity', () => {
  it('lists signer keys', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', items: [{ fingerprint: 'ab' }] }),
    )
    const items = await client(fetchFn).integrity.listKeys('prod')
    expect(items).toEqual([{ fingerprint: 'ab' }])
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/integrity/keys?product_id=prod')
  })

  it('registers a signer key', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(201, { ok: true, fingerprint: 'ab', status: 'active' }),
    )
    const body = { product_id: 'prod', public_key_hex: 'ef'.repeat(32) }
    await client(fetchFn).integrity.registerKey(body, { idempotencyKey: 'req-10' })
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/integrity/keys')
    expect(calls[0].body).toEqual(body)
  })

  it('revokes a signer key with the dry-run discipline', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, dry_run: true, already_revoked: false }),
    )
    await client(fetchFn).integrity.revokeKey('ab', { productId: 'prod' })
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe(
      'https://admin.example.com/v1/admin/integrity/keys/ab/revoke?product_id=prod',
    )
  })

  it('signs a manifest tbs and returns the raw signature bytes', async () => {
    const signatureBytes = new Uint8Array(64).fill(7)
    const calls: RecordedCall[] = []
    const fetchFn: FetchLike = async (input, init) => {
      calls.push({
        url: input,
        method: init?.method ?? 'GET',
        headers: (init?.headers ?? {}) as Record<string, string>,
        body: init?.body,
      })
      return new Response(signatureBytes, {
        status: 200,
        headers: { 'X-CL-Signer-Key': 'deadbeef' },
      })
    }
    const tbs = new Uint8Array([0xa3, 0x00, 0x01])
    const result = await client(fetchFn).integrity.sign(tbs)
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/integrity/sign')
    expect(calls[0].headers['Content-Type']).toBe('application/octet-stream')
    expect(calls[0].body).toBe(tbs)
    expect(result.signature).toEqual(signatureBytes)
    expect(result.signerKeyFingerprint).toBe('deadbeef')
  })
})

describe('auth and URL construction', () => {
  it('sends the bearer token on every request', async () => {
    const { fetchFn, calls } = mockFetch(jsonResponse(200, { ok: true, license: {} }))
    await client(fetchFn).licenses.get('aa')
    expect(calls[0].headers.Authorization).toBe(`Bearer ${TOKEN}`)
  })

  it('strips trailing slashes from the base URL', async () => {
    const { fetchFn, calls } = mockFetch(jsonResponse(200, { ok: true, license: {} }))
    await createAdminClient({ baseUrl: 'https://admin.example.com///', token: TOKEN, fetch: fetchFn })
      .licenses.get('aa')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/licenses/aa')
  })

  it('sets the JSON content type only when a body is sent', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, license: {} }),
      jsonResponse(200, { ok: true, license: {}, version: 2 }),
    )
    const c = client(fetchFn)
    await c.licenses.get('aa')
    await c.licenses.update('aa', { status: 'expired' })
    expect(calls[0].headers['Content-Type']).toBeUndefined()
    expect(calls[1].headers['Content-Type']).toBe('application/json')
  })
})

describe('error handling', () => {
  it('maps the worker error envelope into AdminApiError', async () => {
    const { fetchFn } = mockFetch(
      jsonResponse(401, {
        ok: false,
        error: { code: 'invalid_token', message: 'a valid Admin bearer token is required' },
      }),
    )
    const error = await client(fetchFn)
      .licenses.get('aa')
      .catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(AdminApiError)
    const apiError = error as AdminApiError
    expect(apiError.status).toBe(401)
    expect(apiError.code).toBe('invalid_token')
    expect(apiError.message).toBe('a valid Admin bearer token is required')
  })

  it('maps conflict codes from confirmed mutations', async () => {
    const { fetchFn } = mockFetch(
      jsonResponse(409, {
        ok: false,
        error: { code: 'idempotency_conflict', message: 'Idempotency-Key was already used' },
      }),
    )
    const error = await client(fetchFn)
      .licenses.issue({ product_id: 'prod', policy_id: 'pol' }, { idempotencyKey: 'req-x' })
      .catch((caught: unknown) => caught)
    expect((error as AdminApiError).status).toBe(409)
    expect((error as AdminApiError).code).toBe('idempotency_conflict')
  })

  it('throws a fallback error for unrecognized error bodies', async () => {
    const { fetchFn } = mockFetch(jsonResponse(500, { unexpected: true }))
    const error = await client(fetchFn)
      .accounts.list('prod')
      .catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(AdminApiError)
    expect((error as AdminApiError).code).toBe('unexpected_response')
    expect((error as AdminApiError).status).toBe(500)
  })

  it('throws AdminApiError for a non-JSON error body', async () => {
    const { fetchFn } = mockFetch(new Response('upstream broke', { status: 502 }))
    const error = await client(fetchFn)
      .releases.list('prod')
      .catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(AdminApiError)
    expect((error as AdminApiError).status).toBe(502)
  })

  it('maps error envelopes from the integrity sign endpoint', async () => {
    const { fetchFn } = mockFetch(
      jsonResponse(403, {
        ok: false,
        error: { code: 'signer_key_not_registered', message: 'key not registered' },
      }),
    )
    const error = await client(fetchFn)
      .integrity.sign(new Uint8Array([1, 2, 3]))
      .catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(AdminApiError)
    expect((error as AdminApiError).code).toBe('signer_key_not_registered')
    expect((error as AdminApiError).status).toBe(403)
  })
})

describe('AdminApiError', () => {
  it('parses a valid envelope and falls back on garbage', () => {
    const parsed = AdminApiError.fromBody(404, {
      ok: false,
      error: { code: 'not_found', message: 'release not found' },
    })
    expect(parsed.code).toBe('not_found')
    expect(AdminApiError.fromBody(400, null).code).toBe('unexpected_response')
    expect(AdminApiError.fromBody(400, { error: { code: 1 } }).code).toBe('unexpected_response')
  })
})

describe('catalog', () => {
  it('lists features with the product_id query', async () => {
    const feature = { id: 'export.pdf', label: 'PDF export' }
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', catalog_version: 3, items: [feature] }),
    )
    const result = await client(fetchFn).catalog.list('features', 'prod')
    expect(result.catalogVersion).toBe(3)
    expect(result.items).toEqual([feature])
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/catalog/features?product_id=prod')
  })

  it('creates a tier with the idempotency key header', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(201, {
        ok: true,
        product_id: 'prod',
        catalog_version: 4,
        item: { id: 'pro', label: 'Pro', rank: 2 },
      }),
    )
    const body = {
      product_id: 'prod',
      id: 'pro',
      label: 'Pro',
      rank: 2,
      groups: ['base'],
      features: ['export.*'],
      limits: { seats: 5 },
    }
    await client(fetchFn).catalog.create('tiers', body, { idempotencyKey: 'cat-1' })
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/catalog/tiers')
    expect(calls[0].body).toEqual(body)
    expect(calls[0].headers['Idempotency-Key']).toBe('cat-1')
  })

  it('updates a group with PATCH', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        product_id: 'prod',
        catalog_version: 5,
        item: { id: 'base', label: 'Base', members: { features: ['render.4k'] } },
      }),
    )
    const body = {
      product_id: 'prod',
      id: 'base',
      label: 'Base',
      members: { includes: [], features: ['render.4k'] },
    }
    await client(fetchFn).catalog.update('groups', body, { idempotencyKey: 'cat-2' })
    expect(calls[0].method).toBe('PATCH')
    expect(calls[0].body).toEqual(body)
  })

  it('resolves an entitlement without an idempotency key (read-only)', async () => {
    const entitlements = {
      features: ['export.pdf'],
      limits: { seats: 5 },
      tier_id: 'pro',
      tier_label: 'Pro',
      catalog_version: 3,
      version_scope: null,
      subscription_hint: null,
    }
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        product_id: 'prod',
        catalog_version: 3,
        at: 1_700_000_000,
        entitlements,
      }),
    )
    const body = { product_id: 'prod', entitlement: { tier: 'pro' }, at: 1_700_000_000 }
    const response = await client(fetchFn).catalog.resolve(body)
    expect(response.entitlements).toEqual(entitlements)
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/catalog/resolve')
    expect(calls[0].body).toEqual(body)
    expect(calls[0].headers['Idempotency-Key']).toBeUndefined()
  })
})

describe('policies', () => {
  const policy = {
    id: 'pol_1',
    product_id: 'prod',
    name: 'Pro subscription',
    entitlement: { tier: 'pro' },
    validity: { kind: 'subscription', period_secs: 2_592_000, dunning_grace_secs: 604_800 },
    version_scope: { kind: 'unlimited' },
    seats: { seats: 3 },
    mode: 'offline_hybrid',
    runtime: {
      refresh_after_secs: 604_800,
      grace_secs: 1_209_600,
      fpr_tolerance: 70,
      allow_vm: true,
      allow_olk: false,
      allow_unbound_olk: false,
      vt_signature: 'fast',
      offline_upgrade_policy: 'require_online',
      preload_variants_n: 3,
      report_attrs: false,
    },
  }

  it('lists policies with the product_id query', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', items: [policy] }),
    )
    const items = await client(fetchFn).policies.list('prod')
    expect(items).toEqual([policy])
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/policies?product_id=prod')
  })

  it('gets one policy with version and warnings', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, policy, version: 2, warnings: [] }),
    )
    const response = await client(fetchFn).policies.get('pol_1')
    expect(response.version).toBe(2)
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/policies/pol_1')
  })

  it('creates a policy and surfaces server warnings', async () => {
    const warnings = [{ id: 'perpetual_unlimited', message: 'covers all future versions' }]
    const { fetchFn, calls } = mockFetch(
      jsonResponse(201, { ok: true, policy, version: 1, warnings }),
    )
    const response = await client(fetchFn).policies.create(policy as never, {
      idempotencyKey: 'pol-1',
    })
    expect(response.warnings).toEqual(warnings)
    expect(calls[0].method).toBe('POST')
    expect(calls[0].body).toEqual(policy)
    expect(calls[0].headers['Idempotency-Key']).toBe('pol-1')
  })

  it('updates a policy at its own id path', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, policy, version: 2, warnings: [] }),
    )
    await client(fetchFn).policies.update(policy as never, { idempotencyKey: 'pol-2' })
    expect(calls[0].method).toBe('PATCH')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/policies/pol_1')
  })
})

describe('epochs', () => {
  const epoch = {
    epoch_id: 'aabbccddeeff0011',
    product_id: 'prod',
    suite_id: '01',
    not_before: 1,
    not_after: 2,
    revoked_at: null,
    created_at: 1,
    status: 'active',
    affected_machines_upper_bound: 0,
  }

  it('lists epochs with the product_id query', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', items: [epoch] }),
    )
    const items = await client(fetchFn).epochs.list('prod')
    expect(items).toEqual([epoch])
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/epochs?product_id=prod')
  })

  it('gets one epoch with replacement state', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        epoch,
        replacement_ready: true,
        replacement_epoch_ids: ['0011223344556677'],
      }),
    )
    const response = await client(fetchFn).epochs.get(epoch.epoch_id)
    expect(response.replacement_ready).toBe(true)
    expect(calls[0].url).toBe(`https://admin.example.com/v1/admin/epochs/${epoch.epoch_id}`)
  })

  it('uploads an epoch certificate with the idempotency key header', async () => {
    const { fetchFn, calls } = mockFetch(jsonResponse(201, { ok: true, epoch, version: 1 }))
    const body = { certificate_hex: 'abcd', root_verifying_key_hex: 'ef01' }
    await client(fetchFn).epochs.upload(body, { idempotencyKey: 'ep-1' })
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/epochs')
    expect(calls[0].body).toEqual(body)
    expect(calls[0].headers['Idempotency-Key']).toBe('ep-1')
  })

  it('revoke is a dry run by default (no dry_run param, empty body)', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        dry_run: true,
        epoch,
        affected_machines_upper_bound: 12,
        replacement_ready: true,
        replacement_epoch_ids: ['0011223344556677'],
        already_revoked: false,
        requires_distinct_actors: 2,
      }),
    )
    const response = await client(fetchFn).epochs.revoke(epoch.epoch_id)
    expect(response.dry_run).toBe(true)
    expect(calls[0].url).toBe(`https://admin.example.com/v1/admin/epochs/${epoch.epoch_id}/revoke`)
    expect(calls[0].body).toEqual({})
    expect(calls[0].headers['Idempotency-Key']).toBeUndefined()
  })

  it('confirmed revoke sends dry_run=false and confirm_epoch_id', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(202, {
        ok: true,
        dry_run: false,
        approval_pending: true,
        epoch_id: epoch.epoch_id,
        first_actor: 'ops-a',
        approval_expires_at: 1_700_000_900,
        required_confirmations: 2,
        received_confirmations: 1,
      }),
    )
    const response = await client(fetchFn).epochs.revoke(epoch.epoch_id, {
      dryRun: false,
      confirmEpochId: epoch.epoch_id,
      idempotencyKey: 'ep-rev-1',
    })
    expect(response.dry_run).toBe(false)
    expect(response.approval_pending).toBe(true)
    expect(calls[0].url).toBe(
      `https://admin.example.com/v1/admin/epochs/${epoch.epoch_id}/revoke?dry_run=false`,
    )
    expect(calls[0].body).toEqual({ confirm_epoch_id: epoch.epoch_id })
    expect(calls[0].headers['Idempotency-Key']).toBe('ep-rev-1')
  })
})

describe('revoke', () => {
  it('license revoke dry run sends no idempotency key and no reason', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        dry_run: true,
        kind: 'license',
        target: 'ab'.repeat(16),
        affected_machines: 3,
        already_revoked: false,
      }),
    )
    const response = await client(fetchFn).revoke.license('ab'.repeat(16))
    expect(response.dry_run).toBe(true)
    expect(calls[0].url).toBe(`https://admin.example.com/v1/admin/licenses/${'ab'.repeat(16)}/revoke`)
    expect(calls[0].body).toEqual({})
    expect(calls[0].headers['Idempotency-Key']).toBeUndefined()
  })

  it('license revoke confirmed carries reason and the idempotency key', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        dry_run: false,
        kind: 'license',
        target: 'ab'.repeat(16),
        revocation_epoch: 7,
      }),
    )
    const response = await client(fetchFn).revoke.license('ab'.repeat(16), {
      dryRun: false,
      reason: 4,
      idempotencyKey: 'rev-1',
    })
    expect(response).toMatchObject({ dry_run: false, revocation_epoch: 7 })
    expect(calls[0].url).toBe(
      `https://admin.example.com/v1/admin/licenses/${'ab'.repeat(16)}/revoke?dry_run=false`,
    )
    expect(calls[0].body).toEqual({ reason: 4 })
    expect(calls[0].headers['Idempotency-Key']).toBe('rev-1')
  })

  it('machine revoke targets the machines collection', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        dry_run: true,
        kind: 'machine',
        target: 'cd'.repeat(16),
        affected_machines: 1,
        already_revoked: false,
      }),
    )
    await client(fetchFn).revoke.machine('cd'.repeat(16))
    expect(calls[0].url).toBe(`https://admin.example.com/v1/admin/machines/${'cd'.repeat(16)}/revoke`)
  })
})

describe('products alert webhook', () => {
  it('gets the current alert webhook configuration', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        product_id: 'prod',
        alert_webhook_url: null,
        alert_suspicion_threshold: null,
      }),
    )
    const response = await client(fetchFn).products.getAlertWebhook('prod')
    expect(response.alert_webhook_url).toBeNull()
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/products/prod/alert-webhook')
  })

  it('patches the alert webhook with the idempotency key header', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        product_id: 'prod',
        alert_webhook_url: 'https://hooks.example.com/cl',
        alert_suspicion_threshold: 55,
      }),
    )
    await client(fetchFn).products.updateAlertWebhook(
      'prod',
      { url: 'https://hooks.example.com/cl', threshold: 55 },
      { idempotencyKey: 'wh-1' },
    )
    expect(calls[0].method).toBe('PATCH')
    expect(calls[0].body).toEqual({ url: 'https://hooks.example.com/cl', threshold: 55 })
    expect(calls[0].headers['Idempotency-Key']).toBe('wh-1')
  })
})

describe('analytics', () => {
  it('lists metric definitions', async () => {
    const definition = {
      id: 'act.new',
      name: 'New activations',
      definition: 'Activations creating a new machine_id.',
      tier: 'T0',
      trusted: true,
    }
    const { fetchFn, calls } = mockFetch(jsonResponse(200, { ok: true, items: [definition] }))
    const items = await client(fetchFn).analytics.definitions()
    expect(items).toEqual([definition])
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/analytics/definitions')
  })

  it('queries metrics with comma-joined ids and the window parameters', async () => {
    const meta = { source: 'exact', error_pct: 0, suppressed_buckets: 1 }
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        product_id: 'prod',
        from: '2026-07-01',
        to: '2026-07-31',
        granularity: 'week',
        series: [{ metric_id: 'act.new', points: [{ bucket: '2026-06-29', dims: {}, value: 4 }] }],
        meta,
      }),
    )
    const response = await client(fetchFn).analytics.metrics({
      product: 'prod',
      ids: ['act.new', 'dev.checked_in'],
      from: '2026-07-01',
      to: '2026-07-31',
      granularity: 'week',
      groupBy: 'app_version',
      source: 'hll',
    })
    expect(response.meta).toEqual(meta)
    expect(calls[0].url).toBe(
      'https://admin.example.com/v1/admin/analytics/metrics' +
        '?product=prod&ids=act.new%2Cdev.checked_in&from=2026-07-01&to=2026-07-31' +
        '&granularity=week&group_by=app_version&source=hll',
    )
  })

  it('exports CSV and surfaces the attachment filename', async () => {
    const { fetchFn, calls } = mockFetch(
      new Response('metric_id,bucket,dims_json,value\nact.new,2026-07-01,{},3\n', {
        status: 200,
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': 'attachment; filename="copylocker-analytics.csv"',
        },
      }),
    )
    const result = await client(fetchFn).analytics.export({
      product: 'prod',
      ids: ['act.new'],
      from: '2026-07-01',
      to: '2026-07-02',
      format: 'csv',
    })
    expect(result.filename).toBe('copylocker-analytics.csv')
    expect(result.contentType).toContain('text/csv')
    expect(result.body).toContain('act.new,2026-07-01')
    expect(calls[0].url).toContain('/v1/admin/analytics/export?')
    expect(calls[0].url).toContain('format=csv')
    expect(calls[0].headers.Authorization).toBe(`Bearer ${TOKEN}`)
  })

  it('maps a non-JSON export error to AdminApiError', async () => {
    const { fetchFn } = mockFetch(jsonResponse(413, { ok: false, error: { code: 'result_too_large', message: 'too many rows' } }))
    await expect(
      client(fetchFn).analytics.export({
        product: 'prod',
        ids: ['act.new'],
        from: '2026-07-01',
        to: '2026-07-02',
        format: 'ndjson',
      }),
    ).rejects.toMatchObject({ code: 'result_too_large', status: 413 })
  })

  it('lists subscriptions with an optional product filter', async () => {
    const subscription = {
      schema_version: 1,
      id: 'sub_00112233445566778899aabbccddeeff',
      product_id: 'prod',
      metric_ids: ['act.new'],
      window_days: 30,
      granularity: 'day',
      webhook_url: 'https://hooks.example.com/report',
      created_by: 'ops-a',
      created_at: 1_700_000_000,
      delivery: 'pending',
    }
    const { fetchFn, calls } = mockFetch(jsonResponse(200, { ok: true, items: [subscription] }))
    const items = await client(fetchFn).analytics.listSubscriptions('prod')
    expect(items).toEqual([subscription])
    expect(calls[0].url).toBe(
      'https://admin.example.com/v1/admin/analytics/subscriptions?product_id=prod',
    )
  })

  it('creates a subscription with the idempotency key header', async () => {
    const body = {
      product_id: 'prod',
      metric_ids: ['act.new'],
      window_days: 30,
      granularity: 'day' as const,
      webhook_url: 'https://hooks.example.com/report',
    }
    const { fetchFn, calls } = mockFetch(
      jsonResponse(201, { ok: true, subscription: { ...body, id: 'sub_x' } }),
    )
    await client(fetchFn).analytics.createSubscription(body, { idempotencyKey: 'sub-1' })
    expect(calls[0].method).toBe('POST')
    expect(calls[0].body).toEqual(body)
    expect(calls[0].headers['Idempotency-Key']).toBe('sub-1')
  })
})

describe('dsr', () => {
  it('exports a machine subject without an idempotency key (read-only)', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        product_id: 'prod',
        subject: { machine_id: 'ab'.repeat(16) },
        generated_at: 1_700_000_000,
        machines: [],
        licenses: [],
        audit_references: [],
        audit_truncated: false,
      }),
    )
    const body = { product_id: 'prod', machine_id: 'ab'.repeat(16) }
    const response = await client(fetchFn).dsr.export(body)
    expect(response.subject).toEqual({ machine_id: 'ab'.repeat(16) })
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/dsr/export')
    expect(calls[0].body).toEqual(body)
    expect(calls[0].headers['Idempotency-Key']).toBeUndefined()
  })

  it('delete is a dry run by default', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        dry_run: true,
        product_id: 'prod',
        subject: { license_id: 'cd'.repeat(16) },
        machines: [{ id: 'ab'.repeat(16), license_id: 'cd'.repeat(16), status: 'active' }],
        raw_records: 2,
        audit_tombstone: false,
      }),
    )
    const response = await client(fetchFn).dsr.delete({
      product_id: 'prod',
      license_id: 'cd'.repeat(16),
    })
    expect(response.dry_run).toBe(true)
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/dsr/delete')
    expect(calls[0].headers['Idempotency-Key']).toBeUndefined()
  })

  it('confirmed delete sends dry_run=false and the idempotency key', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        dry_run: false,
        product_id: 'prod',
        subject: { license_id: 'cd'.repeat(16) },
        deleted_machines: 1,
        deleted_raw_records: 2,
        audit_tombstone: false,
        audit_note: 'audit chain entries are content-hashed',
      }),
    )
    const response = await client(fetchFn).dsr.delete(
      { product_id: 'prod', license_id: 'cd'.repeat(16) },
      { dryRun: false, idempotencyKey: 'dsr-1' },
    )
    expect(response).toMatchObject({ dry_run: false, deleted_machines: 1 })
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/dsr/delete?dry_run=false')
    expect(calls[0].headers['Idempotency-Key']).toBe('dsr-1')
  })
})

describe('telemetry purge', () => {
  it('purge is a dry run by default', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        dry_run: true,
        product_id: 'prod',
        cutoff: '2026-07-01',
        raw_records: 10,
        rollup_rows: 0,
      }),
    )
    const response = await client(fetchFn).telemetry.purge({ product_id: 'prod' })
    expect(response.dry_run).toBe(true)
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/telemetry/purge')
    expect(calls[0].body).toEqual({ product_id: 'prod' })
  })

  it('confirmed purge carries the before cutoff and the idempotency key', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        dry_run: false,
        product_id: 'prod',
        cutoff: '2026-06-01',
        deleted_raw_records: 10,
        deleted_rollup_rows: 4,
        journaled: true,
      }),
    )
    await client(fetchFn).telemetry.purge(
      { product_id: 'prod', before: '2026-06-01' },
      { dryRun: false, idempotencyKey: 'purge-1' },
    )
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/telemetry/purge?dry_run=false')
    expect(calls[0].body).toEqual({ product_id: 'prod', before: '2026-06-01' })
    expect(calls[0].headers['Idempotency-Key']).toBe('purge-1')
  })
})

describe('relative base URLs and the response cap', () => {
  it('keeps a relative base relative (same-origin proxy deployments)', async () => {
    const { fetchFn, calls } = mockFetch(jsonResponse(200, { ok: true, product_id: 'p', items: [] }))
    const relative = createAdminClient({ baseUrl: '/admin-api', token: TOKEN, fetch: fetchFn })
    await relative.licenses.list({ productId: 'p' })
    expect(calls[0].url).toBe('/admin-api/v1/admin/licenses?product_id=p')
  })

  it('rejects an oversized response by Content-Length without reading the body', async () => {
    const { fetchFn } = mockFetch(
      new Response('{}', {
        status: 200,
        headers: { 'Content-Length': String(5 * 1024 * 1024) },
      }),
    )
    await expect(client(fetchFn).releases.list('p')).rejects.toMatchObject({
      code: 'response_too_large',
      status: 0,
    })
  })

  it('rejects an oversized response body without a Content-Length', async () => {
    const body = ' '.repeat(4 * 1024 * 1024 + 1)
    const { fetchFn } = mockFetch(new Response(body, { status: 200 }))
    await expect(client(fetchFn).releases.list('p')).rejects.toMatchObject({
      code: 'response_too_large',
    })
  })

  it('honours a custom maxResponseBytes', async () => {
    const { fetchFn } = mockFetch(jsonResponse(200, { ok: true, product_id: 'p', items: [] }))
    const small = createAdminClient({
      baseUrl: 'https://admin.example.com',
      token: TOKEN,
      fetch: fetchFn,
      maxResponseBytes: 8,
    })
    await expect(small.releases.list('p')).rejects.toMatchObject({ code: 'response_too_large' })
  })
})

describe('machines (cross-license)', () => {
  it('lists machines with filters and the pagination cursor verbatim', async () => {
    const machine = { machine_id: 'ab'.repeat(16), license_id: 'cd'.repeat(16), status: 'active' }
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', items: [machine], next_cursor: '1:ab' }),
    )
    const response = await client(fetchFn).machines.list({
      productId: 'prod',
      licenseId: 'cd'.repeat(16),
      status: 'active',
      limit: 1,
      cursor: '0:aa',
    })
    expect(response.items).toEqual([machine])
    expect(response.next_cursor).toBe('1:ab')
    expect(calls[0].method).toBe('GET')
    expect(calls[0].url).toBe(
      `https://admin.example.com/v1/admin/machines?product_id=prod&license_id=${'cd'.repeat(16)}&status=active&limit=1&cursor=0%3Aaa`,
    )
  })

  it('omits optional filters when not provided', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, product_id: 'prod', items: [], next_cursor: null }),
    )
    await client(fetchFn).machines.list({ productId: 'prod' })
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/machines?product_id=prod')
  })

  it('delete is a dry run by default (no dry_run param, no idempotency key)', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        dry_run: true,
        product_id: 'prod',
        subject: { machine_id: 'ab'.repeat(16) },
        machines: [],
        raw_records: 0,
        audit_tombstone: false,
      }),
    )
    const response = await client(fetchFn).machines.delete('ab'.repeat(16))
    expect(response.dry_run).toBe(true)
    expect(calls[0].method).toBe('DELETE')
    expect(calls[0].url).toBe(`https://admin.example.com/v1/admin/machines/${'ab'.repeat(16)}`)
    expect(calls[0].headers['Idempotency-Key']).toBeUndefined()
  })

  it('confirmed delete sends dry_run=false and the idempotency key', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        dry_run: false,
        product_id: 'prod',
        subject: { machine_id: 'ab'.repeat(16) },
        deleted_machines: 1,
        deleted_raw_records: 0,
        audit_tombstone: false,
        audit_note: 'audit chain entries are content-hashed',
      }),
    )
    const response = await client(fetchFn).machines.delete('ab'.repeat(16), {
      dryRun: false,
      idempotencyKey: 'gdpr-1',
    })
    expect(response.dry_run).toBe(false)
    expect(calls[0].url).toBe(
      `https://admin.example.com/v1/admin/machines/${'ab'.repeat(16)}?dry_run=false`,
    )
    expect(calls[0].headers['Idempotency-Key']).toBe('gdpr-1')
  })

  it('maps worker error envelopes on the delete path', async () => {
    const { fetchFn } = mockFetch(
      jsonResponse(404, { ok: false, error: { code: 'not_found', message: 'machine not found' } }),
    )
    await expect(client(fetchFn).machines.delete('ab'.repeat(16))).rejects.toMatchObject({
      status: 404,
      code: 'not_found',
    })
  })
})

describe('admin audit', () => {
  it('lists events with filters and cursor', async () => {
    const item = {
      seq: 7,
      occurred_at: 1_700_000_000,
      actor: 'admin@example.test',
      action: 'revoke:machine',
      target: 'ab'.repeat(16),
      reason: 2,
      request_id: 'req-1',
      source_kind: 'revocation',
      r2_key: 'audit-admin/2023/11/14/7.cbor',
    }
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, { ok: true, items: [item], next_cursor: '7' }),
    )
    const response = await client(fetchFn).audit.list({
      target: 'ab'.repeat(16),
      kind: 'revocation',
      limit: 1,
      cursor: '9',
    })
    expect(response.items).toEqual([item])
    expect(calls[0].method).toBe('GET')
    expect(calls[0].url).toBe(
      `https://admin.example.com/v1/admin/audit?target=${'ab'.repeat(16)}&kind=revocation&limit=1&cursor=9`,
    )
  })

  it('lists events without any query when no filter is given', async () => {
    const { fetchFn, calls } = mockFetch(jsonResponse(200, { ok: true, items: [], next_cursor: null }))
    await client(fetchFn).audit.list()
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/audit')
  })

  it('verifies the chain with a body-less POST and no idempotency key', async () => {
    const { fetchFn, calls } = mockFetch(
      jsonResponse(200, {
        ok: true,
        verified: false,
        event_count: 3,
        first_seq: 1,
        last_seq: 3,
        head: { seq: 3, hash: 'ef'.repeat(32) },
        first_broken: { seq: 2, reason: 'prev_hash_link' },
      }),
    )
    const response = await client(fetchFn).audit.verify()
    expect(response.verified).toBe(false)
    expect(response.first_broken).toEqual({ seq: 2, reason: 'prev_hash_link' })
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe('https://admin.example.com/v1/admin/audit/verify')
    expect(calls[0].body).toBeUndefined()
    expect(calls[0].headers['Idempotency-Key']).toBeUndefined()
    expect(calls[0].headers['Content-Type']).toBeUndefined()
  })

  it('enforces the 4 MiB response cap on the audit list', async () => {
    const { fetchFn } = mockFetch(
      new Response('{}', { status: 200, headers: { 'Content-Length': String(5 * 1024 * 1024) } }),
    )
    await expect(client(fetchFn).audit.list()).rejects.toMatchObject({
      code: 'response_too_large',
      status: 0,
    })
  })
})
