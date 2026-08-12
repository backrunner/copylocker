import { describe, expect, it, vi } from 'vitest';
import { AdminClient, MAX_RESPONSE_BYTES } from './client';
import { ApiError } from './errors';

const TOKEN = `clat_${'a'.repeat(43)}`;

function makeClient(fetcher: typeof fetch) {
	return new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
}

function jsonResponse(status: number, body: unknown) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});
}

describe('AdminClient', () => {
	it('mutation 自动生成 UUID 格式的 Idempotency-Key，GET 不携带', async () => {
		const fetcher = vi.fn<typeof fetch>(async () => jsonResponse(200, { ok: true, items: [] }));
		const client = makeClient(fetcher);

		await client.listLicenses({ product_id: 'demo' });
		const [, getInit] = fetcher.mock.calls[0];
		expect(getInit?.headers).toBeInstanceOf(Headers);
		const getHeaders = getInit?.headers as Headers;
		expect(getHeaders.get('Idempotency-Key')).toBeNull();

		await client.createCatalogItem('features', {
			product_id: 'demo',
			id: 'f1',
			label: 'F1'
		});
		const [, postInit] = fetcher.mock.calls[1];
		const postHeaders = postInit?.headers as Headers;
		const key = postHeaders.get('Idempotency-Key');
		expect(key).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
	});

	it('允许显式覆盖 Idempotency-Key', async () => {
		const fetcher = vi.fn<typeof fetch>(async () => jsonResponse(200, { ok: true }));
		const client = makeClient(fetcher);
		await client.revokeEpoch('abcd1234abcd1234', {
			dryRun: false,
			confirmEpochId: 'abcd1234abcd1234',
			idempotencyKey: 'epoch-revoke-actor-1'
		});
		const [, init] = fetcher.mock.calls[0];
		expect((init?.headers as Headers).get('Idempotency-Key')).toBe('epoch-revoke-actor-1');
	});

	it('token 只出现在 Authorization header，绝不出现在 URL', async () => {
		const fetcher = vi.fn<typeof fetch>(async () => jsonResponse(200, { ok: true, items: [] }));
		const client = makeClient(fetcher);
		await client.listLicenses({ product_id: 'demo', status: 'active', limit: 100 });
		const [href, init] = fetcher.mock.calls[0];
		expect(String(href)).not.toContain(TOKEN);
		expect(String(href)).not.toContain('clat_');
		expect((init?.headers as Headers).get('Authorization')).toBe(`Bearer ${TOKEN}`);
	});

	it('只拼接 /v1/admin/* 路径', async () => {
		const fetcher = vi.fn<typeof fetch>(async () => jsonResponse(200, { ok: true }));
		const client = makeClient(fetcher);
		await client.getPolicy('p1');
		const [href] = fetcher.mock.calls[0];
		expect(String(href)).toBe('http://api.test/v1/admin/policies/p1');
	});

	it('拒绝带凭据的 base URL', () => {
		expect(
			() => new AdminClient({ baseUrl: 'https://user:pass@evil.test', getToken: () => TOKEN })
		).toThrow();
	});

	it('响应超过 4 MiB（Content-Length 预检）时报错，不读 body', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			new Response('{}', {
				status: 200,
				headers: { 'content-length': String(MAX_RESPONSE_BYTES + 1) }
			})
		);
		const client = makeClient(fetcher);
		await expect(client.listLicenses({ product_id: 'demo' })).rejects.toMatchObject({
			code: 'response_too_large'
		});
	});

	it('错误分类：422 → guardrail，401 → auth，403 → forbidden，409 → conflict', async () => {
		const cases = [
			[422, 'invalid_catalog', 'guardrail'],
			[422, 'invalid_policy', 'guardrail'],
			[401, 'invalid_token', 'auth'],
			[403, 'insufficient_scope', 'forbidden'],
			[409, 'idempotency_conflict', 'conflict'],
			[400, 'invalid_request', 'validation']
		] as const;
		for (const [status, code, category] of cases) {
			const fetcher = vi.fn<typeof fetch>(async () =>
				jsonResponse(status, { ok: false, error: { code, message: 'msg' } })
			);
			const client = makeClient(fetcher);
			const error = await client.listLicenses({ product_id: 'demo' }).catch((e: unknown) => e);
			expect(error).toBeInstanceOf(ApiError);
			expect((error as ApiError).category).toBe(category);
			expect((error as ApiError).code).toBe(code);
		}
	});

	it('网络错误分类为 network', async () => {
		const fetcher = vi.fn<typeof fetch>(async () => {
			throw new TypeError('fetch failed');
		});
		const client = makeClient(fetcher);
		await expect(client.listLicenses({ product_id: 'demo' })).rejects.toMatchObject({
			category: 'network'
		});
	});
});
