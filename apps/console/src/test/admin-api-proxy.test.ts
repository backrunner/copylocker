/**
 * /admin-api 代理的回归测试：
 * - 路径白名单（仅 /v1/admin/*）与 token 格式校验；
 * - 转发路径不带双前缀、查询串保留；
 * - DELETE 带 body 透传；
 * - 上游 Retry-After 头透传（429 退避提示）。
 */
import { describe, expect, it } from 'vitest';
import { DELETE, GET } from '../routes/admin-api/[...path]/+server';

const TOKEN = `Bearer clat_${'a'.repeat(43)}`;

interface MockOptions {
	method?: string;
	body?: string;
	search?: string;
	authorization?: string;
	/** 模拟 Service Binding：记录请求并返回固定响应。 */
	upstream?: (url: string, init: RequestInit) => Response;
}

function makeEvent(path: string, options: MockOptions = {}) {
	const calls: { url: string; init: RequestInit }[] = [];
	const upstream =
		options.upstream ??
		(() =>
			new Response(JSON.stringify({ ok: true }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' }
			}));
	const event = {
		params: { path },
		url: new URL(`https://console.test/admin-api/${path}${options.search ?? ''}`),
		request: new Request(`https://console.test/admin-api/${path}${options.search ?? ''}`, {
			method: options.method ?? 'GET',
			headers: {
				authorization: options.authorization ?? TOKEN,
				...(options.body !== undefined ? { 'content-type': 'application/json' } : {})
			},
			body: options.body
		}),
		platform: {
			env: {
				API: {
					fetch: (url: string, init: RequestInit) => {
						calls.push({ url, init });
						return Promise.resolve(upstream(url, init));
					}
				}
			}
		}
	};
	return { event, calls };
}

describe('/admin-api proxy', () => {
	it('转发路径无双前缀且保留查询串', async () => {
		const { event, calls } = makeEvent('v1/admin/licenses', { search: '?product_id=demo' });
		const response = await GET(event as never);
		expect(response.status).toBe(200);
		expect(calls).toHaveLength(1);
		expect(calls[0].url).toBe('https://api.internal/v1/admin/licenses?product_id=demo');
		expect((calls[0].init.headers as Headers).get('Authorization')).toBe(TOKEN);
	});

	it('拒绝 /v1/admin/* 之外的路径（404）', async () => {
		const { event, calls } = makeEvent('v1/offline/request');
		await expect(GET(event as never)).rejects.toMatchObject({ status: 404 });
		expect(calls).toHaveLength(0);
	});

	it('拒绝格式不正确的 token（401）', async () => {
		const { event, calls } = makeEvent('v1/admin/licenses', {
			authorization: 'Bearer not-a-token'
		});
		await expect(GET(event as never)).rejects.toMatchObject({ status: 401 });
		expect(calls).toHaveLength(0);
	});

	it('DELETE 携带 body 透传', async () => {
		const { event, calls } = makeEvent('v1/admin/machines/abc', {
			method: 'DELETE',
			body: JSON.stringify({ dry_run: true })
		});
		const response = await DELETE(event as never);
		expect(response.status).toBe(200);
		expect(calls[0].init.method).toBe('DELETE');
		const body = calls[0].init.body as ArrayBuffer;
		expect(new TextDecoder().decode(body)).toBe(JSON.stringify({ dry_run: true }));
	});

	it('透传上游 Retry-After 头', async () => {
		const { event } = makeEvent('v1/admin/licenses', {
			upstream: () =>
				new Response(JSON.stringify({ ok: false, error: { code: 'rate_limited' } }), {
					status: 429,
					headers: { 'Content-Type': 'application/json', 'Retry-After': '30' }
				})
		});
		const response = await GET(event as never);
		expect(response.status).toBe(429);
		expect(response.headers.get('Retry-After')).toBe('30');
		expect(response.headers.get('Cache-Control')).toBe('no-store');
	});
});
