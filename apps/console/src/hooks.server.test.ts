/**
 * hooks.server.ts 的回归测试：
 * - 安全头（nosniff / Referrer-Policy）与 no-store 策略；
 * - /_app/ 指纹化构建产物允许缓存（不强制 no-store）；
 * - ACCESS_ENFORCE=true 时的 Cloudflare Access 存在性守卫。
 */
import { describe, expect, it } from 'vitest';
import { handle } from './hooks.server';

interface MockEventOptions {
	headers?: Record<string, string>;
	accessEnforce?: boolean;
}

function makeEvent(pathname: string, options: MockEventOptions = {}) {
	return {
		request: new Request(`https://console.test${pathname}`, { headers: options.headers }),
		url: new URL(`https://console.test${pathname}`),
		platform: options.accessEnforce ? { env: { ACCESS_ENFORCE: 'true' } } : undefined,
		locals: {} as Record<string, unknown>
	};
}

const resolveOk = () => Promise.resolve(new Response('ok', { status: 200 }));

function run(event: ReturnType<typeof makeEvent>) {
	return handle({ event: event as never, resolve: resolveOk as never });
}

describe('hooks.server handle', () => {
	it('对页面响应设置 no-store 与安全头', async () => {
		const response = await run(makeEvent('/licenses'));
		expect(response.headers.get('Cache-Control')).toBe('no-store');
		expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
		expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
	});

	it('/_app/ 指纹化构建产物不强制 no-store（仍保留安全头）', async () => {
		const response = await run(makeEvent('/_app/immutable/chunks/hash.js'));
		expect(response.headers.get('Cache-Control')).toBeNull();
		expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
		expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
	});

	it('ACCESS_ENFORCE=true 且缺少 Access JWT 时拒绝非公开路由', async () => {
		const response = await run(makeEvent('/licenses', { accessEnforce: true }));
		expect(response.status).toBe(401);
		expect(response.headers.get('Cache-Control')).toBe('no-store');
	});

	it('ACCESS_ENFORCE=true 时公开路由与带 JWT 的请求放行', async () => {
		const login = await run(makeEvent('/login', { accessEnforce: true }));
		expect(login.status).toBe(200);
		const authed = await run(
			makeEvent('/licenses', {
				accessEnforce: true,
				headers: { 'cf-access-jwt-assertion': 'jwt' }
			})
		);
		expect(authed.status).toBe(200);
	});
});
