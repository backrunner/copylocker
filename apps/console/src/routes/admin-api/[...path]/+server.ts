/**
 * /admin-api/* → API Worker 的服务端代理。
 *
 * - 生产：经 Service Binding `API`（wrangler.jsonc）转发，不出 Cloudflare 网络。
 * - 本地 vite dev（无 binding）：回退到环境变量 API_UPSTREAM（如 wrangler dev
 *   起的 API Worker：http://localhost:8787）。
 * - 只允许 /v1/admin/* 路径；要求 Bearer clat_* 格式 token；不透传 Cookie。
 * - token 只出现在转发请求的 Authorization header，不写日志。
 */
import { error, type RequestHandler } from '@sveltejs/kit';

const TOKEN_HEADER_PATTERN = /^Bearer clat_[A-Za-z0-9_-]{43}$/;
const MAX_UPSTREAM_BODY = 4 * 1024 * 1024;

const handler: RequestHandler = async ({ params, request, platform, url }) => {
	const path = params.path ?? '';
	// The client always calls /admin-api/v1/admin/*; forward exactly that path
	// (anything outside /v1/admin/* is rejected here, per the module contract).
	if (!path.startsWith('v1/admin/') || path.includes('..')) {
		error(404, 'admin route not found');
	}
	const authorization = request.headers.get('authorization') ?? '';
	if (!TOKEN_HEADER_PATTERN.test(authorization)) {
		error(401, 'a valid Admin bearer token is required');
	}

	const upstream = `/${path}${url.search}`;
	const headers = new Headers();
	headers.set('Authorization', authorization);
	headers.set('Accept', 'application/json');
	const contentType = request.headers.get('content-type');
	if (contentType) headers.set('Content-Type', contentType);
	const idempotencyKey = request.headers.get('idempotency-key');
	if (idempotencyKey) headers.set('Idempotency-Key', idempotencyKey);

	let body: BodyInit | null = null;
	if (request.method !== 'GET' && request.method !== 'HEAD') {
		const bytes = await request.arrayBuffer();
		if (bytes.byteLength > MAX_UPSTREAM_BODY) {
			error(413, 'request body exceeds the 4 MiB limit');
		}
		body = bytes;
	}

	const api = platform?.env?.API;
	let response: Response;
	if (api) {
		response = await api.fetch(`https://api.internal${upstream}`, {
			method: request.method,
			headers,
			body
		});
	} else if (platform?.env?.API_UPSTREAM) {
		response = await fetch(`${platform.env.API_UPSTREAM}${upstream}`, {
			method: request.method,
			headers,
			body,
			redirect: 'error'
		});
	} else {
		error(
			502,
			'API Service Binding 不可用：生产部署检查 wrangler.jsonc 的 services；本地开发请用 npm run preview（wrangler dev）或设置 PUBLIC_API_BASE 指向 mock（npm run mock）'
		);
	}

	const passthrough = new Headers();
	passthrough.set('Content-Type', response.headers.get('content-type') ?? 'application/json');
	passthrough.set('Cache-Control', 'no-store');
	passthrough.set('X-Content-Type-Options', 'nosniff');
	// 429 的退避提示与 /offline-api 代理一致透传（CLI/页面据此提示重试时间）。
	const retryAfter = response.headers.get('retry-after');
	if (retryAfter) passthrough.set('Retry-After', retryAfter);
	return new Response(response.body, { status: response.status, headers: passthrough });
};

export const GET = handler;
export const POST = handler;
export const PATCH = handler;
export const DELETE = handler;
