/**
 * /offline-api/request → API Worker `/v1/offline/request` 的公开代理。
 *
 * 与 /admin-api 代理同级，但承载的是**公开协议端点**（气隙激活中继，
 * FR-SRV-016）：无 admin token、无 Cookie 透传。线格式与
 * `copylocker offline redeem` 完全一致：raw canonical CBOR 进、签名后的
 * CBOR envelope 出。
 *
 * 防滥用（设计文档 §5.6：门户不得成为探测 License 有效性的 oracle）：
 * - 请求体上限 16 KiB（copylocker-types `MAX_BODY_BYTES`），与协议上限一致；
 * - 可选 Turnstile：平台变量 TURNSTILE_SECRET_KEY 存在时强制校验
 *   `cf-turnstile-response` 头（默认关闭；页面端由 PUBLIC_TURNSTILE_SITE_KEY
 *   控制是否渲染 widget）。注意 Turnstile 需要外部 script/iframe，
 *   与 `script-src 'self'` 的严格 CSP 互斥 —— 开启即接受该放宽；
 * - 更严格的服务端限流属于 API Worker 的协议端点限流职责，此处不重复实现。
 */
import { error, type RequestHandler } from '@sveltejs/kit';

const MAX_REQUEST_BODY = 16 * 1024;
const MAX_RESPONSE_BODY = 2 * 1024 * 1024;

async function verifyTurnstile(
	secret: string,
	token: string | null,
	remoteIp: string | null
): Promise<boolean> {
	if (!token) return false;
	const body = new URLSearchParams({ secret, response: token });
	if (remoteIp) body.set('remoteip', remoteIp);
	const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body
	});
	if (!response.ok) return false;
	const result = (await response.json()) as { success?: boolean };
	return result.success === true;
}

export const POST: RequestHandler = async ({ request, platform }) => {
	const contentType = request.headers.get('content-type') ?? '';
	if (!contentType.split(';')[0].trim().toLowerCase().startsWith('application/cbor')) {
		error(415, 'Content-Type must be application/cbor');
	}
	const env = platform?.env as
		| { API?: { fetch: typeof fetch }; API_UPSTREAM?: string; TURNSTILE_SECRET_KEY?: string }
		| undefined;

	if (env?.TURNSTILE_SECRET_KEY) {
		const ok = await verifyTurnstile(
			env.TURNSTILE_SECRET_KEY,
			request.headers.get('cf-turnstile-response'),
			request.headers.get('cf-connecting-ip')
		);
		if (!ok) error(403, 'Turnstile verification failed');
	}

	const body = await request.arrayBuffer();
	if (body.byteLength === 0 || body.byteLength > MAX_REQUEST_BODY) {
		error(413, `activation request must be 1..${MAX_REQUEST_BODY} bytes`);
	}

	const headers = new Headers({
		'Content-Type': 'application/cbor',
		Accept: 'application/cbor',
		'X-CL-Proto': '1'
	});
	const idempotencyKey = request.headers.get('idempotency-key');
	if (idempotencyKey) headers.set('Idempotency-Key', idempotencyKey);

	let response: Response;
	if (env?.API) {
		response = await env.API.fetch('https://api.internal/v1/offline/request', {
			method: 'POST',
			headers,
			body
		});
	} else if (env?.API_UPSTREAM) {
		response = await fetch(`${env.API_UPSTREAM}/v1/offline/request`, {
			method: 'POST',
			headers,
			body,
			redirect: 'error'
		});
	} else {
		error(502, 'API upstream unavailable');
	}

	const passthrough = new Headers({
		'Content-Type': response.headers.get('content-type') ?? 'application/cbor',
		'Cache-Control': 'no-store',
		'X-Content-Type-Options': 'nosniff'
	});
	const retryAfter = response.headers.get('retry-after');
	if (retryAfter) passthrough.set('Retry-After', retryAfter);
	if (response.body) {
		// 响应上限与 CLI 一致（2 MiB）；Content-Length 预检 + 流式截断双保险。
		const declared = Number(response.headers.get('content-length') ?? 0);
		if (declared > MAX_RESPONSE_BODY) error(502, 'upstream response too large');
	}
	return new Response(response.body, { status: response.status, headers: passthrough });
};
