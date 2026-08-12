import type { Handle } from '@sveltejs/kit';

/**
 * 认证模型（ADR-0010 / 95-admin-console）：
 *
 * - 生产：Cloudflare Access 在边缘完成 SSO/MFA。本 Worker 只检查
 *   `Cf-Access-Jwt-Assertion` 的存在性做路由守卫 —— 控制台是不可信前端，
 *   真正的授权判定永远发生在 API Worker（Bearer token + scope 校验）。
 *
 *   TODO(deployment): 完整 JWKS 验签属部署期配置 —— 用 CF_ACCESS_TEAM_DOMAIN /
 *   CF_ACCESS_AUD 对 https://<team>.cloudflareaccess.com/cdn-cgi/access/certs
 *   验签并检查 exp/aud。在此之前 ACCESS_ENFORCE=true 只做存在性检查，
 *   不能替代验签；生产部署必须完成该配置。
 *
 * - 开发：/login 页面输入 Admin token（clat_*），存 sessionStorage，
 *   随请求经 /admin-api 代理转发给 API Worker。token 不进 URL、不进日志。
 *
 * - /offline 是公开路由（离线激活门户），不共享 admin 认证路径。
 * - /offline-api 是离线门户的公开协议代理（无 admin token），不在此拦截。
 * - /admin-api 是 API 代理，自带 Bearer 校验，不在此拦截。
 */
const PUBLIC_PATHS = ['/login', '/offline', '/offline-api', '/admin-api'];

function isPublic(pathname: string): boolean {
	if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`))) return true;
	// 静态资产与 svelte-kit 内部路径
	if (pathname.startsWith('/_app/') || pathname.includes('.')) return true;
	return false;
}

export const handle: Handle = async ({ event, resolve }) => {
	const env = event.platform?.env;
	const accessJwt = event.request.headers.get('cf-access-jwt-assertion');
	event.locals.accessJwtPresent = Boolean(accessJwt);
	event.locals.accessEnforced = env?.ACCESS_ENFORCE === 'true';
	event.locals.accessEmail = event.request.headers.get(
		'cf-access-authenticated-user-email'
	);

	if (event.locals.accessEnforced && !event.locals.accessJwtPresent && !isPublic(event.url.pathname)) {
		return new Response('Unauthorized: Cloudflare Access assertion required', {
			status: 401,
			headers: { 'Cache-Control': 'no-store' }
		});
	}

	const response = await resolve(event);
	// /_app/ 下是指纹化的构建产物，允许长期缓存；其余响应一律 no-store
	//（页面可能携带与 admin 会话相关的数据）。
	if (!event.url.pathname.startsWith('/_app/')) {
		response.headers.set('Cache-Control', 'no-store');
	}
	response.headers.set('X-Content-Type-Options', 'nosniff');
	response.headers.set('Referrer-Policy', 'no-referrer');
	return response;
};
