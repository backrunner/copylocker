// See https://svelte.dev/docs/kit/types#app.d.ts
declare global {
	namespace App {
		interface Platform {
			env?: {
				/** Service Binding 到 API Worker（wrangler.jsonc 的 services.API）。 */
				API?: Fetcher;
				/** "true" 时非公开路由必须携带 Cloudflare Access JWT。 */
				ACCESS_ENFORCE?: string;
				/** 部署期配置：Access team domain / AUD，用于完整 JWKS 验签（见 hooks.server.ts TODO）。 */
				CF_ACCESS_TEAM_DOMAIN?: string;
				CF_ACCESS_AUD?: string;
				/** 本地开发回退：无 Service Binding 时直连的 Admin API origin。 */
				API_UPSTREAM?: string;
			};
			cf?: IncomingRequestCfProperties;
			ctx?: ExecutionContext;
		}
		interface Locals {
			accessJwtPresent: boolean;
			accessEnforced: boolean;
			accessEmail: string | null;
		}
	}
}

export {};
