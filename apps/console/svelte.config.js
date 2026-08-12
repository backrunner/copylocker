import adapter from '@sveltejs/adapter-cloudflare';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter(),
		// 单仓源码直引：@copylocker/admin-sdk 的 dist 面向外部消费者，仓内应用直接
		// 编译其 TypeScript 源码（与 vitest alias 一致；dist 构建不参与 console 工具链）。
		alias: {
			'@copylocker/admin-sdk': '../../packages/admin-sdk/src/index.ts'
		},
		// ADR-0010 落地约束：严格 CSP（script-src 'self'，无 unsafe-inline）。
		// SvelteKit 在 auto 模式下为必要的内联脚本生成 hash/nonce。
		csp: {
			mode: 'auto',
			directives: {
				'script-src': ['self'],
				'style-src': ['self', 'unsafe-inline'],
				'object-src': ['none'],
				'base-uri': ['self'],
				'frame-ancestors': ['none']
			}
		}
	}
};

export default config;
