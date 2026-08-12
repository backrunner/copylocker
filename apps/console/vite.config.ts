import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// 单仓源码直引：@copylocker/admin-sdk 的 dist 面向外部消费者，仓内应用直接编译其
// TypeScript 源码（与 tsconfig paths、vitest alias 保持一致）。
const adminSdk = fileURLToPath(new URL('../../packages/admin-sdk/src/index.ts', import.meta.url));

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	resolve: {
		alias: {
			'@copylocker/admin-sdk': adminSdk
		}
	},
	server: {
		port: 5173
	}
});
