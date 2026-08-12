import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const mock = (name: string) => fileURLToPath(new URL(`./src/test/mocks/${name}`, import.meta.url));

export default defineConfig({
	plugins: [svelte(), svelteTesting()],
	resolve: {
		alias: {
			'@copylocker/admin-sdk': fileURLToPath(
				new URL('../../packages/admin-sdk/src/index.ts', import.meta.url)
			),
			$lib: fileURLToPath(new URL('./src/lib', import.meta.url)),
			'$app/environment': mock('app-environment.ts'),
			'$app/navigation': mock('app-navigation.ts'),
			'$env/dynamic/public': mock('env-dynamic-public.ts')
		}
	},
	test: {
		environment: 'jsdom',
		include: ['src/**/*.test.ts'],
		restoreMocks: true
	}
});
