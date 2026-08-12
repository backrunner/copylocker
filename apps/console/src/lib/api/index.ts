/**
 * Admin API 客户端单例。
 *
 * baseUrl 解析顺序：
 * 1. PUBLIC_API_BASE（dev 下指向 mock：http://localhost:8788）
 * 2. '/admin-api'（SvelteKit 服务端代理 → Service Binding API）
 */
import { env } from '$env/dynamic/public';
import { tokenStore } from '../auth/token.svelte';
import { AdminClient } from './client';

let instance: AdminClient | null = null;

export function getApiBase(): string {
	return env.PUBLIC_API_BASE?.replace(/\/+$/, '') || '/admin-api';
}

export function getClient(): AdminClient {
	if (!instance) {
		instance = new AdminClient({
			baseUrl: getApiBase(),
			getToken: () => tokenStore.value
		});
	}
	return instance;
}

export * from './client';
export * from './errors';
export * from './guardrail';
export * as types from './types';
