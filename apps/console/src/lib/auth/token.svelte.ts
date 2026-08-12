/**
 * Admin token 存储（开发模式）。
 *
 * - 仅存 sessionStorage（标签页生命周期），不写 localStorage / IndexedDB。
 * - 生产环境认证由 Cloudflare Access 承担（hooks.server.ts），本模块只是
 *   API Worker Bearer token 的载体；scope 校验永远在 API Worker 侧。
 * - token 绝不写入 URL、日志或分析事件。
 */
import { browser } from '$app/environment';
import { ADMIN_TOKEN_PATTERN } from '../api/client';

const SESSION_KEY = 'copylocker:admin-token';

function readInitial(): string | null {
	if (!browser) return null;
	try {
		const value = sessionStorage.getItem(SESSION_KEY);
		return value && ADMIN_TOKEN_PATTERN.test(value) ? value : null;
	} catch {
		return null;
	}
}

class TokenStore {
	value = $state<string | null>(readInitial());

	get authenticated(): boolean {
		return this.value !== null;
	}

	/** 校验格式后保存；返回是否接受。 */
	login(token: string): boolean {
		const trimmed = token.trim();
		if (!ADMIN_TOKEN_PATTERN.test(trimmed)) return false;
		this.value = trimmed;
		try {
			sessionStorage.setItem(SESSION_KEY, trimmed);
		} catch {
			// sessionStorage 不可用（隐私模式）时仅保存在内存。
		}
		return true;
	}

	logout() {
		this.value = null;
		try {
			sessionStorage.removeItem(SESSION_KEY);
		} catch {
			// 同上。
		}
	}
}

export const tokenStore = new TokenStore();

export function isValidTokenFormat(token: string): boolean {
	return ADMIN_TOKEN_PATTERN.test(token.trim());
}
