/**
 * 当前选中的 product_id。
 *
 * Admin API 没有产品列表端点（M1），所以产品通过手动输入选择并持久化到
 * sessionStorage。所有列表端点都要求 product_id query 参数。
 */
import { browser } from '$app/environment';

const SESSION_KEY = 'copylocker:product-id';

function readInitial(): string {
	if (!browser) return '';
	try {
		return sessionStorage.getItem(SESSION_KEY) ?? '';
	} catch {
		return '';
	}
}

class ProductStore {
	value = $state<string>(readInitial());

	select(productId: string) {
		this.value = productId.trim();
		try {
			if (this.value) sessionStorage.setItem(SESSION_KEY, this.value);
			else sessionStorage.removeItem(SESSION_KEY);
		} catch {
			// sessionStorage 不可用时仅保存在内存。
		}
	}
}

export const productStore = new ProductStore();
