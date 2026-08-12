/**
 * Admin API 错误分类。
 *
 * 服务端错误信封统一为 { ok:false, error:{ code, message } }，
 * 这里把 (status, code) 映射成 UI 可消费的类别。
 */

export type ErrorCategory =
	| 'auth' // 401 invalid_token —— token 缺失/失效，应回到登录页
	| 'forbidden' // 403 insufficient_scope —— scope 不足
	| 'not-found' // 404
	| 'conflict' // 409（idempotency_conflict / concurrent_modification / already_revoked / no_change / ...）
	| 'validation' // 400 invalid_request / invalid_query / missing_idempotency_key
	| 'guardrail' // 422 invalid_catalog / invalid_entitlement / invalid_policy / invalid_epoch —— 服务端护栏
	| 'payload-too-large' // 413
	| 'unsupported-media' // 415
	| 'server' // 5xx
	| 'network' // fetch 抛错 / 响应过大 / 非 JSON
	| 'unknown';

export class ApiError extends Error {
	readonly status: number;
	readonly code: string;
	readonly category: ErrorCategory;

	constructor(status: number, code: string, message: string, category?: ErrorCategory) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
		this.code = code;
		this.category = category ?? classifyError(status, code);
	}
}

export function classifyError(status: number, code: string): ErrorCategory {
	if (status === 401) return 'auth';
	if (status === 403) return 'forbidden';
	if (status === 404) return 'not-found';
	if (status === 409) return 'conflict';
	if (status === 413) return 'payload-too-large';
	if (status === 415) return 'unsupported-media';
	if (status === 422) return 'guardrail';
	if (status === 400) return 'validation';
	if (status >= 500) return 'server';
	if (status === 0) return 'network';
	return code ? 'unknown' : 'network';
}

export function isApiError(value: unknown): value is ApiError {
	return value instanceof ApiError;
}

/** 面向用户的简短描述；message 原样保留（服务端文案本身就是可展示的）。 */
export function describeError(error: unknown): string {
	if (error instanceof ApiError) return error.message;
	if (error instanceof Error) return error.message;
	return String(error);
}
