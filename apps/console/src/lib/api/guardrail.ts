/**
 * Catalog 不可变性护栏（ADR-0009）：把服务端 422 invalid_catalog 的 message
 * 解析成结构化原因，驱动 UI 的禁用态与提示文案。
 *
 * 文案来源：crates/copylocker-server-core/src/catalog.rs 的 CatalogError Display。
 * 服务端契约是唯一权威；这里只做展示层解析，匹配不到时原样展示 message。
 */

export type GuardrailKind =
	| 'feature-published' // 已发布 feature 不能重命名/删除
	| 'limit-key-removed' // 已发布 limit key 不能删除
	| 'unknown-reference' // 引用了不存在的 id
	| 'cycle' // group 循环引用
	| 'duplicate' // 重复 id
	| 'version' // catalog version 必须递增
	| 'malformed-glob'
	| 'unknown';

export interface GuardrailReason {
	kind: GuardrailKind;
	/** 服务端原始 message（唯一权威文案）。 */
	raw: string;
	/** 涉及的对象 id（能解析出时）。 */
	subject: string | null;
	/** 面向操作者的一句话解释。 */
	summary: string;
}

export function parseCatalogGuardrail(message: string): GuardrailReason {
	let match = /^feature `(.+)` was published and cannot be renamed or removed/.exec(message);
	if (match) {
		return {
			kind: 'feature-published',
			raw: message,
			subject: match[1],
			summary: `feature \`${match[1]}\` 已被已签发凭证引用，且 FeatureKey 派生依赖它 —— 不能重命名或删除，只能标记 deprecated。`
		};
	}
	match = /^limit key `(.+)` was published and removed/.exec(message);
	if (match) {
		return {
			kind: 'limit-key-removed',
			raw: message,
			subject: match[1],
			summary: `limit key \`${match[1]}\` 已发布过，不能从目录中移除（会改变已签发凭证的语义）。`
		};
	}
	match = /^`(.+)` references unknown `(.+)`/.exec(message);
	if (match) {
		return {
			kind: 'unknown-reference',
			raw: message,
			subject: match[2],
			summary: `\`${match[1]}\` 引用了不存在的 \`${match[2]}\`。注意：删除仍被引用的 feature 时服务端会先报这个错。`
		};
	}
	match = /^group `(.+)` participates in a cycle/.exec(message);
	if (match) {
		return {
			kind: 'cycle',
			raw: message,
			subject: match[1],
			summary: `group \`${match[1]}\` 存在循环嵌套，解析无法终止。`
		};
	}
	match = /^duplicate identifier `(.+)`/.exec(message);
	if (match) {
		return {
			kind: 'duplicate',
			raw: message,
			subject: match[1],
			summary: `id \`${match[1]}\` 重复。`
		};
	}
	match = /^malformed glob pattern `(.+)`/.exec(message);
	if (match) {
		return {
			kind: 'malformed-glob',
			raw: message,
			subject: match[1],
			summary: `glob 模式 \`${match[1]}\` 不合法（只允许尾部 \`.*\`）。`
		};
	}
	if (/^catalog version must increase/.test(message)) {
		return {
			kind: 'version',
			raw: message,
			subject: null,
			summary: 'catalog version 必须递增；请重新加载最新目录后再提交。'
		};
	}
	return { kind: 'unknown', raw: message, subject: null, summary: message };
}
