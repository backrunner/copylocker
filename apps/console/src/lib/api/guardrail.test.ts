import { describe, expect, it } from 'vitest';
import { parseCatalogGuardrail } from './guardrail';

describe('parseCatalogGuardrail（422 invalid_catalog 护栏原因解析）', () => {
	it('识别"已发布 feature 不能重命名/删除"并给出原因', () => {
		const reason = parseCatalogGuardrail(
			'feature `export.pdf` was published and cannot be renamed or removed; assets sealed under it would become unopenable'
		);
		expect(reason.kind).toBe('feature-published');
		expect(reason.subject).toBe('export.pdf');
		expect(reason.summary).toContain('不能重命名或删除');
	});

	it('识别 limit key 删除', () => {
		const reason = parseCatalogGuardrail('limit key `render.max_dpi` was published and removed');
		expect(reason.kind).toBe('limit-key-removed');
		expect(reason.subject).toBe('render.max_dpi');
	});

	it('识别未知引用（删除仍被引用的 feature 时服务端先报这个）', () => {
		const reason = parseCatalogGuardrail('`pro` references unknown `export.pdf`');
		expect(reason.kind).toBe('unknown-reference');
		expect(reason.subject).toBe('export.pdf');
	});

	it('识别循环引用与非法 glob', () => {
		expect(parseCatalogGuardrail('group `a` participates in a cycle').kind).toBe('cycle');
		expect(parseCatalogGuardrail('malformed glob pattern `ex*port`').kind).toBe('malformed-glob');
	});

	it('未知文案原样透传', () => {
		const reason = parseCatalogGuardrail('some future guardrail message');
		expect(reason.kind).toBe('unknown');
		expect(reason.summary).toBe('some future guardrail message');
		expect(reason.raw).toBe('some future guardrail message');
	});
});
