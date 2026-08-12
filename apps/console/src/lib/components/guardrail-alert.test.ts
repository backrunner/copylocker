import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import GuardrailAlert from './guardrail-alert.svelte';

describe('GuardrailAlert（422 护栏原因展示）', () => {
	it('已发布 feature 重命名被拒绝时展示结构化原因', () => {
		render(GuardrailAlert, {
			props: {
				message:
					'feature `export.pdf` was published and cannot be renamed or removed; assets sealed under it would become unopenable'
			}
		});
		expect(screen.getByTestId('guardrail-summary').textContent).toContain('export.pdf');
		expect(screen.getByTestId('guardrail-summary').textContent).toContain('不能重命名或删除');
		// 服务端原始文案保留展示
		expect(screen.getByTestId('guardrail-alert').textContent).toContain('was published');
	});

	it('未知护栏文案原样展示', () => {
		render(GuardrailAlert, { props: { message: 'brand new guardrail' } });
		expect(screen.getByTestId('guardrail-summary').textContent).toBe('brand new guardrail');
	});
});
