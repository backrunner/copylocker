/**
 * 可访问性门禁（M7 验收：axe 无 critical/serious 违规）。
 *
 * 在 jsdom 中对主要页面跑 axe-core；当前覆盖两个无数据依赖的公开页面
 * （登录、离线门户）。依赖 admin 数据的页面在 E2E（Playwright + 真实后端，
 * M7 后续）中补齐同一门禁。
 */
import { render } from '@testing-library/svelte';
import axe from 'axe-core';
import { describe, expect, it } from 'vitest';
import LoginPage from '../routes/login/+page.svelte';
import OfflinePage from '../routes/offline/+page.svelte';

async function expectNoSeriousViolations(component: object, name: string) {
	const { container } = render(component as never);
	const results = await axe.run(container, {
		// jsdom 没有真实布局，color-contrast 等规则不可靠，只保留结构性规则。
		rules: { 'color-contrast': { enabled: false } }
	});
	const serious = results.violations.filter(
		(violation) => violation.impact === 'critical' || violation.impact === 'serious'
	);
	expect(
		serious.map((violation) => `${violation.id}: ${violation.nodes.map((n) => n.target).join(', ')}`),
		`${name} 存在 critical/serious 可访问性违规`
	).toEqual([]);
}

describe('axe accessibility gate', () => {
	it('登录页无 critical/serious 违规', async () => {
		await expectNoSeriousViolations(LoginPage, 'login');
	});

	it('离线门户无 critical/serious 违规', async () => {
		await expectNoSeriousViolations(OfflinePage, 'offline portal');
	});
});
