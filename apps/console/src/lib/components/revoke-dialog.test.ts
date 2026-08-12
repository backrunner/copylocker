import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte';
import RevokeDialog from './revoke-dialog.svelte';
import { tokenStore } from '$lib/auth/token.svelte';

const TOKEN = `clat_${'c'.repeat(43)}`;
const TARGET = '0123456789abcdef0123456789abcdef';

function jsonResponse(status: number, body: unknown) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});
}

describe('RevokeDialog（吊销两步确认 UI）', () => {
	const fetchMock = vi.fn<typeof fetch>();

	beforeEach(() => {
		fetchMock.mockReset();
		vi.stubGlobal('fetch', fetchMock);
		tokenStore.login(TOKEN);
		fetchMock.mockImplementation(async (input) => {
			const url = String(input);
			if (url.includes('dry_run=true')) {
				return jsonResponse(200, {
					ok: true,
					dry_run: true,
					kind: 'license',
					target: TARGET,
					affected_machines: 3,
					already_revoked: false
				});
			}
			return jsonResponse(200, {
				ok: true,
				dry_run: false,
				kind: 'license',
				target: TARGET,
				revocation_epoch: 11
			});
		});
	});

	it('打开时先 dry-run 展示影响面；ID 不匹配时确认按钮禁用且不发确认请求', async () => {
		render(RevokeDialog, { props: { open: true, kind: 'licenses', targetId: TARGET } });

		// dry-run 影响面
		await screen.findByText(/受影响设备数：3/);
		expect(fetchMock.mock.calls.some(([url]) => String(url).includes('dry_run=true'))).toBe(true);

		const button = screen.getByTestId('revoke-confirm-button');
		expect((button as HTMLButtonElement).disabled).toBe(true);

		// 输入不匹配的 ID：提示 + 仍然禁用
		const input = screen.getByTestId('revoke-confirm-input');
		await fireEvent.input(input, { target: { value: 'wrong-id' } });
		await screen.findByTestId('revoke-mismatch');
		expect((button as HTMLButtonElement).disabled).toBe(true);

		await fireEvent.click(button);
		expect(fetchMock.mock.calls.some(([url]) => String(url).includes('dry_run=false'))).toBe(false);
	});

	it('输入完整 ID 后才能确认，确认走 dry_run=false 并展示结果', async () => {
		render(RevokeDialog, { props: { open: true, kind: 'licenses', targetId: TARGET } });
		await screen.findByText(/受影响设备数：3/);

		const input = screen.getByTestId('revoke-confirm-input');
		await fireEvent.input(input, { target: { value: TARGET } });

		const button = screen.getByTestId('revoke-confirm-button');
		expect((button as HTMLButtonElement).disabled).toBe(false);
		await fireEvent.click(button);

		await screen.findByText(/revocation epoch = 11/);
		const confirmCall = fetchMock.mock.calls.find(([url]) =>
			String(url).includes('dry_run=false')
		);
		expect(confirmCall).toBeDefined();
		const [, init] = confirmCall!;
		expect((init?.headers as Headers).get('Authorization')).toBe(`Bearer ${TOKEN}`);
		expect(String(confirmCall![0])).not.toContain(TOKEN);
		expect((init?.headers as Headers).get('Idempotency-Key')).toBeTruthy();
	});
});
