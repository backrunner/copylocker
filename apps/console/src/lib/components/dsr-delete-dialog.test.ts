import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte';
import DsrDeleteDialog from './dsr-delete-dialog.svelte';
import { tokenStore } from '$lib/auth/token.svelte';

const TOKEN = `clat_${'c'.repeat(43)}`;
const TARGET = '0123456789abcdef0123456789abcdef';

function jsonResponse(status: number, body: unknown) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});
}

describe('DsrDeleteDialog（DSR 删除两步确认 UI）', () => {
	const fetchMock = vi.fn<typeof fetch>();

	beforeEach(() => {
		fetchMock.mockReset();
		vi.stubGlobal('fetch', fetchMock);
		tokenStore.login(TOKEN);
		fetchMock.mockImplementation(async (input, init) => {
			const url = String(input);
			if (init?.method === 'DELETE' && url.includes('dry_run=false')) {
				return jsonResponse(200, {
					ok: true,
					dry_run: false,
					product_id: 'prod',
					subject: { machine_id: TARGET },
					deleted_machines: 1,
					deleted_raw_records: 2,
					audit_tombstone: false,
					audit_note: 'audit chain entries are content-hashed'
				});
			}
			if (init?.method === 'DELETE') {
				return jsonResponse(200, {
					ok: true,
					dry_run: true,
					product_id: 'prod',
					subject: { machine_id: TARGET },
					machines: [{ id: TARGET, license_id: 'ab'.repeat(16), status: 'active' }],
					raw_records: 2,
					audit_tombstone: false
				});
			}
			throw new Error(`unexpected fetch: ${init?.method} ${url}`);
		});
	});

	it('打开时先 dry-run 展示影响面；ID 不匹配时确认按钮禁用且不发确认请求', async () => {
		render(DsrDeleteDialog, { props: { open: true, kind: 'machine', targetId: TARGET } });

		await screen.findByText(/将删除设备数：1/);
		const dryRunCall = fetchMock.mock.calls.find(([, init]) => init?.method === 'DELETE');
		expect(String(dryRunCall?.[0])).toContain(`/v1/admin/machines/${TARGET}`);

		const button = screen.getByTestId('dsr-confirm-button');
		expect((button as HTMLButtonElement).disabled).toBe(true);

		const input = screen.getByTestId('dsr-confirm-input');
		await fireEvent.input(input, { target: { value: 'wrong-id' } });
		await screen.findByTestId('dsr-mismatch');
		expect((button as HTMLButtonElement).disabled).toBe(true);

		await fireEvent.click(button);
		expect(
			fetchMock.mock.calls.some(([url]) => String(url).includes('dry_run=false'))
		).toBe(false);
	});

	it('输入完整 ID 后才能确认，确认后展示删除回执', async () => {
		render(DsrDeleteDialog, { props: { open: true, kind: 'machine', targetId: TARGET } });
		await screen.findByText(/将删除设备数：1/);

		const input = screen.getByTestId('dsr-confirm-input');
		await fireEvent.input(input, { target: { value: TARGET } });

		const button = screen.getByTestId('dsr-confirm-button');
		expect((button as HTMLButtonElement).disabled).toBe(false);
		await fireEvent.click(button);

		await screen.findByText(/已删设备：1/);
		const receipt = await screen.findByTestId('dsr-receipt');
		expect(receipt.textContent).toBeTruthy();

		const confirmCall = fetchMock.mock.calls.find(([url]) =>
			String(url).includes('dry_run=false')
		);
		expect(confirmCall).toBeDefined();
		const [, init] = confirmCall!;
		expect((init?.headers as Headers).get('Authorization')).toBe(`Bearer ${TOKEN}`);
		expect(String(confirmCall![0])).not.toContain(TOKEN);
		expect((init?.headers as Headers).get('Idempotency-Key')).toBe(receipt.textContent);
	});
});
