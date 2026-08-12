import { describe, expect, it, vi } from 'vitest';
import { AdminClient } from '../api/client';
import { createDsrFlow } from './dsr';

const TOKEN = `clat_${'b'.repeat(43)}`;
const MACHINE = '0123456789abcdef0123456789abcdef';

function jsonResponse(status: number, body: unknown) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});
}

describe('DSR / telemetry 两步确认流（与 CLI 行为一致）', () => {
	it('export 只读：无 dry_run 参数、无 Idempotency-Key', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(200, {
				ok: true,
				product_id: 'prod',
				subject: { machine_id: MACHINE },
				generated_at: 1_800_000_000,
				machines: [],
				licenses: [],
				audit_references: [],
				audit_truncated: false
			})
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createDsrFlow(client);

		const body = { product_id: 'prod', machine_id: MACHINE };
		const result = await flow.export(body);
		expect(result.subject).toEqual({ machine_id: MACHINE });
		const [href, init] = fetcher.mock.calls[0];
		expect(String(href)).toBe('http://api.test/v1/admin/dsr/export');
		expect(JSON.parse(String(init?.body))).toEqual(body);
		expect((init?.headers as Headers).get('Idempotency-Key')).toBeNull();
	});

	it('delete 第一步永远是 dry_run=true 的影响面', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(200, {
				ok: true,
				dry_run: true,
				product_id: 'prod',
				subject: { machine_id: MACHINE },
				machines: [{ id: MACHINE, license_id: 'ab'.repeat(16), status: 'active' }],
				raw_records: 2,
				audit_tombstone: false
			})
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createDsrFlow(client);

		const preview = await flow.previewDelete({ product_id: 'prod', machine_id: MACHINE });
		expect(preview.machines).toHaveLength(1);
		const [href] = fetcher.mock.calls[0];
		expect(String(href)).toContain('/v1/admin/dsr/delete?dry_run=true');
	});

	it('机器 GDPR 别名走 DELETE /v1/admin/machines/:id 且默认 dry-run', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(200, {
				ok: true,
				dry_run: true,
				product_id: 'prod',
				subject: { machine_id: MACHINE },
				machines: [],
				raw_records: 0,
				audit_tombstone: false
			})
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createDsrFlow(client);

		await flow.previewMachineDelete(MACHINE);
		const [href, init] = fetcher.mock.calls[0];
		expect(String(href)).toBe(`http://api.test/v1/admin/machines/${MACHINE}?dry_run=true`);
		expect(init?.method).toBe('DELETE');
		expect((init?.headers as Headers).get('Idempotency-Key')).toBeNull();
	});

	it('确认删除返回回执（Idempotency-Key），请求 dry_run=false', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(200, {
				ok: true,
				dry_run: false,
				product_id: 'prod',
				subject: { machine_id: MACHINE },
				deleted_machines: 1,
				deleted_raw_records: 2,
				audit_tombstone: false,
				audit_note: 'audit chain entries are content-hashed'
			})
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createDsrFlow(client);

		const receipt = await flow.confirmDelete({ product_id: 'prod', machine_id: MACHINE });
		expect(receipt.response.deleted_machines).toBe(1);
		expect(receipt.idempotencyKey).toBeTruthy();
		const [href, init] = fetcher.mock.calls[0];
		expect(String(href)).toContain('/v1/admin/dsr/delete?dry_run=false');
		expect((init?.headers as Headers).get('Idempotency-Key')).toBe(receipt.idempotencyKey);
	});

	it('确认机器删除复用同一回执语义（DELETE ?dry_run=false）', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(200, {
				ok: true,
				dry_run: false,
				product_id: 'prod',
				subject: { machine_id: MACHINE },
				deleted_machines: 1,
				deleted_raw_records: 0,
				audit_tombstone: false,
				audit_note: 'audit chain entries are content-hashed'
			})
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createDsrFlow(client);

		const receipt = await flow.confirmMachineDelete(MACHINE);
		expect(receipt.response.deleted_machines).toBe(1);
		const [href, init] = fetcher.mock.calls[0];
		expect(String(href)).toBe(`http://api.test/v1/admin/machines/${MACHINE}?dry_run=false`);
		expect(init?.method).toBe('DELETE');
		expect((init?.headers as Headers).get('Idempotency-Key')).toBe(receipt.idempotencyKey);
	});

	it('telemetry purge 先 dry-run 后确认，回执同样可见', async () => {
		const responses = [
			jsonResponse(200, {
				ok: true,
				dry_run: true,
				product_id: 'prod',
				cutoff: '2026-07-15',
				raw_records: 3,
				rollup_rows: 1
			}),
			jsonResponse(200, {
				ok: true,
				dry_run: false,
				product_id: 'prod',
				cutoff: '2026-07-15',
				deleted_raw_records: 3,
				deleted_rollup_rows: 1,
				journaled: true
			})
		];
		const fetcher = vi.fn<typeof fetch>(async () => responses.shift() as Response);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createDsrFlow(client);

		const body = { product_id: 'prod', before: '2026-07-15' };
		const preview = await flow.previewPurge(body);
		expect(preview.raw_records).toBe(3);
		const receipt = await flow.confirmPurge(body);
		expect(receipt.response.journaled).toBe(true);

		const [previewHref] = fetcher.mock.calls[0];
		expect(String(previewHref)).toContain('/v1/admin/telemetry/purge?dry_run=true');
		const [confirmHref, confirmInit] = fetcher.mock.calls[1];
		expect(String(confirmHref)).toContain('/v1/admin/telemetry/purge?dry_run=false');
		expect((confirmInit?.headers as Headers).get('Idempotency-Key')).toBe(receipt.idempotencyKey);
	});

	it('canConfirm 要求完整匹配目标 id（大小写不敏感）', () => {
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN });
		const flow = createDsrFlow(client);
		expect(flow.canConfirm(MACHINE.toUpperCase(), MACHINE)).toBe(true);
		expect(flow.canConfirm(MACHINE.slice(0, -1), MACHINE)).toBe(false);
	});
});
