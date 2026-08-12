import { describe, expect, it, vi } from 'vitest';
import { AdminClient } from '../api/client';
import { createRevokeFlow } from './revoke';
import { KILL_REASONS } from '../api/types';

const TOKEN = `clat_${'b'.repeat(43)}`;
const TARGET = '0123456789abcdef0123456789abcdef';

function jsonResponse(status: number, body: unknown) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});
}

describe('吊销两步确认流（与 CLI 行为一致）', () => {
	it('第一步永远是 dry_run=true，返回影响面', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(200, {
				ok: true,
				dry_run: true,
				kind: 'license',
				target: TARGET,
				affected_machines: 3,
				already_revoked: false
			})
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createRevokeFlow(client);

		const preview = await flow.preview('licenses', TARGET);
		expect(preview.affected_machines).toBe(3);
		const [href] = fetcher.mock.calls[0];
		expect(String(href)).toContain('dry_run=true');
	});

	it('canConfirm 要求完整匹配目标 ID（大小写不敏感、去空白）', () => {
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN });
		const flow = createRevokeFlow(client);
		expect(flow.canConfirm(TARGET, TARGET)).toBe(true);
		expect(flow.canConfirm(TARGET.toUpperCase(), TARGET)).toBe(true);
		expect(flow.canConfirm(` ${TARGET} `, TARGET)).toBe(true);
		expect(flow.canConfirm(TARGET.slice(0, -1), TARGET)).toBe(false);
		expect(flow.canConfirm('', TARGET)).toBe(false);
	});

	it('确认请求携带 dry_run=false、reason 与新的 Idempotency-Key', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(200, {
				ok: true,
				dry_run: false,
				kind: 'license',
				target: TARGET,
				revocation_epoch: 9
			})
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createRevokeFlow(client);

		const result = await flow.confirm('licenses', TARGET, KILL_REASONS.Fraud);
		expect(result.revocation_epoch).toBe(9);
		const [href, init] = fetcher.mock.calls[0];
		expect(String(href)).toContain('dry_run=false');
		expect((init?.headers as Headers).get('Idempotency-Key')).toBeTruthy();
		expect(JSON.parse(String(init?.body))).toEqual({ reason: KILL_REASONS.Fraud });
	});

	it('两次确认使用不同的 Idempotency-Key（epoch 双 actor 场景）', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(202, { ok: true, dry_run: false, approval_pending: true })
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		await client.revokeEpoch('aabbccddaabbccdd', {
			dryRun: false,
			confirmEpochId: 'aabbccddaabbccdd'
		});
		await client.revokeEpoch('aabbccddaabbccdd', {
			dryRun: false,
			confirmEpochId: 'aabbccddaabbccdd'
		});
		const key1 = (fetcher.mock.calls[0][1]?.headers as Headers).get('Idempotency-Key');
		const key2 = (fetcher.mock.calls[1][1]?.headers as Headers).get('Idempotency-Key');
		expect(key1).toBeTruthy();
		expect(key2).toBeTruthy();
		expect(key1).not.toBe(key2);
	});
});
