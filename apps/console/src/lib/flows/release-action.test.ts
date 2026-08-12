import { describe, expect, it, vi } from 'vitest';
import { AdminClient } from '../api/client';
import { createReleaseActionFlow } from './release-action';
import type { MarkCompromisedDryRunResponse } from '../api/types';

const TOKEN = `clat_${'b'.repeat(43)}`;
const RELEASE_ID = 'rel_2026_08';

function jsonResponse(status: number, body: unknown) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});
}

function compromisedPreview(overrides: Partial<MarkCompromisedDryRunResponse> = {}) {
	return {
		ok: true as const,
		dry_run: true as const,
		action: 'revoke',
		release: { id: RELEASE_ID },
		impact: { devices: 4, checkins_last_7d: 9 },
		effects: ['devices killed at next validation'],
		requires_acknowledgement: true,
		security_floor: { current: 3, next: 5 },
		...overrides
	} as MarkCompromisedDryRunResponse;
}

describe('release 高危操作两步确认流（与 CLI 行为一致）', () => {
	it('deprecate 第一步永远是 dry_run=true', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(200, {
				ok: true,
				dry_run: true,
				action: 'deprecate',
				release: { id: RELEASE_ID },
				impact: { devices: 2, checkins_last_7d: 1 },
				effects: []
			})
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createReleaseActionFlow(client);

		const preview = await flow.previewDeprecate(RELEASE_ID, 'prod');
		expect(preview.impact.devices).toBe(2);
		const [href] = fetcher.mock.calls[0];
		expect(String(href)).toContain(`/releases/${RELEASE_ID}/deprecate`);
		expect(String(href)).toContain('dry_run=true');
		expect(String(href)).toContain('product_id=prod');
	});

	it('canConfirm 要求完整匹配 release id', () => {
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN });
		const flow = createReleaseActionFlow(client);
		expect(flow.canConfirm(RELEASE_ID, RELEASE_ID)).toBe(true);
		expect(flow.canConfirm(RELEASE_ID.slice(0, -1), RELEASE_ID)).toBe(false);
		expect(flow.canConfirm('', RELEASE_ID)).toBe(false);
	});

	it('revoke 动作需要 acknowledge；未勾选时 canConfirmCompromised 为 false', () => {
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN });
		const flow = createReleaseActionFlow(client);
		const preview = compromisedPreview();
		expect(flow.canConfirmCompromised(preview, RELEASE_ID, RELEASE_ID, false)).toBe(false);
		expect(flow.canConfirmCompromised(preview, RELEASE_ID, RELEASE_ID, true)).toBe(true);
		expect(
			flow.canConfirmCompromised(
				compromisedPreview({ requires_acknowledgement: false }),
				RELEASE_ID,
				RELEASE_ID,
				false
			)
		).toBe(true);
		expect(flow.canConfirmCompromised(null, RELEASE_ID, RELEASE_ID, true)).toBe(false);
	});

	it('mark-compromised dry-run 携带 action 与 bump_security_floor，但不带 acknowledge', async () => {
		const fetcher = vi.fn<typeof fetch>(async () => jsonResponse(200, compromisedPreview()));
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createReleaseActionFlow(client);

		await flow.previewCompromised(RELEASE_ID, 'prod', 'revoke', true);
		const [href, init] = fetcher.mock.calls[0];
		expect(String(href)).toContain('mark-compromised');
		expect(String(href)).toContain('dry_run=true');
		expect(JSON.parse(String(init?.body))).toEqual({ action: 'revoke', bump_security_floor: true });
		expect((init?.headers as Headers).get('Idempotency-Key')).toBeNull();
	});

	it('确认请求 dry_run=false，携带 acknowledge_revoke 与新的 Idempotency-Key', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(200, {
				ok: true,
				dry_run: false,
				action: 'revoke',
				release: { id: RELEASE_ID, status: 'compromised', compromised_action: 'revoke' },
				impact: { devices: 4, checkins_last_7d: 9 },
				security_floor: 5
			})
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createReleaseActionFlow(client);

		const result = await flow.confirmCompromised(RELEASE_ID, 'prod', {
			action: 'revoke',
			bump_security_floor: true,
			acknowledge_revoke: true
		});
		expect(result.dry_run).toBe(false);
		const [href, init] = fetcher.mock.calls[0];
		expect(String(href)).toContain('dry_run=false');
		expect(JSON.parse(String(init?.body))).toEqual({
			action: 'revoke',
			bump_security_floor: true,
			acknowledge_revoke: true
		});
		expect((init?.headers as Headers).get('Idempotency-Key')).toBeTruthy();
	});

	it('deprecate 确认请求 dry_run=false 并携带 Idempotency-Key', async () => {
		const fetcher = vi.fn<typeof fetch>(async () =>
			jsonResponse(200, {
				ok: true,
				dry_run: false,
				action: 'deprecate',
				release: { id: RELEASE_ID, status: 'deprecated', deprecated_at: 1_800_000_000 },
				impact: { devices: 2, checkins_last_7d: 1 }
			})
		);
		const client = new AdminClient({ baseUrl: 'http://api.test', getToken: () => TOKEN, fetcher });
		const flow = createReleaseActionFlow(client);

		const result = await flow.confirmDeprecate(RELEASE_ID, 'prod');
		expect(result.dry_run).toBe(false);
		const [href, init] = fetcher.mock.calls[0];
		expect(String(href)).toContain('dry_run=false');
		expect((init?.headers as Headers).get('Idempotency-Key')).toBeTruthy();
	});
});
