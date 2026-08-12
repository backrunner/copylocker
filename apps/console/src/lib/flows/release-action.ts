/**
 * Release 高危操作两步确认流（deprecate / mark-compromised，与 CLI `release` 行为一致）：
 *
 * 1. dry-run：`POST /releases/:id/{deprecate,mark-compromised}?dry_run=true`
 *    → 影响面（devices、近 7 天 check-ins、effects、security_floor）。
 * 2. 操作者必须完整输入 release id；`revoke` 动作还必须显式勾选 acknowledge。
 *    条件不满足时**绝不发请求**。
 * 3. 确认请求 `dry_run=false`，携带新的 Idempotency-Key（由 client 适配层生成）。
 */
import type { AdminClient } from '../api/client';
import type {
	CompromiseAction,
	DeprecateReleaseConfirmedResponse,
	DeprecateReleaseDryRunResponse,
	MarkCompromisedBody,
	MarkCompromisedConfirmedResponse,
	MarkCompromisedDryRunResponse
} from '../api/types';

export interface ReleaseActionFlow {
	previewDeprecate(releaseId: string, productId: string): Promise<DeprecateReleaseDryRunResponse>;
	previewCompromised(
		releaseId: string,
		productId: string,
		action: CompromiseAction,
		bumpSecurityFloor: boolean
	): Promise<MarkCompromisedDryRunResponse>;
	canConfirm(typedId: string, targetId: string): boolean;
	/** revoke 动作的额外门槛：dry-run 要求 acknowledge 且操作者已勾选。 */
	canConfirmCompromised(
		preview: MarkCompromisedDryRunResponse | null,
		typedId: string,
		targetId: string,
		acknowledged: boolean
	): boolean;
	confirmDeprecate(releaseId: string, productId: string): Promise<DeprecateReleaseConfirmedResponse>;
	confirmCompromised(
		releaseId: string,
		productId: string,
		body: MarkCompromisedBody
	): Promise<MarkCompromisedConfirmedResponse>;
}

export function createReleaseActionFlow(
	client: Pick<AdminClient, 'deprecateRelease' | 'markReleaseCompromised'>
): ReleaseActionFlow {
	const canConfirm = (typedId: string, targetId: string) =>
		typedId.trim().toLowerCase() === targetId.trim().toLowerCase();
	return {
		async previewDeprecate(releaseId, productId) {
			const response = await client.deprecateRelease(releaseId, { productId, dryRun: true });
			if (!response.dry_run) throw new Error('服务端未按 dry-run 响应');
			return response;
		},
		async previewCompromised(releaseId, productId, action, bumpSecurityFloor) {
			const body: MarkCompromisedBody = { action, bump_security_floor: bumpSecurityFloor };
			const response = await client.markReleaseCompromised(releaseId, body, {
				productId,
				dryRun: true
			});
			if (!response.dry_run) throw new Error('服务端未按 dry-run 响应');
			return response;
		},
		canConfirm,
		canConfirmCompromised(preview, typedId, targetId, acknowledged) {
			if (!preview || !canConfirm(typedId, targetId)) return false;
			return !preview.requires_acknowledgement || acknowledged;
		},
		async confirmDeprecate(releaseId, productId) {
			const response = await client.deprecateRelease(releaseId, { productId, dryRun: false });
			if (response.dry_run) throw new Error('服务端未执行 deprecate');
			return response;
		},
		async confirmCompromised(releaseId, productId, body) {
			const response = await client.markReleaseCompromised(releaseId, body, {
				productId,
				dryRun: false
			});
			if (response.dry_run) throw new Error('服务端未执行 mark-compromised');
			return response;
		}
	};
}
