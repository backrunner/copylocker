/**
 * License / Machine 吊销的两步确认流（与 CLI 行为一致，见 70-admin-cli-console.md §1.3）：
 *
 * 1. dry-run：`POST /{kind}/:id/revoke?dry_run=true` → 影响面（受影响设备数、是否已吊销）。
 * 2. 确认：操作者必须完整输入目标 id（16 字节 hex）。不匹配时**绝不发请求**。
 * 3. 确认请求：`dry_run=false`，携带新的 Idempotency-Key 与吊销原因。
 */
import type { AdminClient } from '../api/client';
import type { RevokeConfirmedResponse, RevokeDryRunResponse, RevokeKind } from '../api/types';

export interface RevokeFlow {
	preview(kind: RevokeKind, targetId: string): Promise<RevokeDryRunResponse>;
	canConfirm(typedId: string, targetId: string): boolean;
	confirm(kind: RevokeKind, targetId: string, reason?: number): Promise<RevokeConfirmedResponse>;
}

export function createRevokeFlow(client: Pick<AdminClient, 'revoke'>): RevokeFlow {
	return {
		async preview(kind, targetId) {
			const response = await client.revoke(kind, targetId, { dryRun: true });
			if (!response.dry_run) throw new Error('服务端未按 dry-run 响应');
			return response;
		},
		canConfirm(typedId, targetId) {
			return typedId.trim().toLowerCase() === targetId.trim().toLowerCase();
		},
		async confirm(kind, targetId, reason) {
			const response = await client.revoke(kind, targetId, { dryRun: false, reason });
			if (response.dry_run) throw new Error('服务端未执行吊销');
			return response;
		}
	};
}
