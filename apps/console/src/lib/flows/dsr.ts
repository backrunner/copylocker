/**
 * DSR / telemetry 保留的两步确认流（与 CLI `dsr export|delete`、`telemetry purge` 行为一致）：
 *
 * 1. export 是只读操作（不带 Idempotency-Key）。
 * 2. delete / purge 永远先 dry-run 预览影响面（machines、raw_records、rollup_rows、cutoff）。
 * 3. 确认时操作者必须完整输入目标 id（machine/license hex 或 product_id）；不匹配时
 *    **绝不发请求**。确认请求携带 flow 生成的 Idempotency-Key —— 它同时是操作回执
 *    （服务端 operation id = `{vendor_id}/{idempotency_key}`），随结果返回给页面展示。
 */
import type { AdminClient } from '../api/client';
import type {
	DsrDeleteConfirmedResponse,
	DsrDeleteDryRunResponse,
	DsrExportResponse,
	DsrSubjectBody,
	TelemetryPurgeBody,
	TelemetryPurgeConfirmedResponse,
	TelemetryPurgeDryRunResponse
} from '../api/types';

/** 确认结果 + 本次操作的回执（Idempotency-Key）。 */
export interface ConfirmedWithReceipt<T> {
	response: T;
	/** 服务端 operation id 的第二段：`{vendor_id}/{idempotencyKey}`。 */
	idempotencyKey: string;
}

export interface DsrFlow {
	export(subject: DsrSubjectBody): Promise<DsrExportResponse>;
	previewDelete(subject: DsrSubjectBody): Promise<DsrDeleteDryRunResponse>;
	previewMachineDelete(machineId: string): Promise<DsrDeleteDryRunResponse>;
	canConfirm(typedId: string, targetId: string): boolean;
	confirmDelete(subject: DsrSubjectBody): Promise<ConfirmedWithReceipt<DsrDeleteConfirmedResponse>>;
	confirmMachineDelete(
		machineId: string
	): Promise<ConfirmedWithReceipt<DsrDeleteConfirmedResponse>>;
	previewPurge(body: TelemetryPurgeBody): Promise<TelemetryPurgeDryRunResponse>;
	confirmPurge(body: TelemetryPurgeBody): Promise<ConfirmedWithReceipt<TelemetryPurgeConfirmedResponse>>;
}

export function createDsrFlow(
	client: Pick<AdminClient, 'dsrExport' | 'dsrDelete' | 'deleteMachine' | 'telemetryPurge'>
): DsrFlow {
	return {
		async export(subject) {
			return client.dsrExport(subject);
		},
		async previewDelete(subject) {
			const response = await client.dsrDelete(subject, { dryRun: true });
			if (!response.dry_run) throw new Error('服务端未按 dry-run 响应');
			return response;
		},
		async previewMachineDelete(machineId) {
			const response = await client.deleteMachine(machineId, { dryRun: true });
			if (!response.dry_run) throw new Error('服务端未按 dry-run 响应');
			return response;
		},
		canConfirm(typedId, targetId) {
			return typedId.trim().toLowerCase() === targetId.trim().toLowerCase();
		},
		async confirmDelete(subject) {
			const idempotencyKey = crypto.randomUUID();
			const response = await client.dsrDelete(subject, { dryRun: false, idempotencyKey });
			if (response.dry_run) throw new Error('服务端未执行删除');
			return { response, idempotencyKey };
		},
		async confirmMachineDelete(machineId) {
			const idempotencyKey = crypto.randomUUID();
			const response = await client.deleteMachine(machineId, { dryRun: false, idempotencyKey });
			if (response.dry_run) throw new Error('服务端未执行删除');
			return { response, idempotencyKey };
		},
		async previewPurge(body) {
			const response = await client.telemetryPurge(body, { dryRun: true });
			if (!response.dry_run) throw new Error('服务端未按 dry-run 响应');
			return response;
		},
		async confirmPurge(body) {
			const idempotencyKey = crypto.randomUUID();
			const response = await client.telemetryPurge(body, { dryRun: false, idempotencyKey });
			if (response.dry_run) throw new Error('服务端未执行清理');
			return { response, idempotencyKey };
		}
	};
}
