<script lang="ts">
	/**
	 * DSR 删除对话框 —— 两步确认，与 CLI `dsr delete` 行为一致（GDPR 级联：
	 * DO 激活抹除 + D1 投影删除 + R2 raw detail 删除）。打开时 dry-run 拉取影响面；
	 * 输入完整目标 id 才能确认；完成后展示删除回执（Idempotency-Key =
	 * 服务端 operation id 的第二段）。
	 *
	 * kind = 'subject'：DSR 主体删除（machine_id 或 license_id，走 /dsr/delete）。
	 * kind = 'machine'：GDPR 设备删除（DELETE /v1/admin/machines/:id 别名）。
	 */
	import { getClient } from '$lib/api';
	import type { DsrDeleteDryRunResponse, DsrSubjectBody } from '$lib/api/types';
	import { createDsrFlow, type ConfirmedWithReceipt } from '$lib/flows/dsr';
	import type { DsrDeleteConfirmedResponse } from '$lib/api/types';
	import Dialog from './ui/dialog.svelte';
	import Button from './ui/button.svelte';
	import Input from './ui/input.svelte';
	import Label from './ui/label.svelte';
	import Alert from './ui/alert.svelte';
	import ErrorAlert from './error-alert.svelte';

	let {
		open = $bindable(false),
		kind,
		subject,
		targetId,
		onDeleted
	}: {
		open?: boolean;
		kind: 'subject' | 'machine';
		/** kind = 'subject' 时的完整请求体（含 product_id）。 */
		subject?: DsrSubjectBody;
		/** 确认用目标 id：machine_id 或 license_id（hex）。 */
		targetId: string;
		onDeleted?: () => void;
	} = $props();

	const flow = createDsrFlow(getClient());

	let preview = $state<DsrDeleteDryRunResponse | null>(null);
	let loadError = $state<unknown>(null);
	let confirmError = $state<unknown>(null);
	let typedId = $state('');
	let confirming = $state(false);
	let receipt = $state<ConfirmedWithReceipt<DsrDeleteConfirmedResponse> | null>(null);

	const canConfirm = $derived(flow.canConfirm(typedId, targetId));

	$effect(() => {
		if (open) {
			preview = null;
			loadError = null;
			confirmError = null;
			typedId = '';
			receipt = null;
			const load =
				kind === 'machine'
					? flow.previewMachineDelete(targetId)
					: subject
						? flow.previewDelete(subject)
						: Promise.reject(new Error('缺少 DSR 主体'));
			void load.then((value) => (preview = value)).catch((error: unknown) => (loadError = error));
		}
	});

	async function confirm() {
		if (!canConfirm || confirming) return;
		confirming = true;
		confirmError = null;
		try {
			receipt =
				kind === 'machine'
					? await flow.confirmMachineDelete(targetId)
					: await flow.confirmDelete(subject as DsrSubjectBody);
			onDeleted?.();
		} catch (error) {
			confirmError = error;
		} finally {
			confirming = false;
		}
	}
</script>

<Dialog
	bind:open
	title={kind === 'machine' ? 'GDPR 删除设备' : 'DSR 删除主体数据'}
	description="高危操作：删除 DO 激活、D1 投影与 raw detail（审计链按设计保留至保留期结束）。"
>
	<div class="space-y-4">
		{#if receipt}
			<Alert title="删除已生效">
				<ul class="list-inside list-disc">
					<li>已删设备：{receipt.response.deleted_machines}</li>
					<li>已删 raw records：{receipt.response.deleted_raw_records}</li>
					<li>
						删除回执（operation id 第二段）：
						<code class="font-mono text-xs" data-testid="dsr-receipt">{receipt.idempotencyKey}</code>
					</li>
				</ul>
				<p class="mt-2 text-xs text-muted-foreground">{receipt.response.audit_note}</p>
			</Alert>
		{:else}
			{#if loadError}
				<ErrorAlert error={loadError} />
			{:else if preview}
				<Alert variant="warning" title="影响面（dry-run）">
					<ul class="list-inside list-disc">
						<li>将删除设备数：{preview.machines.length}</li>
						<li>将删除 raw records：{preview.raw_records}</li>
						<li>审计链：不 tombstone（内容哈希链，随审计保留期过期）</li>
					</ul>
				</Alert>
			{:else}
				<p class="text-sm text-muted-foreground">正在加载影响面…</p>
			{/if}

			{#if confirmError}
				<ErrorAlert error={confirmError} />
			{/if}

			<div class="space-y-2">
				<Label for="dsr-confirm-input">
					输入完整目标 id 以确认：<code class="font-mono text-xs">{targetId}</code>
				</Label>
				<Input
					id="dsr-confirm-input"
					bind:value={typedId}
					placeholder={targetId}
					autocomplete="off"
					spellcheck="false"
					class="font-mono text-xs"
					data-testid="dsr-confirm-input"
				/>
				{#if typedId && !canConfirm}
					<p class="text-xs text-destructive" data-testid="dsr-mismatch">
						id 不匹配，确认请求不会被发送。
					</p>
				{/if}
			</div>
		{/if}
	</div>

	{#snippet footer()}
		{#if receipt}
			<Button onclick={() => (open = false)}>关闭</Button>
		{:else}
			<Button variant="outline" onclick={() => (open = false)}>取消</Button>
			<Button
				variant="destructive"
				disabled={!canConfirm || confirming || !preview}
				onclick={confirm}
				data-testid="dsr-confirm-button"
			>
				{confirming ? '正在删除…' : '确认删除'}
			</Button>
		{/if}
	{/snippet}
</Dialog>
