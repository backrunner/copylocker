<script lang="ts">
	/**
	 * Telemetry 保留清理对话框 —— 两步确认，与 CLI `telemetry purge` 行为一致：
	 * dry-run 预览 cutoff 与影响面；输入完整 product_id 才能确认。
	 */
	import { getClient } from '$lib/api';
	import type {
		TelemetryPurgeBody,
		TelemetryPurgeConfirmedResponse,
		TelemetryPurgeDryRunResponse
	} from '$lib/api/types';
	import { createDsrFlow, type ConfirmedWithReceipt } from '$lib/flows/dsr';
	import Dialog from './ui/dialog.svelte';
	import Button from './ui/button.svelte';
	import Input from './ui/input.svelte';
	import Label from './ui/label.svelte';
	import Alert from './ui/alert.svelte';
	import ErrorAlert from './error-alert.svelte';

	let {
		open = $bindable(false),
		body,
		onPurged
	}: {
		open?: boolean;
		/** { product_id, before? }；before 缺省 = 30 天 T1 raw 保留策略。 */
		body: TelemetryPurgeBody;
		onPurged?: () => void;
	} = $props();

	const flow = createDsrFlow(getClient());

	let preview = $state<TelemetryPurgeDryRunResponse | null>(null);
	let loadError = $state<unknown>(null);
	let confirmError = $state<unknown>(null);
	let typedId = $state('');
	let confirming = $state(false);
	let receipt = $state<ConfirmedWithReceipt<TelemetryPurgeConfirmedResponse> | null>(null);

	const canConfirm = $derived(flow.canConfirm(typedId, body.product_id));

	$effect(() => {
		if (open) {
			preview = null;
			loadError = null;
			confirmError = null;
			typedId = '';
			receipt = null;
			void flow
				.previewPurge(body)
				.then((value) => (preview = value))
				.catch((error: unknown) => (loadError = error));
		}
	});

	async function confirm() {
		if (!canConfirm || confirming) return;
		confirming = true;
		confirmError = null;
		try {
			receipt = await flow.confirmPurge(body);
			onPurged?.();
		} catch (error) {
			confirmError = error;
		} finally {
			confirming = false;
		}
	}
</script>

<Dialog
	bind:open
	title="清理 telemetry raw detail"
	description="T1 raw 保留策略执行（dry-run 预览 → 输入 product_id 确认）。"
>
	<div class="space-y-4">
		{#if receipt}
			<Alert title="清理已生效">
				<ul class="list-inside list-disc">
					<li>已删 raw records：{receipt.response.deleted_raw_records}</li>
					<li>已删 rollup rows：{receipt.response.deleted_rollup_rows}</li>
					<li>
						操作回执（operation id 第二段）：
						<code class="font-mono text-xs" data-testid="purge-receipt">{receipt.idempotencyKey}</code>
					</li>
					{#if !receipt.response.journaled}
						<li>无可删数据，未写入操作日志。</li>
					{/if}
				</ul>
			</Alert>
		{:else}
			{#if loadError}
				<ErrorAlert error={loadError} />
			{:else if preview}
				<Alert variant="warning" title="影响面（dry-run）">
					<ul class="list-inside list-disc">
						<li>cutoff：{preview.cutoff}</li>
						<li>将删 raw records：{preview.raw_records}</li>
						<li>将删 rollup rows：{preview.rollup_rows}</li>
					</ul>
				</Alert>
			{:else}
				<p class="text-sm text-muted-foreground">正在加载影响面…</p>
			{/if}

			{#if confirmError}
				<ErrorAlert error={confirmError} />
			{/if}

			<div class="space-y-2">
				<Label for="purge-confirm-input">
					输入完整 product_id 以确认：<code class="font-mono text-xs">{body.product_id}</code>
				</Label>
				<Input
					id="purge-confirm-input"
					bind:value={typedId}
					placeholder={body.product_id}
					autocomplete="off"
					spellcheck="false"
					class="font-mono text-xs"
					data-testid="purge-confirm-input"
				/>
				{#if typedId && !canConfirm}
					<p class="text-xs text-destructive" data-testid="purge-mismatch">
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
				data-testid="purge-confirm-button"
			>
				{confirming ? '正在清理…' : '确认清理'}
			</Button>
		{/if}
	{/snippet}
</Dialog>
