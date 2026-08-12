<script lang="ts">
	/**
	 * License / Machine 吊销对话框 —— 两步确认，与 CLI 行为一致：
	 * 打开时自动 dry-run 拉取影响面；确认按钮在输入完整目标 id 前禁用，
	 * 输入不匹配时绝不发送确认请求。
	 */
	import { getClient } from '$lib/api';
	import { KILL_REASONS, type RevokeDryRunResponse, type RevokeKind } from '$lib/api/types';
	import { createRevokeFlow } from '$lib/flows/revoke';
	import Dialog from './ui/dialog.svelte';
	import Button from './ui/button.svelte';
	import Input from './ui/input.svelte';
	import Label from './ui/label.svelte';
	import Select from './ui/select.svelte';
	import Alert from './ui/alert.svelte';
	import ErrorAlert from './error-alert.svelte';

	let {
		open = $bindable(false),
		kind,
		targetId,
		onRevoked
	}: {
		open?: boolean;
		kind: RevokeKind;
		targetId: string;
		onRevoked?: (revocationEpoch: number) => void;
	} = $props();

	const flow = createRevokeFlow(getClient());

	let preview = $state<RevokeDryRunResponse | null>(null);
	let loadError = $state<unknown>(null);
	let confirmError = $state<unknown>(null);
	let typedId = $state('');
	let reason = $state<string>(String(KILL_REASONS.RevokedLicense));
	let confirming = $state(false);
	let done = $state<number | null>(null);

	$effect(() => {
		if (open) {
			preview = null;
			loadError = null;
			confirmError = null;
			typedId = '';
			done = null;
			void flow
				.preview(kind, targetId)
				.then((value) => (preview = value))
				.catch((error: unknown) => (loadError = error));
		}
	});

	const canConfirm = $derived(flow.canConfirm(typedId, targetId));

	async function confirm() {
		if (!canConfirm || confirming) return;
		confirming = true;
		confirmError = null;
		try {
			const response = await flow.confirm(kind, targetId, Number(reason));
			done = response.revocation_epoch;
			onRevoked?.(response.revocation_epoch);
		} catch (error) {
			confirmError = error;
		} finally {
			confirming = false;
		}
	}
</script>

<Dialog
	bind:open
	title="吊销{kind === 'licenses' ? '许可' : '设备'}"
	description="高危操作：先展示 dry-run 影响面，输入完整目标 ID 后才能执行。"
>
	<div class="space-y-4">
		{#if done !== null}
			<Alert title="吊销已生效">
				目标 <code class="font-mono text-xs">{targetId}</code> 已吊销，revocation epoch =
				{done}。
			</Alert>
		{:else}
			{#if loadError}
				<ErrorAlert error={loadError} />
			{:else if preview}
				<Alert variant={preview.already_revoked ? 'warning' : 'default'} title="影响面（dry-run）">
					<ul class="list-inside list-disc">
						<li>受影响设备数：{preview.affected_machines}</li>
						<li>
							目标状态：{preview.already_revoked ? '已吊销（再次确认会被服务端拒绝）' : '有效'}
						</li>
					</ul>
				</Alert>
			{:else}
				<p class="text-sm text-muted-foreground">正在加载影响面…</p>
			{/if}

			{#if confirmError}
				<ErrorAlert error={confirmError} />
			{/if}

			<div class="space-y-2">
				<Label for="revoke-reason">吊销原因</Label>
				<Select id="revoke-reason" bind:value={reason}>
					<option value={String(KILL_REASONS.RevokedLicense)}>手动吊销（RevokedLicense）</option>
					<option value={String(KILL_REASONS.Fraud)}>欺诈（Fraud）</option>
					<option value={String(KILL_REASONS.Refund)}>退款（Refund）</option>
					{#if kind === 'machines'}
						<option value={String(KILL_REASONS.RevokedActivation)}>
							吊销激活（RevokedActivation）
						</option>
						<option value={String(KILL_REASONS.SeatReclaimed)}>座位回收（SeatReclaimed）</option>
					{/if}
				</Select>
			</div>

			<div class="space-y-2">
				<Label for="revoke-confirm-input">
					输入完整目标 ID 以确认：<code class="font-mono text-xs">{targetId}</code>
				</Label>
				<Input
					id="revoke-confirm-input"
					bind:value={typedId}
					placeholder={targetId}
					autocomplete="off"
					spellcheck="false"
					class="font-mono text-xs"
					data-testid="revoke-confirm-input"
				/>
				{#if typedId && !canConfirm}
					<p class="text-xs text-destructive" data-testid="revoke-mismatch">
						ID 不匹配，确认请求不会被发送。
					</p>
				{/if}
			</div>
		{/if}
	</div>

	{#snippet footer()}
		{#if done !== null}
			<Button onclick={() => (open = false)}>关闭</Button>
		{:else}
			<Button variant="outline" onclick={() => (open = false)}>取消</Button>
			<Button
				variant="destructive"
				disabled={!canConfirm || confirming || !preview || preview.already_revoked}
				onclick={confirm}
				data-testid="revoke-confirm-button"
			>
				{confirming ? '正在吊销…' : '确认吊销'}
			</Button>
		{/if}
	{/snippet}
</Dialog>
