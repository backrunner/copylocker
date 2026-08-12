<script lang="ts">
	/**
	 * Epoch 吊销引导 —— dry-run + 双 actor 确认（与 CLI 行为一致）：
	 *
	 * 1. dry-run 展示影响面上界、replacement 就绪状态、所需确认人数。
	 * 2. 确认：输入完整 epoch id（对应服务端 confirm_epoch_id 校验）+ revoke scope。
	 * 3. 第一次批准返回 202 approval_pending；需要另一位不同 actor 在 15 分钟内
	 *    用另一个 Admin token 重复本操作（另一个 Idempotency-Key）才会真正生效。
	 */
	import { getClient } from '$lib/api';
	import type { EpochRevokeDryRunResponse, EpochView } from '$lib/api/types';
	import Dialog from './ui/dialog.svelte';
	import Button from './ui/button.svelte';
	import Input from './ui/input.svelte';
	import Label from './ui/label.svelte';
	import Alert from './ui/alert.svelte';
	import ErrorAlert from './error-alert.svelte';
	import { isApiError } from '$lib/api/errors';

	let {
		open = $bindable(false),
		epoch,
		onRevoked
	}: {
		open?: boolean;
		epoch: EpochView;
		onRevoked?: () => void;
	} = $props();

	let preview = $state<EpochRevokeDryRunResponse | null>(null);
	let loadError = $state<unknown>(null);
	let confirmError = $state<unknown>(null);
	let typedId = $state('');
	let confirming = $state(false);
	let result = $state<
		| { kind: 'pending'; firstActor: string; expiresAt: number }
		| { kind: 'revoked'; revocationEpoch: number }
		| null
	>(null);

	$effect(() => {
		if (open) {
			preview = null;
			loadError = null;
			confirmError = null;
			typedId = '';
			result = null;
			void getClient()
				.revokeEpoch(epoch.epoch_id, { dryRun: true })
				.then((value) => {
					if (value.dry_run) preview = value;
				})
				.catch((error: unknown) => (loadError = error));
		}
	});

	const canConfirm = $derived(
		typedId.trim().toLowerCase() === epoch.epoch_id.toLowerCase() &&
			preview !== null &&
			preview.replacement_ready &&
			!preview.already_revoked
	);

	async function confirm() {
		if (!canConfirm || confirming) return;
		confirming = true;
		confirmError = null;
		try {
			const response = await getClient().revokeEpoch(epoch.epoch_id, {
				dryRun: false,
				confirmEpochId: typedId.trim()
			});
			if (response.dry_run) throw new Error('服务端未执行吊销');
			if (response.approval_pending) {
				result = {
					kind: 'pending',
					firstActor: response.first_actor,
					expiresAt: response.approval_expires_at ?? 0
				};
			} else {
				result = { kind: 'revoked', revocationEpoch: response.revocation_epoch ?? 0 };
				onRevoked?.();
			}
		} catch (error) {
			confirmError = error;
		} finally {
			confirming = false;
		}
	}
</script>

<Dialog
	bind:open
	title="吊销签名 Epoch"
	description="最高危操作：需要 2 位不同 actor 在 15 分钟内先后批准，且必须存在有效的 replacement Epoch。"
>
	<div class="space-y-4">
		{#if result?.kind === 'revoked'}
			<Alert title="Epoch 已吊销">
				第二次批准已完成，revocation epoch = {result.revocationEpoch}。
			</Alert>
		{:else if result?.kind === 'pending'}
			<Alert variant="warning" title="等待第二位 actor 确认（1/2）">
				<p>
					第一位 actor <code class="font-mono text-xs">{result.firstActor}</code> 已批准。
					请在 {new Date(result.expiresAt * 1000).toLocaleString('zh-CN', { hour12: false })} 之前，
					由<strong>另一位 actor</strong>（另一个 Admin token）重复本操作完成吊销。
					过期后批准自动作废。
				</p>
			</Alert>
		{:else}
			{#if loadError}
				<ErrorAlert error={loadError} />
			{:else if preview}
				<Alert
					variant={preview.already_revoked || !preview.replacement_ready ? 'destructive' : 'default'}
					title="影响面（dry-run）"
				>
					<ul class="list-inside list-disc">
						<li>受影响设备数上界：{preview.affected_machines_upper_bound}</li>
						<li>
							Replacement Epoch：{preview.replacement_ready
								? `就绪（${preview.replacement_epoch_ids.join(', ') || '默认作用域'}）`
								: '未就绪 —— 服务端会拒绝确认请求'}
						</li>
						<li>需要确认人数：{preview.requires_distinct_actors} 位不同 actor</li>
						{#if preview.already_revoked}
							<li>该 Epoch 已被吊销。</li>
						{/if}
					</ul>
				</Alert>
			{:else}
				<p class="text-sm text-muted-foreground">正在加载影响面…</p>
			{/if}

			{#if confirmError}
				{#if isApiError(confirmError) && confirmError.code === 'second_actor_required'}
					<Alert variant="warning" title="需要第二位 actor">
						当前 token 的 actor 已经完成第一次批准；请换用另一位 actor 的 Admin token 重复本操作。
					</Alert>
				{:else}
					<ErrorAlert error={confirmError} />
				{/if}
			{/if}

			<div class="space-y-2">
				<Label for="epoch-confirm-input">
					输入完整 Epoch ID 以确认：<code class="font-mono text-xs">{epoch.epoch_id}</code>
				</Label>
				<Input
					id="epoch-confirm-input"
					bind:value={typedId}
					placeholder={epoch.epoch_id}
					autocomplete="off"
					spellcheck="false"
					class="font-mono text-xs"
				/>
			</div>
		{/if}
	</div>

	{#snippet footer()}
		{#if result}
			<Button onclick={() => (open = false)}>关闭</Button>
		{:else}
			<Button variant="outline" onclick={() => (open = false)}>取消</Button>
			<Button variant="destructive" disabled={!canConfirm || confirming} onclick={confirm}>
				{confirming ? '正在提交…' : '提交批准'}
			</Button>
		{/if}
	{/snippet}
</Dialog>
