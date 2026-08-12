<script lang="ts">
	/**
	 * Release 高危操作对话框（deprecate / mark-compromised）—— 两步确认，与 CLI
	 * `release` 行为一致：打开/切换动作时 dry-run 拉取影响面；输入完整 release id
	 * 才能确认；revoke 动作还需显式勾选 acknowledge，否则绝不发送确认请求。
	 */
	import { getClient } from '$lib/api';
	import type {
		CompromiseAction,
		DeprecateReleaseDryRunResponse,
		MarkCompromisedDryRunResponse,
		ReleaseRecord
	} from '$lib/api/types';
	import { createReleaseActionFlow } from '$lib/flows/release-action';
	import Dialog from './ui/dialog.svelte';
	import Button from './ui/button.svelte';
	import Input from './ui/input.svelte';
	import Label from './ui/label.svelte';
	import Select from './ui/select.svelte';
	import Checkbox from './ui/checkbox.svelte';
	import Alert from './ui/alert.svelte';
	import ErrorAlert from './error-alert.svelte';

	let {
		open = $bindable(false),
		action,
		release,
		productId,
		onDone
	}: {
		open?: boolean;
		action: 'deprecate' | 'compromised';
		release: ReleaseRecord;
		productId: string;
		onDone?: () => void;
	} = $props();

	const flow = createReleaseActionFlow(getClient());

	let deprecatePreview = $state<DeprecateReleaseDryRunResponse | null>(null);
	let compromisedPreview = $state<MarkCompromisedDryRunResponse | null>(null);
	let compromiseAction = $state<CompromiseAction>('warn');
	let bumpFloor = $state(false);
	let acknowledged = $state(false);
	let typedId = $state('');
	let loadError = $state<unknown>(null);
	let confirmError = $state<unknown>(null);
	let confirming = $state(false);
	let done = $state(false);

	const preview = $derived(action === 'deprecate' ? deprecatePreview : compromisedPreview);
	const canConfirm = $derived(
		action === 'deprecate'
			? flow.canConfirm(typedId, release.id)
			: flow.canConfirmCompromised(compromisedPreview, typedId, release.id, acknowledged)
	);

	// 序号守卫：快速切换动作/勾选时，迟到的旧 dry-run 响应不得覆盖新选择。
	let previewSeq = 0;

	async function loadPreview(selected: CompromiseAction, bump: boolean) {
		const seq = ++previewSeq;
		loadError = null;
		try {
			if (action === 'deprecate') {
				const result = await flow.previewDeprecate(release.id, productId);
				if (seq === previewSeq) deprecatePreview = result;
			} else {
				const result = await flow.previewCompromised(release.id, productId, selected, bump);
				if (seq === previewSeq) compromisedPreview = result;
			}
		} catch (error) {
			if (seq === previewSeq) loadError = error;
		}
	}

	$effect(() => {
		if (open) {
			deprecatePreview = null;
			compromisedPreview = null;
			compromiseAction = 'warn';
			bumpFloor = false;
			acknowledged = false;
			typedId = '';
			confirmError = null;
			done = false;
			void loadPreview(compromiseAction, bumpFloor);
		}
	});

	async function confirm() {
		if (!canConfirm || confirming) return;
		confirming = true;
		confirmError = null;
		try {
			if (action === 'deprecate') {
				await flow.confirmDeprecate(release.id, productId);
			} else {
				await flow.confirmCompromised(release.id, productId, {
					action: compromiseAction,
					bump_security_floor: bumpFloor,
					...(compromisedPreview?.requires_acknowledgement ? { acknowledge_revoke: true } : {})
				});
			}
			done = true;
			onDone?.();
		} catch (error) {
			confirmError = error;
		} finally {
			confirming = false;
		}
	}
</script>

<Dialog
	bind:open
	title={action === 'deprecate' ? '弃用 Release' : '标记 Release 为 compromised'}
	description="高危操作：先展示 dry-run 影响面，输入完整 release id 后才能执行。"
>
	<div class="space-y-4">
		{#if done}
			<Alert title="操作已生效">
				<code class="font-mono text-xs">{release.id}</code>
				{action === 'deprecate' ? '已弃用。' : `已标记为 compromised（${compromiseAction}）。`}
			</Alert>
		{:else}
			{#if action === 'compromised'}
				<div class="grid grid-cols-2 gap-4">
					<div class="space-y-2">
						<Label for="compromise-action">动作</Label>
						<Select
							id="compromise-action"
							bind:value={compromiseAction}
							onchange={() => {
								compromisedPreview = null;
								void loadPreview(compromiseAction, bumpFloor);
							}}
						>
							<option value="warn">warn（警告）</option>
							<option value="force_upgrade">force_upgrade（强制升级）</option>
							<option value="revoke">revoke（吊销设备）</option>
						</Select>
					</div>
					<div class="flex items-end gap-2 pb-1">
						<Checkbox
							id="bump-floor"
							bind:checked={bumpFloor}
							onchange={() => {
								compromisedPreview = null;
								void loadPreview(compromiseAction, bumpFloor);
							}}
						/>
						<Label for="bump-floor">同时提升 security floor</Label>
					</div>
				</div>
			{/if}

			{#if loadError}
				<ErrorAlert error={loadError} />
			{:else if preview}
				<Alert variant="warning" title="影响面（dry-run）">
					<ul class="list-inside list-disc">
						<li>受影响设备数：{preview.impact.devices}</li>
						<li>近 7 天 check-ins：{preview.impact.checkins_last_7d}</li>
						{#each preview.effects as effect (effect)}
							<li>{effect}</li>
						{/each}
						{#if action === 'compromised' && compromisedPreview}
							<li>
								security floor：{compromisedPreview.security_floor.current} → {compromisedPreview
									.security_floor.next ?? '不变'}
							</li>
						{/if}
					</ul>
				</Alert>
			{:else}
				<p class="text-sm text-muted-foreground">正在加载影响面…</p>
			{/if}

			{#if confirmError}
				<ErrorAlert error={confirmError} />
			{/if}

			{#if action === 'compromised' && compromisedPreview?.requires_acknowledgement}
				<div class="flex items-center gap-2">
					<Checkbox id="acknowledge-revoke" bind:checked={acknowledged} />
					<Label for="acknowledge-revoke">
						我理解 revoke 将在下次验证时吊销受影响设备（不可撤销）
					</Label>
				</div>
			{/if}

			<div class="space-y-2">
				<Label for="release-confirm-input">
					输入完整 release id 以确认：<code class="font-mono text-xs">{release.id}</code>
				</Label>
				<Input
					id="release-confirm-input"
					bind:value={typedId}
					placeholder={release.id}
					autocomplete="off"
					spellcheck="false"
					class="font-mono text-xs"
					data-testid="release-confirm-input"
				/>
				{#if typedId && !flow.canConfirm(typedId, release.id)}
					<p class="text-xs text-destructive" data-testid="release-mismatch">
						id 不匹配，确认请求不会被发送。
					</p>
				{/if}
			</div>
		{/if}
	</div>

	{#snippet footer()}
		{#if done}
			<Button onclick={() => (open = false)}>关闭</Button>
		{:else}
			<Button variant="outline" onclick={() => (open = false)}>取消</Button>
			<Button
				variant="destructive"
				disabled={!canConfirm || confirming || !preview}
				onclick={confirm}
				data-testid="release-confirm-button"
			>
				{confirming ? '正在执行…' : '确认执行'}
			</Button>
		{/if}
	{/snippet}
</Dialog>
