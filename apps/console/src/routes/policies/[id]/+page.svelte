<script lang="ts">
	import { browser } from '$app/environment';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import type { Policy } from '$lib/api/types';
	import PolicyForm from '$lib/components/policy-form.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import Button from '$lib/components/ui/button.svelte';

	const policyId = $derived(page.params.id ?? '');

	let policy = $state<Policy | null>(null);
	let version = $state<number | null>(null);
	let loadError = $state<unknown>(null);
	let saved = $state(false);

	$effect(() => {
		if (!browser || !policyId || !tokenStore.authenticated) return;
		getClient()
			.getPolicy(policyId)
			.then((response) => {
				policy = response.policy;
				version = response.version;
			})
			.catch((error: unknown) => (loadError = error));
	});
</script>

<div class="mx-auto max-w-4xl space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight">
				策略 <code class="font-mono text-lg">{policyId}</code>
				{#if version !== null}<span class="text-sm text-muted-foreground">v{version}</span>{/if}
			</h1>
			<p class="text-sm text-muted-foreground">
				<a href="/policies" class="underline-offset-4 hover:underline">← 返回列表</a>
			</p>
		</div>
		<Button variant="outline" href="/policies/{policyId}/simulate">配置预览器（Simulator）</Button>
	</div>

	{#if saved}
		<Alert title="已保存">策略已更新（PATCH /v1/admin/policies/{policyId}）。</Alert>
	{/if}
	{#if loadError}
		<ErrorAlert error={loadError} />
	{:else if !policy}
		<p class="text-sm text-muted-foreground">加载中…</p>
	{:else}
		<PolicyForm
			initial={policy}
			onSaved={() => {
				saved = true;
				setTimeout(() => (saved = false), 4000);
			}}
		/>
	{/if}
</div>
