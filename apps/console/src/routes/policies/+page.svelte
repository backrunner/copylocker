<script lang="ts">
	import { browser } from '$app/environment';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import type { Policy } from '$lib/api/types';
	import Button from '$lib/components/ui/button.svelte';
	import Badge from '$lib/components/ui/badge.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import { Plus } from '@lucide/svelte';

	let items = $state<Policy[] | null>(null);
	let loadError = $state<unknown>(null);
	let loading = $state(false);

	$effect(() => {
		if (!browser) return;
		const productId = productStore.value;
		if (!productId || !tokenStore.authenticated) {
			items = null;
			loading = false;
			return;
		}
		loading = true;
		loadError = null;
		// teardown 标记：切换产品时丢弃迟到的旧响应。
		let stale = false;
		getClient()
			.listPolicies(productId)
			.then((response) => {
				if (!stale) items = response.items;
			})
			.catch((error: unknown) => {
				if (!stale) loadError = error;
			})
			.finally(() => {
				if (!stale) loading = false;
			});
		return () => {
			stale = true;
		};
	});

	function validityLabel(policy: Policy): string {
		switch (policy.validity.kind) {
			case 'perpetual':
				return '永久';
			case 'fixed_term':
				return `固定 ${Math.round(policy.validity.duration_secs / 86400)} 天`;
			case 'subscription':
				return `订阅 ${Math.round(policy.validity.period_secs / 86400)} 天`;
			case 'trial':
				return `试用 ${Math.round(policy.validity.duration_secs / 86400)} 天`;
		}
	}
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight">Policies</h1>
			<p class="text-sm text-muted-foreground">策略列表（五轴授权模型）。</p>
		</div>
		<Button href="/policies/new"><Plus /> 新建策略</Button>
	</div>

	{#if !productStore.value}
		<Alert title="未选择产品">策略端点要求 product_id，请先在页面顶部选择产品。</Alert>
	{:else if loadError}
		<ErrorAlert error={loadError} />
	{:else if loading && !items}
		<p class="text-sm text-muted-foreground">加载中…</p>
	{:else if items}
		<div class="rounded-md border">
			<table class="w-full text-sm">
				<thead>
					<tr class="border-b bg-muted/50 text-left text-xs text-muted-foreground">
						<th class="px-3 py-2 font-medium">ID</th>
						<th class="px-3 py-2 font-medium">名称</th>
						<th class="px-3 py-2 font-medium">tier</th>
						<th class="px-3 py-2 font-medium">有效期</th>
						<th class="px-3 py-2 font-medium">席位</th>
						<th class="px-3 py-2 font-medium">mode</th>
						<th class="px-3 py-2 font-medium">preset</th>
					</tr>
				</thead>
				<tbody>
					{#each items as policy (policy.id)}
						<tr class="border-b last:border-0 hover:bg-muted/30">
							<td class="px-3 py-2">
								<a
									href="/policies/{policy.id}"
									class="font-mono text-xs text-primary underline-offset-4 hover:underline"
								>
									{policy.id}
								</a>
							</td>
							<td class="px-3 py-2">{policy.name}</td>
							<td class="px-3 py-2 font-mono text-xs">{policy.entitlement.tier}</td>
							<td class="px-3 py-2 text-xs">{validityLabel(policy)}</td>
							<td class="px-3 py-2">{policy.seats.seats}</td>
							<td class="px-3 py-2">
								<Badge variant={policy.mode === 'enforced_online' ? 'destructive' : 'secondary'}>
									{policy.mode}
								</Badge>
							</td>
							<td class="px-3 py-2 font-mono text-xs">{policy.preset ?? '—'}</td>
						</tr>
					{:else}
						<tr>
							<td colspan="7" class="px-3 py-8 text-center text-muted-foreground">
								该产品下还没有策略。
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
