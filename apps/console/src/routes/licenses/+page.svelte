<script lang="ts">
	import { browser } from '$app/environment';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import type { LicenseRecord, LicenseStatus } from '$lib/api/types';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Select from '$lib/components/ui/select.svelte';
	import Badge from '$lib/components/ui/badge.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import { formatTimestamp, cn } from '$lib/utils';
	import { Plus } from '@lucide/svelte';

	const STATUS_VARIANTS: Record<LicenseStatus, 'default' | 'secondary' | 'destructive' | 'outline'> =
		{
			active: 'default',
			suspended: 'secondary',
			expired: 'outline',
			revoked: 'destructive'
		};

	let items = $state<LicenseRecord[] | null>(null);
	let loadError = $state<unknown>(null);
	let loading = $state(false);
	let status = $state<'' | LicenseStatus>('');
	let limit = $state('50');

	const parsedLimit = $derived(Math.max(1, Math.min(100, Number(limit) || 50)));

	$effect(() => {
		if (!browser) return;
		const productId = productStore.value;
		const statusFilter = status;
		const limitValue = parsedLimit;
		if (!productId || !tokenStore.authenticated) {
			items = null;
			loading = false;
			return;
		}
		loading = true;
		loadError = null;
		// teardown 标记：limit 输入逐键触发本 effect，迟到的旧响应必须丢弃。
		let stale = false;
		getClient()
			.listLicenses({
				product_id: productId,
				status: statusFilter || undefined,
				limit: limitValue
			})
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
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight">Licenses</h1>
			<p class="text-sm text-muted-foreground">授权列表（服务端筛选：status；limit ≤ 100）。</p>
		</div>
		<Button href="/licenses/new">
			<Plus /> 签发许可
		</Button>
	</div>

	<div class="flex flex-wrap items-end gap-4">
		<div class="space-y-1">
			<Label for="status-filter">状态</Label>
			<Select id="status-filter" bind:value={status} class="w-40">
				<option value="">全部</option>
				<option value="active">active</option>
				<option value="suspended">suspended</option>
				<option value="expired">expired</option>
				<option value="revoked">revoked</option>
			</Select>
		</div>
		<div class="space-y-1">
			<Label for="limit-input">每页数量（1–100）</Label>
			<Input id="limit-input" bind:value={limit} type="number" min="1" max="100" class="w-28" />
		</div>
	</div>

	{#if !productStore.value}
		<Alert title="未选择产品">列表端点要求 product_id，请先在页面顶部选择产品。</Alert>
	{:else if loadError}
		<ErrorAlert error={loadError} />
	{:else if loading && !items}
		<p class="text-sm text-muted-foreground">加载中…</p>
	{:else if items}
		<div class="rounded-md border">
			<table class="w-full text-sm">
				<thead>
					<tr class="border-b bg-muted/50 text-left text-xs text-muted-foreground">
						<th class="px-3 py-2 font-medium">License ID</th>
						<th class="px-3 py-2 font-medium">状态</th>
						<th class="px-3 py-2 font-medium">策略</th>
						<th class="px-3 py-2 font-medium">账户</th>
						<th class="px-3 py-2 font-medium">席位</th>
						<th class="px-3 py-2 font-medium">到期</th>
						<th class="px-3 py-2 font-medium">创建时间</th>
					</tr>
				</thead>
				<tbody>
					{#each items as license (license.license_id)}
						<tr class="border-b last:border-0 hover:bg-muted/30">
							<td class="px-3 py-2">
								<a
									href="/licenses/{license.license_id}"
									class="font-mono text-xs text-primary underline-offset-4 hover:underline"
								>
									{license.license_id}
								</a>
							</td>
							<td class="px-3 py-2">
								<Badge variant={STATUS_VARIANTS[license.status]}>{license.status}</Badge>
							</td>
							<td class="px-3 py-2 font-mono text-xs">{license.policy_id}</td>
							<td class="px-3 py-2 font-mono text-xs">{license.account_id ?? '—'}</td>
							<td class={cn('px-3 py-2', license.seats_used > 0 && 'font-medium')}>
								{license.seats_used}{license.seats_override ? ` / ${license.seats_override}` : ''}
							</td>
							<td class="px-3 py-2 text-xs">{formatTimestamp(license.expires_at)}</td>
							<td class="px-3 py-2 text-xs">{formatTimestamp(license.created_at)}</td>
						</tr>
					{:else}
						<tr>
							<td colspan="7" class="px-3 py-8 text-center text-muted-foreground">
								没有匹配的许可。
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		{#if items.length === parsedLimit}
			<p class="text-xs text-muted-foreground">
				已达 limit 上限，结果可能被截断（当前端点无游标分页；缩小 status 过滤范围查看）。
			</p>
		{/if}
	{/if}
</div>
