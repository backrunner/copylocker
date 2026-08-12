<script lang="ts">
	import { browser } from '$app/environment';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import Badge from '$lib/components/ui/badge.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import { formatTimestamp } from '$lib/utils';
	import type { LicenseStatus } from '$lib/api/types';

	const LICENSE_STATUSES: LicenseStatus[] = ['active', 'suspended', 'expired', 'revoked'];

	interface OverviewData {
		licenseCounts: Partial<Record<LicenseStatus, number>> | null;
		licensesTruncated: boolean;
		policyCount: number | null;
		catalogVersion: number | null;
		catalogCounts: { features: number; groups: number; tiers: number } | null;
		epochSummary: { active: number; upcoming: number; expired: number; revoked: number } | null;
		nextEpochExpiry: number | null;
	}

	let data = $state<OverviewData | null>(null);
	let loadError = $state<unknown>(null);
	let loading = $state(false);

	$effect(() => {
		if (!browser) return;
		const productId = productStore.value;
		if (!productId || !tokenStore.authenticated) {
			data = null;
			loading = false;
			return;
		}
		loading = true;
		loadError = null;
		// teardown 标记：切换产品时丢弃迟到的旧产品响应。
		let stale = false;
		const client = getClient();
		// 现有端点能拉到什么就展示什么；任何一组失败不拖垮整页。
		Promise.all([
			client.listLicenses({ product_id: productId, limit: 100 }).then(
				(response) => {
					const counts: Partial<Record<LicenseStatus, number>> = {};
					for (const license of response.items) {
						counts[license.status] = (counts[license.status] ?? 0) + 1;
					}
					return { counts, truncated: response.items.length === 100 };
				},
				() => null
			),
			client.listPolicies(productId).then((r) => r.items.length, () => null),
			Promise.all([
				client.listCatalog('features', productId),
				client.listCatalog('groups', productId),
				client.listCatalog('tiers', productId)
			]).then(
				([features, groups, tiers]) => ({
					version: features.catalog_version,
					counts: {
						features: features.items.length,
						groups: groups.items.length,
						tiers: tiers.items.length
					}
				}),
				() => null
			),
			client.listEpochs(productId).then(
				(response) => {
					const summary = { active: 0, upcoming: 0, expired: 0, revoked: 0 };
					let nextExpiry: number | null = null;
					for (const epoch of response.items) {
						summary[epoch.status] += 1;
						if (epoch.status === 'active' && (nextExpiry === null || epoch.not_after < nextExpiry)) {
							nextExpiry = epoch.not_after;
						}
					}
					return { summary, nextExpiry };
				},
				() => null
			)
		])
			.then(([licenses, policyCount, catalog, epochs]) => {
				if (stale) return;
				data = {
					licenseCounts: licenses?.counts ?? null,
					licensesTruncated: licenses?.truncated ?? false,
					policyCount,
					catalogVersion: catalog?.version ?? null,
					catalogCounts: catalog?.counts ?? null,
					epochSummary: epochs?.summary ?? null,
					nextEpochExpiry: epochs?.nextExpiry ?? null
				};
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
	<div>
		<h1 class="text-2xl font-semibold tracking-tight">Overview</h1>
		<p class="text-sm text-muted-foreground">
			{#if productStore.value}
				产品 <code class="font-mono">{productStore.value}</code> 的概览（数据来自现有 Admin API）。
			{:else}
				请先在顶部选择 product_id。
			{/if}
		</p>
	</div>

	{#if loadError}
		<ErrorAlert error={loadError} />
	{/if}

	{#if productStore.value}
		<div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
			<Card>
				<CardHeader>
					<CardTitle class="text-base">许可</CardTitle>
					<CardDescription>GET /v1/admin/licenses</CardDescription>
				</CardHeader>
				<CardContent>
					{#if loading && !data}
						<p class="text-sm text-muted-foreground">加载中…</p>
					{:else if data?.licenseCounts}
						<div class="flex flex-wrap gap-2">
							{#each LICENSE_STATUSES as status (status)}
								<Badge variant={status === 'active' ? 'default' : status === 'revoked' ? 'destructive' : 'secondary'}>
									{status}: {data.licenseCounts[status] ?? 0}
								</Badge>
							{/each}
						</div>
						{#if data.licensesTruncated}
							<p class="mt-2 text-xs text-muted-foreground">仅统计前 100 条（列表端点上限）。</p>
						{/if}
					{:else}
						<p class="text-sm text-muted-foreground">不可用</p>
					{/if}
				</CardContent>
			</Card>

			<Card>
				<CardHeader>
					<CardTitle class="text-base">策略</CardTitle>
					<CardDescription>GET /v1/admin/policies</CardDescription>
				</CardHeader>
				<CardContent>
					{#if loading && !data}
						<p class="text-sm text-muted-foreground">加载中…</p>
					{:else if data?.policyCount !== null && data?.policyCount !== undefined}
						<p class="text-3xl font-semibold">{data.policyCount}</p>
					{:else}
						<p class="text-sm text-muted-foreground">不可用</p>
					{/if}
				</CardContent>
			</Card>

			<Card>
				<CardHeader>
					<CardTitle class="text-base">权益目录</CardTitle>
					<CardDescription>GET /v1/admin/catalog/*</CardDescription>
				</CardHeader>
				<CardContent>
					{#if loading && !data}
						<p class="text-sm text-muted-foreground">加载中…</p>
					{:else if data?.catalogCounts}
						<p class="text-3xl font-semibold">v{data.catalogVersion}</p>
						<p class="mt-1 text-xs text-muted-foreground">
							{data.catalogCounts.features} features · {data.catalogCounts.groups} groups ·
							{data.catalogCounts.tiers} tiers
						</p>
					{:else}
						<p class="text-sm text-muted-foreground">不可用</p>
					{/if}
				</CardContent>
			</Card>

			<Card>
				<CardHeader>
					<CardTitle class="text-base">签名 Epoch</CardTitle>
					<CardDescription>GET /v1/admin/epochs</CardDescription>
				</CardHeader>
				<CardContent>
					{#if loading && !data}
						<p class="text-sm text-muted-foreground">加载中…</p>
					{:else if data?.epochSummary}
						<div class="flex flex-wrap gap-2">
							<Badge>active: {data.epochSummary.active}</Badge>
							<Badge variant="secondary">upcoming: {data.epochSummary.upcoming}</Badge>
							<Badge variant="secondary">expired: {data.epochSummary.expired}</Badge>
							<Badge variant="destructive">revoked: {data.epochSummary.revoked}</Badge>
						</div>
						{#if data.nextEpochExpiry}
							<p class="mt-2 text-xs text-muted-foreground">
								最近到期：{formatTimestamp(data.nextEpochExpiry)}
							</p>
						{/if}
					{:else}
						<p class="text-sm text-muted-foreground">不可用</p>
					{/if}
				</CardContent>
			</Card>
		</div>

		<div class="grid gap-4 md:grid-cols-3">
			<Card class="border-dashed">
				<CardHeader>
					<CardTitle class="text-base">全局设备视图</CardTitle>
					<CardDescription>按 suspicion 排序的跨许可设备列表</CardDescription>
				</CardHeader>
				<CardContent>
					<Badge variant="outline">M5/M6 后端待落地</Badge>
					<p class="mt-2 text-xs text-muted-foreground">
						现有端点仅支持按许可查设备（GET /licenses/:id/machines），见 Licenses 详情页。
					</p>
				</CardContent>
			</Card>
			<Card class="border-dashed">
				<CardHeader>
					<CardTitle class="text-base">发布与变体</CardTitle>
					<CardDescription>release 注册状态、采纳曲线、完整性失败率</CardDescription>
				</CardHeader>
				<CardContent>
					<Badge variant="outline">M5 后端待落地</Badge>
				</CardContent>
			</Card>
			<Card class="border-dashed">
				<CardHeader>
					<CardTitle class="text-base">分析与审计</CardTitle>
					<CardDescription>激活/留存/席位看板与审计哈希链</CardDescription>
				</CardHeader>
				<CardContent>
					<Badge variant="outline">M6 后端待落地</Badge>
				</CardContent>
			</Card>
		</div>
	{/if}
</div>
