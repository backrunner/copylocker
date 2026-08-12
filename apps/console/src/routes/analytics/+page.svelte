<script lang="ts">
	import { browser } from '$app/environment';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import type {
		AnalyticsGroupBy,
		AnalyticsMetricDefinition,
		AnalyticsMetricsResponse
	} from '$lib/api/types';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Select from '$lib/components/ui/select.svelte';
	import Checkbox from '$lib/components/ui/checkbox.svelte';
	import Badge from '$lib/components/ui/badge.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';

	let definitions = $state<AnalyticsMetricDefinition[] | null>(null);
	let definitionsError = $state<unknown>(null);
	let selected = $state<Set<string>>(new Set());
	let from = $state('');
	let to = $state('');
	let granularity = $state<'day' | 'week' | 'month'>('day');
	let groupBy = $state<'' | AnalyticsGroupBy>('');
	let source = $state<'auto' | 'exact' | 'hll'>('auto');
	let report = $state<AnalyticsMetricsResponse | null>(null);
	let queryError = $state<unknown>(null);
	let querying = $state(false);

	function defaultWindow() {
		const end = new Date();
		const start = new Date(end.getTime() - 29 * 86_400_000);
		from = start.toISOString().slice(0, 10);
		to = end.toISOString().slice(0, 10);
	}

	$effect(() => {
		if (!browser || !tokenStore.authenticated) return;
		if (!from || !to) {
			// 设置默认窗口会重新触发本 effect；直接返回，避免重复拉取指标目录。
			defaultWindow();
			return;
		}
		getClient()
			.analyticsDefinitions()
			.then((items) => (definitions = items))
			.catch((error: unknown) => (definitionsError = error));
	});

	function toggle(id: string, checked: boolean) {
		const next = new Set(selected);
		if (checked) next.add(id);
		else next.delete(id);
		selected = next;
	}

	const trusted = $derived((definitions ?? []).filter((definition) => definition.trusted));
	const untrusted = $derived((definitions ?? []).filter((definition) => !definition.trusted));
	const canQuery = $derived(Boolean(productStore.value && selected.size > 0 && from && to));

	async function runQuery() {
		if (!canQuery || querying) return;
		querying = true;
		queryError = null;
		try {
			report = await getClient().analyticsMetrics({
				product: productStore.value,
				ids: [...selected].sort(),
				from,
				to,
				granularity,
				...(groupBy ? { groupBy } : {}),
				source
			});
		} catch (error) {
			queryError = error;
			report = null;
		} finally {
			querying = false;
		}
	}

	function dimsLabel(dims: Record<string, unknown>): string {
		const entries = Object.entries(dims);
		return entries.length === 0
			? '—'
			: entries.map(([key, value]) => `${key}=${String(value)}`).join(' ');
	}
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-semibold tracking-tight">Analytics</h1>
		<p class="text-sm text-muted-foreground">
			指标查询（GET /v1/admin/analytics/metrics）。T0 为签名计量（可信），T1
			为设备自报（不可信），两组指标分列展示。
		</p>
	</div>

	{#if definitionsError}
		<ErrorAlert error={definitionsError} />
	{:else if !definitions}
		<p class="text-sm text-muted-foreground">加载指标目录…</p>
	{:else}
		<Card>
			<CardHeader>
				<CardTitle class="text-base">查询条件</CardTitle>
				<CardDescription>最多 8 个指标；窗口 ≤ 366 天。</CardDescription>
			</CardHeader>
			<CardContent class="space-y-4">
				<div class="grid gap-4 md:grid-cols-2">
					<div class="space-y-2">
						<p class="text-sm font-medium">T0 · 签名计量（trusted）</p>
						{#each trusted as definition (definition.id)}
							<label class="flex items-start gap-2 text-sm">
								<Checkbox
									checked={selected.has(definition.id)}
									onchange={(event) => toggle(definition.id, event.currentTarget.checked)}
								/>
								<span>
									<code class="font-mono text-xs">{definition.id}</code> — {definition.name}
								</span>
							</label>
						{/each}
					</div>
					<div class="space-y-2">
						<p class="text-sm font-medium">T1 · 设备自报（untrusted）</p>
						{#each untrusted as definition (definition.id)}
							<label class="flex items-start gap-2 text-sm">
								<Checkbox
									checked={selected.has(definition.id)}
									onchange={(event) => toggle(definition.id, event.currentTarget.checked)}
								/>
								<span>
									<code class="font-mono text-xs">{definition.id}</code> — {definition.name}
								</span>
							</label>
						{/each}
					</div>
				</div>

				<div class="flex flex-wrap items-end gap-4">
					<div class="space-y-1">
						<Label for="from-date">从</Label>
						<Input id="from-date" type="date" bind:value={from} />
					</div>
					<div class="space-y-1">
						<Label for="to-date">到</Label>
						<Input id="to-date" type="date" bind:value={to} />
					</div>
					<div class="space-y-1">
						<Label for="granularity">粒度</Label>
						<Select id="granularity" bind:value={granularity}>
							<option value="day">day</option>
							<option value="week">week</option>
							<option value="month">month</option>
						</Select>
					</div>
					<div class="space-y-1">
						<Label for="group-by">group_by</Label>
						<Select id="group-by" bind:value={groupBy}>
							<option value="">（无）</option>
							{#each ['app_version', 'os_arch', 'country', 'activation_path', 'mode', 'release_id', 'policy_id', 'sdk_version'] as cube (cube)}
								<option value={cube}>{cube}</option>
							{/each}
						</Select>
					</div>
					<div class="space-y-1">
						<Label for="source">source</Label>
						<Select id="source" bind:value={source}>
							<option value="auto">auto</option>
							<option value="exact">exact</option>
							<option value="hll">hll</option>
						</Select>
					</div>
					<Button disabled={!canQuery || querying} onclick={() => void runQuery()}>
						{querying ? '查询中…' : '运行查询'}
					</Button>
				</div>
				{#if !productStore.value}
					<Alert title="未选择产品">查询要求 product_id，请先在页面顶部选择产品。</Alert>
				{/if}
			</CardContent>
		</Card>
	{/if}

	{#if queryError}
		<ErrorAlert error={queryError} />
	{/if}

	{#if report}
		<Card>
			<CardHeader>
				<CardTitle class="text-base">结果元信息</CardTitle>
				<CardDescription>
					{report.product_id} · {report.from} → {report.to} · {report.granularity}
				</CardDescription>
			</CardHeader>
			<CardContent class="space-y-3">
				<div class="flex flex-wrap items-center gap-3 text-sm">
					<span>
						source：
						<Badge variant={report.meta.source === 'exact' ? 'default' : 'secondary'}>
							{report.meta.source}
						</Badge>
					</span>
					<span>error_pct：{report.meta.error_pct}%</span>
					<span>
						suppressed_buckets：
						{#if report.meta.suppressed_buckets > 0}
							<Badge variant="outline">{report.meta.suppressed_buckets}（k-匿名抑制）</Badge>
						{:else}
							0
						{/if}
					</span>
				</div>
				{#if report.meta.warning}
					<Alert variant="warning" title="分辨率警告">{report.meta.warning}</Alert>
				{/if}
			</CardContent>
		</Card>

		{#each report.series as series (series.metric_id)}
			<Card>
				<CardHeader>
					<CardTitle class="text-base">
						<code class="font-mono text-sm">{series.metric_id}</code>
					</CardTitle>
				</CardHeader>
				<CardContent>
					<div class="rounded-md border">
						<table class="w-full text-sm">
							<thead>
								<tr class="border-b bg-muted/50 text-left text-xs text-muted-foreground">
									<th class="px-3 py-2 font-medium">bucket</th>
									<th class="px-3 py-2 font-medium">dims</th>
									<th class="px-3 py-2 text-right font-medium">value</th>
								</tr>
							</thead>
							<tbody>
								{#each series.points as point (point.bucket + dimsLabel(point.dims))}
									<tr class="border-b last:border-0">
										<td class="px-3 py-2 font-mono text-xs">{point.bucket}</td>
										<td class="px-3 py-2 font-mono text-xs">{dimsLabel(point.dims)}</td>
										<td class="px-3 py-2 text-right">{point.value}</td>
									</tr>
								{:else}
									<tr>
										<td colspan="3" class="px-3 py-6 text-center text-muted-foreground">
											窗口内没有数据。
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				</CardContent>
			</Card>
		{/each}
	{/if}
</div>
