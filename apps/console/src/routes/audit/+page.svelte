<script lang="ts">
	import { browser } from '$app/environment';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import type { AdminAuditEventSummary, VerifyAdminAuditResponse } from '$lib/api/types';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Badge from '$lib/components/ui/badge.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { formatTimestamp } from '$lib/utils';
	import { ShieldCheck, ShieldAlert } from '@lucide/svelte';

	let items = $state<AdminAuditEventSummary[]>([]);
	let nextCursor = $state<string | null>(null);
	let loadError = $state<unknown>(null);
	let loading = $state(false);
	let target = $state('');
	let kind = $state('');
	let initialized = $state(false);

	let verifying = $state(false);
	let verifyError = $state<unknown>(null);
	let verifyResult = $state<VerifyAdminAuditResponse | null>(null);

	function load(cursor?: string) {
		if (!browser || !tokenStore.authenticated) return;
		loading = true;
		loadError = null;
		getClient()
			.listAuditEvents({
				...(target.trim() ? { target: target.trim() } : {}),
				...(kind.trim() ? { kind: kind.trim() } : {}),
				limit: 50,
				...(cursor ? { cursor } : {})
			})
			.then((response) => {
				items = cursor ? [...items, ...response.items] : response.items;
				nextCursor = response.next_cursor;
			})
			.catch((error: unknown) => (loadError = error))
			.finally(() => (loading = false));
	}

	$effect(() => {
		if (!initialized && browser && tokenStore.authenticated) {
			initialized = true;
			load();
		}
	});

	function applyFilters() {
		items = [];
		nextCursor = null;
		load();
	}

	async function verify() {
		if (verifying) return;
		verifying = true;
		verifyError = null;
		try {
			verifyResult = await getClient().verifyAuditChain();
		} catch (error) {
			verifyError = error;
			verifyResult = null;
		} finally {
			verifying = false;
		}
	}
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight">Audit</h1>
			<p class="text-sm text-muted-foreground">
				Admin 审计链（admin_audit_events 投影，按 vendor 隔离；GET /v1/admin/audit）。
			</p>
		</div>
		<Button variant="outline" disabled={verifying} onclick={() => void verify()}>
			{#if verifyResult?.verified}<ShieldCheck />{:else}<ShieldAlert />{/if}
			{verifying ? '验证中…' : '验证链完整性'}
		</Button>
	</div>

	{#if verifyError}
		<ErrorAlert error={verifyError} />
	{/if}
	{#if verifyResult}
		<Card>
			<CardHeader>
				<CardTitle class="flex items-center gap-2 text-base">
					链验证结果
					<Badge variant={verifyResult.verified ? 'default' : 'destructive'}>
						{verifyResult.verified ? 'verified' : 'broken'}
					</Badge>
				</CardTitle>
				<CardDescription>
					POST /v1/admin/audit/verify（只读，重算每个事件的哈希并检查 prev_hash 链接）
				</CardDescription>
			</CardHeader>
			<CardContent>
				<dl class="grid grid-cols-1 gap-x-8 gap-y-2 text-sm md:grid-cols-2">
					<div class="flex justify-between gap-4">
						<dt class="text-muted-foreground">事件数</dt>
						<dd>{verifyResult.event_count}</dd>
					</div>
					<div class="flex justify-between gap-4">
						<dt class="text-muted-foreground">seq 范围</dt>
						<dd>
							{verifyResult.first_seq ?? '—'} → {verifyResult.last_seq ?? '—'}
						</dd>
					</div>
					<div class="flex justify-between gap-4">
						<dt class="text-muted-foreground">链头</dt>
						<dd class="font-mono text-xs">
							{#if verifyResult.head}
								#{verifyResult.head.seq} · {verifyResult.head.hash.slice(0, 16)}…
							{:else}
								—
							{/if}
						</dd>
					</div>
					{#if verifyResult.first_broken}
						<div class="flex justify-between gap-4">
							<dt class="text-muted-foreground">首个断链</dt>
							<dd class="font-mono text-xs text-destructive">
								seq {verifyResult.first_broken.seq}（{verifyResult.first_broken.reason}）
							</dd>
						</div>
					{/if}
				</dl>
			</CardContent>
		</Card>
	{/if}

	<div class="flex flex-wrap items-end gap-4">
		<div class="space-y-1">
			<Label for="target-filter">target（精确匹配）</Label>
			<Input
				id="target-filter"
				bind:value={target}
				placeholder="16 字节 hex id"
				class="w-72 font-mono text-xs"
				spellcheck="false"
			/>
		</div>
		<div class="space-y-1">
			<Label for="kind-filter">source_kind</Label>
			<Input
				id="kind-filter"
				bind:value={kind}
				placeholder="revocation / dsr / catalog…"
				class="w-56 font-mono text-xs"
				spellcheck="false"
			/>
		</div>
		<Button variant="outline" onclick={applyFilters}>应用筛选</Button>
	</div>

	{#if loadError}
		<ErrorAlert error={loadError} />
	{:else}
		<div class="rounded-md border">
			<table class="w-full text-sm">
				<thead>
					<tr class="border-b bg-muted/50 text-left text-xs text-muted-foreground">
						<th class="px-3 py-2 font-medium">seq</th>
						<th class="px-3 py-2 font-medium">时间</th>
						<th class="px-3 py-2 font-medium">actor</th>
						<th class="px-3 py-2 font-medium">action</th>
						<th class="px-3 py-2 font-medium">target</th>
						<th class="px-3 py-2 font-medium">kind</th>
						<th class="px-3 py-2 font-medium">request_id</th>
					</tr>
				</thead>
				<tbody>
					{#each items as event (event.seq)}
						<tr class="border-b last:border-0 hover:bg-muted/30">
							<td class="px-3 py-2 font-mono text-xs">{event.seq}</td>
							<td class="px-3 py-2 text-xs">{formatTimestamp(event.occurred_at)}</td>
							<td class="px-3 py-2 text-xs">{event.actor}</td>
							<td class="px-3 py-2 font-mono text-xs">{event.action}</td>
							<td class="px-3 py-2 font-mono text-xs">{event.target}</td>
							<td class="px-3 py-2"><Badge variant="outline">{event.source_kind}</Badge></td>
							<td class="px-3 py-2 font-mono text-xs">{event.request_id}</td>
						</tr>
					{:else}
						<tr>
							<td colspan="7" class="px-3 py-8 text-center text-muted-foreground">
								{loading ? '加载中…' : '没有匹配的审计事件。'}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		{#if nextCursor}
			<div>
				<Button variant="outline" disabled={loading} onclick={() => load(nextCursor ?? undefined)}>
					{loading ? '加载中…' : '加载更多'}
				</Button>
			</div>
		{/if}
	{/if}
</div>
