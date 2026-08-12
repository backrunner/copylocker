<script lang="ts">
	import { browser } from '$app/environment';
	import { getClient } from '$lib/api';
	import { isApiError } from '$lib/api/errors';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import type {
		Feature,
		FeatureGroup,
		ResolvedEntitlements,
		Tier
	} from '$lib/api/types';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Select from '$lib/components/ui/select.svelte';
	import Textarea from '$lib/components/ui/textarea.svelte';
	import Badge from '$lib/components/ui/badge.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import Dialog from '$lib/components/ui/dialog.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import GuardrailAlert from '$lib/components/guardrail-alert.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Pencil, Plus } from '@lucide/svelte';

	type EditorKind = 'features' | 'groups' | 'tiers';

	let features = $state<Feature[] | null>(null);
	let groups = $state<FeatureGroup[] | null>(null);
	let tiers = $state<Tier[] | null>(null);
	let catalogVersion = $state<number | null>(null);
	let loadError = $state<unknown>(null);

	// ---- 编辑器状态 ----
	let editorKind = $state<EditorKind>('features');
	let editorOpen = $state(false);
	let editorIsCreate = $state(false);
	let editorId = $state('');
	let editorLabel = $state('');
	let editorDescription = $state('');
	let editorRank = $state('0');
	// group/tier 的成员用逗号分隔输入，保持表单简单；glob（export.*）原样支持。
	let editorGroupIncludes = $state('');
	let editorGroupFeatures = $state('');
	let editorTierGroups = $state('');
	let editorTierFeatures = $state('');
	let editorTierLimits = $state('');
	let saveError = $state<unknown>(null);
	let saving = $state(false);

	// ---- resolve 预览 ----
	let previewTier = $state('');
	let resolved = $state<ResolvedEntitlements | null>(null);
	let resolveError = $state<unknown>(null);
	let resolving = $state(false);

	const guardrailMessage = $derived(
		isApiError(saveError) && saveError.code === 'invalid_catalog' ? saveError.message : null
	);

	// 保存成功后通过自增令牌触发重新加载（effect 依赖该值）。
	let reloadToken = $state(0);
	function load() {
		reloadToken += 1;
	}

	$effect(() => {
		void reloadToken;
		if (!browser) return;
		const productId = productStore.value;
		if (!productId || !tokenStore.authenticated) return;
		loadError = null;
		// teardown 标记：切换产品/重新加载时丢弃迟到的旧响应。
		let stale = false;
		const client = getClient();
		Promise.all([
			client.listCatalog('features', productId),
			client.listCatalog('groups', productId),
			client.listCatalog('tiers', productId)
		])
			.then(([f, g, t]) => {
				if (stale) return;
				features = f.items;
				groups = g.items;
				tiers = t.items;
				catalogVersion = f.catalog_version;
			})
			.catch((error: unknown) => {
				if (!stale) loadError = error;
			});
		return () => {
			stale = true;
		};
	});

	function splitList(value: string): string[] {
		return value
			.split(',')
			.map((item) => item.trim())
			.filter(Boolean);
	}

	function parseLimits(value: string): Record<string, number> | null {
		const limits: Record<string, number> = {};
		for (const entry of splitList(value)) {
			const [key, raw] = entry.split('=').map((part) => part.trim());
			const parsed = Number(raw);
			if (!key || raw === undefined || !Number.isFinite(parsed)) return null;
			limits[key] = parsed;
		}
		return limits;
	}

	function openCreate(kind: EditorKind) {
		editorKind = kind;
		editorIsCreate = true;
		editorId = '';
		editorLabel = '';
		editorDescription = '';
		editorRank = '0';
		editorGroupIncludes = '';
		editorGroupFeatures = '';
		editorTierGroups = '';
		editorTierFeatures = '';
		editorTierLimits = '';
		saveError = null;
		editorOpen = true;
	}

	function openEdit(kind: EditorKind, item: Feature | FeatureGroup | Tier) {
		editorKind = kind;
		editorIsCreate = false;
		editorId = item.id;
		editorLabel = item.label;
		saveError = null;
		if (kind === 'features') {
			editorDescription = (item as Feature).description ?? '';
		} else if (kind === 'groups') {
			const members = (item as FeatureGroup).members;
			editorGroupIncludes = (members.includes ?? []).join(', ');
			editorGroupFeatures = (members.features ?? []).join(', ');
		} else {
			const tier = item as Tier;
			editorRank = String(tier.rank);
			editorTierGroups = (tier.groups ?? []).join(', ');
			editorTierFeatures = (tier.features ?? []).join(', ');
			editorTierLimits = Object.entries(tier.limits ?? {})
				.map(([key, value]) => `${key} = ${value}`)
				.join(', ');
		}
		editorOpen = true;
	}

	async function save() {
		if (saving) return;
		const productId = productStore.value;
		if (!productId) return;
		saving = true;
		saveError = null;
		try {
			const client = getClient();
			if (editorKind === 'features') {
				const body = {
					product_id: productId,
					id: editorId,
					label: editorLabel,
					description: editorDescription || undefined
				};
				if (editorIsCreate) await client.createCatalogItem('features', body);
				else await client.updateCatalogItem('features', body);
			} else if (editorKind === 'groups') {
				const body = {
					product_id: productId,
					id: editorId,
					label: editorLabel,
					members: {
						includes: splitList(editorGroupIncludes),
						features: splitList(editorGroupFeatures)
					}
				};
				if (editorIsCreate) await client.createCatalogItem('groups', body);
				else await client.updateCatalogItem('groups', body);
			} else {
				const limits = parseLimits(editorTierLimits);
				if (limits === null) {
					saveError = new Error('limits 格式应为 `key = 数值`，逗号分隔（-1 表示 unlimited）');
					saving = false;
					return;
				}
				const body = {
					product_id: productId,
					id: editorId,
					label: editorLabel,
					rank: Number(editorRank) || 0,
					groups: splitList(editorTierGroups),
					features: splitList(editorTierFeatures),
					limits
				};
				if (editorIsCreate) await client.createCatalogItem('tiers', body);
				else await client.updateCatalogItem('tiers', body);
			}
			editorOpen = false;
			load();
		} catch (error) {
			saveError = error;
		} finally {
			saving = false;
		}
	}

	$effect(() => {
		// 选中 tier 变化时实时解析。全部输入在顶部读取一次（effect 的依赖集合），
		// teardown 标记丢弃迟到的旧响应 —— 不再读取 resolving，避免完成后重复触发。
		const tier = previewTier;
		const productId = productStore.value;
		if (!tier || !productId) {
			resolved = null;
			resolveError = null;
			resolving = false;
			return;
		}
		let stale = false;
		resolving = true;
		resolveError = null;
		resolved = null;
		getClient()
			.resolveCatalog({ product_id: productId, entitlement: { tier } })
			.then((response) => {
				if (!stale) resolved = response.entitlements;
			})
			.catch((error: unknown) => {
				if (!stale) resolveError = error;
			})
			.finally(() => {
				if (!stale) resolving = false;
			});
		return () => {
			stale = true;
		};
	});
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight">Catalog</h1>
			<p class="text-sm text-muted-foreground">
				权益目录编辑器（ADR-0009）。每次保存生成新的不可变 catalog_version
				{#if catalogVersion !== null}<Badge variant="secondary">当前 v{catalogVersion}</Badge>{/if}
			</p>
		</div>
	</div>

	{#if !productStore.value}
		<Alert title="未选择产品">目录端点要求 product_id，请先在页面顶部选择产品。</Alert>
	{:else if loadError}
		<ErrorAlert error={loadError} />
	{:else}
		<div class="grid gap-4 lg:grid-cols-4">
			<Card>
				<CardHeader class="flex-row items-center justify-between space-y-0">
					<CardTitle class="text-base">Features</CardTitle>
					<Button variant="ghost" size="sm" onclick={() => openCreate('features')}><Plus /> 新建</Button>
				</CardHeader>
				<CardContent class="space-y-2">
					{#each features ?? [] as feature (feature.id)}
						<div class="flex items-center justify-between gap-2 rounded-md border px-3 py-2">
							<div class="min-w-0">
								<p class="truncate font-mono text-xs">{feature.id}</p>
								<p class="truncate text-xs text-muted-foreground">{feature.label}</p>
							</div>
							<Button variant="ghost" size="icon" onclick={() => openEdit('features', feature)} aria-label="编辑 {feature.id}">
								<Pencil />
							</Button>
						</div>
					{:else}
						<p class="text-xs text-muted-foreground">空</p>
					{/each}
				</CardContent>
			</Card>

			<Card>
				<CardHeader class="flex-row items-center justify-between space-y-0">
					<CardTitle class="text-base">Groups</CardTitle>
					<Button variant="ghost" size="sm" onclick={() => openCreate('groups')}><Plus /> 新建</Button>
				</CardHeader>
				<CardContent class="space-y-2">
					{#each groups ?? [] as group (group.id)}
						<div class="flex items-center justify-between gap-2 rounded-md border px-3 py-2">
							<div class="min-w-0">
								<p class="truncate font-mono text-xs">{group.id}</p>
								<p class="truncate text-xs text-muted-foreground">
									{group.label} · features: {(group.members.features ?? []).length} · includes: {(group.members.includes ?? []).length}
								</p>
							</div>
							<Button variant="ghost" size="icon" onclick={() => openEdit('groups', group)} aria-label="编辑 {group.id}">
								<Pencil />
							</Button>
						</div>
					{:else}
						<p class="text-xs text-muted-foreground">空</p>
					{/each}
				</CardContent>
			</Card>

			<Card>
				<CardHeader class="flex-row items-center justify-between space-y-0">
					<CardTitle class="text-base">Tiers</CardTitle>
					<Button variant="ghost" size="sm" onclick={() => openCreate('tiers')}><Plus /> 新建</Button>
				</CardHeader>
				<CardContent class="space-y-2">
					{#each tiers ?? [] as tier (tier.id)}
						<div class="flex items-center justify-between gap-2 rounded-md border px-3 py-2">
							<div class="min-w-0">
								<p class="truncate font-mono text-xs">{tier.id} <Badge variant="outline">rank {tier.rank}</Badge></p>
								<p class="truncate text-xs text-muted-foreground">{tier.label}</p>
							</div>
							<Button variant="ghost" size="icon" onclick={() => openEdit('tiers', tier)} aria-label="编辑 {tier.id}">
								<Pencil />
							</Button>
						</div>
					{:else}
						<p class="text-xs text-muted-foreground">空</p>
					{/each}
				</CardContent>
			</Card>

			<Card>
				<CardHeader>
					<CardTitle class="text-base">实时解析预览</CardTitle>
					<CardDescription>POST /catalog/resolve —— 选中 tier 即时查看扁平化结果</CardDescription>
				</CardHeader>
				<CardContent class="space-y-3">
					<Select bind:value={previewTier} aria-label="选择 tier 预览">
						<option value="">选择 tier…</option>
						{#each tiers ?? [] as tier (tier.id)}
							<option value={tier.id}>{tier.label}（{tier.id}）</option>
						{/each}
					</Select>
					{#if resolveError}
						<ErrorAlert error={resolveError} />
					{:else if resolving}
						<p class="text-xs text-muted-foreground">解析中…</p>
					{:else if resolved}
						<div>
							<p class="mb-1 text-xs font-medium text-muted-foreground">
								features（{resolved.features.length}）
							</p>
							<div class="flex flex-wrap gap-1">
								{#each resolved.features as feature (feature)}
									<Badge variant="secondary" class="font-mono">{feature}</Badge>
								{/each}
							</div>
						</div>
						{#if Object.keys(resolved.limits).length > 0}
							<div>
								<p class="mb-1 text-xs font-medium text-muted-foreground">limits</p>
								<ul class="space-y-0.5 font-mono text-xs">
									{#each Object.entries(resolved.limits) as [key, value] (key)}
										<li>{key} = {value === -1 ? 'unlimited' : value}</li>
									{/each}
								</ul>
							</div>
						{/if}
					{/if}
				</CardContent>
			</Card>
		</div>
	{/if}
</div>

<Dialog
	bind:open={editorOpen}
	title="{editorIsCreate ? '新建' : '编辑'} {editorKind.slice(0, -1)}"
	description={editorKind === 'features' && !editorIsCreate
		? '已发布 feature 的 id 不可变（FeatureKey 派生依赖它），只能修改展示信息或标记 deprecated。'
		: '保存会生成新的 catalog_version 快照；已有凭证在续期时生效。'}
>
	<div class="space-y-4">
		{#if guardrailMessage}
			<GuardrailAlert message={guardrailMessage} />
		{:else if saveError}
			<ErrorAlert error={saveError} />
		{/if}

		<div class="space-y-2">
			<Label for="catalog-id">id</Label>
			<Input
				id="catalog-id"
				bind:value={editorId}
				disabled={!editorIsCreate}
				class="font-mono text-xs"
				data-testid="catalog-id-input"
			/>
			{#if !editorIsCreate}
				<p class="text-xs text-muted-foreground">
					{#if editorKind === 'features'}
						已发布的 feature_id 不可重命名：FeatureKey 由它派生，重命名会让所有按旧 id
						封存的资产永久无法解封，且已有签发凭证引用它；服务端以 422 invalid_catalog 拒绝。
					{:else}
						id 发布后不可重命名 —— 服务端会以 422 invalid_catalog 拒绝此类变更。
					{/if}
				</p>
			{/if}
		</div>
		<div class="space-y-2">
			<Label for="catalog-label">label</Label>
			<Input id="catalog-label" bind:value={editorLabel} />
		</div>

		{#if editorKind === 'features'}
			<div class="space-y-2">
				<Label for="catalog-description">description（可选）</Label>
				<Textarea id="catalog-description" bind:value={editorDescription} />
			</div>
		{:else if editorKind === 'groups'}
			<div class="space-y-2">
				<Label for="catalog-includes">includes（嵌套 group id，逗号分隔）</Label>
				<Input id="catalog-includes" bind:value={editorGroupIncludes} class="font-mono text-xs" />
			</div>
			<div class="space-y-2">
				<Label for="catalog-features">features（feature id 或 glob，如 export.*）</Label>
				<Input id="catalog-features" bind:value={editorGroupFeatures} class="font-mono text-xs" />
			</div>
		{:else}
			<div class="space-y-2">
				<Label for="catalog-rank">rank</Label>
				<Input id="catalog-rank" type="number" bind:value={editorRank} class="w-28" />
			</div>
			<div class="space-y-2">
				<Label for="catalog-tier-groups">groups（逗号分隔）</Label>
				<Input id="catalog-tier-groups" bind:value={editorTierGroups} class="font-mono text-xs" />
			</div>
			<div class="space-y-2">
				<Label for="catalog-tier-features">features（逗号分隔）</Label>
				<Input id="catalog-tier-features" bind:value={editorTierFeatures} class="font-mono text-xs" />
			</div>
			<div class="space-y-2">
				<Label for="catalog-tier-limits">limits（`key = 数值`，逗号分隔；-1 = unlimited）</Label>
				<Input id="catalog-tier-limits" bind:value={editorTierLimits} class="font-mono text-xs" />
			</div>
		{/if}
	</div>

	{#snippet footer()}
		<Button variant="outline" onclick={() => (editorOpen = false)}>取消</Button>
		<Button disabled={saving || !editorId || !editorLabel} onclick={save} data-testid="catalog-save">
			{saving ? '保存中…' : '保存'}
		</Button>
	{/snippet}
</Dialog>
