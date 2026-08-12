<script lang="ts">
	import { browser } from '$app/environment';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import type { ReleaseRecord } from '$lib/api/types';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Badge from '$lib/components/ui/badge.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import ReleaseActionDialog from '$lib/components/release-action-dialog.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { formatTimestamp } from '$lib/utils';
	import { Plus, Rocket } from '@lucide/svelte';

	const STATUS_VARIANTS: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
		active: 'default',
		deprecated: 'secondary',
		compromised: 'destructive'
	};

	let items = $state<ReleaseRecord[] | null>(null);
	let loadError = $state<unknown>(null);
	let loading = $state(false);

	let appVersion = $state('');
	let buildFingerprint = $state('');
	let channel = $state('stable');
	let manifestRootHex = $state('');
	let moduleDigestHex = $state('');
	let variantSeedHex = $state('');
	let registering = $state(false);
	let registerError = $state<unknown>(null);
	let registerMessage = $state<string | null>(null);

	let actionDialog = $state<{ action: 'deprecate' | 'compromised'; release: ReleaseRecord } | null>(
		null
	);
	let actionOpen = $state(false);

	// 注册/操作成功后通过自增令牌触发重新加载（effect 依赖该值）。
	let reloadToken = $state(0);

	function load() {
		reloadToken += 1;
	}

	$effect(() => {
		void reloadToken;
		if (!browser) return;
		const productId = productStore.value;
		if (!productId || !tokenStore.authenticated) {
			items = null;
			loading = false;
			return;
		}
		loading = true;
		loadError = null;
		// teardown 标记：切换产品/重新加载时丢弃迟到的旧响应。
		let stale = false;
		getClient()
			.listReleases(productId)
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

	function randomSeed() {
		variantSeedHex = Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) =>
			byte.toString(16).padStart(2, '0')
		).join('');
	}

	const HEX64 = /^[0-9a-f]{64}$/i;
	const canRegister = $derived(
		Boolean(
			productStore.value &&
				appVersion.trim() &&
				buildFingerprint.trim() &&
				channel.trim() &&
				(!manifestRootHex.trim() || HEX64.test(manifestRootHex.trim())) &&
				(!moduleDigestHex.trim() || HEX64.test(moduleDigestHex.trim())) &&
				(!variantSeedHex.trim() || HEX64.test(variantSeedHex.trim()))
		)
	);

	async function register() {
		if (!canRegister || registering) return;
		registering = true;
		registerError = null;
		registerMessage = null;
		try {
			const response = await getClient().registerRelease({
				product_id: productStore.value,
				app_version: appVersion.trim(),
				build_fingerprint: buildFingerprint.trim(),
				channel: channel.trim(),
				...(manifestRootHex.trim() ? { manifest_root_hex: manifestRootHex.trim() } : {}),
				...(moduleDigestHex.trim() ? { module_digest_hex: moduleDigestHex.trim() } : {}),
				...(variantSeedHex.trim() ? { variant_seed_hex: variantSeedHex.trim() } : {})
			});
			registerMessage = response.already_registered
				? `release ${response.release.id} 已注册过（幂等重放）。`
				: `release ${response.release.id} 注册成功（variant ${response.release.variant_id}）。`;
			appVersion = '';
			buildFingerprint = '';
			manifestRootHex = '';
			moduleDigestHex = '';
			variantSeedHex = '';
			load();
		} catch (error) {
			registerError = error;
		} finally {
			registering = false;
		}
	}

	function openAction(action: 'deprecate' | 'compromised', release: ReleaseRecord) {
		actionDialog = { action, release };
		actionOpen = true;
	}
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-semibold tracking-tight">Releases</h1>
		<p class="text-sm text-muted-foreground">
			发布注册与版本级吊销（deprecate / mark-compromised，dry-run + 两步确认，与 CLI
			<code class="font-mono text-xs">release</code> 行为一致）。
		</p>
	</div>

	{#if !productStore.value}
		<Alert title="未选择产品">列表与注册端点要求 product_id，请先在页面顶部选择产品。</Alert>
	{:else}
		<Card>
			<CardHeader>
				<CardTitle class="text-base">注册新 release</CardTitle>
				<CardDescription>
					POST /v1/admin/releases；variant_seed 只在服务端派生 variant params，绝不回显。
				</CardDescription>
			</CardHeader>
			<CardContent>
				<form
					class="grid gap-4 md:grid-cols-3"
					onsubmit={(event) => {
						event.preventDefault();
						void register();
					}}
				>
					<div class="space-y-1">
						<Label for="app-version">app_version *</Label>
						<Input id="app-version" bind:value={appVersion} placeholder="3.2.0" />
					</div>
					<div class="space-y-1">
						<Label for="build-fingerprint">build_fingerprint *</Label>
						<Input id="build-fingerprint" bind:value={buildFingerprint} placeholder="ci-2026-08" />
					</div>
					<div class="space-y-1">
						<Label for="channel">channel *</Label>
						<Input id="channel" bind:value={channel} placeholder="stable" />
					</div>
					<div class="space-y-1">
						<Label for="manifest-root">manifest_root_hex（可选，64 hex）</Label>
						<Input
							id="manifest-root"
							bind:value={manifestRootHex}
							class="font-mono text-xs"
							spellcheck="false"
						/>
					</div>
					<div class="space-y-1">
						<Label for="module-digest">module_digest_hex（可选，64 hex）</Label>
						<Input
							id="module-digest"
							bind:value={moduleDigestHex}
							class="font-mono text-xs"
							spellcheck="false"
						/>
					</div>
					<div class="space-y-1">
						<Label for="variant-seed">variant_seed_hex（可选，64 hex）</Label>
						<div class="flex gap-2">
							<Input
								id="variant-seed"
								bind:value={variantSeedHex}
								class="font-mono text-xs"
								spellcheck="false"
							/>
							<Button type="button" variant="outline" onclick={randomSeed}>随机</Button>
						</div>
					</div>
					<div class="flex items-end gap-3 md:col-span-3">
						<Button type="submit" disabled={!canRegister || registering}>
							<Plus /> {registering ? '注册中…' : '注册 release'}
						</Button>
						{#if registerMessage}
							<p class="text-sm text-muted-foreground">{registerMessage}</p>
						{/if}
					</div>
					{#if registerError}
						<div class="md:col-span-3"><ErrorAlert error={registerError} /></div>
					{/if}
				</form>
			</CardContent>
		</Card>

		{#if loadError}
			<ErrorAlert error={loadError} />
		{:else if loading && !items}
			<p class="text-sm text-muted-foreground">加载中…</p>
		{:else if items}
			<div class="rounded-md border">
				<table class="w-full text-sm">
					<thead>
						<tr class="border-b bg-muted/50 text-left text-xs text-muted-foreground">
							<th class="px-3 py-2 font-medium">Release</th>
							<th class="px-3 py-2 font-medium">app_version</th>
							<th class="px-3 py-2 font-medium">variant</th>
							<th class="px-3 py-2 font-medium">channel</th>
							<th class="px-3 py-2 font-medium">状态</th>
							<th class="px-3 py-2 font-medium">发布时间</th>
							<th class="px-3 py-2 font-medium"></th>
						</tr>
					</thead>
					<tbody>
						{#each items as release (release.id)}
							<tr class="border-b last:border-0 hover:bg-muted/30">
								<td class="px-3 py-2 font-mono text-xs">{release.id}</td>
								<td class="px-3 py-2 text-xs">{release.app_version}</td>
								<td class="px-3 py-2 text-xs">{release.variant_id}</td>
								<td class="px-3 py-2 text-xs">{release.channel}</td>
								<td class="px-3 py-2">
									<Badge variant={STATUS_VARIANTS[release.status] ?? 'outline'}>
										{release.status}{release.compromised_action
											? ` · ${release.compromised_action}`
											: ''}
									</Badge>
								</td>
								<td class="px-3 py-2 text-xs">{formatTimestamp(release.published_at)}</td>
								<td class="px-3 py-2">
									{#if release.status === 'active'}
										<div class="flex gap-1">
											<Button
												variant="ghost"
												size="sm"
												onclick={() => openAction('deprecate', release)}
											>
												弃用…
											</Button>
											<Button
												variant="ghost"
												size="sm"
												class="text-destructive"
												onclick={() => openAction('compromised', release)}
											>
												标记 compromised…
											</Button>
										</div>
									{/if}
								</td>
							</tr>
						{:else}
							<tr>
								<td colspan="7" class="px-3 py-8 text-center text-muted-foreground">
									<Rocket class="mx-auto mb-2 size-5" />
									该产品还没有注册 release。
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	{/if}
</div>

{#if actionDialog && productStore.value}
	<ReleaseActionDialog
		bind:open={actionOpen}
		action={actionDialog.action}
		release={actionDialog.release}
		productId={productStore.value}
		onDone={() => load()}
	/>
{/if}
