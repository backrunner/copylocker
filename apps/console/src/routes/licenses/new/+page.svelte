<script lang="ts">
	import { browser } from '$app/environment';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import type { IssueLicenseResponse, Policy } from '$lib/api/types';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Select from '$lib/components/ui/select.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Download } from '@lucide/svelte';

	let policies = $state<Policy[] | null>(null);
	let policyId = $state('');
	let count = $state('1');
	let accountId = $state('');
	let seatsOverride = $state('');
	let expiresAt = $state('');
	let issuing = $state(false);
	let issueError = $state<unknown>(null);

	// 明文 Key 仅此一次可见；下载 CSV 或离开页面前保持在内存中，之后清除。
	let issued = $state<IssueLicenseResponse | null>(null);
	let downloaded = $state(false);

	$effect(() => {
		if (!browser) return;
		const productId = productStore.value;
		if (!productId || !tokenStore.authenticated) return;
		getClient()
			.listPolicies(productId)
			.then((response) => {
				policies = response.items;
				if (!policyId && response.items.length > 0) policyId = response.items[0].id;
			})
			.catch(() => (policies = []));
	});

	const canSubmit = $derived(
		Boolean(productStore.value && policyId) &&
			Number(count) >= 1 &&
			Number(count) <= 100 &&
			!issuing
	);

	async function submit() {
		if (!canSubmit) return;
		issuing = true;
		issueError = null;
		issued = null;
		downloaded = false;
		try {
			const expires = expiresAt ? Math.floor(new Date(expiresAt).getTime() / 1000) : undefined;
			issued = await getClient().issueLicenses({
				product_id: productStore.value,
				policy_id: policyId,
				count: Number(count),
				account_id: accountId || undefined,
				seats_override: seatsOverride ? Number(seatsOverride) : undefined,
				expires_at: expires
			});
		} catch (error) {
			issueError = error;
		} finally {
			issuing = false;
		}
	}

	function downloadCsv() {
		if (!issued) return;
		const rows = ['license_id,license_key'];
		for (const license of issued.licenses) {
			rows.push(`${license.license_id},${license.license_key}`);
		}
		const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
		const url = URL.createObjectURL(blob);
		const anchor = document.createElement('a');
		anchor.href = url;
		anchor.download = `copylocker-licenses-${issued.product_id}-${Date.now()}.csv`;
		anchor.click();
		URL.revokeObjectURL(url);
		downloaded = true;
	}

	function clearIssued() {
		// 从内存清除明文 key。
		issued = null;
		downloaded = false;
	}
</script>

<div class="mx-auto max-w-2xl space-y-6">
	<div>
		<h1 class="text-2xl font-semibold tracking-tight">签发许可</h1>
		<p class="text-sm text-muted-foreground">
			POST /v1/admin/licenses · 批量上限 100 · 明文 Key 仅在本响应中出现一次。
		</p>
	</div>

	{#if issued}
		<Card>
			<CardHeader>
				<CardTitle class="text-base">已签发 {issued.count} 个许可</CardTitle>
				<CardDescription>
					明文 License Key 只显示这一次。请先下载 CSV，然后清除。
				</CardDescription>
			</CardHeader>
			<CardContent class="space-y-4">
				<div class="max-h-72 overflow-y-auto rounded-md border">
					<table class="w-full text-sm">
						<thead>
							<tr class="border-b bg-muted/50 text-left text-xs text-muted-foreground">
								<th class="px-3 py-2 font-medium">License ID</th>
								<th class="px-3 py-2 font-medium">License Key（明文，仅此一次）</th>
							</tr>
						</thead>
						<tbody>
							{#each issued.licenses as license (license.license_id)}
								<tr class="border-b last:border-0">
									<td class="px-3 py-2 font-mono text-xs">{license.license_id}</td>
									<td class="px-3 py-2 font-mono text-xs">{license.license_key}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
				<div class="flex gap-2">
					<Button onclick={downloadCsv}>
						<Download /> 下载 CSV
					</Button>
					<Button variant="outline" disabled={!downloaded} onclick={clearIssued}>
						已保存，从内存清除
					</Button>
				</div>
				{#if !downloaded}
					<Alert variant="warning" title="尚未下载">
						清除后将无法再次查看这些明文 Key。
					</Alert>
				{/if}
			</CardContent>
		</Card>
	{:else}
		<Card>
			<CardContent class="space-y-4 pt-6">
				{#if issueError}
					<ErrorAlert error={issueError} />
				{/if}
				<div class="space-y-2">
					<Label for="issue-product">产品</Label>
					<Input id="issue-product" value={productStore.value} disabled class="font-mono text-xs" />
					{#if !productStore.value}
						<p class="text-xs text-destructive">请先在页面顶部选择 product_id。</p>
					{/if}
				</div>
				<div class="space-y-2">
					<Label for="issue-policy">策略</Label>
					{#if policies && policies.length > 0}
						<Select id="issue-policy" bind:value={policyId}>
							{#each policies as policy (policy.id)}
								<option value={policy.id}>{policy.name}（{policy.id}）</option>
							{/each}
						</Select>
					{:else}
						<Input
							id="issue-policy"
							bind:value={policyId}
							placeholder="policy_id"
							class="font-mono text-xs"
						/>
						{#if policies && policies.length === 0}
							<p class="text-xs text-muted-foreground">
								该产品下没有策略；可先到 Policies 页创建，或直接输入 policy_id。
							</p>
						{/if}
					{/if}
				</div>
				<div class="grid grid-cols-2 gap-4">
					<div class="space-y-2">
						<Label for="issue-count">数量（1–100）</Label>
						<Input id="issue-count" type="number" min="1" max="100" bind:value={count} />
					</div>
					<div class="space-y-2">
						<Label for="issue-seats">席位覆盖（可选）</Label>
						<Input id="issue-seats" type="number" min="1" max="100000" bind:value={seatsOverride} placeholder="沿用策略" />
					</div>
				</div>
				<div class="grid grid-cols-2 gap-4">
					<div class="space-y-2">
						<Label for="issue-account">账户 ID（可选）</Label>
						<Input id="issue-account" bind:value={accountId} class="font-mono text-xs" />
					</div>
					<div class="space-y-2">
						<Label for="issue-expires">到期时间（可选）</Label>
						<Input id="issue-expires" type="datetime-local" bind:value={expiresAt} />
					</div>
				</div>
				<Button type="submit" disabled={!canSubmit} onclick={submit} class="w-full">
					{issuing ? '正在签发…' : '签发'}
				</Button>
			</CardContent>
		</Card>
	{/if}
</div>
