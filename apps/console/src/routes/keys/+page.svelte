<script lang="ts">
	import { browser } from '$app/environment';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import type { EpochView } from '$lib/api/types';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Textarea from '$lib/components/ui/textarea.svelte';
	import Badge from '$lib/components/ui/badge.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import Dialog from '$lib/components/ui/dialog.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import EpochRevokeDialog from '$lib/components/epoch-revoke-dialog.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { formatTimestamp } from '$lib/utils';

	let items = $state<EpochView[] | null>(null);
	let loadError = $state<unknown>(null);
	let loading = $state(false);

	let revokeTarget = $state<EpochView | null>(null);
	let revokeOpen = $state(false);

	let uploadOpen = $state(false);
	let certificateHex = $state('');
	let rootVkHex = $state('');
	let uploadError = $state<unknown>(null);
	let uploading = $state(false);

	const STATUS_VARIANTS: Record<EpochView['status'], 'default' | 'secondary' | 'destructive' | 'outline'> =
		{
			active: 'default',
			upcoming: 'secondary',
			expired: 'outline',
			revoked: 'destructive'
		};

	// 上传/吊销成功后通过自增令牌触发重新加载（effect 依赖该值）。
	let reloadToken = $state(0);

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
			.listEpochs(productId)
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

	function load() {
		reloadToken += 1;
	}

	async function upload() {
		if (uploading) return;
		uploading = true;
		uploadError = null;
		try {
			await getClient().uploadEpoch({
				certificate_hex: certificateHex.trim(),
				root_verifying_key_hex: rootVkHex.trim()
			});
			uploadOpen = false;
			certificateHex = '';
			rootVkHex = '';
			load();
		} catch (error) {
			uploadError = error;
		} finally {
			uploading = false;
		}
	}
</script>

<div class="space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight">Keys</h1>
			<p class="text-sm text-muted-foreground">
				签名 Epoch 列表与轮换状态。吊销需要 dry-run + 2 位不同 actor 在 15 分钟内批准。
			</p>
		</div>
		<Button variant="outline" onclick={() => (uploadOpen = true)}>上传 Epoch 证书…</Button>
	</div>

	{#if !productStore.value}
		<Alert title="未选择产品">Epoch 端点要求 product_id，请先在页面顶部选择产品。</Alert>
	{:else if loadError}
		<ErrorAlert error={loadError} />
	{:else if loading && !items}
		<p class="text-sm text-muted-foreground">加载中…</p>
	{:else if items}
		<div class="rounded-md border">
			<table class="w-full text-sm">
				<thead>
					<tr class="border-b bg-muted/50 text-left text-xs text-muted-foreground">
						<th class="px-3 py-2 font-medium">Epoch ID</th>
						<th class="px-3 py-2 font-medium">状态</th>
						<th class="px-3 py-2 font-medium">生效区间</th>
						<th class="px-3 py-2 font-medium">受影响设备上界</th>
						<th class="px-3 py-2 font-medium">创建时间</th>
						<th class="px-3 py-2 font-medium"></th>
					</tr>
				</thead>
				<tbody>
					{#each items as epoch (epoch.epoch_id)}
						<tr class="border-b last:border-0">
							<td class="px-3 py-2 font-mono text-xs">{epoch.epoch_id}</td>
							<td class="px-3 py-2">
								<Badge variant={STATUS_VARIANTS[epoch.status]}>{epoch.status}</Badge>
							</td>
							<td class="px-3 py-2 text-xs">
								{formatTimestamp(epoch.not_before)} → {formatTimestamp(epoch.not_after)}
							</td>
							<td class="px-3 py-2">{epoch.affected_machines_upper_bound}</td>
							<td class="px-3 py-2 text-xs">{formatTimestamp(epoch.created_at)}</td>
							<td class="px-3 py-2 text-right">
								{#if epoch.status !== 'revoked'}
									<Button
										variant="ghost"
										size="sm"
										class="text-destructive"
										onclick={() => {
											revokeTarget = epoch;
											revokeOpen = true;
										}}
									>
										吊销…
									</Button>
								{/if}
							</td>
						</tr>
					{:else}
						<tr>
							<td colspan="6" class="px-3 py-8 text-center text-muted-foreground">
								该产品下还没有 Epoch。
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>

{#if revokeTarget}
	<EpochRevokeDialog bind:open={revokeOpen} epoch={revokeTarget} onRevoked={() => load()} />
{/if}

<Dialog
	bind:open={uploadOpen}
	title="上传 Epoch 证书"
	description="证书与 Root 公钥由 CLI 离线生成；服务端会重新验证真实签名。"
>
	<div class="space-y-4">
		{#if uploadError}
			<ErrorAlert error={uploadError} />
		{/if}
		<div class="space-y-2">
			<Label for="epoch-cert">certificate_hex（EpochCert envelope，hex）</Label>
			<Textarea id="epoch-cert" bind:value={certificateHex} class="font-mono text-xs" rows={5} />
		</div>
		<div class="space-y-2">
			<Label for="epoch-root-vk">root_verifying_key_hex</Label>
			<Input id="epoch-root-vk" bind:value={rootVkHex} class="font-mono text-xs" />
		</div>
	</div>
	{#snippet footer()}
		<Button variant="outline" onclick={() => (uploadOpen = false)}>取消</Button>
		<Button disabled={uploading || !certificateHex.trim() || !rootVkHex.trim()} onclick={upload}>
			{uploading ? '上传中…' : '上传'}
		</Button>
	{/snippet}
</Dialog>
