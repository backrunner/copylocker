<script lang="ts">
	import { browser } from '$app/environment';
	import { page } from '$app/state';
	import { Tabs } from 'bits-ui';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import type {
		LicenseRecord,
		MachineView,
		PreviewFallbackResponse,
		Tier
	} from '$lib/api/types';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Select from '$lib/components/ui/select.svelte';
	import Badge from '$lib/components/ui/badge.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import RevokeDialog from '$lib/components/revoke-dialog.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { cn, formatTimestamp } from '$lib/utils';

	const licenseId = $derived(page.params.id ?? '');

	let license = $state<LicenseRecord | null>(null);
	let loadError = $state<unknown>(null);
	let actionError = $state<unknown>(null);
	let actionMessage = $state<string | null>(null);

	let machines = $state<MachineView[] | null>(null);
	let machinesError = $state<unknown>(null);

	let fallback = $state<PreviewFallbackResponse | null>(null);
	let fallbackError = $state<unknown>(null);

	let tiers = $state<Tier[]>([]);
	let selectedTier = $state('');

	let extendDays = $state('30');
	let seatsOverride = $state('');

	let revokeLicenseOpen = $state(false);
	let revokeMachineTarget = $state<string | null>(null);
	let revokeMachineOpen = $state(false);

	function openMachineRevoke(machineId: string) {
		revokeMachineTarget = machineId;
		revokeMachineOpen = true;
	}

	function reloadMachines() {
		if (!browser || !licenseId || !tokenStore.authenticated) return;
		getClient()
			.listLicenseMachines(licenseId)
			.then((response) => (machines = response.items))
			.catch((error: unknown) => (machinesError = error));
	}

	function loadLicense() {
		if (!browser || !licenseId || !tokenStore.authenticated) return;
		getClient()
			.getLicense(licenseId)
			.then((response) => (license = response.license))
			.catch((error: unknown) => (loadError = error));
	}

	$effect(() => {
		loadLicense();
	});

	$effect(() => {
		if (!browser || !licenseId || !tokenStore.authenticated) return;
		getClient()
			.listLicenseMachines(licenseId)
			.then((response) => (machines = response.items))
			.catch((error: unknown) => (machinesError = error));
		getClient()
			.previewLicenseFallback(licenseId)
			.then((response) => (fallback = response))
			.catch((error: unknown) => (fallbackError = error));
	});

	$effect(() => {
		if (!browser) return;
		const productId = productStore.value;
		if (!productId || !tokenStore.authenticated) return;
		getClient()
			.listCatalog('tiers', productId)
			.then((response) => (tiers = response.items))
			.catch(() => (tiers = []));
	});

	async function runAction(action: () => Promise<unknown>, message: string) {
		actionError = null;
		actionMessage = null;
		try {
			await action();
			actionMessage = message;
			loadLicense();
		} catch (error) {
			actionError = error;
		}
	}

	function setStatus(status: 'active' | 'suspended') {
		void runAction(
			() => getClient().patchLicense(licenseId, { status }),
			status === 'active' ? '许可已恢复。' : '许可已挂起。'
		);
	}

	function extend() {
		const days = Number(extendDays);
		if (!Number.isFinite(days) || days < 1) {
			actionError = new Error('延长天数必须是 ≥ 1 的数字。');
			actionMessage = null;
			return;
		}
		void runAction(
			() => getClient().patchLicense(licenseId, { extend_by_seconds: Math.floor(days) * 86400 }),
			`已延长 ${days} 天。`
		);
	}

	function applySeats() {
		const seats = Number(seatsOverride);
		if (!Number.isInteger(seats) || seats < 1) {
			actionError = new Error('席位覆盖必须是 ≥ 1 的整数。');
			actionMessage = null;
			return;
		}
		void runAction(
			() => getClient().patchLicense(licenseId, { seats_override: seats }),
			'席位覆盖已更新。'
		);
	}

	function changeTier() {
		if (!selectedTier) return;
		void runAction(
			() => getClient().changeLicenseTier(licenseId, selectedTier),
			`已切换到 tier ${selectedTier}。`
		);
	}
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-semibold tracking-tight">
			许可 <code class="font-mono text-lg">{licenseId}</code>
		</h1>
		<p class="text-sm text-muted-foreground">
			<a href="/licenses" class="underline-offset-4 hover:underline">← 返回列表</a>
		</p>
	</div>

	{#if loadError}
		<ErrorAlert error={loadError} />
	{:else if !license}
		<p class="text-sm text-muted-foreground">加载中…</p>
	{:else}
		{#if actionError}
			<ErrorAlert error={actionError} />
		{/if}
		{#if actionMessage}
			<Alert title="操作成功">{actionMessage}</Alert>
		{/if}

		<Tabs.Root value="detail" class="space-y-4">
			<Tabs.List class="inline-flex h-9 items-center justify-center rounded-lg bg-muted p-1 text-foreground/70">
				{#each [
					['detail', '详情'],
					['machines', '设备'],
					['subscription', '订阅'],
					['actions', '操作']
				] as [value, label] (value)}
					<Tabs.Trigger
						{value}
						class="inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1 text-sm font-medium transition-all data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow"
					>
						{label}
					</Tabs.Trigger>
				{/each}
			</Tabs.List>

			<Tabs.Content value="detail">
				<Card>
					<CardHeader>
						<CardTitle class="text-base">基本信息</CardTitle>
					</CardHeader>
					<CardContent>
						<dl class="grid grid-cols-1 gap-x-8 gap-y-2 text-sm md:grid-cols-2">
							<div class="flex justify-between gap-4">
								<dt class="text-muted-foreground">状态</dt>
								<dd><Badge>{license.status}</Badge></dd>
							</div>
							<div class="flex justify-between gap-4">
								<dt class="text-muted-foreground">策略</dt>
								<dd class="font-mono text-xs">{license.policy_id}</dd>
							</div>
							<div class="flex justify-between gap-4">
								<dt class="text-muted-foreground">账户</dt>
								<dd class="font-mono text-xs">{license.account_id ?? '—'}</dd>
							</div>
							<div class="flex justify-between gap-4">
								<dt class="text-muted-foreground">席位</dt>
								<dd>
									{license.seats_used} 已用{license.seats_override
										? ` / ${license.seats_override} 覆盖`
										: '（沿用策略）'}
								</dd>
							</div>
							<div class="flex justify-between gap-4">
								<dt class="text-muted-foreground">目录版本</dt>
								<dd>v{license.catalog_version}</dd>
							</div>
							<div class="flex justify-between gap-4">
								<dt class="text-muted-foreground">到期</dt>
								<dd>{license.expires_at ? formatTimestamp(license.expires_at) : '永久'}</dd>
							</div>
							<div class="flex justify-between gap-4">
								<dt class="text-muted-foreground">创建</dt>
								<dd>{formatTimestamp(license.created_at)}</dd>
							</div>
							<div class="flex justify-between gap-4">
								<dt class="text-muted-foreground">最近活跃</dt>
								<dd>{formatTimestamp(license.last_seen_at)}</dd>
							</div>
						</dl>
						{#if license.entitlement_override}
							<div class="mt-4 rounded-md border p-3">
								<p class="mb-1 text-xs font-medium text-muted-foreground">权益覆盖</p>
								<pre class="overflow-x-auto font-mono text-xs">{JSON.stringify(license.entitlement_override, null, 2)}</pre>
							</div>
						{/if}
					</CardContent>
				</Card>
			</Tabs.Content>

			<Tabs.Content value="machines">
				<Card>
					<CardHeader>
						<CardTitle class="text-base">设备</CardTitle>
						<CardDescription>GET /licenses/:id/machines（上限 1000 条）</CardDescription>
					</CardHeader>
					<CardContent>
						{#if machinesError}
							<ErrorAlert error={machinesError} />
						{:else if !machines}
							<p class="text-sm text-muted-foreground">加载中…</p>
						{:else}
							<div class="rounded-md border">
								<table class="w-full text-sm">
									<thead>
										<tr class="border-b bg-muted/50 text-left text-xs text-muted-foreground">
											<th class="px-3 py-2 font-medium">Machine ID</th>
											<th class="px-3 py-2 font-medium">状态</th>
											<th class="px-3 py-2 font-medium">平台</th>
											<th class="px-3 py-2 font-medium">App 版本</th>
											<th class="px-3 py-2 font-medium">suspicion</th>
											<th class="px-3 py-2 font-medium">最近活跃</th>
											<th class="px-3 py-2 font-medium"></th>
										</tr>
									</thead>
									<tbody>
										{#each machines as machine (machine.machine_id)}
											<tr class="border-b last:border-0">
												<td class="px-3 py-2 font-mono text-xs">{machine.machine_id}</td>
												<td class="px-3 py-2">
													<Badge variant={machine.status === 'active' ? 'default' : machine.status === 'revoked' ? 'destructive' : 'secondary'}>
														{machine.status}
													</Badge>
												</td>
												<td class="px-3 py-2 text-xs">
													{[machine.os, machine.arch].filter(Boolean).join(' / ') || '—'}
												</td>
												<td class="px-3 py-2 text-xs">{machine.app_version ?? '—'}</td>
												<td class={cn('px-3 py-2', machine.suspicion > 0 && 'font-medium text-destructive')}>
													{machine.suspicion}
												</td>
												<td class="px-3 py-2 text-xs">{formatTimestamp(machine.last_seen_at)}</td>
												<td class="px-3 py-2">
													{#if machine.status !== 'revoked'}
														<Button
															variant="ghost"
															size="sm"
															class="text-destructive"
															onclick={() => openMachineRevoke(machine.machine_id)}
														>
															吊销
														</Button>
													{/if}
												</td>
											</tr>
										{:else}
											<tr>
												<td colspan="7" class="px-3 py-8 text-center text-muted-foreground">
													该许可还没有激活设备。
												</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{/if}
					</CardContent>
				</Card>
			</Tabs.Content>

			<Tabs.Content value="subscription">
				<Card>
					<CardHeader>
						<CardTitle class="text-base">订阅结束预览</CardTitle>
						<CardDescription>GET /licenses/:id/preview-fallback</CardDescription>
					</CardHeader>
					<CardContent>
						{#if fallbackError}
							<ErrorAlert error={fallbackError} />
						{:else if !fallback}
							<p class="text-sm text-muted-foreground">加载中…</p>
						{:else}
							<dl class="grid grid-cols-1 gap-x-8 gap-y-2 text-sm md:grid-cols-2">
								<div class="flex justify-between gap-4">
									<dt class="text-muted-foreground">当前状态</dt>
									<dd><Badge>{fallback.current_state}</Badge></dd>
								</div>
								<div class="flex justify-between gap-4">
									<dt class="text-muted-foreground">终止状态</dt>
									<dd><Badge variant="secondary">{fallback.end_state}</Badge></dd>
								</div>
								<div class="flex justify-between gap-4">
									<dt class="text-muted-foreground">连续付费月数</dt>
									<dd>{fallback.continuous_paid_months}</dd>
								</div>
								<div class="flex justify-between gap-4">
									<dt class="text-muted-foreground">fallback 获得时间</dt>
									<dd>{formatTimestamp(fallback.fallback_earned_at)}</dd>
								</div>
								<div class="flex justify-between gap-4">
									<dt class="text-muted-foreground">版本封顶</dt>
									<dd>{formatTimestamp(fallback.version_cutoff)}</dd>
								</div>
							</dl>
						{/if}
					</CardContent>
				</Card>
			</Tabs.Content>

			<Tabs.Content value="actions">
				<div class="grid gap-4 md:grid-cols-2">
					<Card>
						<CardHeader>
							<CardTitle class="text-base">挂起 / 恢复 / 延期</CardTitle>
						</CardHeader>
						<CardContent class="space-y-4">
							<div class="flex gap-2">
								{#if license.status === 'suspended'}
									<Button variant="outline" onclick={() => setStatus('active')}>恢复（active）</Button>
								{:else if license.status === 'active'}
									<Button variant="outline" onclick={() => setStatus('suspended')}>挂起（suspended）</Button>
								{/if}
							</div>
							{#if license.expires_at}
								<div class="flex items-end gap-2">
									<div class="space-y-1">
										<Label for="extend-days">延长（天）</Label>
										<Input id="extend-days" type="number" min="1" bind:value={extendDays} class="w-28" />
									</div>
									<Button variant="outline" onclick={extend}>延长</Button>
								</div>
							{/if}
							<div class="flex items-end gap-2">
								<div class="space-y-1">
									<Label for="seats-override">席位覆盖</Label>
									<Input
										id="seats-override"
										type="number"
										min="1"
										max="100000"
										bind:value={seatsOverride}
										placeholder={license.seats_override ? String(license.seats_override) : '沿用策略'}
										class="w-36"
									/>
								</div>
								<Button variant="outline" disabled={!seatsOverride} onclick={applySeats}>应用</Button>
							</div>
						</CardContent>
					</Card>

					<Card>
						<CardHeader>
							<CardTitle class="text-base">变更 tier</CardTitle>
							<CardDescription>POST /licenses/:id/change-tier</CardDescription>
						</CardHeader>
						<CardContent class="space-y-4">
							{#if tiers.length > 0}
								<div class="flex items-end gap-2">
									<div class="flex-1 space-y-1">
										<Label for="tier-select">目标 tier</Label>
										<Select id="tier-select" bind:value={selectedTier}>
											<option value="">选择…</option>
											{#each tiers as tier (tier.id)}
												<option value={tier.id}>{tier.label}（{tier.id}）</option>
											{/each}
										</Select>
									</div>
									<Button variant="outline" disabled={!selectedTier} onclick={changeTier}>变更</Button>
								</div>
							{:else}
								<p class="text-sm text-muted-foreground">先在顶部选择产品以加载 tier 列表。</p>
							{/if}
						</CardContent>
					</Card>

					<Card class="border-destructive/40">
						<CardHeader>
							<CardTitle class="text-base text-destructive">吊销许可</CardTitle>
							<CardDescription>
								dry-run 影响面 → 输入完整 ID 确认（与 CLI 一致）。不可撤销。
							</CardDescription>
						</CardHeader>
						<CardContent>
							{#if license.status === 'revoked'}
								<p class="text-sm text-muted-foreground">该许可已被吊销。</p>
							{:else}
								<Button variant="destructive" onclick={() => (revokeLicenseOpen = true)}>
									吊销此许可…
								</Button>
							{/if}
						</CardContent>
					</Card>
				</div>
			</Tabs.Content>
		</Tabs.Root>
	{/if}
</div>

{#if licenseId}
	<RevokeDialog
		bind:open={revokeLicenseOpen}
		kind="licenses"
		targetId={licenseId}
		onRevoked={() => loadLicense()}
	/>
{/if}
{#if revokeMachineTarget}
	<RevokeDialog
		bind:open={revokeMachineOpen}
		kind="machines"
		targetId={revokeMachineTarget}
		onRevoked={() => reloadMachines()}
	/>
{/if}
