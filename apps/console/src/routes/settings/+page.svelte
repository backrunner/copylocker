<script lang="ts">
	import { browser } from '$app/environment';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import type {
		AdminMachine,
		DsrExportResponse,
		DsrSubjectBody,
		MachineStatus
	} from '$lib/api/types';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Select from '$lib/components/ui/select.svelte';
	import Badge from '$lib/components/ui/badge.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import DsrDeleteDialog from '$lib/components/dsr-delete-dialog.svelte';
	import TelemetryPurgeDialog from '$lib/components/telemetry-purge-dialog.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { formatTimestamp } from '$lib/utils';

	// ----- DSR export -----
	let subjectKind = $state<'machine' | 'license'>('machine');
	let subjectId = $state('');
	let exporting = $state(false);
	let exportError = $state<unknown>(null);
	let exportResult = $state<DsrExportResponse | null>(null);

	// ----- DSR delete -----
	let deleteOpen = $state(false);

	// ----- telemetry purge -----
	let purgeBefore = $state('');
	let purgeOpen = $state(false);

	// ----- machine directory -----
	let machines = $state<AdminMachine[]>([]);
	let machinesCursor = $state<string | null>(null);
	let machinesError = $state<unknown>(null);
	let machinesLoading = $state(false);
	let machineStatus = $state<'' | MachineStatus>('');
	let gdprTarget = $state<string | null>(null);
	let gdprOpen = $state(false);

	const HEX32 = /^[0-9a-f]{32}$/i;
	const subjectValid = $derived(HEX32.test(subjectId.trim()));

	function subjectBody(): DsrSubjectBody {
		return {
			product_id: productStore.value,
			...(subjectKind === 'machine'
				? { machine_id: subjectId.trim() }
				: { license_id: subjectId.trim() })
		};
	}

	async function runExport() {
		if (!subjectValid || exporting) return;
		exporting = true;
		exportError = null;
		exportResult = null;
		try {
			exportResult = await getClient().dsrExport(subjectBody());
		} catch (error) {
			exportError = error;
		} finally {
			exporting = false;
		}
	}

	// 代际计数：筛选/产品变化时使迟到的旧响应失效（“加载更多”共享当前代际）。
	let machinesGeneration = 0;

	function loadMachines(cursor?: string) {
		if (!browser) return;
		const productId = productStore.value;
		if (!productId || !tokenStore.authenticated) {
			machines = [];
			machinesCursor = null;
			machinesLoading = false;
			return;
		}
		const generation = machinesGeneration;
		machinesLoading = true;
		machinesError = null;
		getClient()
			.listMachines({
				product_id: productId,
				...(machineStatus ? { status: machineStatus } : {}),
				limit: 50,
				...(cursor ? { cursor } : {})
			})
			.then((response) => {
				if (generation !== machinesGeneration) return;
				machines = cursor ? [...machines, ...response.items] : response.items;
				machinesCursor = response.next_cursor;
			})
			.catch((error: unknown) => {
				if (generation === machinesGeneration) machinesError = error;
			})
			.finally(() => {
				if (generation === machinesGeneration) machinesLoading = false;
			});
	}

	$effect(() => {
		void productStore.value;
		void machineStatus;
		machinesGeneration += 1;
		machines = [];
		machinesCursor = null;
		loadMachines();
	});

	function openGdpr(machineId: string) {
		gdprTarget = machineId;
		gdprOpen = true;
	}
</script>

<div class="space-y-6">
	<div>
		<h1 class="text-2xl font-semibold tracking-tight">Settings · DSR 控制台</h1>
		<p class="text-sm text-muted-foreground">
			数据主体权利（export / delete）与 telemetry 保留清理，均与 CLI
			<code class="font-mono text-xs">dsr</code> / <code class="font-mono text-xs">telemetry purge</code>
			行为一致（dry-run → 两步确认）。需要 dsr:rw / machines:rw scope。
		</p>
	</div>

	{#if !productStore.value}
		<Alert title="未选择产品">DSR 与设备目录要求 product_id，请先在页面顶部选择产品。</Alert>
	{:else}
		<div class="grid gap-4 lg:grid-cols-2">
			<Card>
				<CardHeader>
					<CardTitle class="text-base">DSR 导出</CardTitle>
					<CardDescription>POST /v1/admin/dsr/export（只读，无 Idempotency-Key）</CardDescription>
				</CardHeader>
				<CardContent class="space-y-4">
					<div class="flex flex-wrap items-end gap-4">
						<div class="space-y-1">
							<Label for="subject-kind">主体类型</Label>
							<Select id="subject-kind" bind:value={subjectKind} class="w-36">
								<option value="machine">machine</option>
								<option value="license">license</option>
							</Select>
						</div>
						<div class="flex-1 space-y-1">
							<Label for="subject-id">主体 id（16 字节 hex）</Label>
							<Input
								id="subject-id"
								bind:value={subjectId}
								class="font-mono text-xs"
								spellcheck="false"
							/>
						</div>
						<Button disabled={!subjectValid || exporting} onclick={() => void runExport()}>
							{exporting ? '导出中…' : '导出'}
						</Button>
					</div>
					{#if exportError}
						<ErrorAlert error={exportError} />
					{/if}
					{#if exportResult}
						{#if exportResult.audit_truncated}
							<Alert variant="warning" title="审计引用被截断">
								该主体的审计引用超过单页上限，导出仅含前 100 条。
							</Alert>
						{/if}
						<pre
							class="max-h-96 overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs"
							data-testid="dsr-export-result">{JSON.stringify(exportResult, null, 2)}</pre>
					{/if}
				</CardContent>
			</Card>

			<Card class="border-destructive/40">
				<CardHeader>
					<CardTitle class="text-base text-destructive">DSR 删除</CardTitle>
					<CardDescription>
						POST /v1/admin/dsr/delete：GDPR 级联（DO 激活 + D1 投影 + raw detail），
						dry-run → 输入完整 id 确认；完成后展示删除回执。
					</CardDescription>
				</CardHeader>
				<CardContent>
					<p class="mb-4 text-sm text-muted-foreground">
						使用左侧的主体类型与 id；删除是不可逆操作。
					</p>
					<Button variant="destructive" disabled={!subjectValid} onclick={() => (deleteOpen = true)}>
						删除该主体的数据…
					</Button>
				</CardContent>
			</Card>

			<Card class="border-destructive/40">
				<CardHeader>
					<CardTitle class="text-base text-destructive">Telemetry 保留清理</CardTitle>
					<CardDescription>
						POST /v1/admin/telemetry/purge：T1 raw detail 保留策略（默认 30 天；显式 before
						才会同时清理 rollup）。
					</CardDescription>
				</CardHeader>
				<CardContent>
					<div class="flex flex-wrap items-end gap-4">
						<div class="space-y-1">
							<Label for="purge-before">before（可选，YYYY-MM-DD）</Label>
							<Input id="purge-before" type="date" bind:value={purgeBefore} />
						</div>
						<Button variant="destructive" onclick={() => (purgeOpen = true)}>清理…</Button>
					</div>
				</CardContent>
			</Card>
		</div>

		<Card>
			<CardHeader>
				<CardTitle class="text-base">设备目录（跨许可）</CardTitle>
				<CardDescription>
					GET /v1/admin/machines（keyset 分页）；每行的 GDPR 删除走 DELETE
					/v1/admin/machines/:id（journaled alias）。
				</CardDescription>
			</CardHeader>
			<CardContent class="space-y-4">
				<div class="flex items-end gap-4">
					<div class="space-y-1">
						<Label for="machine-status">状态</Label>
						<Select id="machine-status" bind:value={machineStatus} class="w-40">
							<option value="">全部</option>
							<option value="active">active</option>
							<option value="pending">pending</option>
							<option value="released">released</option>
							<option value="revoked">revoked</option>
						</Select>
					</div>
				</div>
				{#if machinesError}
					<ErrorAlert error={machinesError} />
				{:else}
					<div class="rounded-md border">
						<table class="w-full text-sm">
							<thead>
								<tr class="border-b bg-muted/50 text-left text-xs text-muted-foreground">
									<th class="px-3 py-2 font-medium">Machine ID</th>
									<th class="px-3 py-2 font-medium">License ID</th>
									<th class="px-3 py-2 font-medium">状态</th>
									<th class="px-3 py-2 font-medium">平台</th>
									<th class="px-3 py-2 font-medium">最近活跃</th>
									<th class="px-3 py-2 font-medium"></th>
								</tr>
							</thead>
							<tbody>
								{#each machines as machine (machine.machine_id)}
									<tr class="border-b last:border-0 hover:bg-muted/30">
										<td class="px-3 py-2 font-mono text-xs">{machine.machine_id}</td>
										<td class="px-3 py-2 font-mono text-xs">{machine.license_id}</td>
										<td class="px-3 py-2">
											<Badge
												variant={machine.status === 'active'
													? 'default'
													: machine.status === 'revoked'
														? 'destructive'
														: 'secondary'}
											>
												{machine.status}
											</Badge>
										</td>
										<td class="px-3 py-2 text-xs">
											{[machine.os, machine.arch].filter(Boolean).join(' / ') || '—'}
										</td>
										<td class="px-3 py-2 text-xs">{formatTimestamp(machine.last_seen_at)}</td>
										<td class="px-3 py-2">
											<Button
												variant="ghost"
												size="sm"
												class="text-destructive"
												onclick={() => openGdpr(machine.machine_id)}
											>
												GDPR 删除…
											</Button>
										</td>
									</tr>
								{:else}
									<tr>
										<td colspan="6" class="px-3 py-8 text-center text-muted-foreground">
											{machinesLoading ? '加载中…' : '没有匹配的设备。'}
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
					{#if machinesCursor}
						<div>
							<Button
								variant="outline"
								disabled={machinesLoading}
								onclick={() => loadMachines(machinesCursor ?? undefined)}
							>
								{machinesLoading ? '加载中…' : '加载更多'}
							</Button>
						</div>
					{/if}
				{/if}
			</CardContent>
		</Card>
	{/if}
</div>

{#if productStore.value && subjectValid}
	<DsrDeleteDialog
		bind:open={deleteOpen}
		kind="subject"
		subject={subjectBody()}
		targetId={subjectId.trim()}
	/>
{/if}
{#if productStore.value}
	<TelemetryPurgeDialog
		bind:open={purgeOpen}
		body={{
			product_id: productStore.value,
			...(purgeBefore ? { before: purgeBefore } : {})
		}}
	/>
{/if}
{#if gdprTarget}
	<DsrDeleteDialog
		bind:open={gdprOpen}
		kind="machine"
		targetId={gdprTarget}
		onDeleted={() => {
			machines = [];
			machinesCursor = null;
			loadMachines();
		}}
	/>
{/if}
