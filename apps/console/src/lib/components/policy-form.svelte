<script lang="ts">
	/**
	 * Policy 五轴表单。五个轴：entitlement / validity / version_scope / seats / mode+runtime。
	 * 保存走完整 Policy 对象（POST 创建 / PATCH 更新），服务端 warnings 原样展示为危险配置警告。
	 */
	import { getClient } from '$lib/api';
	import { productStore } from '$lib/stores/product.svelte';
	import type { Policy, PolicyWarning, Tier } from '$lib/api/types';
	import Button from './ui/button.svelte';
	import Input from './ui/input.svelte';
	import Label from './ui/label.svelte';
	import Select from './ui/select.svelte';
	import Checkbox from './ui/checkbox.svelte';
	import Alert from './ui/alert.svelte';
	import ErrorAlert from './error-alert.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
	import { TriangleAlert } from '@lucide/svelte';
	import { browser } from '$app/environment';
	import { untrack } from 'svelte';
	import { tokenStore } from '$lib/auth/token.svelte';

	let {
		initial,
		onSaved
	}: {
		/** 编辑时传入已有 Policy；创建时为 null（用默认值）。 */
		initial: Policy | null;
		onSaved?: (policy: Policy, warnings: PolicyWarning[]) => void;
	} = $props();

	// initial 只在挂载时读取一次（表单草稿），用 untrack 明示这一意图。
	const p = untrack(() => initial);
	const editing = p !== null;

	let id = $state(p?.id ?? '');
	let name = $state(p?.name ?? '');
	let preset = $state(p?.preset ?? '');

	let tier = $state(p?.entitlement.tier ?? '');
	let extraGroups = $state((p?.entitlement.extra_groups ?? []).join(', '));
	let excludedFeatures = $state((p?.entitlement.excluded_features ?? []).join(', '));

	let validityKind = $state<Policy['validity']['kind']>(p?.validity.kind ?? 'subscription');
	let durationDays = $state(
		p?.validity.kind === 'fixed_term' || p?.validity.kind === 'trial'
			? String(p.validity.duration_secs / 86400)
			: '30'
	);
	let periodDays = $state(
		p?.validity.kind === 'subscription' ? String(p.validity.period_secs / 86400) : '365'
	);
	let dunningDays = $state(
		p?.validity.kind === 'subscription'
			? String(p.validity.dunning_grace_secs / 86400)
			: '14'
	);
	let fallbackEnabled = $state(
		p?.validity.kind === 'subscription' ? p.validity.fallback != null : false
	);
	let fallbackMonths = $state(
		p?.validity.kind === 'subscription' && p.validity.fallback
			? String(p.validity.fallback.after_months)
			: '12'
	);
	let fallbackScopeAt = $state<'earned_at' | 'subscription_start'>(
		p?.validity.kind === 'subscription' && p.validity.fallback
			? p.validity.fallback.scope_at
			: 'earned_at'
	);
	let trialOncePer = $state<'fingerprint' | 'account' | 'email'>(
		p?.validity.kind === 'trial' ? p.validity.once_per : 'fingerprint'
	);

	let scopeKind = $state<Policy['version_scope']['kind']>(p?.version_scope.kind ?? 'unlimited');
	let scopeSemver = $state(
		p?.version_scope.kind === 'semver_range' ? p.version_scope.value : '^1'
	);
	let scopeReleasedBefore = $state(
		p?.version_scope.kind === 'released_before'
			? new Date(p.version_scope.value * 1000).toISOString().slice(0, 10)
			: ''
	);
	let scopePinned = $state(
		p?.version_scope.kind === 'pinned' ? p.version_scope.value.join(', ') : ''
	);

	let seats = $state(String(p?.seats.seats ?? 1));
	let maxTransfers = $state(
		p?.seats.max_transfers != null ? String(p.seats.max_transfers) : ''
	);
	let transferWindowDays = $state(
		p?.seats.transfer_window_secs != null
			? String(p.seats.transfer_window_secs / 86400)
			: ''
	);
	let heartbeatSecs = $state(
		p?.seats.heartbeat_secs != null ? String(p.seats.heartbeat_secs) : ''
	);

	let mode = $state<Policy['mode']>(p?.mode ?? 'offline_hybrid');
	let refreshDays = $state(String((p?.runtime.refresh_after_secs ?? 7 * 86400) / 86400));
	let graceDays = $state(String((p?.runtime.grace_secs ?? 14 * 86400) / 86400));
	let fprTolerance = $state(String(p?.runtime.fpr_tolerance ?? 60));
	let allowVm = $state(p?.runtime.allow_vm ?? true);
	let allowOlk = $state(p?.runtime.allow_olk ?? true);
	let allowUnboundOlk = $state(p?.runtime.allow_unbound_olk ?? false);
	let vtSignature = $state<Policy['runtime']['vt_signature']>(
		p?.runtime.vt_signature ?? 'fast'
	);
	let upgradePolicy = $state<Policy['runtime']['offline_upgrade_policy']>(
		p?.runtime.offline_upgrade_policy ?? 'preload_n'
	);
	let preloadN = $state(String(p?.runtime.preload_variants_n ?? 2));
	let reportAttrs = $state(p?.runtime.report_attrs ?? true);

	let tiers = $state<Tier[]>([]);
	let saveError = $state<unknown>(null);
	let warnings = $state<PolicyWarning[]>([]);
	let saving = $state(false);

	$effect(() => {
		if (!browser) return;
		const productId = productStore.value;
		if (!productId || !tokenStore.authenticated) return;
		getClient()
			.listCatalog('tiers', productId)
			.then((response) => (tiers = response.items))
			.catch(() => (tiers = []));
	});

	function splitList(value: string): string[] {
		return value
			.split(',')
			.map((item) => item.trim())
			.filter(Boolean);
	}

	function buildPolicy(): Policy | string {
		const productId = productStore.value;
		if (!productId) return '请先在页面顶部选择 product_id';
		if (!id.trim() || !name.trim()) return 'id 与名称必填';
		if (!tier.trim()) return '必须选择 entitlement tier';

		let validity: Policy['validity'];
		if (validityKind === 'perpetual') validity = { kind: 'perpetual' };
		else if (validityKind === 'fixed_term')
			validity = { kind: 'fixed_term', duration_secs: Number(durationDays) * 86400 };
		else if (validityKind === 'trial')
			validity = {
				kind: 'trial',
				duration_secs: Number(durationDays) * 86400,
				once_per: trialOncePer
			};
		else
			validity = {
				kind: 'subscription',
				period_secs: Number(periodDays) * 86400,
				dunning_grace_secs: Number(dunningDays) * 86400,
				fallback: fallbackEnabled
					? { after_months: Number(fallbackMonths), scope_at: fallbackScopeAt }
					: null
			};

		let versionScope: Policy['version_scope'];
		if (scopeKind === 'unlimited') versionScope = { kind: 'unlimited' };
		else if (scopeKind === 'semver_range')
			versionScope = { kind: 'semver_range', value: scopeSemver.trim() };
		else if (scopeKind === 'released_before') {
			if (!scopeReleasedBefore) return 'released_before 需要选择日期';
			versionScope = {
				kind: 'released_before',
				value: Math.floor(new Date(scopeReleasedBefore).getTime() / 1000)
			};
		} else versionScope = { kind: 'pinned', value: splitList(scopePinned) };

		return {
			id: id.trim(),
			product_id: productId,
			name: name.trim(),
			preset: preset.trim() || null,
			entitlement: {
				tier: tier.trim(),
				extra_groups: splitList(extraGroups),
				excluded_features: splitList(excludedFeatures),
				grants: [],
				limit_overrides: {},
				limit_merge: {}
			},
			validity,
			version_scope: versionScope,
			seats: {
				seats: Number(seats),
				max_transfers: maxTransfers ? Number(maxTransfers) : null,
				transfer_window_secs: transferWindowDays ? Number(transferWindowDays) * 86400 : null,
				heartbeat_secs: heartbeatSecs ? Number(heartbeatSecs) : null
			},
			mode,
			runtime: {
				refresh_after_secs: Number(refreshDays) * 86400,
				grace_secs: Number(graceDays) * 86400,
				fpr_tolerance: Number(fprTolerance),
				allow_vm: allowVm,
				allow_olk: allowOlk,
				allow_unbound_olk: allowUnboundOlk,
				vt_signature: vtSignature,
				offline_upgrade_policy: upgradePolicy,
				preload_variants_n: Number(preloadN),
				report_attrs: reportAttrs
			}
		};
	}

	async function save() {
		if (saving) return;
		const policy = buildPolicy();
		if (typeof policy === 'string') {
			saveError = new Error(policy);
			return;
		}
		saving = true;
		saveError = null;
		try {
			const client = getClient();
			const response = editing
				? await client.updatePolicy(policy)
				: await client.createPolicy(policy);
			warnings = response.warnings;
			onSaved?.(response.policy, response.warnings);
		} catch (error) {
			saveError = error;
		} finally {
			saving = false;
		}
	}
</script>

<div class="space-y-4">
	{#if saveError}
		<ErrorAlert error={saveError} />
	{/if}
	{#if warnings.length > 0}
		<Alert variant="destructive" title="危险配置警告（服务端返回）" data-testid="policy-warnings">
			{#snippet icon()}
				<TriangleAlert />
			{/snippet}
			<ul class="list-inside list-disc">
				{#each warnings as warning (warning.id)}
					<li>
						<code class="font-mono text-xs">{warning.id}</code> — {warning.message}
					</li>
				{/each}
			</ul>
		</Alert>
	{/if}

	<Card>
		<CardHeader>
			<CardTitle class="text-base">标识</CardTitle>
		</CardHeader>
		<CardContent class="grid gap-4 md:grid-cols-3">
			<div class="space-y-2">
				<Label for="policy-id">id</Label>
				<Input id="policy-id" bind:value={id} disabled={editing} class="font-mono text-xs" />
			</div>
			<div class="space-y-2">
				<Label for="policy-name">名称</Label>
				<Input id="policy-name" bind:value={name} />
			</div>
			<div class="space-y-2">
				<Label for="policy-preset">preset（记录用，可选）</Label>
				<Input id="policy-preset" bind:value={preset} placeholder="如 sub-annual" class="font-mono text-xs" />
			</div>
		</CardContent>
	</Card>

	<Card>
		<CardHeader>
			<CardTitle class="text-base">轴 1 · Entitlement</CardTitle>
		</CardHeader>
		<CardContent class="grid gap-4 md:grid-cols-3">
			<div class="space-y-2">
				<Label for="policy-tier">tier</Label>
				{#if tiers.length > 0}
					<Select id="policy-tier" bind:value={tier}>
						<option value="">选择…</option>
						{#each tiers as item (item.id)}
							<option value={item.id}>{item.label}（{item.id}）</option>
						{/each}
					</Select>
				{:else}
					<Input id="policy-tier" bind:value={tier} class="font-mono text-xs" placeholder="tier id" />
				{/if}
			</div>
			<div class="space-y-2">
				<Label for="policy-extra-groups">extra_groups（逗号分隔）</Label>
				<Input id="policy-extra-groups" bind:value={extraGroups} class="font-mono text-xs" />
			</div>
			<div class="space-y-2">
				<Label for="policy-excluded">excluded_features（逗号分隔）</Label>
				<Input id="policy-excluded" bind:value={excludedFeatures} class="font-mono text-xs" />
			</div>
		</CardContent>
	</Card>

	<Card>
		<CardHeader>
			<CardTitle class="text-base">轴 2 · Validity</CardTitle>
		</CardHeader>
		<CardContent class="space-y-4">
			<div class="grid gap-4 md:grid-cols-4">
				<div class="space-y-2">
					<Label for="validity-kind">类型</Label>
					<Select id="validity-kind" bind:value={validityKind}>
						<option value="perpetual">perpetual（永久）</option>
						<option value="fixed_term">fixed_term（固定期限）</option>
						<option value="subscription">subscription（订阅）</option>
						<option value="trial">trial（试用）</option>
					</Select>
				</div>
				{#if validityKind === 'fixed_term' || validityKind === 'trial'}
					<div class="space-y-2">
						<Label for="validity-duration">时长（天）</Label>
						<Input id="validity-duration" type="number" min="1" bind:value={durationDays} />
					</div>
				{/if}
				{#if validityKind === 'trial'}
					<div class="space-y-2">
						<Label for="trial-once-per">once_per</Label>
						<Select id="trial-once-per" bind:value={trialOncePer}>
							<option value="fingerprint">fingerprint</option>
							<option value="account">account</option>
							<option value="email">email</option>
						</Select>
					</div>
				{/if}
				{#if validityKind === 'subscription'}
					<div class="space-y-2">
						<Label for="validity-period">计费周期（天）</Label>
						<Input id="validity-period" type="number" min="1" bind:value={periodDays} />
					</div>
					<div class="space-y-2">
						<Label for="validity-dunning">dunning 宽限（天）</Label>
						<Input id="validity-dunning" type="number" min="0" bind:value={dunningDays} />
					</div>
				{/if}
			</div>
			{#if validityKind === 'subscription'}
				<div class="flex flex-wrap items-end gap-4 rounded-md border p-3">
					<div class="flex items-center gap-2">
						<Checkbox id="fallback-enabled" bind:checked={fallbackEnabled} />
						<Label for="fallback-enabled">perpetual fallback（连续付费 N 月后获得永久授权）</Label>
					</div>
					{#if fallbackEnabled}
						<div class="space-y-1">
							<Label for="fallback-months">after_months</Label>
							<Input id="fallback-months" type="number" min="1" bind:value={fallbackMonths} class="w-28" />
						</div>
						<div class="space-y-1">
							<Label for="fallback-scope">scope_at</Label>
							<Select id="fallback-scope" bind:value={fallbackScopeAt} class="w-48">
								<option value="earned_at">earned_at</option>
								<option value="subscription_start">subscription_start</option>
							</Select>
						</div>
					{/if}
				</div>
			{/if}
		</CardContent>
	</Card>

	<Card>
		<CardHeader>
			<CardTitle class="text-base">轴 3 · Version Scope</CardTitle>
		</CardHeader>
		<CardContent class="grid gap-4 md:grid-cols-3">
			<div class="space-y-2">
				<Label for="scope-kind">类型</Label>
				<Select id="scope-kind" bind:value={scopeKind}>
					<option value="unlimited">unlimited</option>
					<option value="semver_range">semver_range</option>
					<option value="released_before">released_before</option>
					<option value="pinned">pinned</option>
				</Select>
			</div>
			{#if scopeKind === 'semver_range'}
				<div class="space-y-2">
					<Label for="scope-semver">semver range</Label>
					<Input id="scope-semver" bind:value={scopeSemver} class="font-mono text-xs" placeholder="^3" />
				</div>
			{:else if scopeKind === 'released_before'}
				<div class="space-y-2">
					<Label for="scope-date">发布早于</Label>
					<Input id="scope-date" type="date" bind:value={scopeReleasedBefore} />
				</div>
			{:else if scopeKind === 'pinned'}
				<div class="space-y-2">
					<Label for="scope-pinned">固定版本（逗号分隔）</Label>
					<Input id="scope-pinned" bind:value={scopePinned} class="font-mono text-xs" placeholder="3.2.1, 3.2.2" />
				</div>
			{/if}
		</CardContent>
	</Card>

	<Card>
		<CardHeader>
			<CardTitle class="text-base">轴 4 · Seats</CardTitle>
		</CardHeader>
		<CardContent class="grid gap-4 md:grid-cols-4">
			<div class="space-y-2">
				<Label for="policy-seats">席位数</Label>
				<Input id="policy-seats" type="number" min="1" bind:value={seats} />
			</div>
			<div class="space-y-2">
				<Label for="policy-transfers">max_transfers（可选）</Label>
				<Input id="policy-transfers" type="number" min="0" bind:value={maxTransfers} />
			</div>
			<div class="space-y-2">
				<Label for="policy-window">transfer 窗口（天，可选）</Label>
				<Input id="policy-window" type="number" min="0" bind:value={transferWindowDays} />
			</div>
			<div class="space-y-2">
				<Label for="policy-heartbeat">heartbeat（秒，可选）</Label>
				<Input id="policy-heartbeat" type="number" min="0" bind:value={heartbeatSecs} />
			</div>
		</CardContent>
	</Card>

	<Card>
		<CardHeader>
			<CardTitle class="text-base">轴 5 · Mode & Runtime</CardTitle>
			<CardDescription>刷新/宽限、指纹容忍、离线能力、签名与升级策略</CardDescription>
		</CardHeader>
		<CardContent class="space-y-4">
			<div class="grid gap-4 md:grid-cols-4">
				<div class="space-y-2">
					<Label for="policy-mode">mode</Label>
					<Select id="policy-mode" bind:value={mode}>
						<option value="offline_hybrid">offline_hybrid（离线优先）</option>
						<option value="enforced_online">enforced_online（强制在线）</option>
					</Select>
				</div>
				<div class="space-y-2">
					<Label for="policy-refresh">refresh_after（天）</Label>
					<Input id="policy-refresh" type="number" min="0" bind:value={refreshDays} />
				</div>
				<div class="space-y-2">
					<Label for="policy-grace">grace（天）</Label>
					<Input id="policy-grace" type="number" min="0" bind:value={graceDays} />
				</div>
				<div class="space-y-2">
					<Label for="policy-fpr">fpr_tolerance（0–100）</Label>
					<Input id="policy-fpr" type="number" min="0" max="100" bind:value={fprTolerance} />
				</div>
			</div>
			<div class="grid gap-4 md:grid-cols-4">
				<div class="space-y-2">
					<Label for="policy-vt">vt_signature</Label>
					<Select id="policy-vt" bind:value={vtSignature}>
						<option value="fast">fast</option>
						<option value="pq">pq</option>
					</Select>
				</div>
				<div class="space-y-2">
					<Label for="policy-upgrade">offline_upgrade_policy</Label>
					<Select id="policy-upgrade" bind:value={upgradePolicy}>
						<option value="require_online">require_online</option>
						<option value="preload_n">preload_n</option>
						<option value="variant_stable">variant_stable</option>
					</Select>
				</div>
				<div class="space-y-2">
					<Label for="policy-preload">preload_variants_n</Label>
					<Input id="policy-preload" type="number" min="0" bind:value={preloadN} />
				</div>
			</div>
			<div class="flex flex-wrap gap-6">
				<div class="flex items-center gap-2">
					<Checkbox id="allow-vm" bind:checked={allowVm} />
					<Label for="allow-vm">allow_vm</Label>
				</div>
				<div class="flex items-center gap-2">
					<Checkbox id="allow-olk" bind:checked={allowOlk} />
					<Label for="allow-olk">allow_olk</Label>
				</div>
				<div class="flex items-center gap-2">
					<Checkbox id="allow-unbound-olk" bind:checked={allowUnboundOlk} disabled={!allowOlk} />
					<Label for="allow-unbound-olk">allow_unbound_olk（需先开启 allow_olk）</Label>
				</div>
				<div class="flex items-center gap-2">
					<Checkbox id="report-attrs" bind:checked={reportAttrs} />
					<Label for="report-attrs">report_attrs</Label>
				</div>
			</div>
		</CardContent>
	</Card>

	<div class="flex justify-end">
		<Button onclick={save} disabled={saving} data-testid="policy-save">
			{saving ? '保存中…' : editing ? '保存修改' : '创建策略'}
		</Button>
	</div>
</div>
