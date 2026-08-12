<script lang="ts">
	import { browser } from '$app/environment';
	import { page } from '$app/state';
	import { getClient } from '$lib/api';
	import { tokenStore } from '$lib/auth/token.svelte';
	import { productStore } from '$lib/stores/product.svelte';
	import type { Catalog, Feature, FeatureGroup, Policy, Tier } from '$lib/api/types';
	import {
		runSimulation,
		type ReleaseRegistryDocument,
		type Scenario,
		type ScenarioStep,
		type Simulation,
		type SimulatorRelease
	} from '$lib/simulator';
	import ErrorAlert from '$lib/components/error-alert.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import Badge from '$lib/components/ui/badge.svelte';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Select from '$lib/components/ui/select.svelte';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Plus, Trash2 } from '@lucide/svelte';

	const policyId = $derived(page.params.id ?? '');
	const DAY = 86_400;

	const STEP_KINDS: { value: ScenarioStep['kind']; label: string }[] = [
		{ value: 'activate', label: '激活' },
		{ value: 'renew', label: '续费成功' },
		{ value: 'payment_fails', label: '支付失败' },
		{ value: 'dunning_lapses', label: '宽限期结束' },
		{ value: 'cancel', label: '取消订阅' },
		{ value: 'period_ends', label: '周期结束' },
		{ value: 'run_release', label: '运行某个 release' }
	];

	interface StepDraft {
		kind: ScenarioStep['kind'];
		/** YYYY-MM-DD（UTC）。 */
		date: string;
		releaseId: string;
	}

	let policy = $state<Policy | null>(null);
	let catalog = $state<Catalog | null>(null);
	let registry = $state<ReleaseRegistryDocument>({ releases: [] });
	let loadError = $state<unknown>(null);

	let scenarioName = $state('自定义场景');
	let steps = $state<StepDraft[]>([]);
	let running = $state(false);
	let runError = $state<unknown>(null);
	let simulation = $state<Simulation | null>(null);

	const subscription = $derived(
		policy && policy.validity.kind === 'subscription'
			? {
					period: policy.validity.period_secs,
					dunning: policy.validity.dunning_grace_secs
				}
			: null
	);

	const sortedReleases = $derived(
		[...registry.releases].sort((a, b) => a.published_at - b.published_at)
	);

	function toDate(unix: number): string {
		return new Date(unix * 1000).toISOString().slice(0, 10);
	}

	function toUnix(date: string): number {
		return Date.parse(`${date}T00:00:00Z`) / 1000;
	}

	function latestRelease(): string {
		return sortedReleases.at(-1)?.id ?? '';
	}

	/** 设计文档 §5.3 的内置场景库；release 引用取注册表中最新的一个。 */
	function applyPreset(preset: 'renew' | 'cancel' | 'payment' | 'expiry') {
		if (!policy) return;
		const base = Date.parse(`${toDate(Math.floor(Date.now() / 1000))}T00:00:00Z`) / 1000;
		const period = subscription?.period ?? 365 * DAY;
		const dunning = subscription?.dunning ?? 14 * DAY;
		const rel = latestRelease();
		const at = (offset: number) => toDate(base + offset);
		if (preset === 'renew') {
			scenarioName = '正常续订';
			steps = [
				{ kind: 'activate', date: at(0), releaseId: '' },
				{ kind: 'renew', date: at(period), releaseId: '' },
				{ kind: 'run_release', date: at(period + DAY), releaseId: rel }
			];
		} else if (preset === 'cancel') {
			scenarioName = '中途取消';
			steps = [
				{ kind: 'activate', date: at(0), releaseId: '' },
				{ kind: 'renew', date: at(period), releaseId: '' },
				{ kind: 'cancel', date: at(period + 150 * DAY), releaseId: '' },
				{ kind: 'period_ends', date: at(2 * period), releaseId: '' },
				{ kind: 'run_release', date: at(2 * period + DAY), releaseId: rel }
			];
		} else if (preset === 'payment') {
			scenarioName = '支付失败 → 宽限期结束';
			steps = [
				{ kind: 'activate', date: at(0), releaseId: '' },
				{ kind: 'payment_fails', date: at(period), releaseId: '' },
				{ kind: 'run_release', date: at(period + dunning - DAY), releaseId: rel },
				{ kind: 'dunning_lapses', date: at(period + dunning), releaseId: '' },
				{ kind: 'run_release', date: at(period + dunning), releaseId: rel }
			];
		} else {
			scenarioName = '凭证过期后运行';
			const refresh = policy.runtime.refresh_after_secs;
			const grace = policy.runtime.grace_secs;
			steps = [
				{ kind: 'activate', date: at(0), releaseId: '' },
				{ kind: 'run_release', date: at(refresh + grace + DAY), releaseId: rel }
			];
		}
		simulation = null;
		runError = null;
	}

	function addStep() {
		steps = [
			...steps,
			{
				kind: 'run_release',
				date: steps.at(-1)?.date ?? toDate(Math.floor(Date.now() / 1000)),
				releaseId: latestRelease()
			}
		];
	}

	function removeStep(index: number) {
		steps = steps.filter((_, i) => i !== index);
	}

	function buildScenario(): Scenario {
		return {
			name: scenarioName.trim() || '未命名场景',
			steps: steps.map((step): ScenarioStep => {
				const at = toUnix(step.date);
				return step.kind === 'run_release'
					? { kind: 'run_release', at, release_id: step.releaseId }
					: ({ kind: step.kind, at } as ScenarioStep);
			})
		};
	}

	async function run() {
		if (!policy || !catalog || running) return;
		running = true;
		runError = null;
		try {
			simulation = await runSimulation({
				policy,
				catalog,
				registry,
				scenario: buildScenario()
			});
		} catch (error: unknown) {
			runError = error instanceof Error ? error.message : String(error);
			simulation = null;
		} finally {
			running = false;
		}
	}

	$effect(() => {
		if (!browser || !policyId || !tokenStore.authenticated) return;
		const productId = productStore.value;
		if (!productId) return;
		const client = getClient();
		Promise.all([
			client.getPolicy(policyId),
			client.listCatalog('features', productId),
			client.listCatalog('groups', productId),
			client.listCatalog('tiers', productId),
			client.listReleases(productId)
		])
			.then(([policyResponse, f, g, t, releases]) => {
				policy = policyResponse.policy;
				const catalogDoc: Catalog = {
					product_id: productId,
					version: f.catalog_version,
					features: f.items as Feature[],
					groups: g.items as FeatureGroup[],
					tiers: t.items as Tier[]
				};
				catalog = catalogDoc;
				registry = {
					releases: releases.items.map(
						(release): SimulatorRelease => ({
							id: release.id,
							product_id: release.product_id,
							app_version: release.app_version,
							variant_id: release.variant_id,
							build_fingerprint: release.build_fingerprint,
							channel: release.channel,
							status: release.status as SimulatorRelease['status'],
							compromised_action: release.compromised_action,
							published_at: release.published_at
						})
					)
				};
				applyPreset('cancel');
			})
			.catch((error: unknown) => (loadError = error));
	});
</script>

<div class="mx-auto max-w-5xl space-y-6">
	<div>
		<h1 class="text-2xl font-semibold tracking-tight">配置预览器（Simulator）</h1>
		<p class="text-sm text-muted-foreground">
			策略 <code class="font-mono">{policyId}</code> 的时间轴模拟，浏览器内运行与
			<code class="font-mono">copylocker policy simulate</code> 相同的 Rust 引擎（wasm）。
			<a href="/policies/{policyId}" class="underline-offset-4 hover:underline">← 返回策略</a>
		</p>
	</div>

	{#if loadError}
		<ErrorAlert error={loadError} />
	{:else if !policy || !catalog}
		<p class="text-sm text-muted-foreground">加载中…</p>
	{:else}
		<Card>
			<CardHeader>
				<CardTitle class="text-base">场景</CardTitle>
			</CardHeader>
			<CardContent class="space-y-4">
				<div class="flex flex-wrap items-end gap-3">
					<div class="space-y-1">
						<Label for="scenario-name">场景名称</Label>
						<Input id="scenario-name" bind:value={scenarioName} class="w-56" />
					</div>
					<div class="space-y-1">
						<p class="text-sm font-medium leading-none">内置场景库</p>
						<div class="flex gap-2">
							<Button variant="outline" size="sm" onclick={() => applyPreset('renew')}>
								正常续订
							</Button>
							<Button variant="outline" size="sm" onclick={() => applyPreset('cancel')}>
								中途取消
							</Button>
							<Button variant="outline" size="sm" onclick={() => applyPreset('payment')}>
								支付失败
							</Button>
							<Button variant="outline" size="sm" onclick={() => applyPreset('expiry')}>
								凭证过期
							</Button>
						</div>
					</div>
				</div>

				<div class="space-y-2">
					{#each steps as step, index (index)}
						<div class="flex flex-wrap items-center gap-2">
							<Select bind:value={step.kind} class="w-44" aria-label="步骤类型">
								{#each STEP_KINDS as kind (kind.value)}
									<option value={kind.value}>{kind.label}</option>
								{/each}
							</Select>
							<Input type="date" bind:value={step.date} class="w-40" aria-label="步骤日期" />
							{#if step.kind === 'run_release'}
								<Select bind:value={step.releaseId} class="w-56" aria-label="步骤 release">
									{#each sortedReleases as release (release.id)}
										<option value={release.id}>
											{release.id}（{release.app_version}）
										</option>
									{/each}
								</Select>
							{/if}
							<Button
								variant="ghost"
								size="sm"
								aria-label="删除步骤"
								onclick={() => removeStep(index)}
							>
								<Trash2 class="size-4" />
							</Button>
						</div>
					{/each}
					<Button variant="outline" size="sm" onclick={addStep}>
						<Plus class="size-4" /> 添加步骤
					</Button>
				</div>

				<div class="flex items-center gap-3">
					<Button onclick={run} disabled={running || steps.length === 0}>
						{running ? '模拟中…' : '运行模拟'}
					</Button>
					{#if sortedReleases.length === 0}
						<p class="text-xs text-muted-foreground">
							该产品尚未注册 release；run_release 步骤将全部判定为“未注册”。
						</p>
					{/if}
				</div>
			</CardContent>
		</Card>

		{#if runError}
			<Alert variant="destructive" title="模拟失败">{runError}</Alert>
		{/if}

		{#if simulation}
			<Card>
				<CardHeader>
					<CardTitle class="text-base">
						时间轴：{simulation.scenario}
						{#if simulation.final_subscription_state}
							<Badge variant="outline">终态 {simulation.final_subscription_state}</Badge>
						{/if}
						{#if simulation.final_version_cutoff !== null}
							<Badge variant="outline">
								版本封顶 {toDate(simulation.final_version_cutoff)}
							</Badge>
						{/if}
					</CardTitle>
				</CardHeader>
				<CardContent class="space-y-4">
					{#each simulation.policy_warnings as warning (warning)}
						<Alert variant="warning" title="策略风险">{warning}</Alert>
					{/each}
					<ol class="relative space-y-3 border-l border-border pl-4">
						{#each simulation.timeline as entry, index (index)}
							<li class="space-y-0.5">
								<div class="flex flex-wrap items-baseline gap-2">
									<span
										class={entry.notable ? 'text-amber-500' : 'text-muted-foreground'}
										aria-hidden="true"
									>
										{entry.notable ? '★' : '●'}
									</span>
									<time class="font-mono text-xs text-muted-foreground">
										{toDate(entry.at)}
									</time>
									<code class="font-mono text-xs">{entry.event}</code>
									{#if entry.notable}
										<Badge variant="outline">关注</Badge>
									{/if}
								</div>
								<p class="pl-5 text-sm">{entry.detail}</p>
							</li>
						{/each}
					</ol>
				</CardContent>
			</Card>
		{/if}
	{/if}
</div>
