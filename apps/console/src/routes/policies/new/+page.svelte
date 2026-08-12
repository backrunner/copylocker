<script lang="ts">
	import { goto } from '$app/navigation';
	import PolicyForm from '$lib/components/policy-form.svelte';
	import type { Policy, PolicyWarning } from '$lib/api/types';

	let savedWarnings = $state<PolicyWarning[] | null>(null);

	function onSaved(policy: Policy, warnings: PolicyWarning[]) {
		if (warnings.length > 0) {
			savedWarnings = warnings;
			setTimeout(() => void goto(`/policies/${policy.id}`), 2500);
		} else {
			void goto(`/policies/${policy.id}`);
		}
	}
</script>

<div class="mx-auto max-w-4xl space-y-6">
	<div>
		<h1 class="text-2xl font-semibold tracking-tight">新建策略</h1>
		<p class="text-sm text-muted-foreground">
			POST /v1/admin/policies · 预设展开目前由 CLI 本地完成，console 记录 preset 名称并按完整五轴提交。
			{#if savedWarnings}
				已保存，存在 {savedWarnings.length} 条危险配置警告，即将跳转…
			{/if}
		</p>
	</div>
	<PolicyForm initial={null} {onSaved} />
</div>
