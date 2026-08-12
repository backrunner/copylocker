<script lang="ts">
	import { ShieldAlert } from '@lucide/svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import { parseCatalogGuardrail } from '$lib/api/guardrail';

	/** 服务端 422 invalid_catalog 的 message；UI 用它驱动禁用原因展示。 */
	let { message }: { message: string } = $props();

	const reason = $derived(parseCatalogGuardrail(message));
</script>

<Alert variant="destructive" title="不可变性护栏（服务端 422）" data-testid="guardrail-alert">
	{#snippet icon()}
		<ShieldAlert />
	{/snippet}
	<p data-testid="guardrail-summary">{reason.summary}</p>
	{#if reason.summary !== reason.raw}
		<p class="mt-1 font-mono text-xs opacity-75">{reason.raw}</p>
	{/if}
</Alert>
