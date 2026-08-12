<script lang="ts">
	import { productStore } from '$lib/stores/product.svelte';
	import Input from './ui/input.svelte';
	import Badge from './ui/badge.svelte';

	let draft = $state(productStore.value);

	function apply() {
		productStore.select(draft);
	}
</script>

<form
	class="flex items-center gap-2"
	onsubmit={(event) => {
		event.preventDefault();
		apply();
	}}
>
	<span class="text-xs text-muted-foreground">产品</span>
	<Input
		bind:value={draft}
		onblur={apply}
		placeholder="product_id"
		class="h-8 w-44 font-mono text-xs"
		aria-label="product_id"
	/>
	{#if productStore.value}
		<Badge variant="secondary" class="font-mono">{productStore.value}</Badge>
	{:else}
		<Badge variant="outline">未选择</Badge>
	{/if}
</form>
