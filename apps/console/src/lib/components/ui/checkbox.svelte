<script lang="ts">
	import { cn } from '$lib/utils';
	import type { HTMLInputAttributes } from 'svelte/elements';

	let {
		class: className,
		checked = $bindable(false),
		...rest
	}: Omit<HTMLInputAttributes, 'type'> & { checked?: boolean } = $props();
</script>

<input
	type="checkbox"
	bind:checked
	class={cn(
		'peer h-4 w-4 shrink-0 rounded-sm border border-primary shadow focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50',
		className
	)}
	{...rest}
/>
