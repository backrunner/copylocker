<script lang="ts">
	import { cn } from '$lib/utils';
	import type { HTMLTextareaAttributes } from 'svelte/elements';

	let {
		class: className,
		value = $bindable(),
		...rest
	}: HTMLTextareaAttributes & { value?: string } = $props();
</script>

<textarea
	bind:value
	class={cn(
		'flex min-h-[60px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50',
		className
	)}
	{...rest}
></textarea>
