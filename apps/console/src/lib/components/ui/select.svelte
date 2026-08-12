<script lang="ts" module>
	import type { HTMLSelectAttributes } from 'svelte/elements';

	export interface SelectProps extends HTMLSelectAttributes {
		value?: string;
	}
</script>

<script lang="ts">
	import { cn } from '$lib/utils';

	let { class: className, value = $bindable(''), children, ...rest }: SelectProps = $props();
</script>

<select
	bind:value
	class={cn(
		'flex h-9 w-full appearance-none rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50',
		className
	)}
	{...rest}
>
	{@render children?.()}
</select>
