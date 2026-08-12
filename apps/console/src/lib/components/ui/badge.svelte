<script lang="ts" module>
	import type { HTMLAttributes } from 'svelte/elements';

	export type BadgeVariant = 'default' | 'secondary' | 'destructive' | 'outline';

	const variants: Record<BadgeVariant, string> = {
		default: 'border-transparent bg-primary text-primary-foreground',
		secondary: 'border-transparent bg-secondary text-secondary-foreground',
		destructive: 'border-transparent bg-destructive text-destructive-foreground',
		outline: 'text-foreground'
	};
</script>

<script lang="ts">
	import { cn } from '$lib/utils';

	let {
		variant = 'default',
		class: className,
		children,
		...rest
	}: HTMLAttributes<HTMLDivElement> & { variant?: BadgeVariant } = $props();
</script>

<div
	class={cn(
		'inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors',
		variants[variant],
		className
	)}
	{...rest}
>
	{@render children?.()}
</div>
