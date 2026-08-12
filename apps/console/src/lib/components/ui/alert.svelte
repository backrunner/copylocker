<script lang="ts" module>
	import type { HTMLAttributes } from 'svelte/elements';
	import type { Snippet } from 'svelte';

	export type AlertVariant = 'default' | 'destructive' | 'warning';

	const variants: Record<AlertVariant, string> = {
		default: 'bg-background text-foreground',
		destructive:
			'border-destructive/50 text-destructive dark:border-destructive [&>svg]:text-destructive',
		warning:
			'border-yellow-500/50 text-yellow-700 dark:text-yellow-400 [&>svg]:text-yellow-600 dark:[&>svg]:text-yellow-400'
	};

	export interface AlertProps extends HTMLAttributes<HTMLDivElement> {
		variant?: AlertVariant;
		title?: string;
		icon?: Snippet;
	}
</script>

<script lang="ts">
	import { cn } from '$lib/utils';

	let {
		variant = 'default',
		title,
		icon,
		class: className,
		children,
		...rest
	}: AlertProps = $props();
</script>

<div
	role="alert"
	class={cn('relative w-full rounded-lg border px-4 py-3 text-sm', variants[variant], className)}
	{...rest}
>
	<div class="flex items-start gap-3">
		{#if icon}
			<span class="mt-0.5 [&_svg]:size-4">{@render icon()}</span>
		{/if}
		<div class="flex-1">
			{#if title}
				<h5 class="mb-1 font-medium leading-none tracking-tight">{title}</h5>
			{/if}
			<div class="text-sm opacity-90">{@render children?.()}</div>
		</div>
	</div>
</div>
