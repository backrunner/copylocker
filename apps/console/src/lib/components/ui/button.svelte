<script lang="ts" module>
	import type { HTMLAnchorAttributes, HTMLButtonAttributes } from 'svelte/elements';

	export type ButtonVariant = 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost';
	export type ButtonSize = 'default' | 'sm' | 'lg' | 'icon';

	export interface ButtonProps extends HTMLButtonAttributes {
		variant?: ButtonVariant;
		size?: ButtonSize;
		/** 提供时渲染为 <a>（用于导航）。 */
		href?: HTMLAnchorAttributes['href'];
	}

	const variants: Record<ButtonVariant, string> = {
		default: 'bg-primary text-primary-foreground hover:bg-primary/90',
		destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive/90',
		outline: 'border border-input bg-background hover:bg-accent hover:text-accent-foreground',
		secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80',
		ghost: 'hover:bg-accent hover:text-accent-foreground'
	};

	const sizes: Record<ButtonSize, string> = {
		default: 'h-9 px-4 py-2',
		sm: 'h-8 rounded-md px-3 text-xs',
		lg: 'h-10 rounded-md px-8',
		icon: 'h-9 w-9'
	};
</script>

<script lang="ts">
	import { cn } from '$lib/utils';

	let {
		variant = 'default',
		size = 'default',
		class: className,
		type = 'button',
		href,
		children,
		...rest
	}: ButtonProps = $props();

	const classes = $derived(
		cn(
			'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0',
			variants[variant],
			sizes[size],
			className
		)
	);
</script>

{#if href}
	<!-- svelte-ignore a11y_missing_attribute -- rest 已携带其余属性；href 分支只为导航 -->
	<a {href} class={classes} {...(rest as Record<string, unknown>)}>
		{@render children?.()}
	</a>
{:else}
	<button {type} class={classes} {...rest}>
		{@render children?.()}
	</button>
{/if}
