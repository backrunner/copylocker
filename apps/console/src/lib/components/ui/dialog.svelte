<script lang="ts" module>
	import type { Snippet } from 'svelte';

	export interface DialogProps {
		open?: boolean;
		title: string;
		description?: string;
		children?: Snippet;
		footer?: Snippet;
	}
</script>

<script lang="ts">
	import { Dialog } from 'bits-ui';

	let {
		open = $bindable(false),
		title,
		description,
		children,
		footer
	}: DialogProps = $props();
</script>

<Dialog.Root bind:open>
	<Dialog.Portal>
		<Dialog.Overlay class="fixed inset-0 z-50 bg-black/60" />
		<Dialog.Content
			class="fixed left-1/2 top-1/2 z-50 grid w-full max-w-lg -translate-x-1/2 -translate-y-1/2 gap-4 rounded-lg border bg-card p-6 shadow-lg sm:max-w-xl"
		>
			<div class="flex flex-col space-y-1.5 text-left">
				<Dialog.Title class="text-lg font-semibold leading-none tracking-tight">
					{title}
				</Dialog.Title>
				{#if description}
					<Dialog.Description class="text-sm text-muted-foreground">
						{description}
					</Dialog.Description>
				{/if}
			</div>
			<div>{@render children?.()}</div>
			{#if footer}
				<div class="flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2">
					{@render footer()}
				</div>
			{/if}
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>
