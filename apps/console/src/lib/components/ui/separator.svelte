<script lang="ts">
	import { cn } from '$lib/utils';
	import type { HTMLAttributes } from 'svelte/elements';

	let { class: className, ...rest }: HTMLAttributes<HTMLHRElement> = $props();
</script>

<hr class={cn('shrink-0 border-border', className)} {...rest} />
