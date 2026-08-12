<script lang="ts">
	import { describeError, isApiError } from '$lib/api/errors';
	import Alert from './ui/alert.svelte';
	import { CircleAlert } from '@lucide/svelte';

	let { error }: { error: unknown } = $props();

	const message = $derived(describeError(error));
	const code = $derived(isApiError(error) ? error.code : null);
</script>

<Alert variant="destructive" title={code ? `请求失败（${code}）` : '请求失败'}>
	{#snippet icon()}
		<CircleAlert />
	{/snippet}
	{message}
</Alert>
