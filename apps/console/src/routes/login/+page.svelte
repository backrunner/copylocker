<script lang="ts">
	import { goto } from '$app/navigation';
	import { isValidTokenFormat, tokenStore } from '$lib/auth/token.svelte';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Alert from '$lib/components/ui/alert.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';

	let token = $state('');
	let rejected = $state(false);

	function submit() {
		if (tokenStore.login(token)) {
			token = '';
			void goto('/');
		} else {
			rejected = true;
		}
	}
</script>

<div class="flex min-h-screen items-center justify-center p-6">
	<Card class="w-full max-w-md">
		<CardHeader>
			<CardTitle>CopyLocker 管理控制台</CardTitle>
			<CardDescription>
				生产环境由 Cloudflare Access 完成 SSO；此处输入 Admin token（<code>clat_*</code>）
				仅用于开发/直连模式。token 仅存 sessionStorage，不会写入 URL 或日志。
			</CardDescription>
		</CardHeader>
		<CardContent>
			<form
				class="space-y-4"
				onsubmit={(event) => {
					event.preventDefault();
					submit();
				}}
			>
				{#if rejected}
					<Alert variant="destructive" title="token 格式不正确">
						应为 <code>clat_</code> 前缀 + 43 位 base64url 字符（32 字节）。
					</Alert>
				{/if}
				<div class="space-y-2">
					<Label for="admin-token">Admin token</Label>
					<Input
						id="admin-token"
						type="password"
						bind:value={token}
						placeholder="clat_…"
						autocomplete="off"
						spellcheck="false"
						oninput={() => (rejected = false)}
					/>
				</div>
				<Button type="submit" class="w-full" disabled={!isValidTokenFormat(token)}>
					登录
				</Button>
				<p class="text-xs text-muted-foreground">
					真正的 scope 校验发生在 API Worker；本控制台只是不可信前端（ADR-0010）。
				</p>
			</form>
		</CardContent>
	</Card>
</div>
