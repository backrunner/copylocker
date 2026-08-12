<script lang="ts">
	import '../app.css';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { ModeWatcher, toggleMode, mode } from 'mode-watcher';
	import { tokenStore } from '$lib/auth/token.svelte';
	import AppSidebar from '$lib/components/app-sidebar.svelte';
	import ProductPicker from '$lib/components/product-picker.svelte';
	import Button from '$lib/components/ui/button.svelte';
	import { LogOut, Moon, Sun } from '@lucide/svelte';

	let { children } = $props();

	// 公开路由：登录页与离线门户（不共享 admin 认证路径）。
	const isPublic = $derived(
		page.url.pathname === '/login' || page.url.pathname.startsWith('/offline')
	);

	// 开发模式的客户端路由守卫：无 token 时回到登录页。
	// 生产环境另有 hooks.server.ts 的 Cloudflare Access 存在性守卫；
	// 真正授权永远在 API Worker 侧。
	$effect(() => {
		if (browser && !isPublic && !tokenStore.authenticated) {
			void goto('/login');
		}
	});

	function logout() {
		tokenStore.logout();
		void goto('/login');
	}
</script>

<ModeWatcher />

{#if isPublic}
	{@render children()}
{:else if tokenStore.authenticated}
	<div class="flex h-screen overflow-hidden">
		<AppSidebar />
		<div class="flex min-w-0 flex-1 flex-col">
			<header class="flex h-14 shrink-0 items-center justify-between gap-4 border-b px-4">
				<ProductPicker />
				<div class="flex items-center gap-2">
					<Button
						variant="ghost"
						size="icon"
						onclick={toggleMode}
						aria-label="切换明暗主题"
					>
						{#if mode.current === 'dark'}
							<Sun />
						{:else}
							<Moon />
						{/if}
					</Button>
					<Button variant="ghost" size="sm" onclick={logout}>
						<LogOut />
						退出
					</Button>
				</div>
			</header>
			<main class="min-w-0 flex-1 overflow-y-auto p-6">
				{@render children()}
			</main>
		</div>
	</div>
{:else}
	<!-- 等待客户端守卫重定向到 /login -->
	<div class="flex h-screen items-center justify-center text-sm text-muted-foreground">
		正在检查会话…
	</div>
{/if}
