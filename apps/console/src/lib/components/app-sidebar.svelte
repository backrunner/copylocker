<script lang="ts">
	import { page } from '$app/state';
	import { cn } from '$lib/utils';
	import {
		BarChart3,
		BookOpen,
		FileClock,
		KeyRound,
		KeySquare,
		LayoutDashboard,
		Rocket,
		ScrollText,
		Settings,
		WifiOff
	} from '@lucide/svelte';

	const nav = [
		{ href: '/', label: 'Overview', icon: LayoutDashboard },
		{ href: '/licenses', label: 'Licenses', icon: KeyRound },
		{ href: '/catalog', label: 'Catalog', icon: BookOpen },
		{ href: '/policies', label: 'Policies', icon: ScrollText },
		{ href: '/keys', label: 'Keys', icon: KeySquare },
		{ href: '/releases', label: 'Releases', icon: Rocket },
		{ href: '/analytics', label: 'Analytics', icon: BarChart3 },
		{ href: '/audit', label: 'Audit', icon: FileClock },
		{ href: '/settings', label: 'Settings', icon: Settings },
		{ href: '/offline', label: 'Offline 门户', icon: WifiOff }
	];
</script>

<aside class="flex w-56 shrink-0 flex-col border-r bg-card">
	<div class="flex h-14 items-center border-b px-4">
		<span class="text-sm font-semibold tracking-tight">CopyLocker 控制台</span>
	</div>
	<nav class="flex-1 space-y-1 p-2">
		{#each nav as item (item.href)}
			{@const active =
				item.href === '/' ? page.url.pathname === '/' : page.url.pathname.startsWith(item.href)}
			<a
				href={item.href}
				class={cn(
					'flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors',
					active
						? 'bg-secondary text-secondary-foreground'
						: 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
				)}
			>
				<item.icon class="size-4" />
				<span class="flex-1">{item.label}</span>
			</a>
		{/each}
	</nav>
	<div class="border-t p-3 text-[10px] leading-relaxed text-muted-foreground">
		不可信前端：所有授权判定在 API Worker 侧重新执行（ADR-0010）。
	</div>
</aside>
