<script lang="ts">
	import { browser } from '$app/environment';
	import { env } from '$env/dynamic/public';
	import QRCode from 'qrcode';
	import {
		fitsInQr,
		MAX_AR_BYTES,
		MAX_QR_ARMOR_CHARS,
		normalizeClk1Armor,
		parseArPayload
	} from '$lib/offline/armor';
	import Alert from '$lib/components/ui/alert.svelte';
	import Button from '$lib/components/ui/button.svelte';
	import Input from '$lib/components/ui/input.svelte';
	import Label from '$lib/components/ui/label.svelte';
	import Textarea from '$lib/components/ui/textarea.svelte';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';

	/**
	 * 离线激活门户（公开路由，设计文档 §5.6）。
	 *
	 * 两个互不共享代码路径的功能：
	 * 1. AR 中继：上传/粘贴气隙激活请求（raw canonical CBOR，与
	 *    `copylocker offline redeem` 相同的线格式），经 /offline-api 代理到
	 *    POST /v1/offline/request，下载签名后的激活响应（CBOR envelope）。
	 * 2. CLK1 armor → QR：把 admin 侧签发的 OLK armor 渲染成 QR，供气隙设备
	 *    摄像头扫描（`copylocker offline qr` 的浏览器等价物）。纯客户端，不出网。
	 *
	 * 已知偏差（与 agent.md M5-B 记录一致）：AR 的 Base32 armor 与 QR-for-AR
	 * 未实现；QR 仅覆盖 CLK1 armor（ADR-0015 §4）。
	 */

	// ---- AR 中继 ----
	let arText = $state('');
	let arFile = $state<Uint8Array | null>(null);
	let arError = $state<string | null>(null);
	let submitting = $state(false);
	/** 客户端礼貌限流：两次提交之间的最小间隔，配合服务端限流与 Retry-After。 */
	let cooldownUntil = 0;
	let cooldownLeft = $state(0);
	let aresp = $state<{ bytes: Uint8Array; status: number } | null>(null);
	let turnstileToken = $state<string | null>(null);

	const turnstileEnabled = (env.PUBLIC_TURNSTILE_SITE_KEY ?? '').length > 0;

	$effect(() => {
		if (!browser || !turnstileEnabled) return;
		// 配置门控的 Turnstile（默认关闭）。开启即接受外部 script 的 CSP 放宽。
		const script = document.createElement('script');
		script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
		script.async = true;
		script.onload = () => {
			const api = (
				window as unknown as {
					turnstile?: {
						render: (el: HTMLElement, opts: Record<string, unknown>) => void;
					};
				}
			).turnstile;
			const el = document.getElementById('turnstile-slot');
			if (api && el) {
				api.render(el, {
					sitekey: env.PUBLIC_TURNSTILE_SITE_KEY,
					callback: (token: string) => (turnstileToken = token)
				});
			}
		};
		document.head.appendChild(script);
	});

	function cooldownTick() {
		cooldownLeft = Math.max(0, Math.ceil((cooldownUntil - Date.now()) / 1000));
		if (cooldownLeft > 0) setTimeout(cooldownTick, 500);
	}

	function onArFile(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		const file = input.files?.[0];
		arFile = null;
		arError = null;
		if (!file) return;
		if (file.size === 0 || file.size > MAX_AR_BYTES) {
			arError = `请求文件必须在 1 字节到 ${MAX_AR_BYTES} 字节之间`;
			return;
		}
		file
			.arrayBuffer()
			.then((buffer) => (arFile = new Uint8Array(buffer)))
			.catch(() => (arError = '读取文件失败'));
	}

	async function submitAr() {
		arError = null;
		aresp = null;
		let payload: Uint8Array;
		if (arFile) {
			payload = arFile;
		} else {
			const parsed = parseArPayload(arText);
			if ('error' in parsed) {
				arError = parsed.error;
				return;
			}
			payload = parsed.bytes;
		}
		if (turnstileEnabled && !turnstileToken) {
			arError = '请先完成人机校验（Turnstile）';
			return;
		}
		submitting = true;
		try {
			const headers: Record<string, string> = {
				'Content-Type': 'application/cbor',
				Accept: 'application/cbor',
				'Idempotency-Key': crypto.randomUUID()
			};
			if (turnstileToken) headers['cf-turnstile-response'] = turnstileToken;
			const response = await fetch('/offline-api/request', {
				method: 'POST',
				headers,
				body: payload as BodyInit
			});
			const bytes = new Uint8Array(await response.arrayBuffer());
			if (!response.ok) {
				const retryAfter = response.headers.get('retry-after');
				arError =
					response.status === 429 && retryAfter
						? `请求过于频繁，请 ${retryAfter} 秒后重试`
						: `服务端拒绝了激活请求（HTTP ${response.status}）。请求内容与 License 有效性由服务端判定，请核对后重试。`;
				if (response.status === 429) {
					cooldownUntil = Date.now() + Number(retryAfter ?? 30) * 1000;
					cooldownTick();
				}
				return;
			}
			aresp = { bytes, status: response.status };
			// 成功一次后也保持短冷却，避免被当作枚举 oracle 的载体。
			cooldownUntil = Date.now() + 5_000;
			cooldownTick();
		} catch {
			arError = '网络错误：无法到达激活服务';
		} finally {
			submitting = false;
		}
	}

	function downloadAresp() {
		if (!aresp) return;
		const blob = new Blob([aresp.bytes as BlobPart], { type: 'application/cbor' });
		const url = URL.createObjectURL(blob);
		const anchor = document.createElement('a');
		anchor.href = url;
		anchor.download = 'activation-response.cbor';
		anchor.click();
		URL.revokeObjectURL(url);
	}

	// ---- CLK1 armor → QR ----
	let armorText = $state('');
	let armorError = $state<string | null>(null);
	let qrSvg = $state<string | null>(null);
	let armorChars = $state(0);

	async function renderQr() {
		armorError = null;
		qrSvg = null;
		const normalized = normalizeClk1Armor(armorText);
		if ('error' in normalized) {
			armorError = normalized.error;
			return;
		}
		if (!fitsInQr(normalized.armor)) {
			armorError = `armor 共 ${normalized.armor.length} 字符，超过单张 QR 的 ${MAX_QR_ARMOR_CHARS} 字符上限；请改用文件传输（.clk / armor 文本文件）`;
			return;
		}
		try {
			qrSvg = await QRCode.toString(normalized.armor, {
				type: 'svg',
				errorCorrectionLevel: 'M',
				margin: 2
			});
			armorChars = normalized.armor.length;
		} catch {
			armorError = 'QR 渲染失败';
		}
	}

	function downloadQr() {
		if (!qrSvg) return;
		const blob = new Blob([qrSvg], { type: 'image/svg+xml' });
		const url = URL.createObjectURL(blob);
		const anchor = document.createElement('a');
		anchor.href = url;
		anchor.download = 'offline-license-qr.svg';
		anchor.click();
		URL.revokeObjectURL(url);
	}

	let tab = $state<'ar' | 'qr'>('ar');
</script>

<svelte:head>
	<title>离线激活 · CopyLocker</title>
</svelte:head>

<div class="mx-auto min-h-screen max-w-2xl space-y-6 bg-background p-6">
	<div>
		<h1 class="text-2xl font-semibold tracking-tight">离线激活门户</h1>
		<p class="text-sm text-muted-foreground">
			面向气隙设备的公开中继：提交激活请求（AR）取回签名的激活响应，或把离线许可
			（CLK1 armor）渲染为 QR 供气隙设备扫描。此处不验证任何 License ——
			判定永远在服务端；请勿频繁试探（请求被限流）。
		</p>
	</div>

	<div class="flex gap-2" role="group" aria-label="功能切换">
		<Button
			variant={tab === 'ar' ? 'default' : 'outline'}
			aria-pressed={tab === 'ar'}
			onclick={() => (tab = 'ar')}
		>
			提交激活请求
		</Button>
		<Button
			variant={tab === 'qr' ? 'default' : 'outline'}
			aria-pressed={tab === 'qr'}
			onclick={() => (tab = 'qr')}
		>
			OLK armor → QR
		</Button>
	</div>

	{#if tab === 'ar'}
		<Card>
			<CardHeader>
				<CardTitle class="text-base">激活请求（AR）</CardTitle>
				<CardDescription>
					上传 <code class="font-mono">copylocker offline request</code>
					生成的请求文件（raw CBOR，≤ 16 KiB），或粘贴其 hex / base64 文本。
				</CardDescription>
			</CardHeader>
			<CardContent class="space-y-4">
				<div class="space-y-1">
					<Label for="ar-file">请求文件</Label>
					<Input id="ar-file" type="file" onchange={onArFile} />
				</div>
				<div class="space-y-1">
					<Label for="ar-text">或粘贴 hex / base64</Label>
					<Textarea
						id="ar-text"
						bind:value={arText}
						rows={4}
						placeholder="a4 01 … 或 pAEC…"
						disabled={arFile !== null}
					/>
				</div>
				{#if turnstileEnabled}
					<div id="turnstile-slot" aria-label="人机校验"></div>
				{/if}
				{#if arError}
					<Alert variant="destructive" title="提交失败">{arError}</Alert>
				{/if}
				<div class="flex items-center gap-3">
					<Button
						onclick={submitAr}
						disabled={submitting || cooldownLeft > 0 || (!arFile && arText.trim() === '')}
					>
						{submitting ? '提交中…' : cooldownLeft > 0 ? `冷却中（${cooldownLeft}s）` : '提交激活请求'}
					</Button>
				</div>
				{#if aresp}
					<Alert title="激活响应已签发">
						已收到签名的激活响应（{aresp.bytes.length} 字节，7 天内可导入）。
						<div class="mt-2">
							<Button variant="outline" size="sm" onclick={downloadAresp}>
								下载 activation-response.cbor
							</Button>
						</div>
						<p class="mt-2 text-xs text-muted-foreground">
							把该文件送回气隙设备，用
							<code class="font-mono">copylocker offline import</code> 连同设备密钥文件一起导入。
						</p>
					</Alert>
				{/if}
			</CardContent>
		</Card>
	{:else}
		<Card>
			<CardHeader>
				<CardTitle class="text-base">OLK armor → QR</CardTitle>
				<CardDescription>
					粘贴管理员签发的 CLK1 armor（<code class="font-mono">CLK1:…</code> 或 PEM
					边界形态），渲染为 QR 供气隙设备摄像头扫描。纯客户端处理，armor 不会离开浏览器。
				</CardDescription>
			</CardHeader>
			<CardContent class="space-y-4">
				<div class="space-y-1">
					<Label for="armor-text">CLK1 armor</Label>
					<Textarea id="armor-text" bind:value={armorText} rows={6} placeholder="CLK1:…" />
				</div>
				{#if armorError}
					<Alert variant="destructive" title="无法渲染">{armorError}</Alert>
				{/if}
				<Button onclick={renderQr} disabled={armorText.trim() === ''}>渲染 QR</Button>
				{#if qrSvg}
					<div class="space-y-2">
						<div
							class="inline-block rounded-md border bg-white p-4 [&_svg]:block"
							role="img"
							aria-label="离线许可 QR 码"
						>
							{@html qrSvg}
						</div>
						<p class="text-xs text-muted-foreground">armor 共 {armorChars} 字符，纠错等级 M。</p>
						<Button variant="outline" size="sm" onclick={downloadQr}>下载 SVG</Button>
					</div>
				{/if}
			</CardContent>
		</Card>
	{/if}
</div>
