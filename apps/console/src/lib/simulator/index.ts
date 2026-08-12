/**
 * 策略模拟器（Simulator）的浏览器端入口。
 *
 * wasm 核心是 `crates/copylocker-simulator-wasm` —— 它包裹的是
 * `copylocker_server_core::simulator::simulate`，与 `copylocker policy
 * simulate` CLI、与服务端实际行为调用的是同一个 Rust 函数，因此三方输出
 * 一致（由 crates/copylocker-simulator-wasm/tests/consistency.rs 与本目录的
 * consistency.test.ts 双向锁定）。
 *
 * glue（`./wasm/`）由 `npm run build:wasm` 生成，不进仓库；加载方式与
 * `@copylocker/web` 一致 —— 运行时计算 URL + 动态 import，因此
 * `svelte-check` 与不构建 wasm 的测试都不需要这些产物。
 */

import type { Catalog, Policy } from '$lib/api/types';

/** `ReleaseRegistry` 中的一个 release（copylocker-server-core `version.rs`）。 */
export interface SimulatorRelease {
	id: string;
	product_id: string;
	app_version: string;
	variant_id: number;
	build_fingerprint: string;
	channel: string;
	status: 'active' | 'deprecated' | 'compromised';
	compromised_action?: 'warn' | 'force_upgrade' | 'revoke' | null;
	published_at: number;
}

/** 版本决策所针对的 release 注册表。 */
export interface ReleaseRegistryDocument {
	releases: SimulatorRelease[];
}

/** 一个场景步骤（`simulator.rs` `ScenarioStep`，serde tag = `kind`）。 */
export type ScenarioStep =
	| { kind: 'activate'; at: number }
	| { kind: 'renew'; at: number }
	| { kind: 'payment_fails'; at: number }
	| { kind: 'dunning_lapses'; at: number }
	| { kind: 'cancel'; at: number }
	| { kind: 'period_ends'; at: number }
	| { kind: 'run_release'; at: number; release_id: string };

/** 一个命名场景（`simulator.rs` `Scenario`）。 */
export interface Scenario {
	name: string;
	steps: ScenarioStep[];
}

/** wasm 入口的完整输入（`SimulationRequest`）。 */
export interface SimulationRequest {
	policy: Policy;
	catalog: Catalog;
	registry: ReleaseRegistryDocument;
	scenario: Scenario;
}

/** 时间轴上的一行（`simulator.rs` `TimelineEntry`）。 */
export interface TimelineEntry {
	at: number;
	event: string;
	detail: string;
	notable: boolean;
}

/** 模拟结果（`simulator.rs` `Simulation`）。 */
export interface Simulation {
	scenario: string;
	timeline: TimelineEntry[];
	final_subscription_state: string | null;
	final_version_cutoff: number | null;
	policy_warnings: string[];
}

interface SimulatorGlue {
	default: (input: { module_or_path: BufferSource }) => Promise<unknown>;
	simulate_scenario: (input: string) => string;
}

let ready: Promise<SimulatorGlue> | null = null;

async function load(): Promise<SimulatorGlue> {
	// 与 packages/web 相同的刻意选择：目录 URL 不用字面量，避免 bundler 把
	// `new URL('<dir>', import.meta.url)` 重写为资源引用（webpack/Turbopack 会因此坏掉）。
	const base = new URL('./wasm/', import.meta.url);
	const glueUrl = new URL('copylocker_simulator_wasm.js', base).href;
	const wasmUrl = new URL('copylocker_simulator_wasm_bg.wasm', base).href;

	const response = await fetch(wasmUrl);
	if (!response.ok) {
		throw new Error('模拟器 wasm 未找到 —— 请先运行 `npm run build:wasm`');
	}
	const wasmBytes = new Uint8Array(await response.arrayBuffer());
	let glue: SimulatorGlue;
	try {
		glue = (await import(/* @vite-ignore */ glueUrl)) as SimulatorGlue;
	} catch {
		throw new Error('模拟器 wasm glue 未找到 —— 请先运行 `npm run build:wasm`');
	}
	await glue.default({ module_or_path: wasmBytes });
	return glue;
}

/** 初始化 wasm 模块（幂等；仅在浏览器/测试环境调用）。 */
export function initSimulator(): Promise<SimulatorGlue> {
	ready ??= load();
	return ready;
}

/**
 * 运行一次模拟。输入与 `copylocker policy simulate` 的 JSON 形态一致；
 * 失败时抛出 Rust 侧的错误字符串。
 */
export async function runSimulation(request: SimulationRequest): Promise<Simulation> {
	const glue = await initSimulator();
	const raw = glue.simulate_scenario(JSON.stringify(request));
	return JSON.parse(raw) as Simulation;
}
