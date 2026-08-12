/**
 * 三方一致性测试（M7 验收：Simulator 输出与 CLI、与服务端实际行为一致）。
 *
 * 同一份 scenario fixture 经过两条路径：
 *   (a) wasm 模拟器（本测试，真实 wasm 产物）；
 *   (b) Rust 侧直接调用 `copylocker_server_core::simulator::simulate`
 *       （crates/copylocker-simulator-wasm/tests/consistency.rs 锁定同一对
 *       fixture 文件；CLI `policy simulate` 调用同一函数，故传递覆盖 CLI）。
 *
 * wasm glue 缺失时本测试会先执行 `npm run build:wasm`（cargo + wasm-bindgen，
 * 首次约一分钟）。
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const consoleDir = join(here, '..', '..', '..');
const wasmDir = join(here, 'wasm');
const fixturesDir = join(
	consoleDir,
	'..',
	'..',
	'crates',
	'copylocker-simulator-wasm',
	'fixtures'
);

interface SimulatorGlue {
	default: (input: { module_or_path: BufferSource }) => Promise<unknown>;
	simulate_scenario: (input: string) => string;
}

let glue: SimulatorGlue;

beforeAll(async () => {
	const wasmFile = join(wasmDir, 'copylocker_simulator_wasm_bg.wasm');
	if (!existsSync(wasmFile)) {
		execFileSync('node', ['scripts/build-simulator-wasm.mjs'], {
			cwd: consoleDir,
			stdio: 'inherit'
		});
	}
	const bytes = readFileSync(wasmFile);
	glue = (await import(
		pathToFileURL(join(wasmDir, 'copylocker_simulator_wasm.js')).href
	)) as SimulatorGlue;
	await glue.default({ module_or_path: bytes });
}, 300_000);

describe('simulator three-way consistency', () => {
	it('the wasm simulator reproduces the Rust-side expected simulation', () => {
		const request = readFileSync(join(fixturesDir, 'sub_annual_fallback.request.json'), 'utf8');
		const expected = JSON.parse(
			readFileSync(join(fixturesDir, 'sub_annual_fallback.expected.json'), 'utf8')
		) as unknown;
		const result = JSON.parse(glue.simulate_scenario(request)) as unknown;
		expect(result).toEqual(expected);
	});

	it('flags an out-of-scope release and names the highest covered one', () => {
		const request = readFileSync(join(fixturesDir, 'sub_annual_fallback.request.json'), 'utf8');
		const result = JSON.parse(glue.simulate_scenario(request)) as {
			final_subscription_state: string;
			final_version_cutoff: number;
			timeline: { event: string; detail: string; notable: boolean }[];
		};
		expect(result.final_subscription_state).toBe('perpetual_fallback');
		const runs = result.timeline.filter((entry) => entry.event === 'run_release');
		expect(runs[0].detail).toContain('outside the licensed scope');
		expect(runs[0].detail).toContain('rel_39');
		expect(runs[1].detail).toContain('runs');
	});

	it('rejects a malformed request with an error string, never a panic', () => {
		expect(() => glue.simulate_scenario('{"policy":null}')).toThrowError(
			/invalid simulation request/
		);
	});
});
