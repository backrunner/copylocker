/**
 * M4 performance acceptance (NFR-PERF-006): the guard bootstrap's impact on
 * the vite-spa home page LCP must be < 20 ms.
 *
 * Method: a REAL control build — the same app built with the copylocker
 * plugin disabled (`CL_E2E_DISABLE_COPYLOCKER=1`, see examples/vite-spa
 * vite.config.ts) into target/tmp/web-e2e/control-dist and served by its own
 * `vite preview` on port 4174. The protected build is the one Playwright's
 * webServer already serves on the project baseURL. LCP is collected with a
 * PerformanceObserver installed before any page script runs; each iteration
 * uses a fresh browser context. The assertion compares the medians of 5
 * iterations per group; the full distributions are logged and attached.
 *
 * Caveats:
 * - LCP (`largest-contentful-paint`) is a Chromium-only PerformanceObserver
 *   entry type, so this spec runs in the Chromium `vite-spa` project only.
 * - The example pins `guard.strategy: 'sync'` (every chunk verified before
 *   `__CL_GUARD_R__` resolves) — the most pessimistic configuration, chosen
 *   for e2e determinism. The production default 'idle' defers non-entry
 *   chunks to idle slices and should measure strictly better.
 */
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test, type Browser } from '@playwright/test'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../../..')
const viteSpaDir = path.join(repoRoot, 'examples', 'vite-spa')
const controlDist = path.join(repoRoot, 'target', 'tmp', 'web-e2e', 'control-dist')
const controlPort = 4174
const controlBase = `http://127.0.0.1:${controlPort}`

const ITERATIONS = 5
const MAX_LCP_DELTA_MS = 20 // NFR-PERF-006

function run(cmd: string, args: string[], options: { cwd: string; env?: NodeJS.ProcessEnv }): void {
  const result = spawnSync(cmd, args, {
    cwd: options.cwd,
    env: { ...process.env, ...(options.env ?? {}) },
    stdio: 'inherit',
    shell: process.platform === 'win32',
  })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited with ${result.status}`)
}

async function waitForHttp(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    try {
      const response = await fetch(url)
      if (response.ok) return
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${url}`)
    await new Promise((resolve) => setTimeout(resolve, 300))
  }
}

/** Median of a non-empty numeric sample. */
function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 1
    ? (sorted[mid] as number)
    : ((sorted[mid - 1] as number) + (sorted[mid] as number)) / 2
}

/**
 * One cold-ish LCP measurement: fresh context, observer installed before any
 * page script, read after the app signals readiness and the final paint had
 * a beat to be observed.
 */
async function measureLcp(browser: Browser, url: string): Promise<number> {
  const context = await browser.newContext({ baseURL: undefined })
  try {
    await context.addInitScript(() => {
      const w = window as unknown as { __lcp?: number }
      w.__lcp = 0
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          w.__lcp = Math.max(w.__lcp ?? 0, entry.startTime)
        }
      }).observe({ type: 'largest-contentful-paint', buffered: true })
    })
    const page = await context.newPage()
    await page.goto(url)
    // Same readiness signal both groups: the SDK finished initializing (in
    // the protected build this includes awaiting the guard-computed R).
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    await page.waitForTimeout(250)
    const lcp = await page.evaluate(() => (window as unknown as { __lcp?: number }).__lcp ?? 0)
    await page.close()
    return lcp
  } finally {
    await context.close()
  }
}

test.describe('M4 guard LCP impact (NFR-PERF-006)', () => {
  // Chromium only: LCP entries are not emitted by Firefox/WebKit.
  test.skip(({ browserName }) => browserName !== 'chromium', 'LCP is a Chromium-only entry type')

  let control: ChildProcess | undefined

  test.beforeAll(async () => {
    test.setTimeout(300_000)
    // Glue + wasm land in public/copylocker-wasm (same as the main build).
    run('node', ['scripts/copy-wasm.mjs'], { cwd: viteSpaDir })
    // Real control build: identical source/env, copylocker plugin disabled.
    run('npx', ['vite', 'build', '--outDir', controlDist, '--emptyOutDir'], {
      cwd: viteSpaDir,
      env: { CL_E2E_DISABLE_COPYLOCKER: '1' },
    })
    control = spawn(
      'npx',
      [
        'vite',
        'preview',
        '--outDir',
        controlDist,
        '--host',
        '127.0.0.1',
        '--port',
        String(controlPort),
        '--strictPort',
      ],
      {
        cwd: viteSpaDir,
        env: { ...process.env, CL_E2E_DISABLE_COPYLOCKER: '1' },
        stdio: ['ignore', 'pipe', 'inherit'],
        shell: process.platform === 'win32',
      },
    )
    await waitForHttp(controlBase, 60_000)
  })

  test.afterAll(() => {
    control?.kill('SIGTERM')
  })

  test('guard bootstrap adds < 20 ms to the home page LCP (median of 5)', async ({
    browser,
    baseURL,
  }, testInfo) => {
    test.setTimeout(300_000)
    const controlSamples: number[] = []
    const protectedSamples: number[] = []
    for (let i = 0; i < ITERATIONS; i += 1) {
      controlSamples.push(await measureLcp(browser, `${controlBase}/`))
      protectedSamples.push(await measureLcp(browser, `${baseURL as string}/`))
    }

    const controlMedian = median(controlSamples)
    const protectedMedian = median(protectedSamples)
    const delta = protectedMedian - controlMedian
    const summary = {
      iterations: ITERATIONS,
      controlMs: controlSamples.map((v) => Number(v.toFixed(2))),
      protectedMs: protectedSamples.map((v) => Number(v.toFixed(2))),
      controlMedianMs: Number(controlMedian.toFixed(2)),
      protectedMedianMs: Number(protectedMedian.toFixed(2)),
      deltaMs: Number(delta.toFixed(2)),
      thresholdMs: MAX_LCP_DELTA_MS,
      note: "protected build uses guard.strategy 'sync' (pessimistic; production default is 'idle')",
    }
    console.log(`[lcp] ${JSON.stringify(summary)}`)
    await testInfo.attach('lcp-distribution', {
      body: JSON.stringify(summary, null, 2),
      contentType: 'application/json',
    })
    for (const [label, samples] of [
      ['control', controlSamples],
      ['protected', protectedSamples],
    ] as const) {
      expect(
        Math.min(...samples),
        `${label}: no LCP entry observed in at least one iteration`,
      ).toBeGreaterThan(0)
    }
    expect(
      delta,
      `guard LCP delta ${delta.toFixed(2)} ms exceeds NFR-PERF-006 (${MAX_LCP_DELTA_MS} ms): ` +
        `control ${JSON.stringify(summary.controlMs)} (median ${controlMedian.toFixed(2)}), ` +
        `protected ${JSON.stringify(summary.protectedMs)} (median ${protectedMedian.toFixed(2)})`,
    ).toBeLessThan(MAX_LCP_DELTA_MS)
  })
})
