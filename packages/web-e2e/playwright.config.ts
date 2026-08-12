import { defineConfig } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../..')
const outputRoot = path.join(repoRoot, 'output', 'playwright')

const vitePort = 4173
const nextPort = 3000

export default defineConfig({
  testDir: './e2e',
  // Cleans output/playwright/r-consistency/ so the multi-engine spec never
  // compares against stale per-browser artifacts from a previous build.
  globalSetup: './e2e/global-setup.ts',
  // The suite shares one local Worker + D1 and one license with bounded
  // seats; run serially for determinism.
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: [
    ['list'],
    ['html', { outputFolder: path.join(outputRoot, 'report'), open: 'never' }],
  ],
  outputDir: path.join(outputRoot, 'results'),
  use: {
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
    actionTimeout: 15_000,
  },
  projects: [
    {
      // Chromium (default browser) — the full vite-spa suite, including the
      // r-consistency and lcp specs.
      name: 'vite-spa',
      testMatch: /vite-spa\..*\.spec\.ts/,
      use: { baseURL: `http://127.0.0.1:${vitePort}` },
    },
    {
      name: 'nextjs',
      testMatch: /nextjs\..*\.spec\.ts/,
      use: { baseURL: `http://127.0.0.1:${nextPort}` },
    },
    // M4 multi-engine acceptance (50-unplugin-integrity.md §3.2): the SAME
    // vite-spa build must compute the identical guard root R and guarded
    // body digest on every engine. Firefox/WebKit run ONLY the r-consistency
    // spec so the default `test:e2e` does not multiply the whole suite by
    // three browsers; LCP stays Chromium-only (Largest Contentful Paint is a
    // Chromium-only PerformanceObserver entry type).
    {
      name: 'vite-spa-firefox',
      testMatch: /vite-spa\.r-consistency\.spec\.ts/,
      use: { browserName: 'firefox', baseURL: `http://127.0.0.1:${vitePort}` },
    },
    {
      name: 'vite-spa-webkit',
      testMatch: /vite-spa\.r-consistency\.spec\.ts/,
      use: { browserName: 'webkit', baseURL: `http://127.0.0.1:${vitePort}` },
    },
  ],
  webServer: [
    {
      command: 'npm run preview',
      cwd: path.join(repoRoot, 'examples', 'vite-spa'),
      port: vitePort,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: 'npm start',
      cwd: path.join(repoRoot, 'examples', 'nextjs-app'),
      port: nextPort,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
})
