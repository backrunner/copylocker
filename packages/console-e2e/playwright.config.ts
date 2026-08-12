import { defineConfig } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../..')
const outputRoot = path.join(repoRoot, 'output', 'playwright')

// The console dev server (wrangler dev on the SvelteKit Cloudflare build) is
// started by scripts/run-e2e.mjs, which also brings up the backend; the ports
// are configurable because 8787 is commonly taken locally.
const consolePort = Number(process.env.CL_E2E_CONSOLE_PORT ?? 4174)

export default defineConfig({
  testDir: './e2e',
  // One shared backend + one console server; state is built up across specs.
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 180_000,
  expect: { timeout: 20_000 },
  reporter: [
    ['list'],
    ['html', { outputFolder: path.join(outputRoot, 'console-report'), open: 'never' }],
  ],
  outputDir: path.join(outputRoot, 'console-results'),
  use: {
    baseURL: `http://127.0.0.1:${consolePort}`,
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
    actionTimeout: 20_000,
  },
})
