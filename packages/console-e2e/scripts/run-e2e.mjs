#!/usr/bin/env node
/**
 * Console E2E orchestrator (hermetic: everything local, no external network).
 *
 *   npm run test:e2e                     full run
 *   CL_E2E_BACKEND_PORT=8901 npm run test:e2e   custom backend port
 *
 * Chain:
 *   1. build the device-helper fixture (cached after the first run)
 *   2. bring up the REAL local Worker backend via the web-e2e harness
 *      (packages/web-e2e/scripts/backend-up.mjs --serve; real key material,
 *      catalog/policy/epoch through the real Admin API)
 *   3. build apps/console (vite build, SvelteKit Cloudflare adapter)
 *   4. serve it with `wrangler dev` so /admin-api proxies to the backend via
 *      the API_UPSTREAM platform var
 *   5. run Playwright, then tear everything down
 *
 * Ports (both configurable because 8787 is commonly taken on dev machines):
 *   CL_E2E_BACKEND_PORT  backend wrangler dev    default 8797
 *   CL_E2E_CONSOLE_PORT  console wrangler dev    default 4174
 *
 * Artifacts (all gitignored): target/tmp/web-e2e/, target/tmp/console-e2e/,
 * output/playwright/.
 */

import { spawn, spawnSync, execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, rmSync, createWriteStream } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const packageRoot = path.resolve(here, '..')
const repoRoot = path.resolve(packageRoot, '../..')
const BACKEND_JSON = path.join(repoRoot, 'target', 'tmp', 'web-e2e', 'backend.json')
const CONSOLE_DIR = path.join(repoRoot, 'apps', 'console')
const CONSOLE_WRANGLER = path.join(CONSOLE_DIR, 'node_modules', '.bin', 'wrangler')
const E2E_ROOT = path.join(repoRoot, 'target', 'tmp', 'console-e2e')
const CONSOLE_PID_FILE = path.join(E2E_ROOT, 'console-wrangler.pid')
const LOG_DIR = path.join(repoRoot, 'output', 'playwright')
const CONSOLE_LOG = path.join(LOG_DIR, 'console-wrangler-dev.log')
const DEVICE_HELPER_MANIFEST = path.join(packageRoot, 'device-helper', 'Cargo.toml')
const DEVICE_HELPER_BIN = path.join(E2E_ROOT, 'cargo', 'release', 'copylocker-console-e2e-device')

const BACKEND_PORT = Number(process.env.CL_E2E_BACKEND_PORT ?? 8797)
const CONSOLE_PORT = Number(process.env.CL_E2E_CONSOLE_PORT ?? 4174)

const log = (message) => console.log(`[console-e2e] ${message}`)

function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    stdio: 'inherit',
    env: { ...process.env, ...(options.env ?? {}) },
    cwd: options.cwd,
    shell: process.platform === 'win32',
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(`${cmd} ${args.join(' ')} exited with ${result.status}`)
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function waitForBackendJson(child, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      if (existsSync(BACKEND_JSON)) return
      throw new Error(`backend-up exited with ${child.exitCode} and wrote no backend.json`)
    }
    if (existsSync(BACKEND_JSON)) return
    await sleep(500)
  }
  throw new Error('backend bring-up timed out')
}

async function waitForHttp(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  let lastError = 'no attempt'
  while (Date.now() < deadline) {
    try {
      await fetch(url, { signal: AbortSignal.timeout(2000) })
      return
    } catch (error) {
      lastError = String(error)
      await sleep(500)
    }
  }
  throw new Error(`${url} did not come up within ${timeoutMs}ms (${lastError})`)
}

function buildDeviceHelper() {
  log('building the device-helper fixture (cached after the first run)')
  execFileSync(
    'cargo',
    [
      'build',
      '--release',
      '--manifest-path',
      DEVICE_HELPER_MANIFEST,
      '--target-dir',
      path.join(E2E_ROOT, 'cargo'),
    ],
    { stdio: 'inherit' },
  )
  if (!existsSync(DEVICE_HELPER_BIN)) throw new Error(`device helper missing: ${DEVICE_HELPER_BIN}`)
}

async function main() {
  const extraArgs = process.argv.slice(2)
  mkdirSync(E2E_ROOT, { recursive: true })
  mkdirSync(LOG_DIR, { recursive: true })

  // The backend harness needs the CLI, the prebuilt worker bundle, and the web
  // wasm; all three are produced by the repo's standard build gates.
  for (const required of [
    path.join(repoRoot, 'target', 'debug', 'copylocker'),
    path.join(repoRoot, 'crates', 'copylocker-worker', 'build', 'worker', 'shim.mjs'),
    path.join(repoRoot, 'packages', 'web', 'dist', 'wasm', 'copylocker_wasm_bg.wasm'),
  ]) {
    if (!existsSync(required)) {
      throw new Error(
        `required artifact missing: ${required}\n` +
          'build it first (cargo build -p copylocker-cli; npm test in crates/copylocker-worker; npm run build in packages/web)',
      )
    }
  }

  buildDeviceHelper()

  rmSync(BACKEND_JSON, { force: true })
  log(`bringing up the local Worker backend on :${BACKEND_PORT}`)
  const backendChild = spawn(
    process.execPath,
    [path.join(repoRoot, 'packages', 'web-e2e', 'scripts', 'backend-up.mjs'), '--serve'],
    {
      stdio: ['ignore', 'inherit', 'inherit'],
      env: { ...process.env, CL_E2E_BACKEND_PORT: String(BACKEND_PORT) },
    },
  )

  let consoleChild = null
  const stopConsole = () => {
    if (consoleChild && consoleChild.exitCode === null) {
      try {
        process.kill(-consoleChild.pid, 'SIGTERM')
      } catch {
        try {
          consoleChild.kill('SIGTERM')
        } catch {
          /* already gone */
        }
      }
    }
  }

  try {
    await waitForBackendJson(backendChild, 20 * 60_000)
    const backend = JSON.parse(readFileSync(BACKEND_JSON, 'utf8'))
    if (!backend.available) throw new Error(`backend unavailable: ${backend.reason}`)
    if (!backend.adminToken) throw new Error('backend.json has no adminToken (backend-up too old)')
    log(`backend up at ${backend.serverUrl} (product ${backend.productId})`)

    log('building apps/console (vite build)')
    run('npm', ['run', 'build'], { cwd: CONSOLE_DIR })

    log(`serving the console with wrangler dev on :${CONSOLE_PORT}`)
    const logStream = createWriteStream(CONSOLE_LOG, { flags: 'w' })
    consoleChild = spawn(
      CONSOLE_WRANGLER,
      [
        'dev',
        '--ip',
        '127.0.0.1',
        '--port',
        String(CONSOLE_PORT),
        '--var',
        `API_UPSTREAM:http://127.0.0.1:${BACKEND_PORT}`,
        '--persist-to',
        path.join(E2E_ROOT, 'console-state'),
      ],
      {
        cwd: CONSOLE_DIR,
        env: { ...process.env, CI: '1', NO_UPDATE_NOTIFIER: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: true,
      },
    )
    consoleChild.stdout.pipe(logStream)
    consoleChild.stderr.pipe(logStream)
    await waitForHttp(`http://127.0.0.1:${CONSOLE_PORT}/login`, 120_000)

    log('running playwright')
    run('npx', ['playwright', 'test', ...extraArgs], {
      cwd: packageRoot,
      env: {
        CL_E2E_BACKEND_PORT: String(BACKEND_PORT),
        CL_E2E_CONSOLE_PORT: String(CONSOLE_PORT),
      },
    })
  } finally {
    stopConsole()
    await sleep(500)
    if (backendChild.exitCode === null) {
      backendChild.kill('SIGTERM')
      await sleep(1000)
    }
    spawnSync(
      process.execPath,
      [path.join(repoRoot, 'packages', 'web-e2e', 'scripts', 'backend-up.mjs'), '--stop'],
      { stdio: 'ignore', env: { ...process.env, CL_E2E_BACKEND_PORT: String(BACKEND_PORT) } },
    )
  }
}

await main()
