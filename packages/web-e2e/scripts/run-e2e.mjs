#!/usr/bin/env node
/**
 * E2E orchestrator: (optionally) bring up the real local backend, build the
 * example apps with matching env, then run Playwright.
 *
 *   npm run test:e2e              # full run; backend attempted, degrade if it fails
 *   CL_E2E_BACKEND=0 npm run test:e2e   # skip the backend entirely
 *   npm run test:e2e -- --grep attacks  # extra args are forwarded to playwright
 *
 * Artifacts (all gitignored): target/tmp/web-e2e/ (state, keys, backend.json)
 * and output/playwright/ (traces, videos, reports, wrangler log).
 */

import { spawn, spawnSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const packageRoot = path.resolve(here, '..')
const repoRoot = path.resolve(packageRoot, '../..')
const BACKEND_JSON = path.join(repoRoot, 'target', 'tmp', 'web-e2e', 'backend.json')

const log = (message) => console.log(`[e2e] ${message}`)

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
      // Process exited — backend.json (possibly unavailable) should exist.
      if (existsSync(BACKEND_JSON)) return
      throw new Error(`backend-up exited with ${child.exitCode} and wrote no backend.json`)
    }
    if (existsSync(BACKEND_JSON)) return
    await sleep(500)
  }
  throw new Error('backend bring-up timed out')
}

async function main() {
  const extraArgs = process.argv.slice(2)
  const wantBackend = process.env.CL_E2E_BACKEND !== '0'

  log('building @copylocker/web (tsc + wasm copy)')
  run('npm', ['run', 'build'], { cwd: path.join(repoRoot, 'packages', 'web') })

  // The vite-spa build loads @copylocker/unplugin (M4-A), which imports the
  // guard/seal dists at build time — keep all three current.
  for (const pkg of ['guard', 'seal', 'unplugin']) {
    log(`building @copylocker/${pkg}`)
    run('npm', ['run', 'build'], { cwd: path.join(repoRoot, 'packages', pkg) })
  }

  let backend = { available: false, reason: 'backend disabled (CL_E2E_BACKEND=0)' }
  let backendChild = null
  if (wantBackend) {
    // Remove any stale state file first: backend.json is only rewritten at
    // the very end of a successful bring-up, and reading a previous run's
    // Root pin / license against a fresh backend fails closed ('tampered').
    rmSync(BACKEND_JSON, { force: true })
    log('bringing up the local Worker backend (wrangler dev + CLI chain)')
    backendChild = spawn(
      process.execPath,
      [path.join(here, 'backend-up.mjs'), '--serve'],
      { stdio: ['ignore', 'inherit', 'inherit'] },
    )
    try {
      await waitForBackendJson(backendChild, 20 * 60_000)
      backend = JSON.parse(readFileSync(BACKEND_JSON, 'utf8'))
      if (!backend.available) {
        log(`backend unavailable, backend-dependent specs will skip: ${backend.reason}`)
      } else {
        log(`backend up at ${backend.serverUrl} (product ${backend.productId})`)
      }
    } catch (error) {
      backend = { available: false, reason: String(error?.message ?? error) }
      log(`backend bring-up failed, backend-dependent specs will skip: ${backend.reason}`)
    }
  }

  const viteEnv = backend.available
    ? {
        VITE_CL_SERVER_URL: backend.serverUrl,
        VITE_CL_PRODUCT_ID: backend.productId,
        VITE_CL_ROOT_PIN: backend.rootPin,
        VITE_CL_RELEASE_ID: backend.releaseId,
        VITE_CL_BUILD_FINGERPRINT: backend.buildFingerprint,
        VITE_CL_VARIANT_ID: String(backend.variantId),
        // Fast cadence so the offline→online revalidation fits in a test.
        VITE_CL_SCHEDULER_INTERVAL_MS: '5000',
        VITE_CL_MIN_VALIDATION_INTERVAL_SECS: '5',
      }
    : {}

  try {
    log('building examples/vite-spa (vite build)')
    run('npm', ['run', 'build'], {
      cwd: path.join(repoRoot, 'examples', 'vite-spa'),
      env: viteEnv,
    })

    const nextDir = path.join(repoRoot, 'examples', 'nextjs-app')
    const nextBuildId = path.join(nextDir, '.next', 'BUILD_ID')
    // The Next build inlines @copylocker/web, NEXT_PUBLIC_* env, and the
    // build-integrity plugin config (next.config.ts) — rebuild when any of
    // the example's own sources or the SDK dist is newer than the last build.
    const newestMtime = (target) => {
      if (!existsSync(target)) return 0
      const stat = statSync(target)
      if (!stat.isDirectory()) return stat.mtimeMs
      let newest = 0
      for (const entry of readdirSync(target)) {
        const m = newestMtime(path.join(target, entry))
        if (m > newest) newest = m
      }
      return newest
    }
    const nextInputs = [
      path.join(repoRoot, 'packages', 'web', 'dist', 'index.js'),
      path.join(repoRoot, 'packages', 'unplugin', 'dist', 'index.js'),
      path.join(nextDir, 'app'),
      path.join(nextDir, 'lib'),
      path.join(nextDir, 'next.config.ts'),
      path.join(nextDir, 'proxy.ts'),
    ]
    const nextStale =
      !existsSync(nextBuildId) ||
      Math.max(...nextInputs.map(newestMtime)) > statSync(nextBuildId).mtimeMs
    if (nextStale) {
      log('building examples/nextjs-app (next build)')
      run('npm', ['run', 'build'], { cwd: nextDir })
    } else {
      log('reusing the existing examples/nextjs-app build (.next is current)')
    }

    log('running playwright')
    // viteEnv also reaches the `vite preview` webServer (its CSP connect-src
    // is computed from VITE_CL_SERVER_URL at server start).
    run('npx', ['playwright', 'test', ...extraArgs], { cwd: packageRoot, env: viteEnv })
  } finally {
    if (backendChild && backendChild.exitCode === null) {
      backendChild.kill('SIGTERM')
      await sleep(1000)
    }
    // Belt and braces: kill the wrangler process group via the pidfile.
    spawnSync(process.execPath, [path.join(here, 'backend-up.mjs'), '--stop'], {
      stdio: 'ignore',
    })
  }
}

await main()
