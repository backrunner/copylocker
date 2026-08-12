#!/usr/bin/env node
/**
 * Bring up the real CopyLocker Worker backend for the web E2E suite.
 *
 * Chain (all local, nothing leaves the machine):
 *   1. `copylocker keygen root` + `copylocker keygen epoch` (real key material)
 *   2. `copylocker bootstrap prepare` for the Admin credential bundle
 *      (`bootstrap apply` is --remote-only by design, so its D1 seed SQL is
 *      replicated here against `wrangler d1 execute --local`)
 *   3. `wrangler dev` on the prebuilt worker bundle with ENVIRONMENT=test, so
 *      secrets come from TEST_* vars instead of the (remote-only) Secrets
 *      Store — the same seam the worker's own vitest suite uses
 *   4. D1 migrations + catalog/policy/epoch via the real Admin API
 *      (`copylocker catalog push`, `policy create|push`, `epoch upload`)
 *   5. release row seeded directly (release administration is post-M1; the
 *      variant_params blob is encrypted by the Rust seed-helper with the
 *      at-rest AAD), feature KEK registered through the Admin API
 *      (`copylocker asset-kek register`, which encrypts server-side)
 *   6. `copylocker license issue` — the plaintext key only exists in this output
 *
 * Result: target/tmp/web-e2e/backend.json
 *   { available, reason?, serverUrl, productId, rootPin, licenseKey, ... }
 *
 * Modes:
 *   node scripts/backend-up.mjs            one-shot bring-up, then torn down
 *   node scripts/backend-up.mjs --serve    bring up and stay alive (used by
 *                                          run-e2e.mjs and for manual runs)
 *   node scripts/backend-up.mjs --stop     stop a previously --serve'd backend
 */

import { spawn, spawnSync, execFileSync } from 'node:child_process'
import {
  createHash,
  createHmac,
  randomBytes,
} from 'node:crypto'
import {
  cpSync,
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const packageRoot = path.resolve(here, '..')
const repoRoot = path.resolve(packageRoot, '../..')

const CLI = path.join(repoRoot, 'target', 'debug', 'copylocker')
const WRANGLER = path.join(
  repoRoot,
  'crates',
  'copylocker-worker',
  'node_modules',
  '.bin',
  'wrangler',
)
const WORKER_DIR = path.join(repoRoot, 'crates', 'copylocker-worker')
const WORKER_MAIN = path.join(WORKER_DIR, 'build', 'worker', 'shim.mjs')
const MIGRATIONS_DIR = path.join(WORKER_DIR, 'migrations')
const WEB_WASM = path.join(
  repoRoot,
  'packages',
  'web',
  'dist',
  'wasm',
  'copylocker_wasm_bg.wasm',
)
const SEED_HELPER_MANIFEST = path.join(packageRoot, 'seed-helper', 'Cargo.toml')

const E2E_ROOT = path.join(repoRoot, 'target', 'tmp', 'web-e2e')
const CARGO_TARGET = path.join(E2E_ROOT, 'cargo')
const STATE_DIR = path.join(E2E_ROOT, 'state')
const WORK_DIR = path.join(E2E_ROOT, 'work')
const BACKEND_JSON = path.join(E2E_ROOT, 'backend.json')
const PID_FILE = path.join(E2E_ROOT, 'wrangler.pid')
const LOG_DIR = path.join(repoRoot, 'output', 'playwright')
const WRANGLER_LOG = path.join(LOG_DIR, 'wrangler-dev.log')

const PORT = Number(process.env.CL_E2E_BACKEND_PORT ?? 8787)
const SERVER_URL = `http://127.0.0.1:${PORT}`
const PRODUCT_ID = process.env.CL_E2E_PRODUCT_ID ?? 'kat-product'
const FEATURE_ID = 'demo-feature'
const RELEASE_ID = 'dev'
const BUILD_FINGERPRINT = 'dev'
const VARIANT_ID = 0
// Fixed local-only at-rest keys (the same shape the worker vitest suite uses;
// ENVIRONMENT=test reads them from plain vars instead of the Secrets Store).
const TEST_SERVER_PEPPER = Array(32).fill(9)
const TEST_VARIANT_PARAMS_KEY = Array(32).fill(1)
const TEST_ASSET_KEK_KEY = Array(32).fill(2)

const log = (message) => console.log(`[backend-up] ${message}`)
const fail = (message) => {
  throw new Error(message)
}

function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    encoding: 'utf8',
    env: { ...process.env, ...(options.env ?? {}) },
    cwd: options.cwd,
    maxBuffer: 32 * 1024 * 1024,
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(
      `${path.basename(cmd)} ${args.join(' ')} failed (${result.status}):\n${result.stderr?.slice(-2000)}`,
    )
  }
  return result.stdout
}

function cli(args, env = {}) {
  return run(CLI, ['--json', ...args], { env })
}

function cliJson(args, env = {}) {
  return JSON.parse(cli(args, env))
}

function hex(bytes) {
  return Buffer.from(bytes).toString('hex')
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function waitForHttp(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  let lastError = 'no attempt'
  while (Date.now() < deadline) {
    try {
      await fetch(url, { signal: AbortSignal.timeout(2000) })
      return // any HTTP response means the listener is up
    } catch (error) {
      lastError = String(error)
      await sleep(500)
    }
  }
  fail(`server at ${url} did not come up within ${timeoutMs}ms (${lastError})`)
}

function buildSeedHelper() {
  log('building the Rust seed helper (cached after the first run)')
  run('cargo', [
    'build',
    '--release',
    '--manifest-path',
    SEED_HELPER_MANIFEST,
    '--target-dir',
    CARGO_TARGET,
  ])
  return path.join(CARGO_TARGET, 'release', 'copylocker-web-e2e-seed')
}

function writeBackendJson(state) {
  mkdirSync(E2E_ROOT, { recursive: true })
  writeFileSync(BACKEND_JSON, JSON.stringify(state, null, 2))
}

/** The whole bring-up. Throws on failure; caller decides how to degrade. */
export async function up() {
  for (const required of [CLI, WRANGLER, WORKER_MAIN, WEB_WASM]) {
    if (!existsSync(required)) fail(`required artifact missing: ${required}`)
  }
  rmSync(STATE_DIR, { recursive: true, force: true })
  rmSync(WORK_DIR, { recursive: true, force: true })
  rmSync(BACKEND_JSON, { force: true })
  mkdirSync(STATE_DIR, { recursive: true })
  mkdirSync(WORK_DIR, { recursive: true })
  mkdirSync(LOG_DIR, { recursive: true })

  const seedHelper = buildSeedHelper()

  // --- 1. key material -------------------------------------------------------
  const keysDir = path.join(WORK_DIR, 'keys')
  cli(['keygen', 'root', '--out-dir', keysDir, '--offline-confirm'])
  const rootSecret = path.join(keysDir, 'cl-root.secret.json')
  const rootPublic = JSON.parse(readFileSync(path.join(keysDir, 'cl-root.public.json'), 'utf8'))
  const rootPin = rootPublic.verifying_key_hex
  if (typeof rootPin !== 'string' || rootPin.length === 0) {
    fail('cl-root.public.json has no verifying_key_hex')
  }

  const now = Math.floor(Date.now() / 1000)
  const epochDir = path.join(keysDir, 'epoch')
  cli([
    'keygen',
    'epoch',
    '--root-key',
    rootSecret,
    '--product',
    PRODUCT_ID,
    '--not-before',
    String(now - 300),
    '--not-after',
    String(now + 7 * 86_400),
    '--out-dir',
    epochDir,
  ])
  const cert = readdirSync(epochDir).find((name) => name.endsWith('.cert.cbor'))
  const signingSecret = readdirSync(epochDir).find((name) => name.endsWith('.signing.secret.json'))
  const fastSecret = readdirSync(epochDir).find((name) =>
    name.endsWith('.fast-signing.secret.json'),
  )
  if (!cert || !signingSecret || !fastSecret) fail('keygen epoch output incomplete')
  const epochSigningKeyJson = readFileSync(path.join(epochDir, signingSecret), 'utf8')
  const epochFastSigningKeyJson = readFileSync(path.join(epochDir, fastSecret), 'utf8')

  // --- 2. project + bootstrap bundle ----------------------------------------
  const projectDir = path.join(WORK_DIR, 'project')
  mkdirSync(projectDir, { recursive: true })
  writeFileSync(
    path.join(projectDir, 'copylocker.json'),
    JSON.stringify(
      {
        schema_version: 1,
        project_name: 'copylocker',
        product_id: PRODUCT_ID,
        secret_store_id: '00000000000000000000000000000002',
        api_url: SERVER_URL,
        admin_token_env: 'COPYLOCKER_ADMIN_TOKEN',
      },
      null,
      2,
    ),
  )
  const bundlePath = path.join(WORK_DIR, 'bootstrap.json')
  cli([
    'bootstrap',
    'prepare',
    '--project',
    projectDir,
    '--vendor',
    'vendor-e2e',
    '--actor',
    'e2e',
    '--out',
    bundlePath,
  ])
  const bundle = JSON.parse(readFileSync(bundlePath, 'utf8'))
  const adminEnv = {
    COPYLOCKER_ADMIN_TOKEN: bundle.admin_token,
  }
  const adminArgs = ['--project', projectDir]

  // --- 3. wrangler dev -------------------------------------------------------
  const wasmDigest = createHash('sha256').update(readFileSync(WEB_WASM)).digest('hex')
  const seedJson = JSON.parse(
    execFileSync(
      seedHelper,
      [
        '--product',
        PRODUCT_ID,
        '--release',
        RELEASE_ID,
        '--variant-id',
        String(VARIANT_ID),
        '--build-fingerprint',
        BUILD_FINGERPRINT,
        '--variant-key-hex',
        hex(TEST_VARIANT_PARAMS_KEY),
        '--asset-key-hex',
        hex(TEST_ASSET_KEK_KEY),
        '--module-digest-hex',
        wasmDigest,
        '--feature',
        FEATURE_ID,
      ],
      { encoding: 'utf8' },
    ),
  )

  const wranglerConfigPath = path.join(WORK_DIR, 'wrangler.jsonc')
  const baseConfig = JSON.parse(
    readFileSync(path.join(WORKER_DIR, 'wrangler.jsonc'), 'utf8')
      // The shipped config is JSONC; the only comments are line comments.
      .replace(/^\s*\/\/.*$/gm, ''),
  )
  delete baseConfig.build
  delete baseConfig.secrets_store_secrets
  baseConfig.main = WORKER_MAIN
  baseConfig.d1_databases[0].migrations_dir = MIGRATIONS_DIR
  baseConfig.vars = {
    ENVIRONMENT: 'test',
    TEST_EPOCH_SIGNING_KEY: epochSigningKeyJson,
    TEST_EPOCH_FAST_SIGNING_KEY: epochFastSigningKeyJson,
    TEST_SERVER_PEPPER: JSON.stringify(TEST_SERVER_PEPPER),
    TEST_ADMIN_TOKEN_PEPPER: JSON.stringify(bundle.admin_token_pepper),
    TEST_VARIANT_PARAMS_KEY: JSON.stringify(TEST_VARIANT_PARAMS_KEY),
    TEST_ASSET_KEK_KEY: JSON.stringify(TEST_ASSET_KEK_KEY),
    TEST_STRIPE_WEBHOOK_SECRET: 'stripe-e2e',
    TEST_PADDLE_WEBHOOK_SECRET: 'paddle-e2e',
    TEST_LEMONSQUEEZY_WEBHOOK_SECRET: 'lemon-e2e',
  }
  writeFileSync(wranglerConfigPath, JSON.stringify(baseConfig, null, 2))

  log('starting wrangler dev (prebuilt worker bundle, ENVIRONMENT=test)')
  const logStream = createWriteStream(WRANGLER_LOG, { flags: 'w' })
  const wrangler = spawn(
    WRANGLER,
    [
      'dev',
      '--config',
      wranglerConfigPath,
      '--ip',
      '127.0.0.1',
      '--port',
      String(PORT),
      '--persist-to',
      STATE_DIR,
    ],
    {
      cwd: WORK_DIR,
      env: { ...process.env, CI: '1', NO_UPDATE_NOTIFIER: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    },
  )
  wrangler.stdout.pipe(logStream)
  wrangler.stderr.pipe(logStream)
  writeFileSync(PID_FILE, String(wrangler.pid))

  const stop = () => {
    try {
      process.kill(-wrangler.pid, 'SIGTERM')
    } catch {
      try {
        wrangler.kill('SIGTERM')
      } catch {
        /* already gone */
      }
    }
  }

  try {
    await waitForHttp(`${SERVER_URL}/v1/keys`, 90_000)

    // --- 4. D1 migrations + seed rows ---------------------------------------
    const d1 = (args) =>
      run(
        WRANGLER,
        ['d1', ...args, 'copylocker', '--local', '--config', wranglerConfigPath, '--persist-to', STATE_DIR],
        { cwd: WORK_DIR, env: { CI: '1' } },
      )
    d1(['migrations', 'apply'])

    // `bootstrap apply` replays: vendors / products / admin_tokens. The pepper
    // is the bundle's; the worker hashes bearer tokens with it (test env).
    const tokenHmac = createHmac('sha256', Buffer.from(bundle.admin_token_pepper))
      .update(bundle.admin_token, 'utf8')
      .digest('hex')
    const scopesJson = JSON.stringify(bundle.scopes).replaceAll("'", "''")
    const suiteHex = '01000001' // CL-STD-1, big-endian 0x01000001
    d1([
      'execute',
      '--yes',
      '--command',
      `INSERT INTO vendors(id,name,fpr_salt_ref,created_at) VALUES ('vendor-e2e','vendor-e2e','FPR_SALT',${now});
       INSERT INTO products(id,vendor_id,name,min_suite_id,min_proto_ver,min_sdk_version,created_at)
         VALUES ('${PRODUCT_ID}','vendor-e2e','${PRODUCT_ID}',X'${suiteHex}',1,'0.0.0',${now});
       INSERT INTO admin_tokens(id,vendor_id,token_hmac,actor,scopes_json,not_before,expires_at,created_at)
         VALUES ('${bundle.token_id}','vendor-e2e',X'${tokenHmac}','e2e','${scopesJson}',${now},${bundle.expires_at},${now});`,
    ])

    // --- 5. catalog + policy + epoch through the real Admin API --------------
    const catalogFile = path.join(WORK_DIR, 'catalog.json')
    // `catalog feature add` edits an existing versioned file (the shape
    // `copylocker init server` seeds); start from the empty v1 catalog.
    writeFileSync(
      catalogFile,
      JSON.stringify(
        { product_id: PRODUCT_ID, version: 1, features: [], groups: [], tiers: [] },
        null,
        2,
      ),
    )
    cli(['catalog', '--file', catalogFile, 'feature', 'add', '--id', FEATURE_ID, '--label', 'Demo Feature'])
    cli([
      'catalog', '--file', catalogFile, 'tier', 'add',
      '--id', 'pro', '--label', 'Pro', '--rank', '1', '--feature', FEATURE_ID,
    ])
    cli(['catalog', '--file', catalogFile, 'push', ...adminArgs, '--idempotency-key', `e2e-catalog-${now}`], adminEnv)

    const policyFile = path.join(WORK_DIR, 'policy.json')
    cli([
      'policy', 'create',
      '--preset', 'perpetual',
      '--id', 'policy_e2e',
      '--product', PRODUCT_ID,
      '--tier', 'pro',
      '--at', String(now),
      '--out', policyFile,
    ])
    cli(['policy', 'push', ...adminArgs, '--file', policyFile, '--idempotency-key', `e2e-policy-${now}`], adminEnv)
    // Short validation cadence so the offline→online revalidation scenario
    // fits in a test: refresh after 30s, generous grace.
    d1([
      'execute',
      '--yes',
      '--command',
      `UPDATE policies SET refresh_after_sec = 30, grace_seconds = 600 WHERE id = 'policy_e2e';`,
    ])

    // Release row (release administration is post-M1 → direct seed). The
    // feature KEK goes through the Admin API, which encrypts it server-side.
    d1([
      'execute',
      '--yes',
      '--command',
      `INSERT INTO releases(id, product_id, app_version, variant_id, variant_params, build_fingerprint,
         channel, status, min_sdk_version, proto_ver, suite_id, published_at, created_at)
         VALUES ('${RELEASE_ID}','${PRODUCT_ID}','0.0.0',${VARIANT_ID},X'${seedJson.variant_params_hex}',
         '${BUILD_FINGERPRINT}','stable','active','0.0.0',1,X'${suiteHex}',${now},${now});`,
    ])
    cli(
      [
        'asset-kek', 'register', ...adminArgs,
        '--release', RELEASE_ID,
        '--feature', FEATURE_ID,
        '--kek-hex', seedJson.feature_keks[FEATURE_ID].key_hex,
        '--idempotency-key', `e2e-asset-kek-${now}`,
      ],
      adminEnv,
    )

    cli([
      'epoch', 'upload', ...adminArgs,
      path.join(epochDir, cert),
      '--root-public', path.join(keysDir, 'cl-root.public.json'),
      '--idempotency-key', `e2e-epoch-${now}`,
    ], adminEnv)

    // --- 6. license ----------------------------------------------------------
    const issue = cliJson([
      'license', 'issue', ...adminArgs,
      '--policy', 'policy_e2e',
      '--count', '1',
      '--seats', '10',
      '--idempotency-key', `e2e-issue-${now}-${randomBytes(4).toString('hex')}`,
    ], adminEnv)
    const licenseKey = issue.licenses?.[0]?.license_key
    if (!licenseKey) fail(`license issue returned no key: ${JSON.stringify(issue)}`)

    log('backend is up: license issued, epoch published')
    return {
      state: {
        available: true,
        serverUrl: SERVER_URL,
        productId: PRODUCT_ID,
        rootPin,
        licenseKey,
        featureId: FEATURE_ID,
        releaseId: RELEASE_ID,
        buildFingerprint: BUILD_FINGERPRINT,
        variantId: VARIANT_ID,
        // Local-only test material: the bootstrap Admin token (full scopes) and
        // the web wasm digest the release variant was seeded with. The console
        // E2E logs in with the token and builds its device-helper config from
        // the digest; neither leaves the local state file.
        adminToken: bundle.admin_token,
        wasmDigestHex: wasmDigest,
        // Local-only test material: the raw feature KEK registered above, so
        // the suite can seal `@copylocker/seal`-style assets and prove the
        // credential `wrapped_keks` consumption (`loadSealed`) end to end.
        featureKekHex: seedJson.feature_keks[FEATURE_ID].key_hex,
      },
      stop,
      wranglerPid: wrangler.pid,
    }
  } catch (error) {
    stop()
    throw error
  }
}

async function main() {
  const mode = process.argv[2]
  if (mode === '--stop') {
    if (existsSync(PID_FILE)) {
      const pid = Number(readFileSync(PID_FILE, 'utf8'))
      try {
        process.kill(-pid, 'SIGTERM')
        log(`stopped wrangler process group ${pid}`)
      } catch {
        log(`wrangler process group ${pid} already gone`)
      }
      rmSync(PID_FILE, { force: true })
    }
    return
  }
  try {
    const { state, stop } = await up()
    writeBackendJson(state)
    if (mode === '--serve') {
      log(`serving at ${state.serverUrl} — Ctrl+C to stop`)
      process.on('SIGINT', () => { stop(); process.exit(0) })
      process.on('SIGTERM', () => { stop(); process.exit(0) })
      return // keep the event loop alive with the wrangler child pipes
    }
    stop()
  } catch (error) {
    writeBackendJson({ available: false, reason: String(error?.message ?? error) })
    console.error(`[backend-up] FAILED: ${error?.message ?? error}`)
    process.exit(mode === '--serve' ? 1 : 2)
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main()
}
