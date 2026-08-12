import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { execFileSync, spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../../..')
const backendFile = path.join(repoRoot, 'target', 'tmp', 'web-e2e', 'backend.json')
const e2eRoot = path.join(repoRoot, 'target', 'tmp', 'console-e2e')

export const DEVICE_HELPER_BIN = path.join(
  e2eRoot,
  'cargo',
  'release',
  'copylocker-console-e2e-device',
)

/**
 * Written by packages/web-e2e/scripts/backend-up.mjs (started by
 * scripts/run-e2e.mjs on CL_E2E_BACKEND_PORT).
 */
export interface BackendState {
  available: boolean
  reason?: string
  serverUrl?: string
  productId?: string
  rootPin?: string
  licenseKey?: string
  featureId?: string
  releaseId?: string
  buildFingerprint?: string
  variantId?: number
  adminToken?: string
  wasmDigestHex?: string
}

function loadBackend(): BackendState {
  if (!existsSync(backendFile)) {
    return { available: false, reason: 'backend.json missing (run scripts/run-e2e.mjs)' }
  }
  try {
    return JSON.parse(readFileSync(backendFile, 'utf8')) as BackendState
  } catch {
    return { available: false, reason: 'backend.json unreadable' }
  }
}

export const backend = loadBackend()

export interface DeviceHelperResult {
  status: number
  stdout: string
  stderr: string
}

let deviceCounter = 0

/**
 * Flush pending LicenseDO projection events into D1 (see
 * scripts/flush-projection.mjs — a dev-harness stand-in for the
 * outbox → queue → consumer pipeline, which does not land under wrangler dev).
 * Idempotent; run after every activation and every admin mutation that changes
 * machine state.
 */
export function flushProjection(): void {
  execFileSync(process.execPath, [
    path.join(path.resolve(here, '..'), 'scripts', 'flush-projection.mjs'),
  ])
}

/** One isolated device state directory per call (fresh device identity). */
export function freshDeviceStateDir(): string {
  deviceCounter += 1
  const dir = path.join(e2eRoot, 'devices', `device-${deviceCounter}`)
  mkdirSync(dir, { recursive: true })
  return dir
}

/**
 * Run the device-helper fixture. Optional flags (release id, build fingerprint,
 * variant, module digest) default to the backend's seeded release.
 */
export function runDeviceHelper(
  command: 'activate' | 'validate',
  options: { licenseKey?: string; stateDir: string; machineName?: string },
): DeviceHelperResult {
  if (!backend.serverUrl || !backend.productId || !backend.rootPin) {
    throw new Error('backend state incomplete')
  }
  const args = [
    command,
    '--server',
    backend.serverUrl,
    '--product',
    backend.productId,
    '--root-vk-hex',
    backend.rootPin,
    '--state-dir',
    options.stateDir,
    '--release-id',
    backend.releaseId ?? 'dev',
    '--build-fingerprint',
    backend.buildFingerprint ?? 'dev',
    '--variant-id',
    String(backend.variantId ?? 0),
    '--module-digest-hex',
    backend.wasmDigestHex ?? '00'.repeat(32),
    '--machine-name',
    options.machineName ?? path.basename(options.stateDir),
  ]
  if (command === 'activate') {
    if (!options.licenseKey) throw new Error('activate requires a license key')
    args.push('--license-key', options.licenseKey)
  }
  const result = spawnSync(DEVICE_HELPER_BIN, args, { encoding: 'utf8' })
  return {
    status: result.status ?? 2,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  }
}
