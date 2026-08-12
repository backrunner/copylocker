import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../../..')
const backendFile = path.join(repoRoot, 'target', 'tmp', 'web-e2e', 'backend.json')

/**
 * Written by scripts/backend-up.mjs. When absent or `available: false` the
 * backend-dependent specs skip themselves with an explicit reason.
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
  /** Bootstrap Admin token (full scopes); local test material only. */
  adminToken?: string
  /** SHA-256 of the web wasm the seeded release variant was derived with. */
  wasmDigestHex?: string
  /** Raw feature KEK (hex) registered for `featureId`; local test material only. */
  featureKekHex?: string
}

export function backendState(): BackendState {
  if (!existsSync(backendFile)) {
    return { available: false, reason: 'backend.json missing (run scripts/backend-up.mjs)' }
  }
  try {
    return JSON.parse(readFileSync(backendFile, 'utf8')) as BackendState
  } catch {
    return { available: false, reason: 'backend.json unreadable' }
  }
}

export const backend = backendState()

/** The window hook exposed by examples/vite-spa/src/main.ts. */
export interface CopyLockerPageHook {
  cl: {
    ops: {
      deriveM(
        featureId: string,
        kind: number,
        now: number,
      ): Promise<{ payload?: Uint8Array }>
    }
    constants: { kBuild: Uint8Array; manifestRoot: Uint8Array }
    wasmDigest: Uint8Array
    unseal(featureId: string, sealed: Uint8Array): Promise<Uint8Array>
    loadSealed(url: string, featureId: string): Promise<Uint8Array>
    state: string
  }
  sealAsset(
    finalKey: Uint8Array,
    meta: { productId: string; variantId: number; featureId: string; assetId: string },
    plaintext: Uint8Array,
  ): Promise<Uint8Array>
  decodeSealedAsset(sealed: Uint8Array): unknown
  productId: string
}

export const SESSION_ONLINE = 1
export const SESSION_OFFLINE = 0

declare global {
  interface Window {
    __copylocker?: CopyLockerPageHook
  }
}
