/**
 * CopyLocker Web Lab — Vite SPA entry.
 *
 * Demonstrates the full `@copylocker/web` surface: create (with Worker
 * isolation), activate / deactivate, the advisory state badge, and
 * fetch-and-unseal of a web v1 sealed asset. There is deliberately no
 * `isLicensed()` gate — `unseal()` either returns plaintext or throws.
 */

import { CopyLocker, decodeSealedAsset, sealAsset, type LicenseState } from '@copylocker/web'
import { DEV_ROOT_PIN } from './dev-root-pin'
// M4 e2e fixture: installs the __CL_E2E_GUARD_PROBE__ window hook used by the
// packages/web-e2e multi-engine R-consistency spec.
import './e2e-guard-probe'

const serverUrl = import.meta.env.VITE_CL_SERVER_URL ?? 'http://localhost:8787'
const productId = import.meta.env.VITE_CL_PRODUCT_ID ?? 'kat-product'
const rootPin = import.meta.env.VITE_CL_ROOT_PIN ?? DEV_ROOT_PIN

/** Optional numeric env knob; absent/blank means "leave the SDK default". */
function envNumber(value: string | undefined): number | undefined {
  if (value === undefined || value.trim() === '') return undefined
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : undefined
}

const $ = <T extends HTMLElement>(selector: string): T => {
  const el = document.querySelector<T>(selector)
  if (!el) throw new Error(`missing element ${selector}`)
  return el
}

const logList = $<HTMLUListElement>('[data-testid="status-log"]')
const stateName = $('[data-testid="license-state"]')
const stateDot = $('[data-testid="state-dot"]')
const sdkStatus = $('[data-testid="sdk-status"]')
const unsealOutput = $<HTMLPreElement>('[data-testid="unseal-output"]')

$('[data-testid="server-url"]').textContent = serverUrl
$('[data-testid="product-id"]').textContent = productId

function log(message: string): void {
  const item = document.createElement('li')
  item.textContent = `${new Date().toISOString().slice(11, 19)} ${message}`
  logList.prepend(item)
}

/** Advisory only — never gate features on this value. */
function renderState(state: LicenseState): void {
  stateName.textContent = state
  stateDot.dataset.state = state
  log(`state → ${state} (advisory)`)
}

async function main(): Promise<void> {
  let cl: CopyLocker
  try {
    cl = await CopyLocker.create({
      serverUrl,
      productId,
      rootPins: [rootPin],
      worker: true, // FR-WEB-008: the wasm core runs in a dedicated Worker
      // Glue + wasm are copied to public/copylocker-wasm/ (see
      // scripts/copy-wasm.mjs) so the URL is stable in dev and build alike.
      glueBaseUrl: new URL('./copylocker-wasm/', document.baseURI),
      releaseId: import.meta.env.VITE_CL_RELEASE_ID,
      buildFingerprint: import.meta.env.VITE_CL_BUILD_FINGERPRINT,
      variantId: envNumber(import.meta.env.VITE_CL_VARIANT_ID),
      schedulerIntervalMs: envNumber(import.meta.env.VITE_CL_SCHEDULER_INTERVAL_MS),
      minValidationIntervalSecs: envNumber(import.meta.env.VITE_CL_MIN_VALIDATION_INTERVAL_SECS),
      onStateChange: renderState,
      // M4-A: the unplugin-injected guard bootstrap publishes the
      // ACTUALLY-COMPUTED manifest root as `globalThis.__CL_GUARD_R__`
      // (Promise<Uint8Array>). A tampered bundle computes a different R →
      // wrong FinalKey → sealed assets fail to open. The build also injects
      // `__CL_REQUIRE_INTEGRITY_PROOF__ = true`, so deleting the bootstrap
      // (no R at all) fails derivation closed instead of falling back to the
      // static constant. In `vite dev` there is no injection and the SDK
      // falls back to the development defaults, as before.
      integrity: { manifestRoot: () => globalThis.__CL_GUARD_R__ },
    })
  } catch (error) {
    sdkStatus.textContent = 'failed to initialize'
    sdkStatus.dataset.ready = 'false'
    log(`create failed: ${(error as Error).message}`)
    console.error('CopyLocker create failed', error)
    return
  }

  sdkStatus.textContent = 'ready'
  sdkStatus.dataset.ready = 'true'
  // Debug/E2E hook: the Playwright suite (packages/web-e2e) drives the live
  // instance through this handle, e.g. to seal an asset with the session's
  // derived FinalKey and unseal it again. It exposes nothing the page's own
  // JS could not already reach.
  ;(window as unknown as Record<string, unknown>).__copylocker = {
    cl,
    sealAsset,
    decodeSealedAsset,
    productId,
  }
  if (cl.degradedFlags.storage) log('degraded: IndexedDB unavailable (in-memory store)')
  if (cl.degradedFlags.worker) log('degraded: Worker isolation inactive (main-thread core)')
  renderState(cl.state)

  $<HTMLFormElement>('#activate-form').addEventListener('submit', async (event) => {
    event.preventDefault()
    const key = $<HTMLInputElement>('[data-testid="license-key-input"]').value.trim()
    log('activate…')
    try {
      await cl.activate(key)
      log('activate ok')
    } catch (error) {
      const err = error as Error
      log(`activate failed: ${err.name}: ${err.message}`)
    }
  })

  $('[data-testid="deactivate-button"]').addEventListener('click', async () => {
    log('deactivate…')
    try {
      await cl.deactivate()
      log('deactivate ok')
    } catch (error) {
      log(`deactivate failed: ${(error as Error).message}`)
    }
  })

  $<HTMLFormElement>('#unseal-form').addEventListener('submit', async (event) => {
    event.preventDefault()
    const featureId = $<HTMLInputElement>('[data-testid="feature-id-input"]').value.trim()
    unsealOutput.dataset.kind = 'pending'
    unsealOutput.textContent = 'unsealing…'
    try {
      // Fetch the bytes, then unseal with the session-derived FinalKey (the
      // two-stage transform). `loadSealed(url, featureId)` is the sibling
      // entry point for `@copylocker/seal` KEK-registry assets.
      const response = await fetch('/demo-asset.clx')
      if (!response.ok) throw new Error(`asset fetch failed (${response.status})`)
      const bytes = await cl.unseal(featureId, await response.arrayBuffer())
      unsealOutput.dataset.kind = 'ok'
      unsealOutput.textContent = new TextDecoder().decode(bytes)
      log(`unseal ok (${bytes.byteLength} bytes)`)
    } catch (error) {
      // NotEntitledError / UnsealError / TransportError all land here; this
      // failure — not the advisory state — is the entitlement signal.
      unsealOutput.dataset.kind = 'error'
      unsealOutput.textContent = `${(error as Error).name}: ${(error as Error).message}`
      log(`unseal failed: ${(error as Error).name}: ${(error as Error).message}`)
    }
  })
}

void main()
