/**
 * `@copylocker/svelte` — Svelte bindings for `@copylocker/web` (FR-WEB-010).
 *
 * A thin wrapper only: the store forwards to a `CopyLocker` instance and adds
 * no logic of its own — no caching of `unseal` results, no derived
 * entitlement booleans. The exposed `state` store is advisory (ADR-0004):
 * display it in the UI, never branch entitlement logic on it.
 */

import { readable, type Readable } from 'svelte/store'
import {
  CopyLocker,
  type CopyLockerOptions,
  type LicenseState,
} from '@copylocker/web'

/** The store surface. Every method forwards to the underlying instance. */
export interface CopyLockerStore {
  /**
   * Advisory license state, for UI display only (`$state` in components).
   * It can be stale, spoofed, or bypassed; never gate features on it
   * (ADR-0004).
   */
  state: Readable<LicenseState>
  activate: (key: string) => Promise<void>
  deactivate: () => Promise<void>
  unseal: (featureId: string, sealed: BufferSource) => Promise<Uint8Array>
  loadSealed: (url: string, featureId: string) => Promise<Uint8Array>
  /** Stop the scheduler and release the state subscription. */
  dispose: () => void
}

/**
 * Create the store. The `CopyLocker` instance is created asynchronously in
 * the browser; during SSR (no `window`) nothing is created — mount the store
 * on the client (see the `@copylocker/web` README "SSR" section).
 */
export function createCopyLockerStore(options: CopyLockerOptions): CopyLockerStore {
  let client: CopyLocker | null = null
  let createError: unknown
  let unsubscribe: (() => void) | undefined
  let disposed = false
  let setState: ((s: LicenseState) => void) | undefined

  const state = readable<LicenseState>('unlicensed', (set) => {
    setState = set
    if (client) set(client.state)
    return () => {
      if (setState === set) setState = undefined
    }
  })

  if (typeof window !== 'undefined') {
    void CopyLocker.create(options).then(
      (created) => {
        if (disposed) {
          created.dispose()
          return
        }
        client = created
        setState?.(created.state)
        unsubscribe = created.onStateChange((s) => setState?.(s))
      },
      (error: unknown) => {
        if (!disposed) createError = error
      },
    )
  }

  const requireClient = (): CopyLocker => {
    if (client) return client
    if (createError) throw createError
    throw new Error('CopyLocker: client is not ready yet')
  }

  return {
    state,
    activate: (key) => requireClient().activate(key),
    deactivate: () => requireClient().deactivate(),
    unseal: (featureId, sealed) => requireClient().unseal(featureId, sealed),
    loadSealed: (url, featureId) => requireClient().loadSealed(url, featureId),
    dispose: () => {
      disposed = true
      unsubscribe?.()
      client?.dispose()
      client = null
    },
  }
}
