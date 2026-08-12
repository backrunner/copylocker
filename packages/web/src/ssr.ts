/**
 * `@copylocker/web/ssr` — the no-op SSR stub (`40-web-sdk-wasm-ts.md §4.5`,
 * FR-WEB-009).
 *
 * Importable in Node / server-side rendering with **zero side effects**: this
 * module never touches `window`, `document`, `indexedDB`, the network, or the
 * wasm core. `CopyLocker.create` resolves to an explicitly marked no-op
 * instance (`isSsrStub === true`) so isomorphic components can call the API
 * unconditionally during SSR; every licensing operation rejects with a clear
 * error. Render the real client on top of it in the browser:
 *
 * ```ts
 * import { CopyLocker as SsrCopyLocker } from '@copylocker/web/ssr'
 *
 * let cl: CopyLocker | SsrCopyLocker = await SsrCopyLocker.create(opts)
 * if (typeof window !== 'undefined') {
 *   const { CopyLocker } = await import('@copylocker/web')
 *   cl = await CopyLocker.create(opts)
 * }
 * ```
 *
 * With Next.js, prefer `dynamic(() => import(...), { ssr: false })` for the
 * real SDK and keep this stub for the server render.
 */

import type { DegradedFlags, LicenseState } from './index.js'

function ssrError(): Error {
  return new Error(
    'CopyLocker: `@copylocker/web/ssr` is a server-side stub — create the real client from `@copylocker/web` in the browser',
  )
}

/**
 * No-op stand-in for the real `CopyLocker`. Structurally mirrors the public
 * API; all licensing operations reject. Instances are explicitly marked so
 * application code can detect the stub (`cl.isSsrStub === true`).
 */
export class CopyLocker {
  /** Always true for the SSR stub; absent on the real client. */
  readonly isSsrStub = true
  /** Everything is degraded: nothing ran, nothing persisted. */
  readonly degradedFlags: DegradedFlags = { storage: true, worker: true }

  private constructor() {}

  /** Resolve to a no-op instance. Never touches the DOM, storage, or wasm. */
  static create(_options: unknown): Promise<CopyLocker> {
    return Promise.resolve(new CopyLocker())
  }

  activate(_key: string): Promise<never> {
    return Promise.reject(ssrError())
  }

  activateWithAccount(_token: string): Promise<never> {
    return Promise.reject(ssrError())
  }

  deactivate(): Promise<never> {
    return Promise.reject(ssrError())
  }

  unseal(_featureId: string, _sealed: BufferSource): Promise<never> {
    return Promise.reject(ssrError())
  }

  loadSealed(_url: string, _featureId: string): Promise<never> {
    return Promise.reject(ssrError())
  }

  /**
   * @deprecated for gating — advisory only
   *
   * Always `'unlicensed'` on the stub; never branch entitlement logic on it.
   */
  get state(): LicenseState {
    return 'unlicensed'
  }

  /** No-op subscription; returns an unsubscribe function. */
  onStateChange(_listener: (s: LicenseState) => void): () => void {
    return () => {}
  }

  hintOnline(): void {}
  dispose(): void {}
}

export type { CopyLockerOptions, DegradedFlags, LicenseState } from './index.js'
export type { IntegrityHooks } from './derive.js'
