/**
 * `@copylocker/vue` — Vue 3 bindings for `@copylocker/web` (FR-WEB-010).
 *
 * A thin wrapper only: the plugin provides a `CopyLocker` instance and the
 * composable forwards to it — no caching of `unseal` results, no derived
 * entitlement booleans. The exposed `state` is advisory (ADR-0004): display
 * it in the UI, never branch entitlement logic on it.
 */

import {
  inject,
  readonly,
  ref,
  shallowRef,
  type App,
  type InjectionKey,
  type Plugin,
  type Ref,
} from 'vue'
import {
  CopyLocker,
  type CopyLockerOptions,
  type LicenseState,
} from '@copylocker/web'

/** The composable surface. Every method forwards to the underlying instance. */
export interface CopyLockerApi {
  /**
   * Advisory license state, for UI display only. It can be stale, spoofed,
   * or bypassed; never gate features on it (ADR-0004).
   */
  state: Readonly<Ref<LicenseState>>
  activate: (key: string) => Promise<void>
  deactivate: () => Promise<void>
  unseal: (featureId: string, sealed: BufferSource) => Promise<Uint8Array>
  loadSealed: (url: string, featureId: string) => Promise<Uint8Array>
}

interface CopyLockerContext {
  client: Ref<CopyLocker | null>
  state: Ref<LicenseState>
  /** Set when creation from `options` rejected; rethrown by the methods. */
  createError: Ref<unknown>
}

const CopyLockerKey: InjectionKey<CopyLockerContext> = Symbol('CopyLocker')

export interface CopyLockerPluginOptions {
  /**
   * Create an instance from these options. Creation is async and only runs
   * in the browser (no `window`, no creation); `state` reads `'unlicensed'`
   * and the methods throw until it resolves. Nothing runs until `install`,
   * so module evaluation stays SSR-safe.
   */
  options?: CopyLockerOptions
  /** Use an already-created instance (takes precedence over `options`). */
  instance?: CopyLocker
}

type AppWithUnmount = App & { onUnmount?: (cb: () => void) => void }

/** Vue plugin: `app.use(createCopyLocker({ options }))`. */
export function createCopyLocker(plugin: CopyLockerPluginOptions): Plugin {
  return {
    install(app: App) {
      const client = shallowRef<CopyLocker | null>(plugin.instance ?? null)
      const state = ref<LicenseState>(plugin.instance?.state ?? 'unlicensed')
      const createError = shallowRef<unknown>(null)
      let unsubscribe: (() => void) | undefined
      let cancelled = false

      const attach = (c: CopyLocker): void => {
        if (cancelled) {
          c.dispose()
          return
        }
        client.value = c
        state.value = c.state
        unsubscribe = c.onStateChange((s) => {
          state.value = s
        })
      }

      if (plugin.instance) {
        attach(plugin.instance)
      } else if (plugin.options && typeof window !== 'undefined') {
        void CopyLocker.create(plugin.options).then(attach, (error: unknown) => {
          if (!cancelled) createError.value = error
        })
      }

      app.provide(CopyLockerKey, { client, state, createError })

      // Vue 3.5+: release the subscription (and an owned instance's
      // scheduler) with the app. A provided instance is left to its owner.
      ;(app as AppWithUnmount).onUnmount?.(() => {
        cancelled = true
        unsubscribe?.()
        if (!plugin.instance) client.value?.dispose()
      })
    },
  }
}

/** Access the CopyLocker context installed by {@link createCopyLocker}. */
export function useCopyLocker(): CopyLockerApi {
  const ctx = inject(CopyLockerKey, null)
  if (!ctx) {
    throw new Error('useCopyLocker requires app.use(createCopyLocker(...))')
  }
  const requireClient = (): CopyLocker => {
    if (ctx.client.value) return ctx.client.value
    if (ctx.createError.value) throw ctx.createError.value
    throw new Error('CopyLocker: client is not ready yet')
  }
  return {
    state: readonly(ctx.state),
    activate: (key) => requireClient().activate(key),
    deactivate: () => requireClient().deactivate(),
    unseal: (featureId, sealed) => requireClient().unseal(featureId, sealed),
    loadSealed: (url, featureId) => requireClient().loadSealed(url, featureId),
  }
}
