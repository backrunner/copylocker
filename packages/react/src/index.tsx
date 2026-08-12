/**
 * `@copylocker/react` — React bindings for `@copylocker/web` (FR-WEB-010).
 *
 * A thin wrapper only: it forwards to {@link CopyLocker} and adds no logic of
 * its own — no caching of `unseal` results, no derived entitlement booleans.
 * The exposed `state` is advisory (ADR-0004): display it in the UI, never
 * branch entitlement logic on it.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactElement,
  type ReactNode,
} from 'react'
import {
  CopyLocker,
  type CopyLockerOptions,
  type LicenseState,
} from '@copylocker/web'

/** The hook surface. Every method forwards to the underlying instance. */
export interface CopyLockerApi {
  /**
   * Advisory license state, for UI display only. It can be stale, spoofed,
   * or bypassed; never gate features on it (ADR-0004).
   */
  state: LicenseState
  activate: (key: string) => Promise<void>
  deactivate: () => Promise<void>
  unseal: (featureId: string, sealed: BufferSource) => Promise<Uint8Array>
  loadSealed: (url: string, featureId: string) => Promise<Uint8Array>
}

interface CopyLockerContextValue {
  client: CopyLocker | null
  /** Set when creation from `options` rejected; rethrown by the methods. */
  createError: unknown
}

const CopyLockerContext = createContext<CopyLockerContextValue | null>(null)

export interface CopyLockerProviderProps {
  /**
   * Create an instance from these options. Creation runs in an effect, so
   * nothing touches the browser during SSR. Options are captured on first
   * render; later changes are ignored.
   */
  options?: CopyLockerOptions
  /** Use an already-created instance (takes precedence over `options`). */
  instance?: CopyLocker
  children?: ReactNode
}

function requireClient(client: CopyLocker | null, createError: unknown): CopyLocker {
  if (client) return client
  if (createError) throw createError
  throw new Error('CopyLocker: client is not ready yet')
}

export function CopyLockerProvider(props: CopyLockerProviderProps): ReactElement {
  const [owned, setOwned] = useState<CopyLocker | null>(null)
  const [createError, setCreateError] = useState<unknown>(null)
  const client = props.instance ?? owned

  useEffect(() => {
    if (props.instance) return
    const options = props.options
    if (!options) return
    let cancelled = false
    let created: CopyLocker | null = null
    void CopyLocker.create(options).then(
      (c) => {
        if (cancelled) {
          c.dispose()
          return
        }
        created = c
        setOwned(c)
      },
      (error: unknown) => {
        if (!cancelled) setCreateError(error)
      },
    )
    return () => {
      cancelled = true
      created?.dispose()
    }
    // The instance is created once per provider lifetime; `instance` switches
    // between the provided and the owned client.
  }, [props.instance]) // eslint-disable-line react-hooks/exhaustive-deps

  const value = useMemo<CopyLockerContextValue>(() => ({ client, createError }), [client, createError])
  return <CopyLockerContext.Provider value={value}>{props.children}</CopyLockerContext.Provider>
}

/** Access the CopyLocker instance provided by {@link CopyLockerProvider}. */
export function useCopyLocker(): CopyLockerApi {
  const ctx = useContext(CopyLockerContext)
  if (!ctx) {
    throw new Error('useCopyLocker must be used within a <CopyLockerProvider>')
  }
  const { client, createError } = ctx
  const subscribe = useCallback(
    (notify: () => void): (() => void) => {
      if (!client) return () => {}
      return client.onStateChange(() => notify())
    },
    [client],
  )
  const getSnapshot = useCallback((): LicenseState => client?.state ?? 'unlicensed', [client])
  const getServerSnapshot = useCallback((): LicenseState => 'unlicensed', [])
  const state = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot)

  return useMemo<CopyLockerApi>(
    () => ({
      state,
      activate: (key) => requireClient(client, createError).activate(key),
      deactivate: () => requireClient(client, createError).deactivate(),
      unseal: (featureId, sealed) => requireClient(client, createError).unseal(featureId, sealed),
      loadSealed: (url, featureId) => requireClient(client, createError).loadSealed(url, featureId),
    }),
    [client, createError, state],
  )
}
