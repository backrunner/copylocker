// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { get } from 'svelte/store'
import { CopyLocker, type LicenseState } from '@copylocker/web'
import { createCopyLockerStore } from '../src/index.js'

type Listener = (s: LicenseState) => void

interface MockClient {
  state: LicenseState
  setState: (s: LicenseState) => void
  onStateChange: ReturnType<typeof vi.fn>
  activate: ReturnType<typeof vi.fn>
  deactivate: ReturnType<typeof vi.fn>
  unseal: ReturnType<typeof vi.fn>
  loadSealed: ReturnType<typeof vi.fn>
  dispose: ReturnType<typeof vi.fn>
}

function makeMockClient(initial: LicenseState = 'unlicensed'): MockClient {
  let state = initial
  const listeners = new Set<Listener>()
  return {
    get state() {
      return state
    },
    setState(s: LicenseState) {
      state = s
      for (const listener of [...listeners]) listener(s)
    },
    onStateChange: vi.fn((listener: Listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    }),
    activate: vi.fn(async () => {}),
    deactivate: vi.fn(async () => {}),
    unseal: vi.fn(async () => new Uint8Array([1, 2, 3])),
    loadSealed: vi.fn(async () => new Uint8Array([4, 5])),
    dispose: vi.fn(),
  }
}

vi.mock('@copylocker/web', () => ({
  CopyLocker: { create: vi.fn() },
}))

const createMock = vi.mocked(CopyLocker.create)

const OPTIONS = {
  serverUrl: 'https://license.example.com',
  productId: 'demo',
  rootPins: ['00'.repeat(32)],
}

let client: MockClient

beforeEach(() => {
  vi.clearAllMocks()
  client = makeMockClient()
  createMock.mockResolvedValue(client as unknown as CopyLocker)
})

async function createReadyStore(): Promise<ReturnType<typeof createCopyLockerStore>> {
  const store = createCopyLockerStore(OPTIONS)
  await vi.waitFor(() => expect(client.onStateChange).toHaveBeenCalled())
  return store
}

describe('createCopyLockerStore', () => {
  it('creates an instance from options and satisfies the store contract', async () => {
    const store = createCopyLockerStore(OPTIONS)
    const seen: LicenseState[] = []
    const stop = store.state.subscribe((s) => seen.push(s))
    expect(seen).toEqual(['unlicensed'])
    await vi.waitFor(() => expect(createMock).toHaveBeenCalledWith(OPTIONS))
    stop()
  })

  it('publishes advisory state changes to subscribers', async () => {
    const store = await createReadyStore()
    const seen: LicenseState[] = []
    const stop = store.state.subscribe((s) => seen.push(s))
    expect(get(store.state)).toBe('unlicensed')
    client.setState('active')
    client.setState('grace')
    expect(seen).toEqual(['unlicensed', 'active', 'grace'])
    stop()
  })

  it('reflects the current state for late subscribers', async () => {
    const store = await createReadyStore()
    const stop = store.state.subscribe(() => {})
    client.setState('active')
    stop()
    expect(get(store.state)).toBe('active')
  })

  it('forwards method calls to the instance', async () => {
    const store = await createReadyStore()
    const sealed = new Uint8Array([9])
    await store.activate('KEY-1')
    await store.deactivate()
    await store.unseal('feat', sealed)
    await store.loadSealed('https://cdn.example.com/a.sealed', 'feat')
    expect(client.activate).toHaveBeenCalledWith('KEY-1')
    expect(client.deactivate).toHaveBeenCalledTimes(1)
    expect(client.unseal).toHaveBeenCalledWith('feat', sealed)
    expect(client.loadSealed).toHaveBeenCalledWith('https://cdn.example.com/a.sealed', 'feat')
  })

  it('throws a not-ready error before the instance exists', () => {
    createMock.mockReturnValue(new Promise(() => {}) as Promise<CopyLocker>)
    const store = createCopyLockerStore(OPTIONS)
    expect(get(store.state)).toBe('unlicensed')
    expect(() => store.activate('K')).toThrow(/not ready/)
  })

  it('rethrows a creation failure from the methods', async () => {
    const failure = new Error('create boom')
    createMock.mockRejectedValue(failure)
    const store = createCopyLockerStore(OPTIONS)
    expect(get(store.state)).toBe('unlicensed')
    await vi.waitFor(() => expect(() => store.activate('K')).toThrow(failure))
  })

  it('creates nothing during SSR (no window)', () => {
    vi.stubGlobal('window', undefined)
    const store = createCopyLockerStore(OPTIONS)
    vi.unstubAllGlobals()
    expect(createMock).not.toHaveBeenCalled()
    expect(get(store.state)).toBe('unlicensed')
    expect(() => store.activate('K')).toThrow(/not ready/)
  })

  it('disposes the instance and stops publishing', async () => {
    const store = await createReadyStore()
    const seen: LicenseState[] = []
    store.state.subscribe((s) => seen.push(s))
    store.dispose()
    expect(client.dispose).toHaveBeenCalledTimes(1)
    client.setState('locked')
    expect(seen).toEqual(['unlicensed'])
  })
})
