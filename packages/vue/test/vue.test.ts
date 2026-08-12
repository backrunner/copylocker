// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, nextTick } from 'vue'
import { CopyLocker, type LicenseState } from '@copylocker/web'
import { createCopyLocker, useCopyLocker, type CopyLockerApi } from '../src/index.js'

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

function mountWith(pluginOptions: Parameters<typeof createCopyLocker>[0]): {
  api: CopyLockerApi
  unmount: () => void
} {
  let api: CopyLockerApi | null = null
  const app = createApp(
    defineComponent({
      setup() {
        api = useCopyLocker()
        return () => null
      },
    }),
  )
  app.use(createCopyLocker(pluginOptions))
  app.mount(document.createElement('div'))
  if (!api) throw new Error('composable did not run')
  return { api, unmount: () => app.unmount() }
}

describe('createCopyLocker plugin', () => {
  it('creates an instance from options and exposes its state', async () => {
    const { api } = mountWith({ options: OPTIONS })
    expect(api.state.value).toBe('unlicensed')
    await vi.waitFor(() => expect(createMock).toHaveBeenCalledWith(OPTIONS))
    await vi.waitFor(() => expect(client.onStateChange).toHaveBeenCalled())
    expect(api.state.value).toBe('unlicensed')
  })

  it('uses a provided instance instead of creating one', () => {
    client.setState('active')
    mountWith({ instance: client as unknown as CopyLocker })
    expect(createMock).not.toHaveBeenCalled()
  })

  it('tracks advisory state changes reactively', async () => {
    const { api } = mountWith({ instance: client as unknown as CopyLocker })
    expect(api.state.value).toBe('unlicensed')
    client.setState('grace')
    await nextTick()
    expect(api.state.value).toBe('grace')
  })
})

describe('useCopyLocker', () => {
  it('throws when the plugin is not installed', () => {
    const app = createApp(
      defineComponent({
        setup() {
          expect(() => useCopyLocker()).toThrow(/createCopyLocker/)
          return () => null
        },
      }),
    )
    app.mount(document.createElement('div'))
  })

  it('forwards method calls to the instance', async () => {
    const { api } = mountWith({ instance: client as unknown as CopyLocker })
    const sealed = new Uint8Array([9])
    await api.activate('KEY-1')
    await api.deactivate()
    await api.unseal('feat', sealed)
    await api.loadSealed('https://cdn.example.com/a.sealed', 'feat')
    expect(client.activate).toHaveBeenCalledWith('KEY-1')
    expect(client.deactivate).toHaveBeenCalledTimes(1)
    expect(client.unseal).toHaveBeenCalledWith('feat', sealed)
    expect(client.loadSealed).toHaveBeenCalledWith('https://cdn.example.com/a.sealed', 'feat')
  })

  it('throws a not-ready error before the instance exists', () => {
    createMock.mockReturnValue(new Promise(() => {}) as Promise<CopyLocker>)
    const { api } = mountWith({ options: OPTIONS })
    expect(api.state.value).toBe('unlicensed')
    expect(() => api.activate('K')).toThrow(/not ready/)
  })

  it('rethrows a creation failure from the methods', async () => {
    const failure = new Error('create boom')
    createMock.mockRejectedValue(failure)
    const { api } = mountWith({ options: OPTIONS })
    expect(api.state.value).toBe('unlicensed')
    await vi.waitFor(() => expect(() => api.activate('K')).toThrow(failure))
  })

  it('creates nothing during SSR (no window)', () => {
    vi.stubGlobal('window', undefined)
    const app = createApp(defineComponent({ setup: () => () => null }))
    app.use(createCopyLocker({ options: OPTIONS }))
    vi.unstubAllGlobals()
    expect(createMock).not.toHaveBeenCalled()
  })
})
