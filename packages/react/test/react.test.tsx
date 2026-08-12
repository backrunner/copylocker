// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createElement, type ReactNode } from 'react'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { CopyLocker, type LicenseState } from '@copylocker/web'
import { CopyLockerProvider, useCopyLocker, type CopyLockerApi } from '../src/index.js'

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
  cleanup()
  vi.clearAllMocks()
  client = makeMockClient()
  createMock.mockResolvedValue(client as unknown as CopyLocker)
})

function Probe({ onApi }: { onApi: (api: CopyLockerApi) => void }): ReactNode {
  onApi(useCopyLocker())
  return null
}

function StateView(): ReactNode {
  const { state } = useCopyLocker()
  return createElement('span', null, state)
}

describe('CopyLockerProvider', () => {
  it('creates an instance from options and exposes its state', async () => {
    render(
      createElement(CopyLockerProvider, { options: OPTIONS }, createElement(StateView)),
    )
    expect(screen.getByText('unlicensed')).toBeTruthy()
    await waitFor(() => expect(createMock).toHaveBeenCalledWith(OPTIONS))
  })

  it('uses a provided instance instead of creating one', () => {
    client.setState('active')
    render(
      createElement(CopyLockerProvider, { instance: client as unknown as CopyLocker },
        createElement(StateView)),
    )
    expect(createMock).not.toHaveBeenCalled()
    expect(screen.getByText('active')).toBeTruthy()
  })

  it('re-renders on advisory state changes', async () => {
    render(
      createElement(CopyLockerProvider, { instance: client as unknown as CopyLocker },
        createElement(StateView)),
    )
    expect(screen.getByText('unlicensed')).toBeTruthy()
    act(() => client.setState('grace'))
    expect(screen.getByText('grace')).toBeTruthy()
  })

  it('disposes an owned instance on unmount', async () => {
    const { unmount } = render(
      createElement(CopyLockerProvider, { options: OPTIONS }, createElement(StateView)),
    )
    // Wait until the created client reached the hook (subscription is live).
    await waitFor(() => expect(client.onStateChange).toHaveBeenCalled())
    unmount()
    expect(client.dispose).toHaveBeenCalledTimes(1)
  })
})

describe('useCopyLocker', () => {
  it('throws outside a provider', () => {
    expect(() => render(createElement(StateView))).toThrow(/CopyLockerProvider/)
  })

  it('forwards method calls to the instance', async () => {
    let api: CopyLockerApi | null = null
    render(
      createElement(CopyLockerProvider, { instance: client as unknown as CopyLocker },
        createElement(Probe, { onApi: (a: CopyLockerApi) => { api = a } })),
    )
    expect(api).not.toBeNull()
    const sealed = new Uint8Array([9])
    await api!.activate('KEY-1')
    await api!.deactivate()
    await api!.unseal('feat', sealed)
    await api!.loadSealed('https://cdn.example.com/a.sealed', 'feat')
    expect(client.activate).toHaveBeenCalledWith('KEY-1')
    expect(client.deactivate).toHaveBeenCalledTimes(1)
    expect(client.unseal).toHaveBeenCalledWith('feat', sealed)
    expect(client.loadSealed).toHaveBeenCalledWith('https://cdn.example.com/a.sealed', 'feat')
  })

  it('throws a not-ready error before the instance exists', async () => {
    createMock.mockReturnValue(new Promise(() => {}) as Promise<CopyLocker>)
    let api: CopyLockerApi | null = null
    render(
      createElement(CopyLockerProvider, { options: OPTIONS },
        createElement(Probe, { onApi: (a: CopyLockerApi) => { api = a } })),
    )
    expect(api!.state).toBe('unlicensed')
    expect(() => api!.activate('K')).toThrow(/not ready/)
  })

  it('rethrows a creation failure from the methods', async () => {
    const failure = new Error('create boom')
    createMock.mockRejectedValue(failure)
    let api: CopyLockerApi | null = null
    render(
      createElement(CopyLockerProvider, { options: OPTIONS },
        createElement(Probe, { onApi: (a: CopyLockerApi) => { api = a } })),
    )
    expect(api!.state).toBe('unlicensed')
    await waitFor(() => expect(() => api!.activate('K')).toThrow(failure))
  })
})
