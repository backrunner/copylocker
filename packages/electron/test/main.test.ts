import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  CopyLocker,
  SecurityConfigurationError,
  type CopyLockerConfig,
  type ElectronMainLike,
  type InvokeEventLike,
  type NativeClientLike,
  type NativeModuleLike,
  type WebContentsLike,
} from '../src/main/index'
import {
  HOST_NOT_ENTITLED,
  HOST_TRANSIENT,
  IPC_CHANNELS,
  type IpcResult,
} from '../src/shared'

function secureContents(): WebContentsLike {
  return {
    getLastWebPreferences: () => ({
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    }),
  }
}

function event(sender: WebContentsLike = secureContents()): InvokeEventLike {
  return { sender, senderFrame: { parent: null } }
}

function config(): CopyLockerConfig {
  return {
    serverUrl: 'https://license.example/',
    appId: 'com.example.app',
    productId: 'product',
    appVersion: '1.0.0',
    releaseId: 'release-a',
    buildFingerprint: 'build-a',
    currentRootKey: new Uint8Array(32).fill(1),
    fingerprintSalt: new Uint8Array(32).fill(2),
    variantId: 7,
    variantConst: new Uint8Array(32).fill(3),
    expectedModuleDigest: new Uint8Array(32).fill(4),
  }
}

function harness() {
  const handlers = new Map<string, (...args: unknown[]) => unknown>()
  const listeners = new Set<(event: unknown, contents: WebContentsLike) => void>()
  const native: NativeClientLike = {
    activate: vi.fn().mockResolvedValue(undefined),
    deactivate: vi.fn().mockResolvedValue(undefined),
    state: vi.fn().mockReturnValue({ state: 'unlicensed' }),
    unseal: vi.fn().mockResolvedValue(Buffer.from([7, 8])),
    challenge: vi.fn().mockResolvedValue(Buffer.from([9])),
    offlineRequest: vi.fn().mockResolvedValue(Buffer.from([10])),
    offlineImport: vi.fn().mockResolvedValue(undefined),
    importOlk: vi.fn().mockResolvedValue(undefined),
  }
  const create = vi.fn().mockResolvedValue(native)
  const nativeModule: NativeModuleLike = {
    CopyLockerNative: { create },
    nativeBindingPath: '/tmp/copylocker.darwin-arm64.node',
  }
  const windows: Array<{ webContents: WebContentsLike }> = []
  const electron: ElectronMainLike = {
    app: {
      getAppPath: () => '/Applications/Test.app/Contents/Resources/app.asar',
      on: (_event, listener) => listeners.add(listener),
      removeListener: (_event, listener) => listeners.delete(listener),
    },
    ipcMain: {
      handle: (channel, handler) => {
        if (handlers.has(channel)) throw new Error('duplicate handler')
        handlers.set(channel, handler as (...args: unknown[]) => unknown)
      },
      removeHandler: (channel) => {
        handlers.delete(channel)
      },
    },
    BrowserWindow: {
      getAllWindows: () => windows,
    },
  }
  return { create, electron, handlers, listeners, native, nativeModule, windows }
}

describe('@copylocker/electron main process', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('passes the loaded node and packaged ASAR paths into native evidence', async () => {
    const test = harness()
    await CopyLocker.create(config(), { native: test.nativeModule, electron: test.electron })
    expect(test.create).toHaveBeenCalledOnce()
    expect(test.create.mock.calls[0]?.[0]).toMatchObject({
      evidence: {
        modulePath: '/tmp/copylocker.darwin-arm64.node',
        asarPath: '/Applications/Test.app/Contents/Resources/app.asar',
      },
    })
  })

  it('registers only the fixed channel set and detaches idempotently', async () => {
    const test = harness()
    const client = await CopyLocker.create(config(), {
      native: test.nativeModule,
      electron: test.electron,
    })
    const detach = client.attachIpc()
    expect([...test.handlers.keys()].sort()).toEqual(Object.values(IPC_CHANNELS).sort())
    expect(test.listeners.size).toBe(1)
    detach()
    detach()
    expect(test.handlers.size).toBe(0)
    expect(test.listeners.size).toBe(0)
  })

  it('enforces the main-process feature allowlist', async () => {
    const test = harness()
    const client = await CopyLocker.create(config(), {
      native: test.nativeModule,
      electron: test.electron,
    })
    client.attachIpc({ allowedFeatures: ['pro'] })
    const unseal = test.handlers.get(IPC_CHANNELS.unseal)!

    const denied = (await unseal(event(), 'other', new Uint8Array([1]))) as IpcResult<Uint8Array>
    expect(denied).toEqual({ ok: false, error: { code: HOST_NOT_ENTITLED } })
    expect(test.native.unseal).not.toHaveBeenCalled()

    const allowed = (await unseal(event(), 'pro', new Uint8Array([1]))) as IpcResult<Uint8Array>
    expect(allowed).toEqual({ ok: true, value: new Uint8Array([7, 8]) })
  })

  it('rate-limits each renderer by requests and bytes', async () => {
    const test = harness()
    const client = await CopyLocker.create(config(), {
      native: test.nativeModule,
      electron: test.electron,
    })
    client.attachIpc({ rateLimit: { maxRequests: 1, maxBytes: 1, windowMs: 60_000 } })
    const state = test.handlers.get(IPC_CHANNELS.state)!
    const senderEvent = event()
    await expect(state(senderEvent)).resolves.toEqual({
      ok: true,
      value: { state: 'unlicensed' },
    })
    await expect(state(senderEvent)).resolves.toEqual({
      ok: false,
      error: { code: HOST_TRANSIENT },
    })
  })

  it('rejects insecure windows and non-main frames', async () => {
    const test = harness()
    test.windows.push({
      webContents: {
        getLastWebPreferences: () => ({
          contextIsolation: false,
          nodeIntegration: true,
          sandbox: false,
        }),
      },
    })
    const client = await CopyLocker.create(config(), {
      native: test.nativeModule,
      electron: test.electron,
    })
    expect(() => client.attachIpc()).toThrow(SecurityConfigurationError)

    const clean = harness()
    const attached = await CopyLocker.create(config(), {
      native: clean.nativeModule,
      electron: clean.electron,
    })
    attached.attachIpc()
    const state = clean.handlers.get(IPC_CHANNELS.state)!
    const sender = secureContents()
    const denied = await state({ sender, senderFrame: { parent: { parent: null } } })
    expect(denied).toEqual({ ok: false, error: { code: HOST_NOT_ENTITLED } })
  })

  it('normalizes native failures without crossing error details', async () => {
    const test = harness()
    vi.mocked(test.native.activate).mockRejectedValueOnce(new Error('CL:4100'))
    const client = await CopyLocker.create(config(), {
      native: test.nativeModule,
      electron: test.electron,
    })
    client.attachIpc()
    const activate = test.handlers.get(IPC_CHANNELS.activate)!
    const result = await activate(event(), 'CL1-TEST')
    expect(result).toEqual({ ok: false, error: { code: 4100 } })
    expect(JSON.stringify(result)).not.toContain('secret')
  })
})
