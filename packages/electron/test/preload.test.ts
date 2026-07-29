import { describe, expect, it, vi } from 'vitest'

import { installCopyLockerBridge, type PreloadRuntime } from '../src/preload/index'
import { CopyLockerCommandError, IPC_CHANNELS, type CopyLockerBridge } from '../src/shared'

function runtime(result: unknown = { ok: true, value: undefined }) {
  let exposed: CopyLockerBridge | undefined
  const invoke = vi.fn().mockResolvedValue(result)
  const value: PreloadRuntime = {
    contextBridge: {
      exposeInMainWorld: (key, api) => {
        expect(key).toBe('__cl')
        exposed = api
      },
    },
    ipcRenderer: { invoke },
    process: { contextIsolated: true, sandboxed: true },
  }
  return { exposed: () => exposed, invoke, value }
}

describe('@copylocker/electron preload', () => {
  it('exposes only the fixed bridge methods and channels', async () => {
    const test = runtime({ ok: true, value: new Uint8Array([3, 4]) })
    const bridge = installCopyLockerBridge(test.value)
    expect(test.exposed()).toBe(bridge)
    expect(Object.keys(bridge).sort()).toEqual([
      'activate',
      'challenge',
      'deactivate',
      'importOlk',
      'offlineImport',
      'offlineRequest',
      'state',
      'unseal',
    ])
    await expect(bridge.challenge(new Uint8Array([1]))).resolves.toEqual(new Uint8Array([3, 4]))
    expect(test.invoke).toHaveBeenCalledWith(IPC_CHANNELS.challenge, new Uint8Array([1]))
  })

  it('refuses a preload without isolation and sandboxing', () => {
    const test = runtime()
    test.value.process.contextIsolated = false
    expect(() => installCopyLockerBridge(test.value)).toThrow(/context isolation/)
  })

  it('turns failure envelopes into stable numeric errors', async () => {
    const test = runtime({ ok: false, error: { code: 4100, detail: 'hidden' } })
    const bridge = installCopyLockerBridge(test.value)
    await expect(bridge.activate('CL1-TEST')).rejects.toEqual(new CopyLockerCommandError(4100))
  })

  it('does not expose invoke rejection details', async () => {
    const test = runtime()
    test.invoke.mockRejectedValueOnce(new Error('main-process detail'))
    const bridge = installCopyLockerBridge(test.value)
    await expect(bridge.deactivate()).rejects.toEqual(new CopyLockerCommandError(3999))
  })
})
