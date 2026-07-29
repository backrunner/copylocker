import { describe, expect, it, vi } from 'vitest'

import {
  CopyLockerCommandError,
  CopyLockerRendererClient,
} from '../src/renderer/index'
import type { CopyLockerBridge } from '../src/shared'

function bridge(): CopyLockerBridge {
  return {
    activate: vi.fn().mockResolvedValue(undefined),
    deactivate: vi.fn().mockResolvedValue(undefined),
    state: vi.fn().mockResolvedValue({ state: 'active' }),
    unseal: vi.fn().mockResolvedValue(new Uint8Array([2])),
    challenge: vi.fn().mockResolvedValue(new Uint8Array([3])),
    offlineRequest: vi.fn().mockResolvedValue(new Uint8Array([4])),
    offlineImport: vi.fn().mockResolvedValue(undefined),
    importOlk: vi.fn().mockResolvedValue(undefined),
  }
}

describe('@copylocker/electron renderer', () => {
  it('exposes productive transformations and advisory state, never a boolean gate', async () => {
    const client = new CopyLockerRendererClient(bridge())
    expect('isLicensed' in client).toBe(false)
    expect('isValid' in client).toBe(false)
    await expect(client.unseal('pro', new Uint8Array([1]))).resolves.toEqual(
      new Uint8Array([2]),
    )
    await expect(client.state()).resolves.toEqual({ state: 'active' })
  })

  it('normalizes unknown bridge failures', async () => {
    const fake = bridge()
    vi.mocked(fake.activate).mockRejectedValueOnce(new Error('sensitive detail'))
    const client = new CopyLockerRendererClient(fake)
    await expect(client.activate('CL1-TEST')).rejects.toEqual(
      new CopyLockerCommandError(3999),
    )
  })
})
