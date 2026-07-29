import { beforeEach, describe, expect, it, vi } from 'vitest'

const { invoke, listen } = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
}))

vi.mock('@tauri-apps/api/core', () => ({ invoke }))
vi.mock('@tauri-apps/api/event', () => ({ listen }))

import {
  CopyLockerCommandError,
  activate,
  challenge,
  onStateChanged,
  state,
  unseal,
} from '../src/index'

describe('@copylocker/tauri', () => {
  beforeEach(() => {
    invoke.mockReset()
    listen.mockReset()
  })

  it('uses only the fixed plugin command namespace', async () => {
    invoke.mockResolvedValueOnce(undefined)
    await activate('CL1-TEST')
    expect(invoke).toHaveBeenCalledWith('plugin:copylocker|cl_activate', { key: 'CL1-TEST' })

    invoke.mockResolvedValueOnce({ state: 'active', reason: null })
    await state()
    expect(invoke).toHaveBeenLastCalledWith('plugin:copylocker|cl_state', undefined)
  })

  it('forwards productive byte operations without exposing a verdict', async () => {
    invoke.mockResolvedValueOnce([1, 2, 3])
    await expect(unseal('pro', new Uint8Array([9]))).resolves.toEqual(new Uint8Array([1, 2, 3]))

    invoke.mockResolvedValueOnce([4, 5])
    await expect(challenge(new Uint8Array([8]))).resolves.toEqual(new Uint8Array([4, 5]))
  })

  it('rejects invalid input before IPC', async () => {
    await expect(activate('')).rejects.toBeInstanceOf(TypeError)
    await expect(unseal('', new Uint8Array([1]))).rejects.toBeInstanceOf(TypeError)
    await expect(challenge(new Uint8Array())).rejects.toBeInstanceOf(TypeError)
    expect(invoke).not.toHaveBeenCalled()
  })

  it('normalizes native errors to stable numeric codes', async () => {
    invoke.mockRejectedValueOnce({ code: 4100, secret: 'must not cross the wrapper' })
    await expect(activate('CL1-TEST')).rejects.toEqual(new CopyLockerCommandError(4100))
  })

  it('subscribes only to the fixed state event', async () => {
    const unlisten = vi.fn()
    listen.mockResolvedValueOnce(unlisten)
    const handler = vi.fn()
    await expect(onStateChanged(handler)).resolves.toBe(unlisten)
    expect(listen).toHaveBeenCalledWith('copylocker://state-changed', expect.any(Function))
  })
})
