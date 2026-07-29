import {
  CopyLockerCommandError,
  HOST_UNKNOWN_FATAL,
  IPC_CHANNELS,
  requireBytes,
  requireText,
  type CopyLockerBridge,
  type IpcResult,
  type NativeState,
} from '../shared'

const MAX_KEY_BYTES = 4 * 1024
const MAX_FEATURE_BYTES = 1024
const MAX_ASSET_BYTES = 64 * 1024 * 1024
const MAX_CHALLENGE_BYTES = 64 * 1024
const MAX_OFFLINE_RESPONSE_BYTES = 1024 * 1024
const MAX_ARMORED_OLK_BYTES = 2 * 1024 * 1024

export interface PreloadRuntime {
  contextBridge: {
    exposeInMainWorld(key: string, api: CopyLockerBridge): void
  }
  ipcRenderer: {
    invoke(channel: string, ...args: unknown[]): Promise<unknown>
  }
  process: {
    contextIsolated?: boolean
    sandboxed?: boolean
  }
}

/** Install the fixed renderer bridge from a sandboxed preload script. */
export function installCopyLockerBridge(runtime: PreloadRuntime = loadRuntime()): CopyLockerBridge {
  if (runtime.process.contextIsolated !== true || runtime.process.sandboxed !== true) {
    throw new Error('CopyLocker preload requires context isolation and renderer sandboxing')
  }

  const bridge: CopyLockerBridge = Object.freeze({
    activate: async (key: string): Promise<void> => {
      await invoke<void>(
        runtime,
        IPC_CHANNELS.activate,
        requireText(key, MAX_KEY_BYTES, 'activation key'),
      )
    },
    deactivate: async (): Promise<void> => {
      await invoke<void>(runtime, IPC_CHANNELS.deactivate)
    },
    state: async (): Promise<NativeState> => {
      const state = await invoke<unknown>(runtime, IPC_CHANNELS.state)
      if (!state || typeof state !== 'object' || typeof (state as NativeState).state !== 'string') {
        throw new CopyLockerCommandError(HOST_UNKNOWN_FATAL)
      }
      return { state: (state as NativeState).state }
    },
    unseal: async (feature: string, data: Uint8Array): Promise<Uint8Array> => {
      const output = await invoke<unknown>(
        runtime,
        IPC_CHANNELS.unseal,
        requireText(feature, MAX_FEATURE_BYTES, 'feature'),
        requireBytes(data, MAX_ASSET_BYTES, 'sealed asset'),
      )
      return outputBytes(output)
    },
    challenge: async (input: Uint8Array): Promise<Uint8Array> => {
      const output = await invoke<unknown>(
        runtime,
        IPC_CHANNELS.challenge,
        requireBytes(input, MAX_CHALLENGE_BYTES, 'challenge'),
      )
      return outputBytes(output)
    },
    offlineRequest: async (key: string): Promise<Uint8Array> => {
      const output = await invoke<unknown>(
        runtime,
        IPC_CHANNELS.offlineRequest,
        requireText(key, MAX_KEY_BYTES, 'activation key'),
      )
      return outputBytes(output)
    },
    offlineImport: async (data: Uint8Array): Promise<void> => {
      await invoke<void>(
        runtime,
        IPC_CHANNELS.offlineImport,
        requireBytes(data, MAX_OFFLINE_RESPONSE_BYTES, 'offline response'),
      )
    },
    importOlk: async (data: string): Promise<void> => {
      await invoke<void>(
        runtime,
        IPC_CHANNELS.importOlk,
        requireText(data, MAX_ARMORED_OLK_BYTES, 'offline license key'),
      )
    },
  })

  runtime.contextBridge.exposeInMainWorld('__cl', bridge)
  return bridge
}

async function invoke<T>(
  runtime: PreloadRuntime,
  channel: string,
  ...args: unknown[]
): Promise<T> {
  let raw: unknown
  try {
    raw = await runtime.ipcRenderer.invoke(channel, ...args)
  } catch {
    throw new CopyLockerCommandError(HOST_UNKNOWN_FATAL)
  }
  if (!raw || typeof raw !== 'object' || typeof (raw as { ok?: unknown }).ok !== 'boolean') {
    throw new CopyLockerCommandError(HOST_UNKNOWN_FATAL)
  }
  const result = raw as IpcResult<T>
  if (result.ok) return result.value
  const code = result.error?.code
  throw new CopyLockerCommandError(Number.isSafeInteger(code) ? code : HOST_UNKNOWN_FATAL)
}

function outputBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new CopyLockerCommandError(HOST_UNKNOWN_FATAL)
  }
  return Uint8Array.from(value)
}

function loadRuntime(): PreloadRuntime {
  const electron = require('electron') as Pick<PreloadRuntime, 'contextBridge' | 'ipcRenderer'>
  return {
    ...electron,
    process: process as unknown as PreloadRuntime['process'],
  }
}
