export const HOST_UNKNOWN_FATAL = 3999
export const HOST_TRANSIENT = 2000
export const HOST_INVALID_ARGUMENT = 4010
export const HOST_NOT_ENTITLED = 4100

export const IPC_CHANNELS = Object.freeze({
  state: 'cl:state',
  activate: 'cl:activate',
  deactivate: 'cl:deactivate',
  unseal: 'cl:unseal',
  challenge: 'cl:challenge',
  offlineRequest: 'cl:offline-request',
  offlineImport: 'cl:offline-import',
  importOlk: 'cl:import-olk',
})

export type CopyLockerChannel = (typeof IPC_CHANNELS)[keyof typeof IPC_CHANNELS]

export interface NativeState {
  state: string
}

export interface CopyLockerBridge {
  activate(key: string): Promise<void>
  deactivate(): Promise<void>
  /** Advisory UI state only. Never use this value as a product gate. */
  state(): Promise<NativeState>
  unseal(feature: string, data: Uint8Array): Promise<Uint8Array>
  challenge(input: Uint8Array): Promise<Uint8Array>
  offlineRequest(key: string): Promise<Uint8Array>
  offlineImport(data: Uint8Array): Promise<void>
  importOlk(data: string): Promise<void>
}

export interface IpcSuccess<T> {
  ok: true
  value: T
}

export interface IpcFailure {
  ok: false
  error: {
    code: number
  }
}

export type IpcResult<T> = IpcSuccess<T> | IpcFailure

export class CopyLockerCommandError extends Error {
  readonly code: number

  constructor(code: number) {
    super(`CopyLocker command failed (${code})`)
    this.name = 'CopyLockerCommandError'
    this.code = code
  }
}

export function stableErrorCode(error: unknown): number {
  const direct = (error as { code?: unknown } | null)?.code
  if (Number.isSafeInteger(direct) && (direct as number) >= 0) {
    return direct as number
  }
  const message = (error as { message?: unknown } | null)?.message
  if (typeof message === 'string') {
    const match = /^CL:(\d{1,10})$/.exec(message)
    if (match) {
      const parsed = Number(match[1])
      if (Number.isSafeInteger(parsed)) return parsed
    }
  }
  return HOST_UNKNOWN_FATAL
}

export function requireText(value: unknown, maxBytes: number, field: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.includes('\0') ||
    new TextEncoder().encode(value).byteLength > maxBytes
  ) {
    throw new TypeError(`Invalid ${field}`)
  }
  return value
}

export function requireBytes(value: unknown, maxBytes: number, field: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > maxBytes) {
    throw new TypeError(`Invalid ${field}`)
  }
  return Uint8Array.from(value)
}
