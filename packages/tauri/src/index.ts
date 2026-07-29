import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

export type { CommandError, StateDto, StateName, StateReasonName } from './generated/index'
import type { CommandError, StateDto } from './generated/index'

const COMMAND = 'plugin:copylocker|'
const MAX_KEY_BYTES = 4 * 1024
const MAX_FEATURE_BYTES = 1024
const MAX_ASSET_BYTES = 64 * 1024 * 1024
const MAX_CHALLENGE_BYTES = 64 * 1024
const MAX_OFFLINE_BYTES = 1024 * 1024

export class CopyLockerCommandError extends Error {
  readonly code: number

  constructor(code: number) {
    super(`CopyLocker command failed (${code})`)
    this.name = 'CopyLockerCommandError'
    this.code = code
  }
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength
}

function requireText(value: string, maxBytes: number, field: string): void {
  if (value.length === 0 || value.includes('\0') || utf8Length(value) > maxBytes) {
    throw new TypeError(`Invalid ${field}`)
  }
}

function requireBytes(value: Uint8Array, maxBytes: number, field: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > maxBytes) {
    throw new TypeError(`Invalid ${field}`)
  }
}

function normalizeError(error: unknown): never {
  const code = (error as Partial<CommandError> | null)?.code
  throw new CopyLockerCommandError(Number.isSafeInteger(code) ? code as number : 3999)
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(`${COMMAND}${command}`, args)
  } catch (error) {
    return normalizeError(error)
  }
}

export async function activate(key: string): Promise<void> {
  requireText(key, MAX_KEY_BYTES, 'activation key')
  await call<void>('cl_activate', { key })
}

export async function deactivate(): Promise<void> {
  await call<void>('cl_deactivate')
}

/** @deprecated for gating - advisory UI state only. Use unseal or challenge for access. */
export async function state(): Promise<StateDto> {
  return call<StateDto>('cl_state')
}

export async function unseal(feature: string, data: Uint8Array): Promise<Uint8Array> {
  requireText(feature, MAX_FEATURE_BYTES, 'feature')
  requireBytes(data, MAX_ASSET_BYTES, 'sealed asset')
  return new Uint8Array(await call<number[]>('cl_unseal', { feature, data: Array.from(data) }))
}

export async function challenge(input: Uint8Array): Promise<Uint8Array> {
  requireBytes(input, MAX_CHALLENGE_BYTES, 'challenge')
  return new Uint8Array(await call<number[]>('cl_challenge', { input: Array.from(input) }))
}

export async function offlineRequest(key: string): Promise<Uint8Array> {
  requireText(key, MAX_KEY_BYTES, 'activation key')
  return new Uint8Array(await call<number[]>('cl_offline_request', { key }))
}

export async function offlineImport(data: Uint8Array): Promise<void> {
  requireBytes(data, MAX_OFFLINE_BYTES, 'offline response')
  await call<void>('cl_offline_import', { data: Array.from(data) })
}

export async function importOlk(data: string): Promise<void> {
  requireText(data, MAX_OFFLINE_BYTES, 'offline license key')
  await call<void>('cl_import_olk', { data })
}

export async function onStateChanged(
  handler: (state: StateDto) => void,
): Promise<UnlistenFn> {
  return listen<StateDto>('copylocker://state-changed', (event) => handler(event.payload))
}
