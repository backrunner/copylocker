/**
 * KEK registry (`50-unplugin-integrity.md` §4.1): one random 32-byte
 * `KEK_asset` per feature, shared by every asset sealed for that feature.
 *
 * Security red lines:
 * - The registry is ALWAYS stored encrypted (AES-256-GCM under a deployment
 *   wrapping key). Plaintext KEKs never touch disk.
 * - Registry and wrapping-key files are written with mode 0600 and must be
 *   gitignored (the CLI `init` command arranges both).
 * - `registry list` / logs only ever show the KEK *fingerprint*
 *   (truncated SHA-256), never key bytes.
 *
 * On-disk envelope (JSON, keys stable):
 * `{ "v": 1, "alg": "AES-256-GCM", "nonce": b64, "ct": b64 }`
 * where `ct` decrypts (AAD `copylocker/seal-registry/v1`) to the registry
 * JSON `{ "v": 1, "features": { "<feature>": { "kek": hex64, "createdAt": iso } } }`.
 *
 * M4-B replaces the operator-held wrapping key with server-side KEK storage
 * (MC `wrapped_keks`); this file format is a build-time local artifact only.
 */

import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import { configError, ioError, notEntitled } from './errors.js'
import type { KeyUsage } from './webcrypto.js'

export const REGISTRY_AAD_LABEL = 'copylocker/seal-registry/v1'
export const REGISTRY_VERSION = 1
export const DEFAULT_REGISTRY_DIR = '.copylocker'
export const DEFAULT_REGISTRY_FILE = 'seal-registry.json'
export const DEFAULT_WRAPPING_KEY_FILE = 'wrapping-key'
export const WRAPPING_KEY_ENV = 'COPYLOCKER_SEAL_WRAPPING_KEY'

export interface KekEntry {
  /** 32-byte KEK_asset, hex-encoded. Never log or print this. */
  kek: string
  createdAt: string
}

export interface KekRegistry {
  v: number
  features: Record<string, KekEntry>
}

export function emptyRegistry(): KekRegistry {
  return { v: REGISTRY_VERSION, features: {} }
}

const AAD = new TextEncoder().encode(REGISTRY_AAD_LABEL)

function b64encode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}

function b64decode(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'base64'))
}

export function hexEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}

export function hexDecode(text: string, what: string): Uint8Array {
  if (!/^[0-9a-fA-F]+$/.test(text) || text.length % 2 !== 0) {
    throw configError(`CopyLocker seal: ${what} must be hex`)
  }
  return new Uint8Array(Buffer.from(text, 'hex'))
}

/** Generate a fresh 32-byte wrapping key. */
export function generateWrappingKey(): Uint8Array {
  const key = new Uint8Array(32)
  globalThis.crypto.getRandomValues(key)
  return key
}

/** Generate a fresh 32-byte KEK_asset. */
export function generateKek(): Uint8Array {
  const key = new Uint8Array(32)
  globalThis.crypto.getRandomValues(key)
  return key
}

/** Non-reversible display fingerprint for a KEK (SHA-256, first 16 hex chars). */
export async function kekFingerprint(kek: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    'SHA-256',
    kek as unknown as ArrayBuffer,
  )
  return hexEncode(new Uint8Array(digest)).slice(0, 16)
}

/**
 * Resolve the wrapping key from (in priority order) an explicit key, the
 * `COPYLOCKER_SEAL_WRAPPING_KEY` env var (64 hex chars), or a key file
 * (raw 32 bytes, or 64 hex chars).
 */
export async function resolveWrappingKey(options: {
  key?: Uint8Array
  keyFile?: string
  env?: NodeJS.ProcessEnv
}): Promise<Uint8Array> {
  if (options.key) {
    if (options.key.byteLength !== 32) throw configError('CopyLocker seal: wrapping key must be 32 bytes')
    return options.key
  }
  const env = options.env ?? process.env
  const fromEnv = env[WRAPPING_KEY_ENV]
  if (fromEnv) {
    const key = hexDecode(fromEnv, `${WRAPPING_KEY_ENV}`)
    if (key.byteLength !== 32) {
      throw configError(`CopyLocker seal: ${WRAPPING_KEY_ENV} must be 64 hex characters`)
    }
    return key
  }
  if (options.keyFile) {
    let raw: Uint8Array
    try {
      raw = new Uint8Array(await readFile(options.keyFile))
    } catch {
      throw ioError(`CopyLocker seal: cannot read wrapping key file ${options.keyFile}`)
    }
    const text = new TextDecoder().decode(raw).trim()
    if (/^[0-9a-fA-F]{64}$/.test(text)) return hexDecode(text, 'wrapping key file')
    if (raw.byteLength === 32) return raw
    throw configError(
      `CopyLocker seal: wrapping key file ${options.keyFile} must be 32 raw bytes or 64 hex chars`,
    )
  }
  throw configError(
    `CopyLocker seal: no wrapping key — set ${WRAPPING_KEY_ENV} or pass a key file`,
  )
}

async function registryCryptoKey(wrappingKey: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    'raw',
    wrappingKey as unknown as ArrayBuffer,
    'AES-GCM',
    false,
    usages,
  )
}

function parseRegistry(plaintext: Uint8Array): KekRegistry {
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder().decode(plaintext))
  } catch {
    throw configError('CopyLocker seal: registry plaintext is not valid JSON')
  }
  const registry = value as KekRegistry
  if (
    typeof registry !== 'object' ||
    registry === null ||
    registry.v !== REGISTRY_VERSION ||
    typeof registry.features !== 'object' ||
    registry.features === null
  ) {
    throw configError('CopyLocker seal: unsupported registry format')
  }
  for (const [feature, entry] of Object.entries(registry.features)) {
    if (!feature || typeof entry?.kek !== 'string' || !/^[0-9a-fA-F]{64}$/.test(entry.kek)) {
      throw configError(`CopyLocker seal: registry entry for "${feature}" is malformed`)
    }
  }
  return registry
}

/** Load and decrypt the registry. A missing file yields an empty registry. */
export async function loadRegistry(options: {
  path: string
  wrappingKey: Uint8Array
}): Promise<KekRegistry> {
  let raw: Uint8Array
  try {
    raw = new Uint8Array(await readFile(options.path))
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return emptyRegistry()
    throw ioError(`CopyLocker seal: cannot read registry ${options.path}`)
  }
  let envelope: { v?: unknown; alg?: unknown; nonce?: unknown; ct?: unknown }
  try {
    envelope = JSON.parse(new TextDecoder().decode(raw))
  } catch {
    throw configError(`CopyLocker seal: registry ${options.path} is not a valid envelope`)
  }
  if (envelope.v !== REGISTRY_VERSION || envelope.alg !== 'AES-256-GCM') {
    throw configError(`CopyLocker seal: registry ${options.path} has an unsupported format`)
  }
  if (typeof envelope.nonce !== 'string' || typeof envelope.ct !== 'string') {
    throw configError(`CopyLocker seal: registry ${options.path} is malformed`)
  }
  const key = await registryCryptoKey(options.wrappingKey, ['decrypt'])
  try {
    const plaintext = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: b64decode(envelope.nonce) as unknown as ArrayBuffer,
        additionalData: AAD as unknown as ArrayBuffer,
      },
      key,
      b64decode(envelope.ct) as unknown as ArrayBuffer,
    )
    return parseRegistry(new Uint8Array(plaintext))
  } catch (error) {
    if (error instanceof Error && error.name === 'SealError') throw error
    // Wrong wrapping key or tampered registry.
    throw notEntitled('CopyLocker seal: registry does not decrypt under this wrapping key')
  }
}

/** Encrypt and write the registry atomically (tmp + rename), mode 0600. */
export async function saveRegistry(options: {
  path: string
  wrappingKey: Uint8Array
  registry: KekRegistry
}): Promise<void> {
  const key = await registryCryptoKey(options.wrappingKey, ['encrypt'])
  const nonce = new Uint8Array(12)
  globalThis.crypto.getRandomValues(nonce)
  const plaintext = new TextEncoder().encode(JSON.stringify(options.registry))
  const ct = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce as unknown as ArrayBuffer,
        additionalData: AAD as unknown as ArrayBuffer,
      },
      key,
      plaintext as unknown as ArrayBuffer,
    ),
  )
  const envelope = JSON.stringify(
    { v: REGISTRY_VERSION, alg: 'AES-256-GCM', nonce: b64encode(nonce), ct: b64encode(ct) },
    null,
    2,
  )
  await mkdir(dirname(options.path), { recursive: true })
  // Unique tmp name: two concurrent saves in one process must not truncate
  // and rename each other's temp file. Best-effort cleanup on failure.
  const tmp = `${options.path}.tmp-${process.pid}-${globalThis.crypto.randomUUID()}`
  try {
    await writeFile(tmp, envelope, { mode: 0o600 })
    await chmod(tmp, 0o600)
    await rename(tmp, options.path)
    await chmod(options.path, 0o600)
  } catch (error) {
    await unlink(tmp).catch(() => {})
    throw error
  }
}

/**
 * Fetch the KEK for `featureId`, creating and persisting a fresh random one
 * on first use. Callers must save the registry when `created` is true (or use
 * the CLI, which does it for them).
 */
export function getOrCreateKek(
  registry: KekRegistry,
  featureId: string,
): { kek: Uint8Array; created: boolean } {
  const existing = registry.features[featureId]
  if (existing) return { kek: hexDecode(existing.kek, `KEK for feature "${featureId}"`), created: false }
  const kek = generateKek()
  registry.features[featureId] = { kek: hexEncode(kek), createdAt: new Date().toISOString() }
  return { kek, created: true }
}

/** Look up a KEK without creating one. */
export function getKek(registry: KekRegistry, featureId: string): Uint8Array | undefined {
  const entry = registry.features[featureId]
  return entry ? hexDecode(entry.kek, `KEK for feature "${featureId}"`) : undefined
}
