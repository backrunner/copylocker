/** Digest plumbing: SHA-256 (WebCrypto, matching the guard runtime) or custom. */

import type { Hasher } from './config.js'
import { ConfigError } from './config.js'

export type HashFn = (bytes: Uint8Array) => Promise<Uint8Array>

/** SHA-256 via WebCrypto — byte-identical to `@copylocker/guard`'s runtime. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('CopyLocker unplugin: WebCrypto SubtleCrypto is required (Node >= 20)')
  }
  return new Uint8Array(await subtle.digest('SHA-256', bytes as unknown as ArrayBuffer))
}

/** Resolve the configured hasher to a function, validating its output. */
export function resolveHasher(hasher: Exclude<Hasher, 'blake3'> | undefined): HashFn {
  if (hasher === undefined || hasher === 'sha256') return sha256
  if (typeof hasher === 'function') {
    return async (bytes) => {
      const digest = await hasher(bytes)
      if (!(digest instanceof Uint8Array) || digest.byteLength !== 32) {
        throw new ConfigError('CopyLocker unplugin: custom hasher must return a 32-byte Uint8Array')
      }
      return digest
    }
  }
  throw new ConfigError(`CopyLocker unplugin: unsupported hasher '${String(hasher)}'`)
}

const HEX = '0123456789abcdef'

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) out += (HEX[byte >> 4] as string) + (HEX[byte & 0xf] as string)
  return out
}

export function fromHex(hex: string): Uint8Array {
  if (!/^([0-9a-fA-F]{2})*$/.test(hex)) {
    throw new ConfigError('CopyLocker unplugin: invalid hex string')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.byteLength; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}
