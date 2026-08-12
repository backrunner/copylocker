/**
 * FinalKey derivation, mirroring `packages/web/src/derive.ts`:
 *
 * ```text
 * FinalKey = SHA-256(M ‖ K_BUILD ‖ MANIFEST_ROOT ‖ SHA-256(wasmBytes))
 * ```
 *
 * This exists for the M4-A development bridge only: E2E/dev loops can take
 * the runtime-derived `M` plus the build constants and reproduce the FinalKey
 * that `@copylocker/web` computes, then use `wrap-kek` to bind a feature KEK
 * to it. Production wrapping is the M4-B server-side issuance chain.
 */

import { configError } from './errors.js'

export const ZERO_32 = new Uint8Array(32)

export async function sha256(parts: Uint8Array[]): Promise<Uint8Array> {
  let total = 0
  for (const part of parts) total += part.byteLength
  const joined = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    joined.set(part, offset)
    offset += part.byteLength
  }
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', joined as unknown as ArrayBuffer))
}

/**
 * Complete the two-stage transform. `m`, `kBuild`, `manifestRoot` and
 * `wasmDigest` must each be 32 bytes (`wasmDigest` is the SHA-256 of the
 * exact `.wasm` bytes that produced `M`).
 */
export async function deriveFinalKey(options: {
  m: Uint8Array
  kBuild?: Uint8Array
  manifestRoot?: Uint8Array
  wasmDigest: Uint8Array
}): Promise<Uint8Array> {
  const kBuild = options.kBuild ?? ZERO_32
  const manifestRoot = options.manifestRoot ?? ZERO_32
  for (const [name, value] of [
    ['M', options.m],
    ['K_BUILD', kBuild],
    ['MANIFEST_ROOT', manifestRoot],
    ['wasmDigest', options.wasmDigest],
  ] as const) {
    if (value.byteLength !== 32) {
      throw configError(`CopyLocker seal: ${name} must be 32 bytes`)
    }
  }
  return sha256([options.m, kBuild, manifestRoot, options.wasmDigest])
}
