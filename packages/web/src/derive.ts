/**
 * The second stage of the key transform (`40-web-sdk-wasm-ts.md §2/§3.2`):
 *
 * ```text
 * FinalKey = SHA-256(M ‖ K_BUILD ‖ MANIFEST_ROOT ‖ SHA-256(wasmBytes))
 * ```
 *
 * `M` is the "half-baked" 32-byte material derived inside the wasm core; the
 * remaining inputs are build-time environment probes. The transform provides
 * **engineering inseparability, not cryptographic protection**: every input
 * is present on the client, but an attacker cannot stub a single function to
 * recover the key — replacing the wasm, editing the bundle, or skipping the
 * manifest verification each silently changes `FinalKey`.
 */

import { ERR_DERIVATION, errorFromCode } from './errors.js'

/** Build-time environment probes feeding the two-stage transform. */
export interface BuildConstants {
  /** 32-byte build constant injected by the M4 `@copylocker/unplugin`. */
  kBuild: Uint8Array
  /** 32-byte integrity-manifest root injected by the M4 `@copylocker/guard`. */
  manifestRoot: Uint8Array
}

/**
 * Runtime integrity hook (M4 `@copylocker/guard`). When configured, the
 * ACTUALLY-COMPUTED manifest root `R` from `bootGuard()` is used for key
 * derivation instead of the build-time injected constant — this is what
 * makes removing or tampering with the guard change `FinalKey`
 * (`40-web-sdk-wasm-ts.md §6`).
 */
export interface IntegrityHooks {
  /**
   * Returns the actually-computed 32-byte Merkle root (may be async). May
   * also return `undefined` — e.g. `() => globalThis.__CL_GUARD_R__` when the
   * unplugin's guard bootstrap is absent (dev build, or deleted by an
   * attacker); the fallback/strictness semantics are governed by
   * `requireIntegrityProof` (see {@link resolveManifestRoot}).
   */
  manifestRoot?: () => Uint8Array | undefined | Promise<Uint8Array | undefined>
}

const ZERO_32 = new Uint8Array(32)

function injectedBytes(name: string): Uint8Array | undefined {
  // The M4 unplugin replaces these globals at bundle time. They are read
  // through `globalThis` so the module loads unchanged when no injection ran.
  const value = (globalThis as Record<string, unknown>)[name]
  if (value instanceof Uint8Array && value.byteLength === 32) return value
  if (typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value)) {
    const bytes = new Uint8Array(32)
    for (let i = 0; i < 32; i += 1) {
      bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16)
    }
    return bytes
  }
  return undefined
}

const MAX_SHARDS = 64

/**
 * Sharded build constants (M4 `@copylocker/unplugin` `splitConstants`): the
 * unplugin may inject a 32-byte constant as N consecutive hex shards
 * `<prefix>0__` … `<prefix><n-1>__` instead of one global, so no single
 * bundle location holds the whole value. The shards are concatenated here.
 * A malformed shard set is a build-integration bug and throws (matching the
 * strictness of `resolveManifestRoot`) rather than silently falling back.
 */
function injectedShardedBytes(prefix: string): Uint8Array | undefined {
  const globals = globalThis as Record<string, unknown>
  if (globals[`${prefix}0__`] === undefined) return undefined
  const parts: string[] = []
  for (let i = 0; i < MAX_SHARDS; i += 1) {
    const value = globals[`${prefix}${i}__`]
    if (value === undefined) break
    if (typeof value !== 'string' || !/^([0-9a-fA-F]{2})+$/.test(value)) {
      throw new TypeError(`CopyLocker: ${prefix}${i}__ must be an even-length hex string`)
    }
    parts.push(value)
  }
  const hex = parts.join('')
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new TypeError(
      `CopyLocker: ${prefix}<i>__ shards must concatenate to exactly 64 hex characters (32 bytes)`,
    )
  }
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/**
 * Resolve the build constants: explicit options win, then the M4 injection
 * points (`__COPYLOCKER_K_BUILD__` / `__COPYLOCKER_MANIFEST_ROOT__`), then the
 * all-zeros development default. The zeros default is NOT safe for production
 * builds — the M4 unplugin is responsible for real injection.
 */
export function resolveBuildConstants(override?: Partial<BuildConstants>): BuildConstants {
  return {
    kBuild:
      override?.kBuild ??
      injectedBytes('__COPYLOCKER_K_BUILD__') ??
      injectedShardedBytes('__CL_K_BUILD_') ??
      ZERO_32,
    manifestRoot:
      override?.manifestRoot ?? injectedBytes('__COPYLOCKER_MANIFEST_ROOT__') ?? ZERO_32,
  }
}

async function sha256(parts: Uint8Array[]): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('CopyLocker: WebCrypto SubtleCrypto is required (secure context)')
  }
  let total = 0
  for (const part of parts) total += part.byteLength
  const joined = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    joined.set(part, offset)
    offset += part.byteLength
  }
  return new Uint8Array(await subtle.digest('SHA-256', joined as unknown as ArrayBuffer))
}

/**
 * Injected WASM_DIGEST (`40-web-sdk-wasm-ts.md §5`, M4 `@copylocker/unplugin`):
 * the build-time SHA-256 of the single covered `.wasm` artifact, published by
 * the unplugin bootstrap as `__CL_WASM_DIGEST__`. The runtime compares it
 * against the digest of the wasm bytes it actually loaded — a swapped or
 * patched artifact then fails closed at `create()` instead of deriving a key.
 * `undefined` means no injection ran (dev build): no comparison is possible.
 */
export function resolveExpectedWasmDigest(): Uint8Array | undefined {
  return injectedBytes('__CL_WASM_DIGEST__')
}

/**
 * Resolve the fail-closed integrity-proof requirement (M4-A). The explicit
 * option wins; otherwise the `__CL_REQUIRE_INTEGRITY_PROOF__` global injected
 * by the `@copylocker/unplugin` prelude decides. The flag lives in the
 * prelude's config assignment — NOT in the guard bootstrap — so deleting the
 * bootstrap (the classic "remove the integrity check" attack) cannot disable
 * it without also removing the build constants the fallback would need.
 */
export function resolveRequireIntegrityProof(option?: boolean): boolean {
  if (option !== undefined) return option
  return (globalThis as Record<string, unknown>).__CL_REQUIRE_INTEGRITY_PROOF__ === true
}

/**
 * Resolve the manifest root for one key derivation: a configured
 * {@link IntegrityHooks} provider wins (its actually-computed `R`), otherwise
 * the injected/static constant is used. Throws TypeError on a malformed
 * provider result — a misconfigured hook is a build integration bug and must
 * not silently fall back.
 *
 * When `requireProof` is set, there is no fallback: a missing provider or an
 * `undefined` result means the guard did not produce `R` (bootstrap deleted,
 * verification never ran), and derivation fails closed with the same
 * indistinguishable `NotEntitledError` the wasm core uses for forbidden
 * derivations (NFR-SEC-011 — probing must not tell the two apart).
 */
export async function resolveManifestRoot(
  integrity: IntegrityHooks | undefined,
  fallback: Uint8Array,
  requireProof = false,
): Promise<Uint8Array> {
  const provided = await integrity?.manifestRoot?.()
  if (provided === undefined) {
    if (requireProof) throw errorFromCode(ERR_DERIVATION)
    return fallback
  }
  if (!(provided instanceof Uint8Array) || provided.byteLength !== 32) {
    throw new TypeError('CopyLocker: integrity.manifestRoot must return a 32-byte Uint8Array')
  }
  return provided
}

/**
 * Complete the two-stage transform. `wasmDigest` must be the SHA-256 of the
 * exact `.wasm` bytes that produced `M` (computed at load time by
 * `loadWasmSession`).
 */
export async function deriveFinalKey(
  m: Uint8Array,
  constants: BuildConstants,
  wasmDigest: Uint8Array,
): Promise<Uint8Array> {
  if (m.byteLength !== 32 || wasmDigest.byteLength !== 32) {
    throw new TypeError('CopyLocker: invalid key material length')
  }
  return sha256([m, constants.kBuild, constants.manifestRoot, wasmDigest])
}
