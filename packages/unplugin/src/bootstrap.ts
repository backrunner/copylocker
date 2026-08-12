/**
 * Runtime bootstrap — bundled to a self-contained IIFE by
 * `scripts/build-bootstrap.mjs` and prepended to every entry chunk by the
 * plugin (after the `__CL_GUARD_CONFIG__` assignment).
 *
 * It publishes the injection contract (see README):
 * - `__CL_MANIFEST__` (Uint8Array), `__CL_ROOT_PINS__`, `__CL_CHUNKS__`
 * - `__COPYLOCKER_K_BUILD__` (single) or `__CL_K_BUILD_<i>__` shards
 * - `__COPYLOCKER_MANIFEST_ROOT__` (expected root, hex)
 * - `__CL_WASM_DIGESTS__` (file name → SHA-256 hex) and, when exactly one
 *   covered `.wasm` asset exists, the singular `__CL_WASM_DIGEST__` (hex)
 * - `__CL_GUARD_FN__` — the `guardedFn` wrapper with the configured rate
 * - `__CL_GUARD_R__` — Promise<Uint8Array> of the ACTUALLY-COMPUTED root
 */

import { bootGuard, guardedFn, type GuardChunk, type GuardStrategy } from '@copylocker/guard'

interface InjectedConfig {
  manifest: string
  root: string
  pins: string[]
  chunks: GuardChunk[]
  kbuild: string | string[]
  wasmDigests?: Record<string, string>
  strategy: GuardStrategy
  sampleRate: number
}

const g = globalThis as Record<string, unknown>

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.byteLength; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function start(): boolean {
  const config = g.__CL_GUARD_CONFIG__ as InjectedConfig | undefined
  if (!config || g.__CL_GUARD_R__) return config !== undefined
  g.__CL_MANIFEST__ = hexToBytes(config.manifest)
  g.__CL_ROOT_PINS__ = config.pins
  g.__CL_CHUNKS__ = config.chunks
  if (Array.isArray(config.kbuild)) {
    config.kbuild.forEach((shard, index) => {
      g[`__CL_K_BUILD_${index}__`] = shard
    })
  } else {
    g.__COPYLOCKER_K_BUILD__ = config.kbuild
  }
  g.__COPYLOCKER_MANIFEST_ROOT__ = config.root
  // WASM_DIGEST (design §5): the build-time SHA-256 of the covered .wasm
  // assets. `@copylocker/web` compares the singular constant against the
  // digest of the wasm it actually loaded; the map covers custom wiring.
  const wasmDigests = config.wasmDigests ?? {}
  g.__CL_WASM_DIGESTS__ = wasmDigests
  const digestValues = Object.values(wasmDigests)
  if (digestValues.length === 1) g.__CL_WASM_DIGEST__ = digestValues[0]
  g.__CL_GUARD_FN__ = <F extends (...args: never[]) => unknown>(
    id: string,
    fn: F,
    options?: { sampleRate?: number },
  ): F => guardedFn(id, fn, { sampleRate: options?.sampleRate ?? config.sampleRate })
  g.__CL_GUARD_R__ = bootGuard({
    manifest: g.__CL_MANIFEST__ as Uint8Array,
    rootPins: config.pins,
    chunks: config.chunks,
    strategy: config.strategy,
  }).then((result) => result.R)
  return true
}

// The config assignment is prepended directly before this IIFE, so it is
// normally already set. The microtask retry covers bundlers that split the
// bootstrap into a chunk evaluated before the entry chunk's prelude.
if (!start()) {
  queueMicrotask(() => {
    start()
  })
}

export {}
