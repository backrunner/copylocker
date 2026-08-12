/**
 * The two-round self-reference scheme (`50-unplugin-integrity.md §2.3`).
 *
 * The entry chunk embeds the manifest, and the manifest embeds the entry
 * chunk's digest — a cycle. It is broken with fixed-length placeholders:
 *
 * 1. The prelude is prepended with the `manifest` and `root` fields filled
 *    with ASCII `'0'` placeholders (exact final length).
 * 2. Round 1 digests the chunk with the placeholder spans ZEROED
 *    (`zeroExcludedRanges` semantics from `@copylocker/guard`); the spans are
 *    recorded in the entry's `excludedRanges`.
 * 3. Round 2 writes the real manifest hex and Merkle root hex into the
 *    spans — same byte length, so every other offset is unchanged.
 * 4. The runtime zeroes `excludedRanges` before digesting → digests match.
 *
 * The prelude is pure ASCII, so character offsets equal byte offsets in the
 * UTF-8 output file (asserted here).
 */

export interface GuardChunkSpec {
  url: string
  pattern: string
}

/** Data carried by `globalThis.__CL_GUARD_CONFIG__` (see README). */
export interface PreludeConfig {
  pins: string[]
  chunks: GuardChunkSpec[]
  /** Single 64-char hex, or N shards for `__CL_K_BUILD_<i>__`. */
  kbuild: string | string[]
  /**
   * WASM_DIGEST (`40-web-sdk-wasm-ts.md §5`): covered `.wasm` file name →
   * 64-char SHA-256 hex of the final emitted bytes. Published by the
   * bootstrap as `__CL_WASM_DIGESTS__` (and `__CL_WASM_DIGEST__` when
   * exactly one asset is covered).
   */
  wasmDigests?: Record<string, string>
  strategy: 'sync' | 'idle' | 'lazy' | 'report-only'
  sampleRate: number
}

export interface PreludeSpans {
  /** [start, end) of the manifest hex content (inside the quotes). */
  manifest: [number, number]
  /** [start, end) of the manifest-root hex content. */
  root: [number, number]
}

export interface Prelude {
  text: string
  spans: PreludeSpans
}

const ASCII_ONLY = /^[\x00-\x7f]*$/

function assertAscii(value: string, what: string): void {
  if (!ASCII_ONLY.test(value)) {
    throw new Error(`CopyLocker unplugin: ${what} must be ASCII ('${value.slice(0, 64)}')`)
  }
}

/**
 * Build the prelude text with zero-filled placeholders. `manifestHexLength`
 * is `2 * <manifest container bytes>` and is found by the fixpoint iteration
 * in `core.ts`. Offsets are tracked while assembling, so they are exact.
 */
export function buildPrelude(
  config: PreludeConfig,
  manifestHexLength: number,
  bootstrapSource: string,
): Prelude {
  const chunksJson = JSON.stringify(config.chunks)
  const pinsJson = JSON.stringify(config.pins)
  const kbuildJson = JSON.stringify(config.kbuild)
  const wasmDigestsJson = JSON.stringify(config.wasmDigests ?? {})
  assertAscii(chunksJson, 'chunk file names')
  assertAscii(pinsJson, 'root pins')
  assertAscii(kbuildJson, 'K_BUILD')
  assertAscii(wasmDigestsJson, 'WASM_DIGEST file names')
  assertAscii(bootstrapSource, 'bootstrap source')

  let text = ''
  const push = (part: string): void => {
    text += part
  }

  push(';globalThis.__CL_GUARD_CONFIG__={"manifest":"')
  const manifestStart = text.length
  push('0'.repeat(manifestHexLength))
  const manifestEnd = text.length
  push('","root":"')
  const rootStart = text.length
  push('0'.repeat(64))
  const rootEnd = text.length
  push('","pins":')
  push(pinsJson)
  push(',"chunks":')
  push(chunksJson)
  push(',"kbuild":')
  push(kbuildJson)
  push(',"wasmDigests":')
  push(wasmDigestsJson)
  push(',"strategy":')
  push(JSON.stringify(config.strategy))
  push(',"sampleRate":')
  push(JSON.stringify(config.sampleRate))
  push('};\n')
  // Fail-closed key derivation (M4-A): `@copylocker/web` treats this build
  // constant as the default for `requireIntegrityProof` — no guard root `R`,
  // no derivation. It is emitted by the PRELUDE, not the bootstrap, so an
  // attacker who deletes the bootstrap but keeps the constants block (the
  // fallback-enabling move) still trips it.
  push(';globalThis.__CL_REQUIRE_INTEGRITY_PROOF__=true;\n;')
  push(bootstrapSource)
  push('\n;')

  return {
    text,
    spans: { manifest: [manifestStart, manifestEnd], root: [rootStart, rootEnd] },
  }
}

/**
 * Round 2: write the real manifest hex and root hex into the placeholders.
 * Lengths MUST match — that is what keeps every other offset stable.
 */
export function backfillPrelude(
  chunkText: string,
  spans: PreludeSpans,
  manifestHex: string,
  rootHex: string,
): string {
  const [ms, me] = spans.manifest
  const [rs, re] = spans.root
  if (manifestHex.length !== me - ms) {
    throw new Error(
      `CopyLocker unplugin: manifest hex length drifted (${manifestHex.length} != ${me - ms}) — fixpoint did not converge`,
    )
  }
  if (rootHex.length !== re - rs) {
    throw new Error('CopyLocker unplugin: internal error — root hex must be 64 chars')
  }
  return chunkText.slice(0, ms) + manifestHex + chunkText.slice(me, rs) + rootHex + chunkText.slice(re)
}

/** Excluded ranges (byte offsets) contributed by a prelude at `baseOffset`. */
export function preludeExcludedRanges(spans: PreludeSpans, baseOffset = 0): [number, number][] {
  return [
    [spans.manifest[0] + baseOffset, spans.manifest[1] + baseOffset],
    [spans.root[0] + baseOffset, spans.root[1] + baseOffset],
  ]
}
