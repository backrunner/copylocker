/**
 * `bootGuard` — runtime self-verification of the build artifacts
 * (`50-unplugin-integrity.md §3.1`).
 *
 * The contract that makes this un-removable: **`R` is the actually-computed
 * Merkle root, never a boolean.** A tampered chunk does not throw — it
 * produces a different `R`, and `R` feeds `FinalKey` derivation in
 * `@copylocker/web`, so sealed assets simply fail to open.
 *
 * Strategies:
 * - `'sync'` — verify every entry before returning.
 * - `'idle'` (default, NFR-PERF-006) — the FIRST listed chunk (the entry
 *   chunk by injection convention) is verified inline; the rest are
 *   processed one per `requestIdleCallback` slice (setTimeout fallback).
 *   The returned promise resolves when verification is complete; `R` is
 *   over actual digests, same as `'sync'`.
 * - `'lazy'` — `R` is computed immediately from the manifest's EXPECTED
 *   digests and verification continues in the background; discrepancies
 *   land in the report (`settled` signals completion). Weakest binding —
 *   use only where boot latency dominates.
 * - `'report-only'` — identical computation to `'sync'` (R semantics do
 *   NOT change); additionally logs every discrepancy via `log`. This is
 *   the development/diagnosis mode from §3.3.
 *
 * Missing/unfetchable chunks contribute a 32-zero-byte digest, which
 * differs from any real expected digest, so `R` changes — tampering by
 * deletion is still detectable through key derivation. Under `'lazy'` any
 * non-`ok` background result is mixed into {@link GuardState} instead.
 */

import { bytesEqual, fromHex, sha256, toHex } from './bytes.js'
import {
  decodeManifest,
  verifyManifestSignature,
  type SignatureStatus,
  type SignedManifest,
} from './manifest.js'
import { merkleRootFromEntries } from './merkle.js'
import { GuardState } from './guarded.js'

export type GuardStrategy = 'sync' | 'idle' | 'lazy' | 'report-only'

/** Static chunk mapping injected by `@copylocker/unplugin` at build time. */
export interface GuardChunk {
  /** Fetch URL of the built chunk. */
  url: string
  /** Manifest pattern this chunk satisfies. */
  pattern: string
}

/** Minimal fetch shape the guard relies on (subset of global `fetch`). */
export type GuardFetch = (
  url: string,
  init?: { cache?: 'force-cache' },
) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>

export interface BootGuardOptions {
  /** Signed manifest container (CBOR bytes) or an already-decoded one. */
  manifest: Uint8Array | SignedManifest
  /** Pinned Ed25519 public keys (raw 32-byte or hex); verifies provenance. */
  rootPins?: (Uint8Array | string)[]
  /** Verification strategy; default `'idle'`. */
  strategy?: GuardStrategy
  /**
   * Injected static chunk mapping (primary source). The entry chunk MUST be
   * listed first — `'idle'` verifies it synchronously. Patterns not covered
   * here fall back to `performance.getEntriesByType('resource')` suffix
   * matching.
   */
  chunks?: GuardChunk[]
  /** Test/DI seam for fetch. Defaults to global `fetch`. */
  fetchImpl?: GuardFetch
  /** Clock seam (defaults to `performance.now`). */
  now?: () => number
  /** Diagnostic sink (defaults to `console.warn`). */
  log?: (message: string) => void
}

export type EntryStatus = 'ok' | 'mismatch' | 'missing' | 'fetch-error' | 'unmatched'

export interface EntryReport {
  pattern: string
  url?: string
  status: EntryStatus
  /** Hex of the manifest's expected digest. */
  expected: string
  /** Hex of the actually-computed digest (zeros when unavailable). */
  actual: string
}

export interface GuardReport {
  signature: SignatureStatus
  entries: EntryReport[]
  /** False while `'lazy'`/`'idle'` background work is still running. */
  complete: boolean
  startedAt: number
  durationMs: number
}

export interface BootResult {
  /** The actually-computed Merkle root (32 bytes) — NOT a boolean. */
  R: Uint8Array
  report: GuardReport
  /** Resolves when all verification (incl. background) has completed. */
  settled: Promise<GuardReport>
}

const ZERO_DIGEST = new Uint8Array(32)

/**
 * Return a copy of `bytes` with every `[start, end)` excluded range zeroed.
 * Out-of-bounds ranges are clamped; inverted ranges are ignored. This is the
 * runtime half of the two-round self-reference scheme (§2.3): the build-time
 * half writes the real root into the placeholder AFTER digesting, so both
 * sides digest with the placeholder region zeroed.
 */
export function zeroExcludedRanges(
  bytes: Uint8Array,
  ranges: readonly [number, number][],
): Uint8Array {
  const out = new Uint8Array(bytes)
  for (const [start, end] of ranges) {
    if (end <= start) continue
    const s = Math.min(start, out.byteLength)
    const e = Math.min(end, out.byteLength)
    out.fill(0, s, e)
  }
  return out
}

function defaultFetch(): GuardFetch | undefined {
  const f = (globalThis as { fetch?: typeof fetch }).fetch
  if (!f) return undefined
  return (url, init) => f(url, { cache: init?.cache }) as Promise<Response>
}

function findResourceUrl(pattern: string): string | undefined {
  const perf = (globalThis as { performance?: Performance }).performance
  if (!perf || typeof perf.getEntriesByType !== 'function') return undefined
  const resources = perf.getEntriesByType('resource') as PerformanceEntry[]
  for (const entry of resources) {
    if (entry.name.endsWith(pattern)) return entry.name
  }
  return undefined
}

function idleSlice(): Promise<void> {
  const ric = (
    globalThis as {
      requestIdleCallback?: (cb: () => void) => number
    }
  ).requestIdleCallback
  if (ric) return new Promise((resolve) => ric(() => resolve()))
  return new Promise((resolve) => setTimeout(resolve, 0))
}

async function verifyEntry(
  pattern: string,
  expected: Uint8Array,
  excludedRanges: readonly [number, number][],
  url: string | undefined,
  fetchImpl: GuardFetch | undefined,
): Promise<EntryReport & { digest: Uint8Array }> {
  const expectedHex = toHex(expected)
  const done = (
    status: EntryStatus,
    digest: Uint8Array,
  ): EntryReport & { digest: Uint8Array } => ({
    pattern,
    url,
    status,
    expected: expectedHex,
    actual: toHex(digest),
    digest,
  })
  if (!url || !fetchImpl) return done('unmatched', ZERO_DIGEST)
  let response: { ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }
  try {
    response = await fetchImpl(url, { cache: 'force-cache' })
  } catch {
    return done('fetch-error', ZERO_DIGEST)
  }
  if (!response.ok) return done('missing', ZERO_DIGEST)
  try {
    const bytes = new Uint8Array(await response.arrayBuffer())
    const digest = await sha256(zeroExcludedRanges(bytes, excludedRanges))
    return done(bytesEqual(digest, expected) ? 'ok' : 'mismatch', digest)
  } catch {
    // A body read can fail after the headers arrive (network abort mid-stream,
    // opaque CORS stream error) — same fail-closed outcome as a failed fetch.
    return done('fetch-error', ZERO_DIGEST)
  }
}

/** Boot-time self-verification. See module docs for strategy semantics. */
export async function bootGuard(options: BootGuardOptions): Promise<BootResult> {
  const now = options.now ?? (() => globalThis.performance?.now() ?? Date.now())
  const log = options.log ?? ((message: string) => console.warn(message))
  const startedAt = now()
  const strategy = options.strategy ?? 'idle'

  const signed =
    options.manifest instanceof Uint8Array ? decodeManifest(options.manifest) : options.manifest
  const { manifest } = signed

  const pins = (options.rootPins ?? []).map((pin) =>
    typeof pin === 'string' ? fromHex(pin) : pin,
  )
  const signature = await verifyManifestSignature(signed, pins)
  if (signature === 'failed') {
    log('CopyLocker guard: manifest signature does not match any root pin')
  } else if (signature === 'unsupported') {
    log('CopyLocker guard: WebCrypto Ed25519 unavailable — signature not verified (provenance degraded; integrity still enforced via R)')
  } else if (signature === 'unsigned') {
    log('CopyLocker guard: unsigned manifest (development build)')
  } else if (signature === 'no-pins') {
    log('CopyLocker guard: manifest signed but no rootPins configured')
  }
  if (manifest.hashAlg !== 'sha256') {
    log(
      `CopyLocker guard: manifest hash_alg '${manifest.hashAlg}' not implemented by this runtime; computing with SHA-256`,
    )
  }

  const fetchImpl = options.fetchImpl ?? defaultFetch()
  const chunkUrl = new Map<string, string>()
  for (const chunk of options.chunks ?? []) chunkUrl.set(chunk.pattern, chunk.url)
  const resolveUrl = (pattern: string): string | undefined =>
    chunkUrl.get(pattern) ?? findResourceUrl(pattern)

  const report: GuardReport = {
    signature,
    entries: [],
    complete: false,
    startedAt,
    durationMs: 0,
  }
  const finalize = (): GuardReport => {
    report.complete = true
    report.durationMs = now() - startedAt
    return report
  }
  const noteFailure = (entry: EntryReport): void => {
    if (strategy === 'report-only' && entry.status !== 'ok') {
      log(
        `CopyLocker guard: chunk '${entry.pattern}' ${entry.status} (expected ${entry.expected}, actual ${entry.actual})`,
      )
    }
  }

  const digests = new Map<string, Uint8Array>()

  const runEntry = async (pattern: string): Promise<void> => {
    const entry = manifest.entries.get(pattern)
    if (!entry) return
    const result = await verifyEntry(
      pattern,
      entry.digest,
      entry.excludedRanges,
      resolveUrl(pattern),
      fetchImpl,
    )
    digests.set(pattern, result.digest)
    report.entries.push({
      pattern: result.pattern,
      url: result.url,
      status: result.status,
      expected: result.expected,
      actual: result.actual,
    })
    noteFailure(result)
    if (result.status !== 'ok') {
      // Late (background) discrepancies also harden the shared guard state:
      // consumers combining GuardState.getR() into derivation pick them up.
      // Any non-ok status counts — an unfetchable or unmatched chunk is as
      // much a deviation from the build as a mismatched one.
      GuardState.mix(`boot:${pattern}`, result.digest)
    }
    return undefined
  }

  // 'idle' verifies the entry chunk inline — the FIRST chunk of the injected
  // `chunks` mapping (the entry chunk by injection convention), not whatever
  // pattern happens to sort first in the manifest's canonical CBOR order.
  const declared = (options.chunks ?? [])
    .map((chunk) => chunk.pattern)
    .filter((pattern) => manifest.entries.has(pattern))
  const patterns = [...new Set([...declared, ...manifest.entries.keys()])]

  if (strategy === 'lazy') {
    // R over EXPECTED digests now; verification proceeds in the background.
    for (const [pattern, entry] of manifest.entries) digests.set(pattern, entry.digest)
    const R = await merkleRootFromEntries(digests)
    const background = (async () => {
      digests.clear()
      for (const pattern of patterns) {
        await idleSlice()
        await runEntry(pattern)
      }
      return finalize()
    })()
    return { R, report, settled: background }
  }

  const verifyAll = async (): Promise<GuardReport> => {
    if (strategy === 'idle') {
      // Entry chunk (first listed) inline; the rest one per idle slice.
      const [first, ...rest] = patterns
      if (first !== undefined) await runEntry(first)
      for (const pattern of rest) {
        await idleSlice()
        await runEntry(pattern)
      }
    } else {
      for (const pattern of patterns) await runEntry(pattern)
    }
    return finalize()
  }

  const done = await verifyAll()
  // R is over leaves in the manifest's canonical CBOR key order (merkle.ts),
  // regardless of the order verification ran in (idle runs the entry chunk
  // first, which may not be the canonically-first pattern).
  const ordered = new Map<string, Uint8Array>()
  for (const pattern of manifest.entries.keys()) {
    const digest = digests.get(pattern)
    if (digest) ordered.set(pattern, digest)
  }
  const R = await merkleRootFromEntries(ordered)
  return { R, report: done, settled: Promise.resolve(done) }
}
