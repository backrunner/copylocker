/** Shared fixtures: build signed manifests exactly as the unplugin will. */

import { encode, type CborValue } from '../src/cbor.js'
import { sha256 } from '../src/bytes.js'
import { zeroExcludedRanges, type GuardFetch } from '../src/guard.js'
import { merkleRootFromEntries } from '../src/merkle.js'
import { signManifestTbs } from '../src/manifest.js'

export interface FixtureChunk {
  pattern: string
  url: string
  content: Uint8Array
  excludedRanges: [number, number][]
}

export interface Fixture {
  /** CBOR bytes of the signed container (what gets inlined as __CL_MANIFEST__). */
  manifestBytes: Uint8Array
  publicKey: Uint8Array
  privateKey: CryptoKey
  chunks: FixtureChunk[]
  /** Merkle root over the untampered chunk contents. */
  expectedRoot: Uint8Array
}

/** Canonical CBOR key order for text keys: shorter first, then bytewise. */
function canonicalKeyOrder(a: string, b: string): number {
  if (a.length !== b.length) return a.length - b.length
  return a < b ? -1 : a > b ? 1 : 0
}

export async function makeFixture(
  chunks: { pattern: string; content: Uint8Array; excludedRanges?: [number, number][] }[],
  options: { sign?: boolean } = {},
): Promise<Fixture> {
  const sorted = [...chunks].sort((a, b) => canonicalKeyOrder(a.pattern, b.pattern))
  const entries = new Map<string, CborValue>()
  const digests = new Map<string, Uint8Array>()
  const outChunks: FixtureChunk[] = []
  for (const chunk of sorted) {
    const ranges = chunk.excludedRanges ?? []
    const digest = await sha256(zeroExcludedRanges(chunk.content, ranges))
    digests.set(chunk.pattern, digest)
    const entry = new Map<number, CborValue>()
    entry.set(1, digest)
    if (ranges.length > 0) entry.set(2, ranges.map(([s, e]) => [s, e]))
    entries.set(chunk.pattern, entry)
    outChunks.push({
      pattern: chunk.pattern,
      url: `https://app.example.com/assets/${chunk.pattern}`,
      content: chunk.content,
      excludedRanges: ranges,
    })
  }
  const expectedRoot = await merkleRootFromEntries(digests)

  const tbs = new Map<number, CborValue>()
  tbs.set(0, 1)
  tbs.set(1, new Uint8Array([1, 2, 3, 4]))
  tbs.set(2, 'test-product')
  tbs.set(3, 'build-fp-0001')
  tbs.set(4, 1754600000)
  tbs.set(5, 'sha256')
  tbs.set(6, entries)
  tbs.set(9, expectedRoot)
  const tbsBytes = encode(tbs)

  const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))
  const signature =
    options.sign === false
      ? new Uint8Array(0)
      : await signManifestTbs(tbsBytes, keys.privateKey)

  const container = new Map<number, CborValue>()
  container.set(0, tbsBytes)
  container.set(1, signature)
  return {
    manifestBytes: encode(container),
    publicKey,
    privateKey: keys.privateKey,
    chunks: outChunks,
    expectedRoot,
  }
}

/** Fetch mock over an in-memory file table. */
export function mockFetch(files: Map<string, Uint8Array>): GuardFetch {
  return async (url: string) => {
    const body = files.get(url)
    if (!body) {
      return { ok: false, status: 404, arrayBuffer: async () => new ArrayBuffer(0) }
    }
    return { ok: true, status: 200, arrayBuffer: async () => body.slice().buffer }
  }
}

/** File table from a fixture, optionally with per-pattern content overrides. */
export function filesOf(
  fixture: Fixture,
  overrides: Record<string, Uint8Array | null> = {},
): Map<string, Uint8Array> {
  const files = new Map<string, Uint8Array>()
  for (const chunk of fixture.chunks) {
    const override = overrides[chunk.pattern]
    if (override === null) continue // simulate a missing chunk
    files.set(chunk.url, override ?? chunk.content)
  }
  return files
}

export function chunkMapping(fixture: Fixture): { url: string; pattern: string }[] {
  return fixture.chunks.map((chunk) => ({ url: chunk.url, pattern: chunk.pattern }))
}

export function textBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}
