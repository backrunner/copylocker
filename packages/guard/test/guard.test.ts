import { describe, expect, it } from 'vitest'
import { bootGuard, zeroExcludedRanges } from '../src/guard.js'
import { sha256 } from '../src/bytes.js'
import { GuardState } from '../src/guarded.js'
import { chunkMapping, filesOf, makeFixture, mockFetch, textBytes } from './helpers.js'

const silent = () => {}

async function threeChunkFixture() {
  return makeFixture([
    { pattern: 'a.js', content: textBytes('entry chunk contents') },
    { pattern: 'b.js', content: textBytes('second chunk contents') },
    { pattern: 'c.js', content: textBytes('third chunk contents') },
  ])
}

describe('zeroExcludedRanges', () => {
  it('zeroes [start, end) and nothing else', () => {
    const bytes = textBytes('0123456789')
    const zeroed = zeroExcludedRanges(bytes, [[2, 5]])
    expect([...zeroed]).toEqual([...textBytes('01'), 0, 0, 0, ...textBytes('56789')])
  })

  it('clamps out-of-bounds ranges and ignores inverted ones', () => {
    const bytes = textBytes('0123456789')
    expect([...zeroExcludedRanges(bytes, [[8, 100]])]).toEqual([...textBytes('01234567'), 0, 0])
    expect([...zeroExcludedRanges(bytes, [[5, 5], [7, 3]])]).toEqual([...bytes])
  })

  it('makes the digest stable regardless of placeholder content', async () => {
    // Same span [6, 42) (36 bytes) filled differently — zeroed digests match.
    const a = textBytes(`chunk CL_ROOT_PLACEHOLDER_${'0'.repeat(16)} tail`)
    const b = textBytes(`chunk ${'X'.repeat(36)} tail`)
    expect(b.byteLength).toBe(a.byteLength)
    const range: [number, number] = [6, 42]
    expect(await sha256(zeroExcludedRanges(a, [range]))).toEqual(
      await sha256(zeroExcludedRanges(b, [range])),
    )
  })
})

describe('bootGuard', () => {
  it('is deterministic and matches the build-time root for an untampered bundle', async () => {
    const fixture = await threeChunkFixture()
    const options = {
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      chunks: chunkMapping(fixture),
      fetchImpl: mockFetch(filesOf(fixture)),
      log: silent,
    }
    const a = await bootGuard({ ...options, strategy: 'sync' as const })
    const b = await bootGuard({ ...options, strategy: 'idle' as const })
    expect(a.R).toEqual(fixture.expectedRoot)
    expect(b.R).toEqual(fixture.expectedRoot)
    expect(a.report.entries.every((e) => e.status === 'ok')).toBe(true)
    expect(a.report.signature).toBe('verified')
  })

  it('a single tampered byte changes R (never throws)', async () => {
    const fixture = await threeChunkFixture()
    const tampered = textBytes('second chunk contents')
    tampered[0] = (tampered[0] as number) ^ 0x01
    const result = await bootGuard({
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      strategy: 'sync',
      chunks: chunkMapping(fixture),
      fetchImpl: mockFetch(filesOf(fixture, { 'b.js': tampered })),
      log: silent,
    })
    expect(result.R).not.toEqual(fixture.expectedRoot)
    const entry = result.report.entries.find((e) => e.pattern === 'b.js')
    expect(entry?.status).toBe('mismatch')
    expect(entry?.expected).not.toBe(entry?.actual)
  })

  it('a missing chunk changes R and is recorded in the report', async () => {
    const fixture = await threeChunkFixture()
    const result = await bootGuard({
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      strategy: 'sync',
      chunks: chunkMapping(fixture),
      fetchImpl: mockFetch(filesOf(fixture, { 'c.js': null })),
      log: silent,
    })
    expect(result.R).not.toEqual(fixture.expectedRoot)
    expect(result.report.entries.find((e) => e.pattern === 'c.js')?.status).toBe('missing')
  })

  it('report-only and sync produce the SAME R (report-only only adds diagnostics)', async () => {
    const fixture = await threeChunkFixture()
    const tampered = textBytes('entry chunk contents')
    tampered[5] = (tampered[5] as number) ^ 0x20
    const base = {
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      chunks: chunkMapping(fixture),
      fetchImpl: mockFetch(filesOf(fixture, { 'a.js': tampered })),
      log: silent,
    }
    const syncResult = await bootGuard({ ...base, strategy: 'sync' as const })
    const logs: string[] = []
    const reportOnly = await bootGuard({
      ...base,
      strategy: 'report-only' as const,
      log: (m) => logs.push(m),
    })
    expect(reportOnly.R).toEqual(syncResult.R)
    expect(reportOnly.R).not.toEqual(fixture.expectedRoot)
    expect(logs.some((m) => m.includes('a.js'))).toBe(true)
  })

  it('excludedRanges are zeroed before digesting (placeholder scheme)', async () => {
    // The bundle contains the REAL root at the placeholder span; the manifest
    // digest was computed with the span zeroed. Verification must still match.
    const placeholderSpan: [number, number] = [6, 38]
    const built = textBytes('chunk ________________________________ tail')
    const fixture = await makeFixture([
      { pattern: 'a.js', content: built, excludedRanges: [placeholderSpan] },
    ])
    // Simulate the unplugin's second round: write the root into the span.
    const shipped = new Uint8Array(built)
    shipped.set(fixture.expectedRoot, placeholderSpan[0])
    const result = await bootGuard({
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      strategy: 'sync',
      chunks: chunkMapping(fixture),
      fetchImpl: mockFetch(filesOf(fixture, { 'a.js': shipped })),
      log: silent,
    })
    expect(result.R).toEqual(fixture.expectedRoot)
    expect(result.report.entries[0]?.status).toBe('ok')
  })

  it('lazy returns R over expected digests immediately; background fills the report', async () => {
    const fixture = await threeChunkFixture()
    const tampered = textBytes('third chunk contents')
    tampered[0] = (tampered[0] as number) ^ 0x01
    const result = await bootGuard({
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      strategy: 'lazy',
      chunks: chunkMapping(fixture),
      fetchImpl: mockFetch(filesOf(fixture, { 'c.js': tampered })),
      log: silent,
    })
    // Lazy R is over the manifest's expected digests…
    expect(result.R).toEqual(fixture.expectedRoot)
    expect(result.report.complete).toBe(false)
    const report = await result.settled
    expect(report.complete).toBe(true)
    expect(report.entries.find((e) => e.pattern === 'c.js')?.status).toBe('mismatch')
    // …and the background discrepancy is mixed into the shared guard state.
    await GuardState.settled()
  })

  it('degrades gracefully when fetch fails for every chunk', async () => {
    const fixture = await threeChunkFixture()
    const failing = (() =>
      Promise.reject(new Error('network down'))) as unknown as import('../src/guard.js').GuardFetch
    const result = await bootGuard({
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      strategy: 'sync',
      chunks: chunkMapping(fixture),
      fetchImpl: failing,
      log: silent,
    })
    expect(result.R).not.toEqual(fixture.expectedRoot)
    expect(result.report.entries.every((e) => e.status === 'fetch-error')).toBe(true)
  })

  it('a body read failure after the headers degrades to fetch-error (never rejects)', async () => {
    const fixture = await threeChunkFixture()
    const brokenBody = (async () => ({
      ok: true,
      status: 200,
      arrayBuffer: () => Promise.reject(new Error('stream aborted')),
    })) as unknown as import('../src/guard.js').GuardFetch
    const result = await bootGuard({
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      strategy: 'sync',
      chunks: chunkMapping(fixture),
      fetchImpl: brokenBody,
      log: silent,
    })
    expect(result.R).not.toEqual(fixture.expectedRoot)
    expect(result.report.entries.every((e) => e.status === 'fetch-error')).toBe(true)
  })

  it('lazy: a body read failure still completes the report and mixes into GuardState', async () => {
    GuardState.reset()
    const fixture = await threeChunkFixture()
    const brokenBody = (async () => ({
      ok: true,
      status: 200,
      arrayBuffer: () => Promise.reject(new Error('stream aborted')),
    })) as unknown as import('../src/guard.js').GuardFetch
    const result = await bootGuard({
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      strategy: 'lazy',
      chunks: chunkMapping(fixture),
      fetchImpl: brokenBody,
      log: silent,
    })
    const report = await result.settled // must resolve, not reject
    expect(report.complete).toBe(true)
    expect(report.entries.every((e) => e.status === 'fetch-error')).toBe(true)
    await GuardState.settled()
    expect(GuardState.getR()).not.toEqual(new Uint8Array(32))
    GuardState.reset()
  })

  it("idle verifies the first INJECTED chunk inline, whatever the manifest's canonical order", async () => {
    const fixture = await threeChunkFixture()
    const fetched: string[] = []
    const base = mockFetch(filesOf(fixture))
    const recording = (async (url: string, init?: { cache?: 'force-cache' }) => {
      fetched.push(url)
      return base(url, init)
    }) as import('../src/guard.js').GuardFetch
    const reversed = chunkMapping(fixture).reverse() // injected entry chunk: c.js
    const result = await bootGuard({
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      strategy: 'idle',
      chunks: reversed,
      fetchImpl: recording,
      log: silent,
    })
    expect(fetched[0]).toBe(reversed[0]?.url)
    // R stays canonical regardless of verification order (merkle.ts rules).
    expect(result.R).toEqual(fixture.expectedRoot)
  })
})
