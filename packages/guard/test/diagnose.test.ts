import { describe, expect, it } from 'vitest'
import { diagnose, formatDiagnosis } from '../src/diagnose.js'
import { toHex } from '../src/bytes.js'
import { chunkMapping, filesOf, makeFixture, mockFetch, textBytes } from './helpers.js'

const silent = () => {}

describe('diagnose', () => {
  it('reports a matching bundle as rootMatches: true', async () => {
    const fixture = await makeFixture([
      { pattern: 'a.js', content: textBytes('entry') },
      { pattern: 'b.js', content: textBytes('other') },
    ])
    const result = await diagnose({
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      chunks: chunkMapping(fixture),
      fetchImpl: mockFetch(filesOf(fixture)),
      log: silent,
    })
    expect(result.rootMatches).toBe(true)
    expect(result.actualRoot).toBe(toHex(fixture.expectedRoot))
    expect(result.signature).toBe('verified')
  })

  it('pinpoints the tampered entry with expected/actual digests', async () => {
    const fixture = await makeFixture([
      { pattern: 'a.js', content: textBytes('entry') },
      { pattern: 'b.js', content: textBytes('other') },
    ])
    const tampered = textBytes('oth3r')
    const result = await diagnose({
      manifest: fixture.manifestBytes,
      rootPins: [fixture.publicKey],
      chunks: chunkMapping(fixture),
      fetchImpl: mockFetch(filesOf(fixture, { 'b.js': tampered })),
      log: silent,
    })
    expect(result.rootMatches).toBe(false)
    const bad = result.entries.find((e) => e.pattern === 'b.js')
    expect(bad?.status).toBe('mismatch')
    expect(bad?.expected).not.toBe(bad?.actual)
    const text = formatDiagnosis(result)
    expect(text).toContain('b.js')
    expect(text).toContain('mismatch')
    expect(text).toContain('root matches:  NO')
  })
})
