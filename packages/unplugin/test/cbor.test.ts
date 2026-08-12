import { describe, expect, it } from 'vitest'
import { decodeManifest } from '@copylocker/guard'
import { canonicalTextKeyOrder, encode } from '../src/cbor.js'
import { encodeContainer, encodeTbs, type ManifestInput } from '../src/manifest.js'

function sampleInput(overrides: Partial<ManifestInput> = {}): ManifestInput {
  return {
    suiteId: new Uint8Array([1, 0, 0, 1]),
    productId: 'test-app',
    buildFingerprint: 'clb-xyz-nogit-0011223344556677',
    builtAt: 1_754_600_000,
    hashAlg: 'sha256',
    entries: new Map([
      ['assets/index-aaa.js', { digest: new Uint8Array(32).fill(1), excludedRanges: [[10, 74]] }],
      ['assets/chunk-bbb.js', { digest: new Uint8Array(32).fill(2), excludedRanges: [] }],
    ]),
    guarded: new Map([['engine.render', new Uint8Array(32).fill(3)]]),
    sealed: ['assets/pro.json'],
    root: new Uint8Array(32).fill(9),
    ...overrides,
  }
}

describe('cbor encoder (parity with @copylocker/guard decoder)', () => {
  it('round-trips a full manifest through the strict guard decoder', () => {
    const input = sampleInput()
    const tbs = encodeTbs(input)
    const container = encodeContainer(tbs, new Uint8Array(64).fill(7))
    const decoded = decodeManifest(container)
    expect(decoded.manifest.productId).toBe('test-app')
    expect(decoded.manifest.buildFingerprint).toBe(input.buildFingerprint)
    expect(decoded.manifest.builtAt).toBe(input.builtAt)
    expect(decoded.manifest.hashAlg).toBe('sha256')
    expect([...decoded.manifest.suiteId]).toEqual([1, 0, 0, 1])
    expect(decoded.signature).toHaveLength(64)
    expect(decoded.tbsBytes).toEqual(tbs)
    const entry = decoded.manifest.entries.get('assets/index-aaa.js')
    expect(entry?.digest).toEqual(new Uint8Array(32).fill(1))
    expect(entry?.excludedRanges).toEqual([[10, 74]])
    expect(decoded.manifest.entries.get('assets/chunk-bbb.js')?.excludedRanges).toEqual([])
    expect(decoded.manifest.guarded.get('engine.render')).toEqual(new Uint8Array(32).fill(3))
    expect(decoded.manifest.sealed).toEqual(['assets/pro.json'])
    expect(decoded.manifest.root).toEqual(new Uint8Array(32).fill(9))
  })

  it('omits optional keys 7/8 when empty (decoder defaults)', () => {
    const input = sampleInput({ guarded: new Map(), sealed: [] })
    const decoded = decodeManifest(encodeContainer(encodeTbs(input), new Uint8Array(0)))
    expect(decoded.manifest.guarded.size).toBe(0)
    expect(decoded.manifest.sealed).toEqual([])
    expect(decoded.signature).toHaveLength(0)
  })

  it('emits entries in canonical CBOR key order (the Merkle leaf order)', () => {
    // 'a.js' (4) < 'bb.js' (5) < 'c-long.js' (9): length first, then bytewise.
    const entries = new Map([
      ['c-long.js', { digest: new Uint8Array(32).fill(1), excludedRanges: [] }],
      ['bb.js', { digest: new Uint8Array(32).fill(2), excludedRanges: [] }],
      ['a.js', { digest: new Uint8Array(32).fill(3), excludedRanges: [] }],
    ])
    const decoded = decodeManifest(
      encodeContainer(encodeTbs(sampleInput({ entries })), new Uint8Array(0)),
    )
    expect([...decoded.manifest.entries.keys()]).toEqual(['a.js', 'bb.js', 'c-long.js'])
  })

  it('canonicalTextKeyOrder matches encoded-byte ordering (incl. multi-byte utf8)', () => {
    const cases: [string, string][] = [
      ['a.js', 'bb.js'],
      ['zz', 'aaaa'],
      ['é.js', 'f.js'], // é is 2 utf8 bytes → encoded length 6 vs 5
    ]
    for (const [a, b] of cases) {
      const encodedA = encode(a)
      const encodedB = encode(b)
      const byBytes =
        encodedA.byteLength !== encodedB.byteLength
          ? Math.sign(encodedA.byteLength - encodedB.byteLength)
          : Math.sign(Buffer.compare(Buffer.from(encodedA), Buffer.from(encodedB)))
      expect(Math.sign(canonicalTextKeyOrder(a, b))).toBe(byBytes)
    }
  })

  it('rejects unsafe integers', () => {
    expect(() => encode(2 ** 60)).toThrow()
  })
})
