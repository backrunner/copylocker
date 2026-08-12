import { describe, expect, it } from 'vitest'
import { decodeManifest, verifyManifestSignature, signManifestTbs } from '../src/manifest.js'
import { encode, type CborValue } from '../src/cbor.js'
import { makeFixture, textBytes } from './helpers.js'

describe('manifest decode', () => {
  it('round-trips the fixture container', async () => {
    const fixture = await makeFixture([
      { pattern: 'a.js', content: textBytes('entry chunk') },
      {
        pattern: 'b.js',
        content: textBytes('chunk with placeholder'),
        excludedRanges: [[4, 8]],
      },
    ])
    const signed = decodeManifest(fixture.manifestBytes)
    expect(signed.manifest.protoVer).toBe(1)
    expect(signed.manifest.productId).toBe('test-product')
    expect(signed.manifest.hashAlg).toBe('sha256')
    expect([...signed.manifest.entries.keys()]).toEqual(['a.js', 'b.js'])
    expect(signed.manifest.entries.get('b.js')?.excludedRanges).toEqual([[4, 8]])
    expect(signed.manifest.entries.get('a.js')?.excludedRanges).toEqual([])
    expect(signed.manifest.root).toEqual(fixture.expectedRoot)
    expect(signed.signature.byteLength).toBe(64)
  })

  it('rejects truncated / malformed CBOR', async () => {
    const fixture = await makeFixture([{ pattern: 'a.js', content: textBytes('x') }])
    expect(() => decodeManifest(fixture.manifestBytes.slice(0, 5))).toThrow()
    expect(() => decodeManifest(textBytes('not cbor at all'))).toThrow()
  })

  it('rejects an unsupported proto_ver', async () => {
    const tbs = new Map<number, CborValue>()
    tbs.set(0, 99)
    tbs.set(1, new Uint8Array(4))
    tbs.set(2, 'p')
    tbs.set(3, 'fp')
    tbs.set(4, 0)
    tbs.set(5, 'sha256')
    tbs.set(6, new Map())
    tbs.set(9, new Uint8Array(32))
    const container = new Map<number, CborValue>()
    container.set(0, encode(tbs))
    container.set(1, new Uint8Array(0))
    expect(() => decodeManifest(encode(container))).toThrow(/proto_ver/)
  })
})

describe('manifest signature (WebCrypto Ed25519)', () => {
  it('verifies a correctly signed manifest', async () => {
    const fixture = await makeFixture([{ pattern: 'a.js', content: textBytes('x') }])
    const signed = decodeManifest(fixture.manifestBytes)
    expect(await verifyManifestSignature(signed, [fixture.publicKey])).toBe('verified')
  })

  it('fails when one payload byte is flipped', async () => {
    const fixture = await makeFixture([{ pattern: 'a.js', content: textBytes('x') }])
    const signed = decodeManifest(fixture.manifestBytes)
    const tamperedTbs = new Uint8Array(signed.tbsBytes)
    tamperedTbs[3] = (tamperedTbs[3] as number) ^ 0xff
    const status = await verifyManifestSignature(
      { ...signed, tbsBytes: tamperedTbs },
      [fixture.publicKey],
    )
    expect(status).toBe('failed')
  })

  it('fails under a different public key', async () => {
    const fixture = await makeFixture([{ pattern: 'a.js', content: textBytes('x') }])
    const other = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
    const otherRaw = new Uint8Array(await crypto.subtle.exportKey('raw', other.publicKey))
    const signed = decodeManifest(fixture.manifestBytes)
    expect(await verifyManifestSignature(signed, [otherRaw])).toBe('failed')
  })

  it('a malformed first pin does not mask a valid second pin', async () => {
    const fixture = await makeFixture([{ pattern: 'a.js', content: textBytes('x') }])
    const signed = decodeManifest(fixture.manifestBytes)
    const garbagePin = new Uint8Array([1, 2, 3]) // importKey rejects the length
    expect(await verifyManifestSignature(signed, [garbagePin, fixture.publicKey])).toBe('verified')
  })

  it('reports unsupported only when no pin could even be attempted', async () => {
    const fixture = await makeFixture([{ pattern: 'a.js', content: textBytes('x') }])
    const signed = decodeManifest(fixture.manifestBytes)
    const garbagePin = new Uint8Array([1, 2, 3])
    expect(await verifyManifestSignature(signed, [garbagePin])).toBe('unsupported')
  })

  it('reports unsigned / no-pins distinctly', async () => {
    const unsigned = await makeFixture([{ pattern: 'a.js', content: textBytes('x') }], {
      sign: false,
    })
    const signed = decodeManifest(unsigned.manifestBytes)
    expect(await verifyManifestSignature(signed, [unsigned.publicKey])).toBe('unsigned')

    const fixture = await makeFixture([{ pattern: 'a.js', content: textBytes('x') }])
    const signed2 = decodeManifest(fixture.manifestBytes)
    expect(await verifyManifestSignature(signed2, [])).toBe('no-pins')
  })

  it('signManifestTbs round-trips through the verifier', async () => {
    const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))
    const tbs = textBytes('payload')
    const signature = await signManifestTbs(tbs, keys.privateKey)
    const signed = {
      manifest: undefined as never,
      tbsBytes: tbs,
      signature,
    }
    expect(await verifyManifestSignature(signed, [raw])).toBe('verified')
  })
})
