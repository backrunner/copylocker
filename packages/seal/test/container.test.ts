import { describe, expect, it } from 'vitest'
// Cross-tests import the @copylocker/web sources directly so byte
// compatibility is checked against the web package's current implementation.
import {
  openSealedAsset as webOpen,
  sealAsset as webSeal,
  decodeSealedAsset as webDecode,
  UnsealError,
} from '../../web/src/unseal.js'
import { decode, encode, mapGet, type CborValue } from '../src/cbor.js'
import {
  decodeSealedAsset,
  openSealedBytes,
  sealAad,
  sealBytes,
} from '../src/container.js'
import { SealError } from '../src/errors.js'

const kek = new Uint8Array(32).fill(7)
const meta = { productId: 'demo', variantId: 0, featureId: 'pro', assetId: 'assets/model.bin' }
const plaintext = new Uint8Array([1, 2, 3, 4, 5, 250, 251, 252])

function bigPlaintext(size: number): Uint8Array {
  const bytes = new Uint8Array(size)
  for (let i = 0; i < size; i += 1) bytes[i] = (i * 31) & 0xff
  return bytes
}

/** Re-encode a container with a swapped payload (test surgery). */
function reencodeWithPayload(sealed: Uint8Array, payload: Uint8Array): Uint8Array {
  const value = decode(sealed, { maxDepth: 8, maxItems: 32, maxString: 64 * 1024 * 1024 })
  if (!(value instanceof Map)) throw new Error('test: expected map')
  const entries: [number, CborValue][] = []
  for (const [k, v] of value) entries.push([k as number, v])
  const next = entries.map(([k, v]): [number, CborValue] => (k === 6 ? [6, payload] : [k, v]))
  return encode(new Map<number, CborValue>(next))
}

describe('container: byte compatibility with @copylocker/web', () => {
  it('seal → web opens (plain)', async () => {
    const sealed = await sealBytes(kek, meta, plaintext)
    const opened = await webOpen(kek, sealed, { productId: 'demo', featureId: 'pro' })
    expect(opened).toEqual(plaintext)
  })

  it('web → seal opens (plain)', async () => {
    const sealed = await webSeal(kek, meta, plaintext)
    const opened = await openSealedBytes(kek, sealed, { productId: 'demo', featureId: 'pro' })
    expect(opened).toEqual(plaintext)
  })

  it('seal → web opens (chunked)', async () => {
    const big = bigPlaintext(10_000)
    const sealed = await sealBytes(kek, meta, big, { chunkSize: 4096 })
    const header = webDecode(sealed)
    expect(header.chunking).toEqual({ chunkSize: 4096, chunkCount: 3 })
    const opened = await webOpen(kek, sealed, { productId: 'demo', featureId: 'pro' })
    expect(opened).toEqual(big)
  })

  it('web → seal opens (chunked)', async () => {
    const big = bigPlaintext(10_000)
    const sealed = await webSeal(kek, meta, big, { chunkSize: 4096 })
    const header = decodeSealedAsset(sealed)
    expect(header.chunking).toEqual({ chunkSize: 4096, chunkCount: 3 })
    const opened = await openSealedBytes(kek, sealed, { productId: 'demo', featureId: 'pro' })
    expect(opened).toEqual(big)
  })

  it('header fields decode identically in both directions', async () => {
    const sealedBySeal = await sealBytes(kek, meta, plaintext)
    const sealedByWeb = await webSeal(kek, meta, plaintext)
    for (const [label, sealed] of [
      ['seal', sealedBySeal],
      ['web', sealedByWeb],
    ] as const) {
      const viaSeal = decodeSealedAsset(sealed)
      const viaWeb = webDecode(sealed)
      expect(viaSeal.productId, label).toBe('demo')
      expect(viaSeal.featureId, label).toBe('pro')
      expect(viaSeal.assetId, label).toBe('assets/model.bin')
      expect(viaWeb.productId, label).toBe(viaSeal.productId)
      expect(viaWeb.variantId, label).toBe(viaSeal.variantId)
      expect(viaWeb.featureId, label).toBe(viaSeal.featureId)
      expect(viaWeb.assetId, label).toBe(viaSeal.assetId)
      expect(viaWeb.ciphertext.byteLength, label).toBe(viaSeal.ciphertext.byteLength)
    }
  })

  it('header bytes (everything before the payload) are identical', async () => {
    const sealedBySeal = await sealBytes(kek, meta, plaintext)
    const sealedByWeb = await webSeal(kek, meta, plaintext)
    // The payload is a bstr of identical length; the CBOR prefix up to and
    // including the bstr head must match byte for byte.
    const payloadLen = plaintext.byteLength + 12 + 16
    const headLen = (bytes: Uint8Array) =>
      bytes.byteLength - payloadLen
    const headSeal = sealedBySeal.subarray(0, headLen(sealedBySeal))
    const headWeb = sealedByWeb.subarray(0, headLen(sealedByWeb))
    expect(headSeal).toEqual(headWeb)
  })
})

describe('container: tamper detection and error classification', () => {
  it('distinguishes NOT_ENTITLED (AEAD) from CORRUPT (structure)', async () => {
    const sealed = await sealBytes(kek, meta, plaintext)

    // Structural: truncated container → CORRUPT.
    const truncated = sealed.subarray(0, sealed.byteLength - 10)
    const errTrunc = await openSealedBytes(kek, truncated).catch((e: unknown) => e)
    expect(errTrunc).toBeInstanceOf(SealError)
    expect((errTrunc as SealError).code).toBe('CORRUPT')

    // AEAD: flipped ciphertext byte → NOT_ENTITLED.
    const tampered = sealed.slice()
    tampered[tampered.byteLength - 3] = (tampered[tampered.byteLength - 3] as number) ^ 1
    const errTamper = await openSealedBytes(kek, tampered).catch((e: unknown) => e)
    expect(errTamper).toBeInstanceOf(SealError)
    expect((errTamper as SealError).code).toBe('NOT_ENTITLED')
  })

  it('nonce tamper fails authentication', async () => {
    const sealed = await sealBytes(kek, meta, plaintext)
    const header = decodeSealedAsset(sealed)
    const payloadStart = sealed.byteLength - header.ciphertext.byteLength
    const tampered = sealed.slice()
    tampered[payloadStart] = (tampered[payloadStart] as number) ^ 1 // first nonce byte
    await expect(openSealedBytes(kek, tampered)).rejects.toMatchObject({ code: 'NOT_ENTITLED' })
  })

  it('AAD tamper (assetId rewrite) fails authentication', async () => {
    const sealed = await sealBytes(kek, meta, plaintext)
    const value = decode(sealed, { maxDepth: 8, maxItems: 32, maxString: 64 * 1024 * 1024 })
    if (!(value instanceof Map)) throw new Error('test: expected map')
    value.set(5, 'assets/other.bin')
    const tampered = encode(value)
    await expect(openSealedBytes(kek, tampered)).rejects.toMatchObject({ code: 'NOT_ENTITLED' })
  })

  it('expected product/feature mismatch is NOT_ENTITLED', async () => {
    const sealed = await sealBytes(kek, meta, plaintext)
    await expect(
      openSealedBytes(kek, sealed, { productId: 'demo', featureId: 'other' }),
    ).rejects.toMatchObject({ code: 'NOT_ENTITLED' })
    await expect(
      openSealedBytes(kek, sealed, { productId: 'other', featureId: 'pro' }),
    ).rejects.toMatchObject({ code: 'NOT_ENTITLED' })
  })

  it('wrong KEK fails authentication', async () => {
    const sealed = await sealBytes(kek, meta, plaintext)
    const wrong = new Uint8Array(32).fill(8)
    await expect(openSealedBytes(wrong, sealed)).rejects.toMatchObject({ code: 'NOT_ENTITLED' })
  })
})

describe('container: chunked extension robustness', () => {
  it('reordered chunks fail (index bound in nonce and AAD)', async () => {
    const big = bigPlaintext(10_000)
    const sealed = await sealBytes(kek, meta, big, { chunkSize: 4096 })
    const header = decodeSealedAsset(sealed)
    const recordLen = 4096 + 28
    const payload = header.ciphertext
    const swapped = new Uint8Array(payload.byteLength)
    swapped.set(payload.subarray(recordLen, 2 * recordLen), 0)
    swapped.set(payload.subarray(0, recordLen), recordLen)
    swapped.set(payload.subarray(2 * recordLen), 2 * recordLen)
    const reordered = reencodeWithPayload(sealed, swapped)
    await expect(openSealedBytes(kek, reordered)).rejects.toMatchObject({ code: 'NOT_ENTITLED' })
    // The web runtime must reject it too.
    await expect(
      webOpen(kek, reordered, { productId: 'demo', featureId: 'pro' }),
    ).rejects.toThrow(UnsealError)
  })

  it('a dropped chunk fails structural validation (CORRUPT)', async () => {
    const big = bigPlaintext(10_000)
    const sealed = await sealBytes(kek, meta, big, { chunkSize: 4096 })
    const header = decodeSealedAsset(sealed)
    const recordLen = 4096 + 28
    const payload = header.ciphertext
    const dropped = new Uint8Array(payload.byteLength - recordLen)
    dropped.set(payload.subarray(0, recordLen), 0)
    dropped.set(payload.subarray(2 * recordLen), recordLen)
    const damaged = reencodeWithPayload(sealed, dropped)
    await expect(openSealedBytes(kek, damaged)).rejects.toMatchObject({ code: 'CORRUPT' })
    await expect(
      webOpen(kek, damaged, { productId: 'demo', featureId: 'pro' }),
    ).rejects.toThrow(UnsealError)
  })

  it('chunk params are authenticated — edited chunkCount fails', async () => {
    const big = bigPlaintext(10_000)
    const sealed = await sealBytes(kek, meta, big, { chunkSize: 4096 })
    const value = decode(sealed, { maxDepth: 8, maxItems: 32, maxString: 64 * 1024 * 1024 })
    if (!(value instanceof Map)) throw new Error('test: expected map')
    value.set(8, 2) // lie about the chunk count
    const tampered = encode(value)
    await expect(openSealedBytes(kek, tampered)).rejects.toMatchObject({ code: 'CORRUPT' })
  })

  it('round-trips a >4MiB asset with the default chunk size', async () => {
    const big = bigPlaintext(4 * 1024 * 1024 + 123)
    const sealed = await sealBytes(kek, meta, big)
    expect(decodeSealedAsset(sealed).chunking).toBeUndefined() // sealBytes defaults to plain
    const chunked = await sealBytes(kek, meta, big, { chunkSize: 4 * 1024 * 1024 })
    expect(decodeSealedAsset(chunked).chunking).toEqual({
      chunkSize: 4 * 1024 * 1024,
      chunkCount: 2,
    })
    const opened = await openSealedBytes(kek, chunked)
    expect(opened).toEqual(big)
  }, 20_000)

  it('sealAad matches the web v1 AAD layout', () => {
    // {0: label, 1: alg, 2..5: ids} — decode and verify fields directly.
    const aadBytes = sealAad(meta)
    const value = decode(aadBytes)
    expect(mapGet(value, 0)).toBe('copylocker/web-asset-aad/v1')
    expect(mapGet(value, 1)).toBe('AES-256-GCM')
    expect(mapGet(value, 2)).toBe('demo')
    expect(mapGet(value, 4)).toBe('pro')
    expect(mapGet(value, 5)).toBe('assets/model.bin')
    expect(mapGet(value, 6)).toBeUndefined()
    const chunkedAad = sealAad(meta, { index: 2, count: 3 })
    const decoded = decode(chunkedAad)
    expect(mapGet(decoded, 6)).toBe(2)
    expect(mapGet(decoded, 7)).toBe(3)
  })
})
