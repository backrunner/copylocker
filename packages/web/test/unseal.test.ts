import { describe, expect, it } from 'vitest'
import { decodeSealedAsset, openSealedAsset, sealAsset, UnsealError } from '../src/unseal.js'

const key = new Uint8Array(32).fill(11)
const meta = { productId: 'demo', variantId: 0, featureId: 'pro', assetId: 'chunk.wasm' }
const plaintext = new Uint8Array([1, 2, 3, 4, 5])

describe('unseal (web v1 sealed asset)', () => {
  it('round-trips a sealed asset', async () => {
    const sealed = await sealAsset(key, meta, plaintext)
    const header = decodeSealedAsset(sealed)
    expect(header.productId).toBe('demo')
    expect(header.featureId).toBe('pro')
    const opened = await openSealedAsset(key, sealed, { productId: 'demo', featureId: 'pro' })
    expect(opened).toEqual(plaintext)
  })

  it('fails with the wrong final key', async () => {
    const sealed = await sealAsset(key, meta, plaintext)
    const wrong = new Uint8Array(32).fill(12)
    await expect(
      openSealedAsset(wrong, sealed, { productId: 'demo', featureId: 'pro' }),
    ).rejects.toThrow(UnsealError)
  })

  it('fails on feature/product mismatch (no cross-feature key reuse)', async () => {
    const sealed = await sealAsset(key, meta, plaintext)
    await expect(
      openSealedAsset(key, sealed, { productId: 'demo', featureId: 'other' }),
    ).rejects.toThrow(UnsealError)
    await expect(
      openSealedAsset(key, sealed, { productId: 'other', featureId: 'pro' }),
    ).rejects.toThrow(UnsealError)
  })

  it('detects any tampered byte in the container', async () => {
    const sealed = await sealAsset(key, meta, plaintext)
    sealed[sealed.byteLength - 3] = (sealed[sealed.byteLength - 3] as number) ^ 1
    await expect(
      openSealedAsset(key, sealed, { productId: 'demo', featureId: 'pro' }),
    ).rejects.toThrow(UnsealError)
  })

  it('rejects malformed containers', async () => {
    await expect(
      openSealedAsset(key, new Uint8Array([0]), { productId: 'demo', featureId: 'pro' }),
    ).rejects.toThrow(UnsealError)
    await expect(
      openSealedAsset(key, new Uint8Array(0), { productId: 'demo', featureId: 'pro' }),
    ).rejects.toThrow(UnsealError)
  })
})

describe('unseal (web v1 chunked extension)', () => {
  const bigPlaintext = new Uint8Array(10_000)
  for (let i = 0; i < bigPlaintext.byteLength; i += 1) bigPlaintext[i] = i & 0xff

  it('round-trips a chunked sealed asset', async () => {
    const sealed = await sealAsset(key, meta, bigPlaintext, { chunkSize: 4096 })
    const header = decodeSealedAsset(sealed)
    expect(header.chunking).toEqual({ chunkSize: 4096, chunkCount: 3 })
    const opened = await openSealedAsset(key, sealed, { productId: 'demo', featureId: 'pro' })
    expect(opened).toEqual(bigPlaintext)
  })

  it('emits the plain form when the plaintext fits in one chunk', async () => {
    const sealed = await sealAsset(key, meta, plaintext, { chunkSize: 4096 })
    expect(decodeSealedAsset(sealed).chunking).toBeUndefined()
    const opened = await openSealedAsset(key, sealed, { productId: 'demo', featureId: 'pro' })
    expect(opened).toEqual(plaintext)
  })

  it('rejects a reordered chunk', async () => {
    const chunkSize = 4096
    const sealed = await sealAsset(key, meta, bigPlaintext, { chunkSize })
    const header = decodeSealedAsset(sealed)
    const recordLen = chunkSize + 28
    // Swap chunk records 0 and 1 inside the payload. The header occupies the
    // leading bytes; locate the payload by its declared length.
    const payloadLen = header.ciphertext.byteLength
    const payloadStart = sealed.byteLength - payloadLen
    const swapped = sealed.slice()
    const first = sealed.subarray(payloadStart, payloadStart + recordLen)
    const second = sealed.subarray(payloadStart + recordLen, payloadStart + 2 * recordLen)
    swapped.set(second, payloadStart)
    swapped.set(first, payloadStart + recordLen)
    await expect(
      openSealedAsset(key, swapped, { productId: 'demo', featureId: 'pro' }),
    ).rejects.toThrow(UnsealError)
  })

  it('rejects a dropped chunk', async () => {
    const chunkSize = 4096
    const sealed = await sealAsset(key, meta, bigPlaintext, { chunkSize })
    // Truncate one whole record: the header's wire-math validation must
    // reject the payload before any decryption is attempted.
    const recordLen = chunkSize + 28
    const truncated = sealed.subarray(0, sealed.byteLength - recordLen)
    await expect(
      openSealedAsset(key, truncated, { productId: 'demo', featureId: 'pro' }),
    ).rejects.toThrow(UnsealError)
  })

  it('rejects tampered chunk parameters', async () => {
    const sealed = await sealAsset(key, meta, bigPlaintext, { chunkSize: 4096 })
    const tampered = sealed.slice()
    // Flip a byte inside the first chunk record (payload lives at the tail).
    tampered[tampered.byteLength - 3] = (tampered[tampered.byteLength - 3] as number) ^ 1
    await expect(
      openSealedAsset(key, tampered, { productId: 'demo', featureId: 'pro' }),
    ).rejects.toThrow(UnsealError)
  })
})
