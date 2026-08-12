/**
 * Sealed-asset opening for the web (design §3.2).
 *
 * **Web v1 container.** The native `SealedAsset` format
 * (`crates/copylocker-proto/src/sealed_asset.rs`) encrypts with
 * XChaCha20-Poly1305 (24-byte nonce), which WebCrypto does not implement and
 * this package will not polyfill (zero-dependency, CSP-friendly). The web
 * container therefore keeps the native layout and AAD discipline but swaps
 * the payload AEAD to AES-256-GCM (12-byte nonce, WebCrypto
 * `nonce ‖ ciphertext ‖ tag` layout):
 *
 * ```cddl
 * web-sealed-asset = {
 *   0: 1,                  ; schema
 *   1: "AES-256-GCM",      ; payload algorithm label
 *   2: tstr,               ; product_id
 *   3: uint,               ; variant_id
 *   4: tstr,               ; feature_id
 *   5: tstr,               ; asset_id
 *   6: bstr,               ; nonce(12) ‖ ciphertext ‖ tag(16)
 * }
 * aad = {0: "copylocker/web-asset-aad/v1", 1: alg, 2: product_id,
 *        3: variant_id, 4: feature_id, 5: asset_id}
 * ```
 *
 * **Chunked extension (`web v1 chunked`).** Assets larger than the configured
 * chunk size add header keys `7: chunk_size` and `8: chunk_count`; field 6
 * then holds `chunk_count` concatenated `nonce(12) ‖ ct ‖ tag(16)` records,
 * one per `chunk_size`-byte plaintext block (the last may be short). Chunk
 * `i` uses nonce `prefix(8) ‖ uint32be(i)` and AAD extended with
 * `{6: chunk_index, 7: chunk_count}`, so reordering or dropping a chunk fails
 * authentication. Small assets always use the plain form above, so older
 * decoders keep working on them.
 *
 * This is a deliberate divergence from the native container; the M4
 * `@copylocker/seal` package emits both forms for web targets.
 * See README "Sealed asset format".
 */

import { encode, decode, mapGet, type CborValue } from './cbor.js'

export const WEB_SEALED_ASSET_SCHEMA = 1
export const WEB_SEALED_ASSET_ALG = 'AES-256-GCM'
export const MAX_SEALED_ASSET_BYTES = 64 * 1024 * 1024

const NONCE_BYTES = 12
const TAG_BYTES = 16
const CHUNK_OVERHEAD = NONCE_BYTES + TAG_BYTES
const NONCE_PREFIX_BYTES = 8
const AAD_LABEL = 'copylocker/web-asset-aad/v1'

const ASSET_LIMITS = { maxDepth: 8, maxItems: 32, maxString: MAX_SEALED_ASSET_BYTES }

export class UnsealError extends Error {
  constructor(message = 'CopyLocker: sealed asset cannot be opened') {
    super(message)
    this.name = 'UnsealError'
  }
}

export interface SealedAssetMeta {
  productId: string
  variantId: number
  featureId: string
  assetId: string
}

/** Chunked-extension parameters carried in header keys 7/8. */
export interface Chunking {
  chunkSize: number
  chunkCount: number
}

function requireText(value: CborValue | undefined): string {
  if (typeof value !== 'string') throw new UnsealError()
  return value
}

function requireUint(value: CborValue | undefined): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new UnsealError()
  }
  return value
}

function identifiersValid(meta: SealedAssetMeta): boolean {
  return [meta.productId, meta.featureId, meta.assetId].every(
    (id) => id.length > 0 && id.length <= 1024 && !id.includes('\0'),
  )
}

function aad(meta: SealedAssetMeta, chunk?: { index: number; count: number }): Uint8Array {
  const entries: [number, CborValue][] = [
    [0, AAD_LABEL],
    [1, WEB_SEALED_ASSET_ALG],
    [2, meta.productId],
    [3, meta.variantId],
    [4, meta.featureId],
    [5, meta.assetId],
  ]
  if (chunk) {
    entries.push([6, chunk.index], [7, chunk.count])
  }
  return encode(new Map<number, CborValue>(entries))
}

async function importKey(finalKey: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('CopyLocker: WebCrypto SubtleCrypto is required (secure context)')
  }
  return subtle.importKey('raw', finalKey as unknown as ArrayBuffer, 'AES-GCM', false, usages)
}

/** Decode and validate the container header without touching the payload. */
export function decodeSealedAsset(
  sealed: Uint8Array,
): SealedAssetMeta & { ciphertext: Uint8Array; chunking?: Chunking } {
  if (sealed.byteLength === 0 || sealed.byteLength > MAX_SEALED_ASSET_BYTES) {
    throw new UnsealError()
  }
  try {
    const value = decode(sealed, ASSET_LIMITS)
    if (requireUint(mapGet(value, 0)) !== WEB_SEALED_ASSET_SCHEMA) throw new UnsealError()
    if (requireText(mapGet(value, 1)) !== WEB_SEALED_ASSET_ALG) throw new UnsealError()
    const meta: SealedAssetMeta = {
      productId: requireText(mapGet(value, 2)),
      variantId: requireUint(mapGet(value, 3)),
      featureId: requireText(mapGet(value, 4)),
      assetId: requireText(mapGet(value, 5)),
    }
    const ciphertext = mapGet(value, 6)
    if (!(ciphertext instanceof Uint8Array) || ciphertext.byteLength < CHUNK_OVERHEAD) {
      throw new UnsealError()
    }
    if (!identifiersValid(meta)) throw new UnsealError()
    const rawChunkSize = mapGet(value, 7)
    const rawChunkCount = mapGet(value, 8)
    if (rawChunkSize === undefined && rawChunkCount === undefined) {
      return { ...meta, ciphertext }
    }
    const chunking: Chunking = {
      chunkSize: requireUint(rawChunkSize),
      chunkCount: requireUint(rawChunkCount),
    }
    validateChunking(ciphertext.byteLength, chunking)
    return { ...meta, ciphertext, chunking }
  } catch (error) {
    if (error instanceof UnsealError) throw error
    throw new UnsealError()
  }
}

function validateChunking(payloadBytes: number, chunking: Chunking): void {
  const { chunkSize, chunkCount } = chunking
  if (chunkSize < 1 || chunkCount < 1 || chunkCount > 0xffff_ffff) throw new UnsealError()
  const fullWire = chunkSize + CHUNK_OVERHEAD
  const lastWire = payloadBytes - (chunkCount - 1) * fullWire
  // The final record must hold at least one plaintext byte and at most a
  // full chunk; anything else means a dropped or truncated chunk.
  if (lastWire <= CHUNK_OVERHEAD || lastWire > fullWire) throw new UnsealError()
}

/** nonce for chunk `index`: 8-byte random prefix ‖ uint32be(index). */
function chunkNonce(prefix: Uint8Array, index: number): Uint8Array {
  const nonce = new Uint8Array(NONCE_BYTES)
  nonce.set(prefix, 0)
  nonce[NONCE_PREFIX_BYTES] = (index >>> 24) & 0xff
  nonce[NONCE_PREFIX_BYTES + 1] = (index >>> 16) & 0xff
  nonce[NONCE_PREFIX_BYTES + 2] = (index >>> 8) & 0xff
  nonce[NONCE_PREFIX_BYTES + 3] = index & 0xff
  return nonce
}

async function gcmDecryptRecord(
  key: CryptoKey,
  record: Uint8Array,
  aadBytes: Uint8Array,
): Promise<Uint8Array> {
  const nonce = record.subarray(0, NONCE_BYTES)
  const body = record.subarray(NONCE_BYTES)
  try {
    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce as unknown as ArrayBuffer, additionalData: aadBytes as unknown as ArrayBuffer },
      key,
      body as unknown as ArrayBuffer,
    )
    return new Uint8Array(plaintext)
  } catch {
    throw new UnsealError()
  }
}

/**
 * Open a web v1 sealed asset with the two-stage `FinalKey`. `expected` binds
 * the caller's product and feature to the authenticated header; any mismatch
 * — or any bit flip in the container — throws {@link UnsealError}. Chunked
 * containers (header keys 7/8) are decrypted chunk by chunk; a reordered,
 * dropped, or truncated chunk fails authentication.
 */
export async function openSealedAsset(
  finalKey: Uint8Array,
  sealed: Uint8Array,
  expected: { productId: string; featureId: string },
): Promise<Uint8Array> {
  const asset = decodeSealedAsset(sealed)
  if (asset.productId !== expected.productId || asset.featureId !== expected.featureId) {
    throw new UnsealError()
  }
  const key = await importKey(finalKey, ['decrypt'])
  const meta: SealedAssetMeta = {
    productId: asset.productId,
    variantId: asset.variantId,
    featureId: asset.featureId,
    assetId: asset.assetId,
  }
  if (!asset.chunking) {
    return gcmDecryptRecord(key, asset.ciphertext, aad(meta))
  }
  const chunking = asset.chunking
  const fullWire = chunking.chunkSize + CHUNK_OVERHEAD
  const parts: Uint8Array[] = []
  let total = 0
  let offset = 0
  for (let i = 0; i < chunking.chunkCount; i += 1) {
    const wire = Math.min(fullWire, asset.ciphertext.byteLength - offset)
    const record = asset.ciphertext.subarray(offset, offset + wire)
    offset += wire
    const part = await gcmDecryptRecord(key, record, aad(meta, { index: i, count: chunking.chunkCount }))
    parts.push(part)
    total += part.byteLength
  }
  const plaintext = new Uint8Array(total)
  let write = 0
  for (const part of parts) {
    plaintext.set(part, write)
    write += part.byteLength
  }
  return plaintext
}

/**
 * Seal an asset into the web v1 container.
 *
 * This exists so tests (and the M4 `@copylocker/seal` web target) can
 * produce fixtures; production sealing is a build-time operation, not a
 * runtime one. With `options.chunkSize`, plaintexts larger than the chunk
 * size are emitted in the chunked form (header keys 7/8).
 */
export async function sealAsset(
  finalKey: Uint8Array,
  meta: SealedAssetMeta,
  plaintext: Uint8Array,
  options?: { chunkSize?: number },
): Promise<Uint8Array> {
  if (!identifiersValid(meta)) throw new UnsealError()
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('CopyLocker: WebCrypto SubtleCrypto is required (secure context)')
  }
  const key = await importKey(finalKey, ['encrypt'])

  let ciphertext: Uint8Array
  let chunking: Chunking | undefined
  const chunkSize = options?.chunkSize ?? 0
  if (chunkSize > 0 && plaintext.byteLength > chunkSize) {
    const chunkCount = Math.ceil(plaintext.byteLength / chunkSize)
    const prefix = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_PREFIX_BYTES))
    const records: Uint8Array[] = []
    let total = 0
    for (let i = 0; i < chunkCount; i += 1) {
      const nonce = chunkNonce(prefix, i)
      const body = new Uint8Array(
        await subtle.encrypt(
          { name: 'AES-GCM', iv: nonce as unknown as ArrayBuffer, additionalData: aad(meta, { index: i, count: chunkCount }) as unknown as ArrayBuffer },
          key,
          plaintext.subarray(i * chunkSize, (i + 1) * chunkSize) as unknown as ArrayBuffer,
        ),
      )
      const record = new Uint8Array(NONCE_BYTES + body.byteLength)
      record.set(nonce, 0)
      record.set(body, NONCE_BYTES)
      records.push(record)
      total += record.byteLength
    }
    ciphertext = new Uint8Array(total)
    let offset = 0
    for (const record of records) {
      ciphertext.set(record, offset)
      offset += record.byteLength
    }
    chunking = { chunkSize, chunkCount }
  } else {
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
    const body = new Uint8Array(
      await subtle.encrypt(
        { name: 'AES-GCM', iv: nonce as unknown as ArrayBuffer, additionalData: aad(meta) as unknown as ArrayBuffer },
        key,
        plaintext as unknown as ArrayBuffer,
      ),
    )
    ciphertext = new Uint8Array(NONCE_BYTES + body.byteLength)
    ciphertext.set(nonce, 0)
    ciphertext.set(body, NONCE_BYTES)
  }

  const entries: [number, CborValue][] = [
    [0, WEB_SEALED_ASSET_SCHEMA],
    [1, WEB_SEALED_ASSET_ALG],
    [2, meta.productId],
    [3, meta.variantId],
    [4, meta.featureId],
    [5, meta.assetId],
    [6, ciphertext],
  ]
  if (chunking) {
    entries.push([7, chunking.chunkSize], [8, chunking.chunkCount])
  }
  return encode(new Map<number, CborValue>(entries))
}
