/**
 * Web v1 sealed-asset container, byte-compatible with `@copylocker/web`
 * (`packages/web/src/unseal.ts`):
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
 *   ? 7: uint,             ; chunk_size   (chunked extension, plaintext bytes/chunk)
 *   ? 8: uint,             ; chunk_count  (chunked extension)
 * }
 * aad = {0: "copylocker/web-asset-aad/v1", 1: alg, 2: product_id,
 *        3: variant_id, 4: feature_id, 5: asset_id}
 * ```
 *
 * **Chunked extension (`web v1 chunked`).** When keys 7/8 are present, field 6
 * is the concatenation of `chunk_count` records of
 * `nonce(12) ‖ ct ‖ tag(16)`, one per `chunk_size`-byte plaintext block (the
 * last block may be short). Chunk `i` uses nonce `prefix(8) ‖ uint32be(i)`
 * and AAD extended with `{6: chunk_index, 7: chunk_count}`, so reordering or
 * dropping a chunk fails authentication. A plaintext that fits in one chunk
 * is always emitted in the non-chunked form, so existing decoders keep
 * working on small assets.
 *
 * NOTE on AAD discipline: the design sketch (`50-unplugin-integrity.md` §4.1)
 * binds `assetId ‖ buildFingerprint` as AAD. The implemented web v1 AAD binds
 * product/variant/feature/asset ids instead; byte compatibility with the
 * shipped `@copylocker/web` runtime wins, and the build fingerprint flows
 * into `MANIFEST_ROOT` (hence FinalKey) instead of the per-asset AAD.
 */

import { encode, decode, mapGet, type CborValue } from './cbor.js'
import { corrupt, notEntitled, configError } from './errors.js'
import type { KeyUsage } from './webcrypto.js'

export const WEB_SEALED_ASSET_SCHEMA = 1
export const WEB_SEALED_ASSET_ALG = 'AES-256-GCM'
export const MAX_SEALED_ASSET_BYTES = 64 * 1024 * 1024

export const NONCE_BYTES = 12
export const TAG_BYTES = 16
const CHUNK_OVERHEAD = NONCE_BYTES + TAG_BYTES
/** Default plaintext chunk size for the chunked extension (design §4.2: 4 MiB). */
export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
const NONCE_PREFIX_BYTES = 8
const AAD_LABEL = 'copylocker/web-asset-aad/v1'

const ASSET_LIMITS = { maxDepth: 8, maxItems: 32, maxString: MAX_SEALED_ASSET_BYTES }

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
  if (typeof value !== 'string') throw corrupt()
  return value
}

function requireUint(value: CborValue | undefined): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw corrupt()
  }
  return value
}

function identifiersValid(meta: SealedAssetMeta): boolean {
  return [meta.productId, meta.featureId, meta.assetId].every(
    (id) => id.length > 0 && id.length <= 1024 && !id.includes('\0'),
  )
}

/** AAD for the whole asset, or for one chunk when `chunk` is given. */
export function sealAad(meta: SealedAssetMeta, chunk?: { index: number; count: number }): Uint8Array {
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

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  globalThis.crypto.getRandomValues(bytes)
  return bytes
}

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle
  if (!s) throw configError('CopyLocker seal: WebCrypto SubtleCrypto is required (Node 20+)')
  return s
}

async function importKey(keyBytes: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (keyBytes.byteLength !== 32) {
    throw configError('CopyLocker seal: AES-256 keys must be 32 bytes')
  }
  return subtle().importKey('raw', keyBytes as unknown as ArrayBuffer, 'AES-GCM', false, usages)
}

async function gcmEncrypt(
  key: CryptoKey,
  nonce: Uint8Array,
  aadBytes: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const body = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv: nonce as unknown as ArrayBuffer, additionalData: aadBytes as unknown as ArrayBuffer },
      key,
      plaintext as unknown as ArrayBuffer,
    ),
  )
  const record = new Uint8Array(NONCE_BYTES + body.byteLength)
  record.set(nonce, 0)
  record.set(body, NONCE_BYTES)
  return record
}

async function gcmDecrypt(
  key: CryptoKey,
  record: Uint8Array,
  aadBytes: Uint8Array,
): Promise<Uint8Array> {
  const nonce = record.subarray(0, NONCE_BYTES)
  const body = record.subarray(NONCE_BYTES)
  try {
    const plaintext = await subtle().decrypt(
      { name: 'AES-GCM', iv: nonce as unknown as ArrayBuffer, additionalData: aadBytes as unknown as ArrayBuffer },
      key,
      body as unknown as ArrayBuffer,
    )
    return new Uint8Array(plaintext)
  } catch {
    // AEAD tag failure: wrong key or tampered ciphertext — indistinguishable.
    throw notEntitled()
  }
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

/** Split a concatenated chunked payload into per-chunk records. */
function splitChunks(payload: Uint8Array, chunking: Chunking): Uint8Array[] {
  const fullWire = chunking.chunkSize + CHUNK_OVERHEAD
  const records: Uint8Array[] = []
  let offset = 0
  for (let i = 0; i < chunking.chunkCount; i += 1) {
    const remaining = payload.byteLength - offset
    const wire = Math.min(fullWire, remaining)
    records.push(payload.subarray(offset, offset + wire))
    offset += wire
  }
  return records
}

function validateChunking(payloadBytes: number, chunking: Chunking): void {
  const { chunkSize, chunkCount } = chunking
  if (chunkSize < 1 || chunkCount < 1 || chunkCount > 0xffff_ffff) throw corrupt()
  const fullWire = chunkSize + CHUNK_OVERHEAD
  const lastWire = payloadBytes - (chunkCount - 1) * fullWire
  // The final record must hold at least one plaintext byte and at most a
  // full chunk; anything else means a dropped or truncated chunk.
  if (lastWire <= CHUNK_OVERHEAD || lastWire > fullWire) throw corrupt()
}

/** Decode and validate the container header without touching the payload. */
export function decodeSealedAsset(
  sealed: Uint8Array,
): SealedAssetMeta & { ciphertext: Uint8Array; chunking?: Chunking } {
  if (sealed.byteLength === 0 || sealed.byteLength > MAX_SEALED_ASSET_BYTES) {
    throw corrupt()
  }
  try {
    const value = decode(sealed, ASSET_LIMITS)
    if (requireUint(mapGet(value, 0)) !== WEB_SEALED_ASSET_SCHEMA) throw corrupt()
    if (requireText(mapGet(value, 1)) !== WEB_SEALED_ASSET_ALG) throw corrupt()
    const meta: SealedAssetMeta = {
      productId: requireText(mapGet(value, 2)),
      variantId: requireUint(mapGet(value, 3)),
      featureId: requireText(mapGet(value, 4)),
      assetId: requireText(mapGet(value, 5)),
    }
    const ciphertext = mapGet(value, 6)
    if (!(ciphertext instanceof Uint8Array) || ciphertext.byteLength < CHUNK_OVERHEAD) {
      throw corrupt()
    }
    if (!identifiersValid(meta)) throw corrupt()
    const rawSize = mapGet(value, 7)
    const rawCount = mapGet(value, 8)
    if (rawSize === undefined && rawCount === undefined) {
      return { ...meta, ciphertext }
    }
    const chunking: Chunking = {
      chunkSize: requireUint(rawSize),
      chunkCount: requireUint(rawCount),
    }
    validateChunking(ciphertext.byteLength, chunking)
    return { ...meta, ciphertext, chunking }
  } catch (error) {
    if (error instanceof Error && error.name === 'SealError') throw error
    throw corrupt()
  }
}

/**
 * Seal `plaintext` into the web v1 container under `kek` (a per-feature
 * `KEK_asset`, or a FinalKey when wrapping KEKs for the dev bridge). When
 * `options.chunkSize` is set and the plaintext exceeds it, the chunked
 * extension is emitted.
 */
export async function sealBytes(
  kek: Uint8Array,
  meta: SealedAssetMeta,
  plaintext: Uint8Array,
  options?: { chunkSize?: number },
): Promise<Uint8Array> {
  if (!identifiersValid(meta)) {
    throw configError('CopyLocker seal: invalid product/feature/asset identifier')
  }
  if (!Number.isSafeInteger(meta.variantId) || meta.variantId < 0) {
    throw configError('CopyLocker seal: variantId must be a non-negative safe integer')
  }
  const chunkSize = options?.chunkSize ?? 0
  const key = await importKey(kek, ['encrypt'])

  let payload: Uint8Array
  let chunking: Chunking | undefined
  if (chunkSize > 0 && plaintext.byteLength > chunkSize) {
    const chunkCount = Math.ceil(plaintext.byteLength / chunkSize)
    const prefix = randomBytes(NONCE_PREFIX_BYTES)
    const records: Uint8Array[] = []
    let total = 0
    for (let i = 0; i < chunkCount; i += 1) {
      const slice = plaintext.subarray(i * chunkSize, (i + 1) * chunkSize)
      const record = await gcmEncrypt(
        key,
        chunkNonce(prefix, i),
        sealAad(meta, { index: i, count: chunkCount }),
        slice,
      )
      records.push(record)
      total += record.byteLength
    }
    payload = new Uint8Array(total)
    let offset = 0
    for (const record of records) {
      payload.set(record, offset)
      offset += record.byteLength
    }
    chunking = { chunkSize, chunkCount }
  } else {
    payload = await gcmEncrypt(key, randomBytes(NONCE_BYTES), sealAad(meta), plaintext)
  }

  const entries: [number, CborValue][] = [
    [0, WEB_SEALED_ASSET_SCHEMA],
    [1, WEB_SEALED_ASSET_ALG],
    [2, meta.productId],
    [3, meta.variantId],
    [4, meta.featureId],
    [5, meta.assetId],
    [6, payload],
  ]
  if (chunking) {
    entries.push([7, chunking.chunkSize], [8, chunking.chunkCount])
  }
  const container = encode(new Map<number, CborValue>(entries))
  if (container.byteLength > MAX_SEALED_ASSET_BYTES) {
    // The decode side (here and in the web runtime) hard-rejects containers
    // over this cap — never emit a container nothing can open.
    throw configError(
      `CopyLocker seal: sealed container exceeds the ${MAX_SEALED_ASSET_BYTES}-byte limit — split the asset`,
    )
  }
  return container
}

/**
 * Open a web v1 container with `kek`. Structural failures throw
 * `SealError` with code `CORRUPT`; an AEAD tag mismatch (wrong key,
 * wrong feature, tampered bytes) throws code `NOT_ENTITLED`.
 */
export async function openSealedBytes(
  kek: Uint8Array,
  sealed: Uint8Array,
  expected?: { productId: string; featureId: string },
): Promise<Uint8Array> {
  const asset = decodeSealedAsset(sealed)
  if (
    expected &&
    (asset.productId !== expected.productId || asset.featureId !== expected.featureId)
  ) {
    // Well-formed container for a different product/feature: the key is not
    // entitled to this content.
    throw notEntitled()
  }
  const key = await importKey(kek, ['decrypt'])
  const meta: SealedAssetMeta = {
    productId: asset.productId,
    variantId: asset.variantId,
    featureId: asset.featureId,
    assetId: asset.assetId,
  }
  if (!asset.chunking) {
    return gcmDecrypt(key, asset.ciphertext, sealAad(meta))
  }
  const records = splitChunks(asset.ciphertext, asset.chunking)
  const parts: Uint8Array[] = []
  let total = 0
  for (let i = 0; i < records.length; i += 1) {
    const part = await gcmDecrypt(
      key,
      records[i] as Uint8Array,
      sealAad(meta, { index: i, count: asset.chunking.chunkCount }),
    )
    parts.push(part)
    total += part.byteLength
  }
  const plaintext = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    plaintext.set(part, offset)
    offset += part.byteLength
  }
  return plaintext
}
