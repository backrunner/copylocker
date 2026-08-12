/**
 * `@copylocker/seal` — build-time asset sealing for CopyLocker web targets
 * (M4-A slice). See README.md for the full contract and security red lines.
 */

export {
  WEB_SEALED_ASSET_SCHEMA,
  WEB_SEALED_ASSET_ALG,
  MAX_SEALED_ASSET_BYTES,
  NONCE_BYTES,
  TAG_BYTES,
  DEFAULT_CHUNK_SIZE,
  decodeSealedAsset,
  openSealedBytes,
  sealAad,
  sealBytes,
  type Chunking,
  type SealedAssetMeta,
} from './container.js'
export { SealError, type SealErrorCode } from './errors.js'
export { deriveFinalKey, sha256 } from './derive.js'
export { expandGlobs, globToRegExp, isGlob } from './glob.js'
export {
  DEFAULT_REGISTRY_DIR,
  DEFAULT_REGISTRY_FILE,
  DEFAULT_WRAPPING_KEY_FILE,
  REGISTRY_AAD_LABEL,
  REGISTRY_VERSION,
  WRAPPING_KEY_ENV,
  emptyRegistry,
  generateKek,
  generateWrappingKey,
  getKek,
  getOrCreateKek,
  hexDecode,
  hexEncode,
  kekFingerprint,
  loadRegistry,
  resolveWrappingKey,
  saveRegistry,
  type KekEntry,
  type KekRegistry,
} from './keystore.js'
export {
  chunkLoaderStub,
  sealAssets,
  sealChunk,
  type SealAssetsOptions,
  type SealChunkOptions,
  type SealedAssetResult,
  type SealedChunk,
} from './seal.js'
