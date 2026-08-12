/**
 * `@copylocker/unplugin` — build-time integrity plugin (M4-A). See README.md
 * for the full contract.
 */

export { unplugin, default } from './plugin.js'
export {
  resolveConfig,
  ConfigError,
  type CopyLockerOptions,
  type GuardConfig,
  type Hasher,
  type ResolvedConfig,
  type SealAssetSpec,
  type SealChunkSpec,
  type SealConfig,
  type SignerConfig,
} from './config.js'
export { generateLocalKeyFile, resolveSigner, SignerError, type SignerErrorCode } from './signer.js'
export { makeBuildFingerprint, makeBuildSeed, splitHex } from './fingerprint.js'
export { buildPrelude, backfillPrelude, preludeExcludedRanges } from './prelude.js'
export {
  extractGuarded,
  extractFunctionSource,
  findGuardedFnBindings,
  guardedDigest,
  rewriteGuardedMarkers,
  GUARD_FN_GLOBAL,
} from './guarded.js'
export { encodeTbs, encodeContainer, type ManifestInput, type ManifestEntryInput } from './manifest.js'
export { runPipeline, type PipelineInput, type PipelineResult, type BuildIdentity } from './core.js'
export { verifyDist, formatVerifyResult, type VerifyOptions, type VerifyResult } from './verify.js'
