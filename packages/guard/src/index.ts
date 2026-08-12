/**
 * `@copylocker/guard` — runtime integrity verification for CopyLocker-built
 * web bundles (M4). Injected into the bundle entry by `@copylocker/unplugin`.
 *
 * The one-sentence contract: `bootGuard` returns the ACTUALLY-COMPUTED
 * Merkle root `R`, and `R` participates in key derivation — integrity
 * failure changes derived keys instead of throwing.
 */

export { bootGuard, zeroExcludedRanges } from './guard.js'
export type {
  BootGuardOptions,
  BootResult,
  EntryReport,
  EntryStatus,
  GuardChunk,
  GuardFetch,
  GuardReport,
  GuardStrategy,
} from './guard.js'

export {
  decodeManifest,
  verifyManifestSignature,
  signManifestTbs,
  ManifestError,
  MANIFEST_SIGNATURE_DOMAIN,
} from './manifest.js'
export type {
  IntegrityManifest,
  ManifestEntry,
  SignatureStatus,
  SignedManifest,
} from './manifest.js'

export { leafHash, merkleRoot, merkleRootFromEntries } from './merkle.js'

export {
  guarded,
  guardedFn,
  shouldSample,
  GuardState,
  isToStringIntact,
  startToStringWatch,
} from './guarded.js'
export type { GuardedOptions } from './guarded.js'

export { normalizeSource } from './normalize.js'

export { toHex, fromHex } from './bytes.js'
