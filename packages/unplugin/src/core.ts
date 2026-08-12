/**
 * Bundler-agnostic integrity pipeline (`50-unplugin-integrity.md §2.2/§2.3`).
 *
 * Consumes a flat view of the build outputs (chunks as text, assets as
 * bytes) and produces: patched entry-chunk texts (prelude injected and
 * backfilled), extra assets (L3 sealed-chunk payloads), and the signed
 * manifest bytes. The rollup/vite adapter feeds the `generateBundle` bundle
 * object; the esbuild adapter feeds files read from the outdir (`onEnd`).
 *
 * Order of operations (§2.2 generateBundle):
 *   ① seal chunk stubs (L3, opt-in)     ② seal assets (fs, via seal package)
 *   ②b randomize WASM exports (opt-in)  ③ collect guarded digests
 *   ④ round-1 digests (spans zeroed)    ⑤ Merkle root
 *   ⑥ manifest + signature              ⑦ round-2 backfill (length-preserving)
 */

import { merkleRootFromEntries, zeroExcludedRanges } from '@copylocker/guard'
import {
  getOrCreateKek,
  globToRegExp,
  loadRegistry,
  resolveWrappingKey,
  saveRegistry,
  sealAssets,
  sealChunk,
} from '@copylocker/seal'
import { relative, sep } from 'node:path'
import { ConfigError, type ResolvedConfig } from './config.js'
import { resolveHasher, sha256, toHex, type HashFn } from './hash.js'
import { canonicalTextKeyOrder } from './cbor.js'
import { encodeContainer, encodeTbs, type ManifestEntryInput } from './manifest.js'
import {
  backfillPrelude,
  buildPrelude,
  preludeExcludedRanges,
  type GuardChunkSpec,
  type Prelude,
} from './prelude.js'
import { extractGuarded, guardedDigest } from './guarded.js'
import { resolveSigner, type ResolvedSigner, type SignerEnvironment } from './signer.js'
import {
  countGlueReferences,
  randomizeExports,
  rewriteGlueReferences,
} from './wasm-randomize.js'
import { BOOTSTRAP_SOURCE } from './generated/bootstrap-source.js'

export interface PipelineInput {
  /** Output path relative to the out dir, POSIX separators. */
  fileName: string
  kind: 'chunk' | 'asset'
  isEntry: boolean
  /** Chunk code (UTF-8 text). */
  text?: string
  /** Asset bytes. */
  bytes?: Uint8Array
}

/** Per-build identity created in `buildStart` (§2.2). */
export interface BuildIdentity {
  buildFingerprint: string
  builtAt: number
  /** Single 64-char hex or N shards (splitConstants). */
  kbuild: string | string[]
  /** 64-char hex seed for the M5 hardening passes (WASM export randomization). */
  buildSeed?: string
}

export interface PipelineHooks {
  warn: (message: string) => void
  /** Absolute output directory (required when seal.assets is configured). */
  outDir?: string
  /** Prefix for runtime chunk URLs (e.g. vite `base`). */
  urlBase?: string
  signerEnv?: SignerEnvironment
}

export interface PipelineResult {
  /** fileName → new chunk text (entry chunks, sealed-chunk stubs, rewritten glue). */
  patchedTexts: Map<string, string>
  /** fileName → new asset bytes (randomized WASM binaries). */
  patchedAssets: Map<string, Uint8Array>
  /** New asset files to emit (sealed chunk payloads). */
  extraAssets: Map<string, Uint8Array>
  manifestBytes: Uint8Array
  root: Uint8Array
  sealedAssetIds: string[]
  entryCount: number
  coveredCount: number
}

const textEncoder = new TextEncoder()

function posix(path: string): string {
  return path.split(sep).join('/')
}

export function matchesPatterns(fileName: string, include: string[], exclude: string[]): boolean {
  for (const pattern of exclude) {
    if (globToRegExp(pattern).test(fileName)) return false
  }
  for (const pattern of include) {
    if (globToRegExp(pattern).test(fileName)) return true
  }
  return false
}

interface KekContext {
  kekFor(feature: string): Promise<Uint8Array>
}

async function openKekRegistry(config: ResolvedConfig): Promise<KekContext> {
  const seal = config.seal
  if (!seal) throw new ConfigError('CopyLocker unplugin: internal — seal config missing')
  const wrappingKey = await resolveWrappingKey({ keyFile: seal.wrappingKeyFile })
  const registry = await loadRegistry({ path: seal.registryFile, wrappingKey })
  return {
    async kekFor(feature: string): Promise<Uint8Array> {
      const { kek, created } = getOrCreateKek(registry, feature)
      if (created) {
        await saveRegistry({ path: seal.registryFile, wrappingKey, registry })
      }
      return kek
    },
  }
}

/** L3 chunk sealing: replace matched non-entry chunks with loader stubs. */
async function sealMatchedChunks(
  inputs: PipelineInput[],
  config: ResolvedConfig,
  keks: KekContext,
  result: PipelineResult,
): Promise<void> {
  const seal = config.seal
  if (!seal || seal.chunks.length === 0) return
  for (const input of inputs) {
    if (input.kind !== 'chunk' || input.text === undefined) continue
    const spec = seal.chunks.find((candidate) => candidate.match.test(input.fileName))
    if (!spec) continue
    if (input.isEntry) {
      throw new ConfigError(
        `CopyLocker unplugin: seal.chunks matched the entry chunk '${input.fileName}' — entry chunks carry the guard bootstrap and cannot be sealed`,
      )
    }
    const kek = await keks.kekFor(spec.feature)
    const sealedUrl = `${input.fileName}.sealed`
    const { sealed, stub } = await sealChunk({
      code: textEncoder.encode(input.text),
      featureId: spec.feature,
      productId: config.productId,
      kek,
      assetId: input.fileName,
      sealedUrl,
    })
    result.patchedTexts.set(input.fileName, stub)
    result.extraAssets.set(sealedUrl, sealed)
    result.sealedAssetIds.push(input.fileName)
    input.text = stub
  }
}

/** seal.assets: glob the source tree, write `<asset>.sealed` into the out dir. */
async function sealConfiguredAssets(
  config: ResolvedConfig,
  keks: KekContext,
  hooks: PipelineHooks,
  result: PipelineResult,
): Promise<void> {
  const seal = config.seal
  if (!seal || seal.assets.length === 0) return
  if (!hooks.outDir) {
    throw new ConfigError('CopyLocker unplugin: seal.assets requires a known output directory')
  }
  const outDirRelative = posix(relative(seal.cwd, hooks.outDir))
  for (const asset of seal.assets) {
    const kek = await keks.kekFor(asset.feature)
    const results = await sealAssets({
      cwd: seal.cwd,
      globs: asset.globs,
      featureId: asset.feature,
      productId: config.productId,
      kek,
      outDir: outDirRelative,
    })
    for (const sealed of results) result.sealedAssetIds.push(sealed.assetId)
  }
}

/** Round-1 digest map in canonical key order (the Merkle leaf order). */
async function digestEntries(
  inputs: PipelineInput[],
  hash: HashFn,
  preludes: Map<string, Prelude>,
  finalTexts: Map<string, string>,
): Promise<Map<string, ManifestEntryInput>> {
  const sorted = [...inputs].sort((a, b) => canonicalTextKeyOrder(a.fileName, b.fileName))
  const entries = new Map<string, ManifestEntryInput>()
  for (const input of sorted) {
    let bytes: Uint8Array
    let ranges: [number, number][] = []
    if (input.isEntry) {
      const prelude = preludes.get(input.fileName) as Prelude
      bytes = textEncoder.encode(finalTexts.get(input.fileName) as string)
      ranges = preludeExcludedRanges(prelude.spans)
    } else if (input.kind === 'chunk') {
      bytes = textEncoder.encode(input.text as string)
    } else {
      bytes = input.bytes as Uint8Array
    }
    const digest = await hash(zeroExcludedRanges(bytes, ranges))
    entries.set(input.fileName, { digest, excludedRanges: ranges })
  }
  return entries
}

const WASM_ASSET = /\.wasm$/

/**
 * WASM export-name randomization (`40-web-sdk-wasm-ts.md §5`). Runs on the
 * covered inputs BEFORE digests are computed, so the manifest always covers
 * the renamed bytes. A `.wasm` asset is renamed only when at least one
 * covered chunk references its exports (the glue) — otherwise the rename
 * would break the runtime, so the asset is skipped with a warning.
 */
function randomizeCoveredWasm(
  covered: PipelineInput[],
  allInputs: PipelineInput[],
  identity: BuildIdentity,
  hooks: PipelineHooks,
  result: PipelineResult,
): void {
  if (!identity.buildSeed) {
    throw new ConfigError(
      'CopyLocker unplugin: randomizeWasmExports requires identity.buildSeed (the plugin sets it in buildStart; custom pipeline drivers must provide it)',
    )
  }
  const wasmInputs = covered.filter(
    (input) => input.kind === 'asset' && input.bytes !== undefined && WASM_ASSET.test(input.fileName),
  )
  if (wasmInputs.length === 0) {
    hooks.warn(
      'CopyLocker unplugin: randomizeWasmExports is enabled but no covered .wasm asset was found — nothing to randomize',
    )
    return
  }
  const chunks = covered.filter((input) => input.kind === 'chunk' && input.text !== undefined)
  const coveredSet = new Set(covered)
  const uncoveredChunks = allInputs.filter(
    (input) => input.kind === 'chunk' && input.text !== undefined && !coveredSet.has(input),
  )
  for (const wasmInput of wasmInputs) {
    const { bytes, renames } = randomizeExports(wasmInput.bytes as Uint8Array, identity.buildSeed)
    if (renames.size === 0) continue
    const glueChunks = chunks.filter(
      (chunk) => countGlueReferences(chunk.text as string, renames.keys()) > 0,
    )
    if (glueChunks.length === 0) {
      hooks.warn(
        `CopyLocker unplugin: randomizeWasmExports skipped '${wasmInput.fileName}' — no covered chunk references its exports (is the glue outside the include set?)`,
      )
      continue
    }
    const uncoveredGlue = uncoveredChunks.filter(
      (chunk) => countGlueReferences(chunk.text as string, renames.keys()) > 0,
    )
    if (uncoveredGlue.length > 0) {
      // Covered chunks are rewritten to the new names; excluded chunks that
      // also reference them are NOT — the app would break at load. Surface it.
      hooks.warn(
        `CopyLocker unplugin: randomizeWasmExports renamed exports of '${wasmInput.fileName}', but excluded chunk(s) ${uncoveredGlue.map((c) => c.fileName).join(', ')} still reference the old names — cover them or the runtime will break`,
      )
    }
    for (const chunk of glueChunks) {
      chunk.text = rewriteGlueReferences(chunk.text as string, renames)
      // Entry chunks are re-assembled (prelude + text) into patchedTexts by
      // the backfill step; every other rewritten chunk is patched here.
      if (!chunk.isEntry) result.patchedTexts.set(chunk.fileName, chunk.text)
    }
    wasmInput.bytes = bytes
    result.patchedAssets.set(wasmInput.fileName, bytes)
  }
}

/**
 * WASM_DIGEST injection (`40-web-sdk-wasm-ts.md §5`, `50 §2.2` step ④):
 * digest every covered `.wasm` asset so the runtime can compare the
 * build-time digest against the bytes it actually loaded — a swapped or
 * patched artifact then fails closed instead of deriving a key.
 *
 * Runs AFTER export randomization, so the constant binds the final emitted
 * bytes. Always SHA-256 regardless of the configured `hasher`: the
 * `@copylocker/web` runtime computes `sha256(wasmBytes)` at load time, and
 * the comparison only works when both sides use the same algorithm.
 */
async function digestCoveredWasm(
  covered: PipelineInput[],
  hooks: PipelineHooks,
): Promise<Record<string, string>> {
  const digests: Record<string, string> = {}
  for (const input of covered) {
    if (input.kind === 'asset' && input.bytes !== undefined && WASM_ASSET.test(input.fileName)) {
      digests[input.fileName] = toHex(await sha256(input.bytes))
    }
  }
  if (Object.keys(digests).length === 0) {
    hooks.warn(
      'CopyLocker unplugin: no covered .wasm asset found — WASM_DIGEST was NOT injected (the runtime has no build-time digest to compare the loaded wasm against)',
    )
  }
  return digests
}

/**
 * Run the full pipeline. `inputs` are mutated for in-place stub replacement;
 * patched/extra/manifest outputs are returned in the result.
 */
export async function runPipeline(
  allInputs: PipelineInput[],
  config: ResolvedConfig,
  identity: BuildIdentity,
  hooks: PipelineHooks,
): Promise<PipelineResult> {
  const hash = resolveHasher(config.hasher)
  const result: PipelineResult = {
    patchedTexts: new Map(),
    patchedAssets: new Map(),
    extraAssets: new Map(),
    manifestBytes: new Uint8Array(0),
    root: new Uint8Array(32),
    sealedAssetIds: [],
    entryCount: 0,
    coveredCount: 0,
  }

  const sealing = config.seal && (config.seal.assets.length > 0 || config.seal.chunks.length > 0)
  const keks = sealing ? await openKekRegistry(config) : undefined
  if (keks) {
    await sealMatchedChunks(allInputs, config, keks, result)
    await sealConfiguredAssets(config, keks, hooks, result)
  }

  const covered = allInputs.filter((input) =>
    matchesPatterns(input.fileName, config.include, config.exclude),
  )
  const entryChunks = covered.filter((input) => input.kind === 'chunk' && input.isEntry)
  result.entryCount = entryChunks.length
  result.coveredCount = covered.length
  if (covered.length === 0) {
    hooks.warn('CopyLocker unplugin: no build output matched include/exclude — manifest is empty')
  }
  if (entryChunks.length === 0) {
    hooks.warn(
      'CopyLocker unplugin: no entry chunk found among covered outputs — the guard bootstrap was NOT injected',
    )
  }

  // WASM export randomization runs before any digest is computed so the
  // manifest covers the renamed bytes (§5 hardening pass).
  if (config.randomizeWasmExports) {
    randomizeCoveredWasm(covered, allInputs, identity, hooks, result)
  }

  // WASM_DIGEST: digests of the final wasm bytes, injected into the prelude
  // config and published by the bootstrap for the runtime comparison.
  const wasmDigests = await digestCoveredWasm(covered, hooks)

  // Guarded functions: digests come from the FINAL (minified) chunk text —
  // the same text `Function.prototype.toString` returns at runtime.
  const guarded = new Map<string, Uint8Array>()
  for (const input of covered) {
    if (input.kind !== 'chunk' || input.text === undefined) continue
    for (const { id, source } of extractGuarded(input.text)) {
      const digest = await guardedDigest(source)
      const existing = guarded.get(id)
      if (existing && toHex(existing) !== toHex(digest)) {
        hooks.warn(`CopyLocker unplugin: guarded id '${id}' has conflicting bodies across chunks`)
      }
      guarded.set(id, digest)
    }
  }

  // Signer (adds its public key to the pins for the local kind).
  const pinBytes: Uint8Array[] = []
  for (const pin of config.rootPins) {
    const bytes = new Uint8Array(32)
    for (let i = 0; i < 32; i += 1) bytes[i] = Number.parseInt(pin.slice(i * 2, i * 2 + 2), 16)
    pinBytes.push(bytes)
  }
  const signer: ResolvedSigner | undefined = await resolveSigner(config.signer, pinBytes, {
    ...hooks.signerEnv,
    warn: hooks.warn,
  })
  const pins = pinBytes.map(toHex)
  const signatureLength = signer?.signatureLength ?? 0

  // Static chunk mapping: entry chunks first (guard 'idle' verifies the
  // first listed chunk inline), then the remaining covered outputs.
  const chunkSpecs: GuardChunkSpec[] = []
  const pushSpec = (fileName: string): void => {
    chunkSpecs.push({ url: `${hooks.urlBase ?? ''}${fileName}`, pattern: fileName })
  }
  for (const input of covered) if (input.isEntry) pushSpec(input.fileName)
  for (const input of covered) if (!input.isEntry) pushSpec(input.fileName)

  const preludeConfig = {
    pins,
    chunks: chunkSpecs,
    kbuild: identity.kbuild,
    wasmDigests,
    strategy: config.guard.strategy,
    sampleRate: config.guard.sampleRate,
  }

  // Two-round fixpoint: the manifest hex placeholder length depends on the
  // manifest size, which depends on the excluded-range offsets, which depend
  // on the placeholder length. All backfilled values are fixed-size, so the
  // container length settles within a few iterations.
  let manifestHexLength = 0
  let tbsBytes: Uint8Array | undefined
  let preludes = new Map<string, Prelude>()
  let finalTexts = new Map<string, string>()
  let root: Uint8Array = new Uint8Array(32)
  for (let iteration = 0; iteration < 8; iteration += 1) {
    preludes = new Map()
    finalTexts = new Map()
    for (const entry of entryChunks) {
      const prelude = buildPrelude(preludeConfig, manifestHexLength, BOOTSTRAP_SOURCE)
      preludes.set(entry.fileName, prelude)
      finalTexts.set(entry.fileName, prelude.text + (entry.text as string))
    }
    const entries = await digestEntries(covered, hash, preludes, finalTexts)
    const digestMap = new Map<string, Uint8Array>()
    for (const [pattern, entry] of entries) digestMap.set(pattern, entry.digest)
    root = await merkleRootFromEntries(digestMap)
    tbsBytes = encodeTbs({
      suiteId: config.suiteId,
      productId: config.productId,
      buildFingerprint: identity.buildFingerprint,
      builtAt: identity.builtAt,
      hashAlg: config.hashAlg,
      entries,
      guarded,
      sealed: result.sealedAssetIds,
      root,
    })
    const containerLength = encodeContainer(tbsBytes, new Uint8Array(signatureLength)).byteLength
    const needed = containerLength * 2
    if (needed === manifestHexLength) break
    manifestHexLength = needed
    if (iteration === 7) {
      throw new Error('CopyLocker unplugin: manifest length fixpoint did not converge')
    }
  }

  const signature = signer ? await signer.sign(tbsBytes as Uint8Array) : new Uint8Array(0)
  const manifestBytes = encodeContainer(tbsBytes as Uint8Array, signature)
  if (manifestBytes.byteLength * 2 !== manifestHexLength) {
    throw new Error(
      `CopyLocker unplugin: manifest size changed after signing (${manifestBytes.byteLength}) — the signer must return a fixed ${signatureLength}-byte signature`,
    )
  }

  const manifestHex = toHex(manifestBytes)
  const rootHex = toHex(root)
  for (const entry of entryChunks) {
    const prelude = preludes.get(entry.fileName) as Prelude
    const finalText = finalTexts.get(entry.fileName) as string
    result.patchedTexts.set(
      entry.fileName,
      backfillPrelude(finalText, prelude.spans, manifestHex, rootHex),
    )
  }

  result.manifestBytes = manifestBytes
  result.root = root
  return result
}
