/**
 * Build-time asset sealing orchestration (M4-A).
 *
 * The unplugin integration (M4 follow-up task) consumes these entry points:
 *
 * - {@link sealAssets} — seal matched files under the feature's `KEK_asset`
 *   into web v1 containers (`<asset>.sealed`); dry-run without `outDir`.
 * - {@link sealChunk} — L3 code-chunk sealing: encrypt a JS chunk and emit
 *   the loader stub that replaces it in the bundle (design §5.1).
 * - {@link chunkLoaderStub} — the stub template on its own.
 *
 * Key discipline: assets are sealed under the per-feature `KEK_asset` from
 * the registry (see `keystore.ts`), never under FinalKey — FinalKey only
 * exists at runtime. The M4-A bridge (`wrap-kek`) seals the KEK itself under
 * a FinalKey for development loops; M4-B moves that wrapping server-side.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import {
  DEFAULT_CHUNK_SIZE,
  decodeSealedAsset,
  sealBytes,
  type Chunking,
  type SealedAssetMeta,
} from './container.js'
import { configError } from './errors.js'
import { expandGlobs } from './glob.js'

export interface SealedAssetResult {
  /** POSIX path of the source file, relative to `cwd`. */
  source: string
  /** Asset id bound into the container AAD (defaults to `source`). */
  assetId: string
  /** Output path relative to `cwd`, or `<dry-run>` when nothing was written. */
  output: string
  plaintextBytes: number
  sealedBytes: number
  chunking?: Chunking
  /** True when the output file was actually written (false in dry-run). */
  written: boolean
}

export interface SealAssetsOptions {
  cwd: string
  globs: string[]
  featureId: string
  productId: string
  variantId?: number
  /** Per-feature KEK_asset (32 bytes), from the registry. */
  kek: Uint8Array
  /**
   * Output directory relative to `cwd`. When omitted this is a dry-run:
   * the result (including sealed sizes) is computed but nothing is written.
   */
  outDir?: string
  /** Chunk size for large assets; defaults to 4 MiB. `0` disables chunking. */
  chunkSize?: number
  /** Override the asset id for a source path (defaults to the source path). */
  assetId?: (source: string) => string
}

function assertMeta(productId: string, featureId: string): void {
  if (!productId) throw configError('CopyLocker seal: productId is required')
  if (!featureId) throw configError('CopyLocker seal: featureId is required')
}

/**
 * Seal every matched asset. Without `outDir` this is a dry-run: results are
 * returned with `written: false` and no filesystem writes happen.
 */
export async function sealAssets(options: SealAssetsOptions): Promise<SealedAssetResult[]> {
  assertMeta(options.productId, options.featureId)
  const variantId = options.variantId ?? 0
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE
  const expanded = await expandGlobs(options.cwd, options.globs)
  // Never seal our own output: with `--out` inside the glob scope a repeat
  // run would otherwise seal `x.sealed` into `x.sealed.sealed`, growing
  // every run.
  const outRoot = options.outDir ? resolve(options.cwd, options.outDir) : undefined
  const sources = expanded.filter((source) => {
    if (!outRoot) return true
    const rel = relative(outRoot, resolve(options.cwd, source))
    return rel.startsWith('..') || isAbsolute(rel)
  })
  const results: SealedAssetResult[] = []
  for (const source of sources) {
    const plaintext = new Uint8Array(await readFile(join(options.cwd, source)))
    const meta: SealedAssetMeta = {
      productId: options.productId,
      variantId,
      featureId: options.featureId,
      assetId: options.assetId?.(source) ?? source,
    }
    const sealed = await sealBytes(options.kek, meta, plaintext, { chunkSize })
    const header = decodeSealedAsset(sealed)
    const output = options.outDir ? join(options.outDir, `${source}.sealed`) : '<dry-run>'
    if (options.outDir) {
      const target = join(options.cwd, output)
      await mkdir(dirname(target), { recursive: true })
      await writeFile(target, sealed)
    }
    results.push({
      source,
      assetId: meta.assetId,
      output,
      plaintextBytes: plaintext.byteLength,
      sealedBytes: sealed.byteLength,
      chunking: header.chunking,
      written: Boolean(options.outDir),
    })
  }
  return results
}

export interface SealChunkOptions {
  code: Uint8Array
  featureId: string
  productId: string
  variantId?: number
  kek: Uint8Array
  /** Logical chunk name, bound into the AAD (e.g. the chunk file name). */
  assetId: string
  /** URL the runtime fetches the sealed chunk from (goes into the stub). */
  sealedUrl: string
  chunkSize?: number
}

export interface SealedChunk {
  sealed: Uint8Array
  stub: string
  meta: SealedAssetMeta
}

/**
 * Loader stub template (design `60-instrumentation-guard.md` §5.1).
 *
 * The stub expects the runtime CopyLocker client at `globalThis.__cl`
 * (the M4 unplugin injects that binding). CSP trade-off: the Blob-URL dynamic
 * import requires `script-src blob:`; deployments that cannot allow it must
 * use the WASM-segment variant instead. Chunk sealing is therefore opt-in.
 */
export function chunkLoaderStub(sealedUrl: string, featureId: string): string {
  // JSON.stringify is the correct JS-string-literal escaping: hand-rolled
  // single-quote interpolation silently mangles backslashes (`'\c'` → `'c'`)
  // and a raw line terminator would break the emitted module outright.
  return [
    '// Generated by @copylocker/seal — sealed chunk loader (L3).',
    '// Requires the CopyLocker client at globalThis.__cl and CSP `script-src blob:`.',
    'export default async function load() {',
    `  const code = await __cl.loadSealed(${JSON.stringify(sealedUrl)}, ${JSON.stringify(featureId)})`,
    `  return import(URL.createObjectURL(new Blob([code], { type: 'text/javascript' })))`,
    '}',
    '',
  ].join('\n')
}

/**
 * Seal a JS chunk (L3). Returns the web v1 container plus the loader stub
 * that replaces the chunk in the bundle.
 */
export async function sealChunk(options: SealChunkOptions): Promise<SealedChunk> {
  assertMeta(options.productId, options.featureId)
  const meta: SealedAssetMeta = {
    productId: options.productId,
    variantId: options.variantId ?? 0,
    featureId: options.featureId,
    assetId: options.assetId,
  }
  const sealed = await sealBytes(options.kek, meta, options.code, {
    chunkSize: options.chunkSize ?? DEFAULT_CHUNK_SIZE,
  })
  return {
    sealed,
    stub: chunkLoaderStub(options.sealedUrl, options.featureId),
    meta,
  }
}
