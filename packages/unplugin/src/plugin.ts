/**
 * The unplugin factory (`50-unplugin-integrity.md §2.6`).
 *
 * The pipeline runs on the FINAL bytes on disk, after every other plugin —
 * including the host's own internal ones — has finished mutating chunks:
 *
 * - Vite / Rollup: `writeBundle` (bundle object → entry list, disk → bytes).
 *   `enforce: 'post'` orders the earlier hooks (transform) after user
 *   plugins; keep the plugin LAST in the plugins array (see README).
 * - esbuild: `onEnd` + outdir reads (metafile forced on for entry discovery).
 * - webpack / rspack: `afterEmit` + outdir reads (entries from the
 *   compilation) via the raw `webpack(compiler)` / `rspack(compiler)` hooks.
 * - farm: `finalizeResources` (awaited; farm writes the patched bytes
 *   verbatim) via the raw `farm` key — farm has no awaited post-write hook.
 */

import { dirname, isAbsolute, resolve } from 'node:path'
import { createUnplugin } from 'unplugin'
import { resolveConfig, type CopyLockerOptions, type ResolvedConfig } from './config.js'
import { makeBuildFingerprint, makeBuildSeed, makeKBuild, splitHex } from './fingerprint.js'
import { toHex } from './hash.js'
import type { BuildIdentity, PipelineResult } from './core.js'
import { runOutdirPipeline, type OutdirEntry } from './outdir.js'
import { rewriteGuardedMarkers } from './guarded.js'
import { runEsbuildPipeline, type EsbuildBuildLike } from './esbuild-core.js'
import {
  runWebpackLikePipeline,
  type WebpackLikeCompiler,
  type WebpackLikeCompilation,
} from './webpack-core.js'
import { runFarmPipeline, type FarmFinalizeResourcesParams } from './farm-core.js'

const JS_LIKE = /\.[cm]?[jt]sx?$/

interface RollupOutputOptions {
  dir?: string
  file?: string
}

type RollupBundle = Record<
  string,
  { type: string; isEntry?: boolean }
>

class PluginState {
  readonly config: ResolvedConfig
  private identity: BuildIdentity | undefined
  private urlBase: string
  lastResult: PipelineResult | undefined

  constructor(options: CopyLockerOptions) {
    this.config = resolveConfig(options)
    this.urlBase = this.config.urlBase
  }

  private readonly warn = (message: string): void => {
    console.warn(message)
  }

  /** buildStart: fresh identity per build (watch-mode rebuilds differ). */
  async beginBuild(): Promise<void> {
    const fingerprint = await makeBuildFingerprint(process.cwd())
    const kbuildHex = toHex(makeKBuild())
    this.identity = {
      buildFingerprint: fingerprint,
      builtAt: Math.floor(Date.now() / 1000),
      kbuild:
        this.config.splitConstants > 1 ? splitHex(kbuildHex, this.config.splitConstants) : kbuildHex,
      buildSeed: makeBuildSeed(),
    }
  }

  private async ensureIdentity(): Promise<BuildIdentity> {
    if (!this.identity) await this.beginBuild()
    return this.identity as BuildIdentity
  }

  /** transform: rewrite guardedFn markers (vite/rollup/esbuild onLoad). */
  rewriteGuarded(code: string, id: string): { code: string; map: null } | null {
    if (!JS_LIKE.test(id) || id.includes('node_modules')) return null
    const rewritten = rewriteGuardedMarkers(code)
    return rewritten === null ? null : { code: rewritten, map: null }
  }

  setViteConfig(config: { base?: string; build?: { outDir?: string } }): void {
    // An explicit `urlBase` option wins over the vite `base` config.
    if (this.config.urlBase) return
    const base = config.base ?? '/'
    this.urlBase = base.endsWith('/') ? base : `${base}/`
  }

  /** Vite/Rollup `writeBundle`: pipeline over the final files on disk. */
  async processWriteBundle(
    outputOptions: RollupOutputOptions,
    bundle: RollupBundle,
  ): Promise<void> {
    const identity = await this.ensureIdentity()
    const outDirOption = outputOptions.dir ?? (outputOptions.file ? dirname(outputOptions.file) : undefined)
    if (!outDirOption) {
      this.warn('CopyLocker unplugin: no output dir — integrity pipeline skipped')
      return
    }
    const outDir = isAbsolute(outDirOption) ? outDirOption : resolve(outDirOption)
    const entries: OutdirEntry[] = []
    for (const [fileName, item] of Object.entries(bundle)) {
      entries.push({
        fileName,
        isEntry: item.type === 'chunk' && item.isEntry === true,
        kind: item.type === 'chunk' ? 'chunk' : 'asset',
      })
    }
    this.lastResult = await runOutdirPipeline(outDir, entries, this.config, identity, {
      warn: this.warn,
      urlBase: this.urlBase,
    })
  }

  /** esbuild `onEnd`: same pipeline, entry list from the metafile. */
  async processEsbuild(build: EsbuildBuildLike, result: unknown): Promise<void> {
    // onEnd fires for FAILED builds too; running the pipeline over a partial
    // outdir would mask the real build errors with a confusing follow-up one.
    const errors = (result as { errors?: unknown[] } | undefined)?.errors
    if (errors && errors.length > 0) {
      this.warn('CopyLocker unplugin: esbuild build failed — integrity pipeline skipped')
      return
    }
    const identity = await this.ensureIdentity()
    const outcome = await runEsbuildPipeline(build, result, this.config, identity, {
      warn: this.warn,
      urlBase: this.urlBase,
    })
    this.lastResult = outcome.result
  }

  /**
   * webpack / rspack raw hook: tap `afterEmit` so the pipeline runs over the
   * final files on disk (entries from the compilation). Tapped once per
   * compiler; `buildStart` (the `make` hook) refreshes the identity per
   * rebuild, so watch mode re-runs the full pipeline each time.
   */
  setupWebpackLike(compiler: WebpackLikeCompiler): void {
    compiler.hooks.afterEmit.tapPromise('copylocker', async (compilation: WebpackLikeCompilation) => {
      const identity = await this.ensureIdentity()
      const outcome = await runWebpackLikePipeline(compilation, this.config, identity, {
        warn: this.warn,
        urlBase: this.urlBase,
      })
      this.lastResult = outcome?.result
    })
  }

  /**
   * farm `finalizeResources`: farm's only awaited late hook — it runs after
   * rendering/minification and farm writes the returned bytes verbatim.
   * Entry chunks are patched in memory; the manifest is written to the
   * outdir by the pipeline itself.
   */
  async processFarmFinalize(
    param: FarmFinalizeResourcesParams,
  ): Promise<FarmFinalizeResourcesParams['resourcesMap']> {
    const identity = await this.ensureIdentity()
    const outcome = await runFarmPipeline(param, this.config, identity, {
      warn: this.warn,
      urlBase: this.urlBase,
    })
    this.lastResult = outcome?.result
    return outcome?.resourcesMap ?? param.resourcesMap
  }
}

export const unplugin = createUnplugin<CopyLockerOptions>((options) => {
  const state = new PluginState(options)

  const writeBundle = async (
    outputOptions: RollupOutputOptions,
    bundle: RollupBundle,
  ): Promise<void> => {
    await state.processWriteBundle(outputOptions, bundle)
  }

  return {
    name: 'copylocker',
    enforce: 'post',

    async buildStart() {
      await state.beginBuild()
    },

    transform(code, id) {
      return state.rewriteGuarded(code, id)
    },

    rollup: { writeBundle },

    vite: {
      apply: 'build',
      configResolved(config: { base?: string; build?: { outDir?: string } }) {
        state.setViteConfig(config)
      },
      writeBundle,
    },

    esbuild: {
      // The pipeline needs the metafile to find entry chunks (§2.6).
      config(buildOptions: { metafile?: boolean }) {
        buildOptions.metafile = true
      },
      setup(build: EsbuildBuildLike) {
        build.onStart(() => state.beginBuild())
        build.onEnd(async (result: unknown) => {
          await state.processEsbuild(build, result)
        })
      },
    },

    webpack(compiler) {
      state.setupWebpackLike(compiler as unknown as WebpackLikeCompiler)
    },

    rspack(compiler) {
      state.setupWebpackLike(compiler as unknown as WebpackLikeCompiler)
    },

    farm: {
      finalizeResources: {
        async executor(param) {
          // The internal structural type is a read-only subset of farm's
          // `Resource`; the returned map contains the same objects.
          return (await state.processFarmFinalize(
            param as FarmFinalizeResourcesParams,
          )) as typeof param.resourcesMap
        },
      },
    },
  }
})

export default unplugin
