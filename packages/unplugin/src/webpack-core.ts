/**
 * webpack / rspack adapter half (§2.6).
 *
 * Both bundlers expose the same hook surface (`compiler.hooks.afterEmit`),
 * so one implementation serves both; the unplugin `webpack(compiler)` /
 * `rspack(compiler)` raw hooks hand us the compiler.
 *
 * Hook choice: the pipeline runs in `afterEmit` — AFTER webpack has written
 * every asset to disk — and reads the final bytes from the outdir, exactly
 * like the esbuild `onEnd` adapter. This keeps the "digest covers the bytes
 * actually served" invariant regardless of what any other plugin did in
 * `processAssets` (minifiers, SRI, banner injection, compression), and it
 * also covers files emitted by plugins that write in `emit`/`afterEmit`
 * before us (tap order = plugin order, so keep copylocker last).
 *
 * `compilation.hooks.processAssets` was considered (it allows in-memory
 * patching, which would also reach webpack-dev-server's memfs), but it runs
 * BEFORE emit: any later-stage mutation — including the host's own filename
 * interpolation edge cases and `emit`-hook writers — would silently escape
 * the digests. Reading from disk in `afterEmit` matches the design rule
 * that only terminal bytes are covered.
 *
 * Entry chunks come from `compilation.entrypoints`; everything emitted is
 * enumerated with `compilation.getAssets()`.
 */

import { isAbsolute, resolve } from 'node:path'
import type { ResolvedConfig } from './config.js'
import type { BuildIdentity, PipelineResult } from './core.js'
import { runOutdirPipeline, type OutdirEntry } from './outdir.js'

export interface WebpackLikeChunk {
  files: Iterable<string>
}

export interface WebpackLikeEntrypoint {
  chunks: Iterable<WebpackLikeChunk>
}

export interface WebpackLikeCompilation {
  outputOptions: { path?: string }
  entrypoints: Map<string, WebpackLikeEntrypoint>
  getAssets(): ReadonlyArray<{ name: string }>
}

interface AfterEmitHook {
  tapPromise(name: string, callback: (compilation: WebpackLikeCompilation) => Promise<void>): void
}

export interface WebpackLikeCompiler {
  options: { context?: string }
  hooks: { afterEmit: AfterEmitHook }
}

export interface WebpackPipelineOutcome {
  outDir: string
  result: PipelineResult
}

const JS_LIKE = /\.[cm]?js$/

export async function runWebpackLikePipeline(
  compilation: WebpackLikeCompilation,
  config: ResolvedConfig,
  identity: BuildIdentity,
  hooks: { warn: (message: string) => void; urlBase?: string },
): Promise<WebpackPipelineOutcome | undefined> {
  const outDirOption = compilation.outputOptions.path
  if (!outDirOption) {
    hooks.warn('CopyLocker unplugin: no output.path configured — integrity pipeline skipped')
    return undefined
  }
  const outDir = isAbsolute(outDirOption) ? outDirOption : resolve(outDirOption)

  const entryFiles = new Set<string>()
  for (const entrypoint of compilation.entrypoints.values()) {
    for (const chunk of entrypoint.chunks) {
      for (const file of chunk.files) entryFiles.add(file)
    }
  }

  const entries: OutdirEntry[] = []
  for (const asset of compilation.getAssets()) {
    entries.push({
      fileName: asset.name,
      isEntry: entryFiles.has(asset.name),
      kind: JS_LIKE.test(asset.name) ? 'chunk' : 'asset',
    })
  }

  try {
    const result = await runOutdirPipeline(outDir, entries, config, identity, hooks)
    return { outDir, result }
  } catch (error) {
    // webpack-dev-server keeps output in an in-memory fs: nothing to read
    // from disk. Dev output is out of scope (like `apply: 'build'` in Vite),
    // so skip with a warning instead of crashing the dev server.
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      hooks.warn(
        'CopyLocker unplugin: build output is not on disk (dev-server in-memory fs?) — integrity pipeline skipped',
      )
      return undefined
    }
    throw error
  }
}
