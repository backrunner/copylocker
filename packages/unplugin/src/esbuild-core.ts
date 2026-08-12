/**
 * esbuild adapter half (§2.6): esbuild has no bundle hooks, so the pipeline
 * runs in `onEnd` over the files in the outdir. Entry chunks come from the
 * metafile (the plugin forces `metafile: true` via the esbuild `config`
 * hook).
 */

import { isAbsolute, relative, resolve, sep } from 'node:path'
import { ConfigError, type ResolvedConfig } from './config.js'
import type { BuildIdentity, PipelineResult } from './core.js'
import { runOutdirPipeline, type OutdirEntry } from './outdir.js'

export interface EsbuildBuildLike {
  initialOptions: {
    outdir?: string
    outfile?: string
    absWorkingDir?: string
  }
  onStart(callback: () => void | Promise<void>): void
  onEnd(callback: (result: unknown) => void | Promise<void>): void
}

interface EsbuildMetafileOutput {
  entryPoint?: string
}

interface EsbuildResultLike {
  metafile?: { outputs: Record<string, EsbuildMetafileOutput> }
}

function posix(path: string): string {
  return path.split(sep).join('/')
}

export interface EsbuildPipelineOutcome {
  manifestBytes: Uint8Array
  outDir: string
  result: PipelineResult
}

export async function runEsbuildPipeline(
  build: EsbuildBuildLike,
  buildResult: unknown,
  config: ResolvedConfig,
  identity: BuildIdentity,
  hooks: { warn: (message: string) => void; urlBase?: string },
): Promise<EsbuildPipelineOutcome> {
  const cwd = build.initialOptions.absWorkingDir ?? process.cwd()
  const outdirOption = build.initialOptions.outdir
  if (!outdirOption) {
    throw new ConfigError(
      'CopyLocker unplugin: esbuild builds must use `outdir` (single `outfile` builds are not supported)',
    )
  }
  const outDir = isAbsolute(outdirOption) ? outdirOption : resolve(cwd, outdirOption)

  const metafile = (buildResult as EsbuildResultLike).metafile
  if (!metafile) {
    throw new ConfigError('CopyLocker unplugin: esbuild metafile is unavailable (it is forced on by the plugin)')
  }

  const entries: OutdirEntry[] = []
  for (const [outputPath, output] of Object.entries(metafile.outputs)) {
    const absolute = isAbsolute(outputPath) ? outputPath : resolve(cwd, outputPath)
    const fileName = posix(relative(outDir, absolute))
    if (fileName.startsWith('..')) continue
    entries.push({
      fileName,
      isEntry: output.entryPoint !== undefined,
      kind: /\.[cm]?js$/.test(fileName) ? 'chunk' : 'asset',
    })
  }

  const result = await runOutdirPipeline(outDir, entries, config, identity, hooks)
  return { manifestBytes: result.manifestBytes, outDir, result }
}
