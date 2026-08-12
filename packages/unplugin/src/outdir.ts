/**
 * Outdir-based pipeline driver shared by all three bundlers.
 *
 * The pipeline runs on the FINAL bytes on disk — after every other plugin
 * (including the host's own internal ones, e.g. Vite's module-preload
 * placeholder resolution) has finished mutating chunks:
 *
 * - Vite / Rollup: `writeBundle` (bundle object → entry list, disk → bytes)
 * - esbuild:       `onEnd` (metafile → entry list, disk → bytes)
 *
 * Patched chunks are written back in place; the manifest copy goes to
 * `<outdir>/.copylocker/manifest.cbor`.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import type { ResolvedConfig } from './config.js'
import {
  runPipeline,
  type BuildIdentity,
  type PipelineInput,
  type PipelineResult,
} from './core.js'

export interface OutdirEntry {
  /** Output path relative to the out dir, POSIX separators. */
  fileName: string
  isEntry: boolean
  kind: 'chunk' | 'asset'
}

export interface OutdirHooks {
  warn: (message: string) => void
  urlBase?: string
}

const textDecoder = new TextDecoder()
const textEncoder = new TextEncoder()

export async function runOutdirPipeline(
  outDir: string,
  entries: OutdirEntry[],
  config: ResolvedConfig,
  identity: BuildIdentity,
  hooks: OutdirHooks,
): Promise<PipelineResult> {
  const inputs: PipelineInput[] = []
  for (const entry of entries) {
    const bytes = new Uint8Array(await readFile(join(outDir, ...entry.fileName.split('/'))))
    if (entry.kind === 'chunk') {
      inputs.push({
        fileName: entry.fileName,
        kind: 'chunk',
        isEntry: entry.isEntry,
        text: textDecoder.decode(bytes),
      })
    } else {
      inputs.push({ fileName: entry.fileName, kind: 'asset', isEntry: false, bytes })
    }
  }

  const result = await runPipeline(inputs, config, identity, {
    warn: hooks.warn,
    outDir,
    urlBase: hooks.urlBase,
  })

  for (const [fileName, text] of result.patchedTexts) {
    await writeFile(join(outDir, ...fileName.split('/')), textEncoder.encode(text))
  }
  for (const [fileName, bytes] of result.patchedAssets) {
    await writeFile(join(outDir, ...fileName.split('/')), bytes)
  }
  for (const [fileName, bytes] of result.extraAssets) {
    const target = join(outDir, ...fileName.split('/'))
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, bytes)
  }
  const manifestTarget = join(outDir, '.copylocker', 'manifest.cbor')
  await mkdir(dirname(manifestTarget), { recursive: true })
  await writeFile(manifestTarget, result.manifestBytes)

  return result
}
