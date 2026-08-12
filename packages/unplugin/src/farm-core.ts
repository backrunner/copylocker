/**
 * farm adapter half (§2.6).
 *
 * Farm has no `writeBundle`/`afterEmit`-style hook that is awaited after
 * disk write: `writeResources` fires after `writeResourcesToDisk()` but its
 * return value is never awaited, and `finish` fires before it. The one hook
 * that is both awaited AND late enough is `finalizeResources`: it runs after
 * minification/rendering, receives the full resources map, and its (async)
 * result is what farm writes to disk verbatim. So the pipeline patches the
 * entry-chunk bytes in memory there (same "terminal bytes" rule — farm
 * writes exactly these bytes), and writes the manifest copy to
 * `<outdir>/.copylocker/manifest.cbor` itself (farm's output cleaning runs
 * before compile, so the file survives).
 *
 * Wired through the raw unplugin `farm` key; verified empirically against
 * @farmfe/core 1.7 (hook order, async adoption of modified bytes, entry
 * flags via `resource.info.data.isEntry`).
 */

import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import type { ResolvedConfig } from './config.js'
import { runPipeline, type BuildIdentity, type PipelineInput, type PipelineResult } from './core.js'

export interface FarmResource {
  name: string
  bytes: number[]
  resourceType: string
  info?: { data?: { isEntry?: boolean } }
}

export interface FarmFinalizeResourcesParams {
  resourcesMap: Record<string, FarmResource>
  config: { root?: string; output?: { path?: string } }
}

export interface FarmPipelineOutcome {
  resourcesMap: Record<string, FarmResource>
  result: PipelineResult
}

const JS_LIKE = /\.[cm]?js$/
const textDecoder = new TextDecoder()
const textEncoder = new TextEncoder()

/** Farm appends `?query`/`#hash` suffixes to some resource names. */
function cleanName(name: string): string {
  return name.split('?')[0].split('#')[0]
}

export async function runFarmPipeline(
  param: FarmFinalizeResourcesParams,
  config: ResolvedConfig,
  identity: BuildIdentity,
  hooks: { warn: (message: string) => void; urlBase?: string },
): Promise<FarmPipelineOutcome | undefined> {
  const outDirOption = param.config.output?.path
  if (!outDirOption) {
    hooks.warn('CopyLocker unplugin: no compilation.output.path configured — integrity pipeline skipped')
    return undefined
  }
  const outDir = isAbsolute(outDirOption)
    ? outDirOption
    : resolve(param.config.root ?? process.cwd(), outDirOption)

  const inputs: PipelineInput[] = []
  const resources = new Map<string, FarmResource>()
  for (const [rawName, resource] of Object.entries(param.resourcesMap)) {
    const fileName = cleanName(rawName)
    if (resources.has(fileName)) continue
    resources.set(fileName, resource)
    if (JS_LIKE.test(fileName)) {
      inputs.push({
        fileName,
        kind: 'chunk',
        isEntry: resource.info?.data?.isEntry === true,
        text: textDecoder.decode(new Uint8Array(resource.bytes)),
      })
    } else {
      inputs.push({
        fileName,
        kind: 'asset',
        isEntry: false,
        bytes: new Uint8Array(resource.bytes),
      })
    }
  }

  const result = await runPipeline(inputs, config, identity, {
    warn: hooks.warn,
    outDir,
    urlBase: hooks.urlBase,
  })

  // Patch the entry chunks in place — farm writes exactly these bytes.
  for (const [fileName, text] of result.patchedTexts) {
    const resource = resources.get(fileName)
    if (resource) resource.bytes = [...textEncoder.encode(text)]
  }
  for (const [fileName, bytes] of result.patchedAssets) {
    const resource = resources.get(fileName)
    if (resource) resource.bytes = [...bytes]
  }
  // Extra assets (L3 sealed payloads) and the manifest copy go straight to
  // the outdir; farm's clean step already ran, so they survive the write.
  for (const [fileName, bytes] of result.extraAssets) {
    const target = join(outDir, ...fileName.split('/'))
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, bytes)
  }
  const manifestTarget = join(outDir, '.copylocker', 'manifest.cbor')
  await mkdir(dirname(manifestTarget), { recursive: true })
  await writeFile(manifestTarget, result.manifestBytes)

  return { resourcesMap: param.resourcesMap, result }
}
