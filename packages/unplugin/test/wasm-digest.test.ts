/**
 * WASM_DIGEST injection tests (`40-web-sdk-wasm-ts.md §5`,
 * `50-unplugin-integrity.md §2.2` generateBundle step ④).
 *
 * The plugin digests every covered `.wasm` asset (SHA-256 — the same
 * algorithm `@copylocker/web` uses at load time), carries the map in the
 * `__CL_GUARD_CONFIG__` prelude, and the bootstrap publishes it as
 * `__CL_WASM_DIGESTS__` (plus the singular `__CL_WASM_DIGEST__` when exactly
 * one wasm asset is covered). The runtime then compares the build-time
 * digest against the bytes it actually loaded; a swapped or patched artifact
 * fails closed.
 */

import { writeFile, mkdir } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { build } from 'vite'
import { decodeManifest } from '@copylocker/guard'
import { resolveConfig } from '../src/config.js'
import { runPipeline, type BuildIdentity, type PipelineInput, type PipelineResult } from '../src/core.js'
import { sha256, toHex } from '../src/hash.js'
import copylocker from '../src/vite.js'
import { readDist } from './integration-checks.js'
import { makeLocalSigner, distFetch, withTempDir } from './helpers.js'

const IDENTITY: BuildIdentity = {
  buildFingerprint: 'clb-test-nogit-0123456789abcdef',
  builtAt: 1_754_600_000,
  kbuild: 'ab'.repeat(32),
  buildSeed: 'aa'.repeat(32),
}

// ---------------------------------------------------------------------------
// Real wasm fixtures (minimal valid modules, wasm-bindgen-style glue)
// ---------------------------------------------------------------------------

function leb(value: number): number[] {
  const out: number[] = []
  let remaining = value
  do {
    let byte = remaining % 128
    remaining = Math.floor(remaining / 128)
    if (remaining > 0) byte |= 0x80
    out.push(byte)
  } while (remaining > 0)
  return out
}

function section(id: number, payload: number[]): number[] {
  return [id, ...leb(payload.length), ...payload]
}

function nameBytes(value: string): number[] {
  return [...leb(value.length), ...new TextEncoder().encode(value)]
}

/** Valid module: exported `memory` plus a renameable `demo_step(i32,i32)->i32`. */
function buildFixtureWasm(): Uint8Array {
  const typeSec = section(1, [1, 0x60, 2, 0x7f, 0x7f, 1, 0x7f])
  const funcSec = section(3, [1, 0])
  const memSec = section(5, [1, 0x00, 1])
  const exportSec = section(7, [
    2,
    ...nameBytes('memory'), 0x02, 0,
    ...nameBytes('demo_step'), 0x00, 0,
  ])
  const body = [0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b]
  const codeSec = section(10, [1, ...leb(body.length), ...body])
  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...typeSec, ...funcSec, ...memSec, ...exportSec, ...codeSec,
  ])
}

/** Glue in the shape wasm-bindgen generates (references `demo_step`). */
function fixtureGlue(): string {
  return `
let wasm
export function initSync(bytes) {
  wasm = new WebAssembly.Instance(new WebAssembly.Module(bytes), {}).exports
  return wasm
}
export function step(a, b) { return wasm.demo_step(a, b) }
`
}

const WASM_FILE = 'assets/core.wasm'

function wasmInputs(wasmBytes: Uint8Array, extra: PipelineInput[] = []): PipelineInput[] {
  return [
    {
      fileName: 'assets/index-aaa.js',
      kind: 'chunk',
      isEntry: true,
      text: 'console.log("entry");\n',
    },
    { fileName: WASM_FILE, kind: 'asset', isEntry: false, bytes: wasmBytes },
    ...extra,
  ]
}

/** Final on-disk bytes for every covered output after patching. */
function finalFiles(inputs: PipelineInput[], result: PipelineResult): Map<string, Uint8Array> {
  const files = new Map<string, Uint8Array>()
  const encoder = new TextEncoder()
  for (const input of inputs) {
    const patchedText = result.patchedTexts.get(input.fileName)
    const patchedAsset = result.patchedAssets.get(input.fileName)
    if (patchedText !== undefined) files.set(input.fileName, encoder.encode(patchedText))
    else if (patchedAsset !== undefined) files.set(input.fileName, patchedAsset)
    else if (input.text !== undefined) files.set(input.fileName, encoder.encode(input.text))
    else files.set(input.fileName, input.bytes as Uint8Array)
  }
  for (const [name, bytes] of result.extraAssets) files.set(name, bytes)
  return files
}

/** Parse the `__CL_GUARD_CONFIG__` object out of a patched entry chunk. */
function readGuardConfig(entryText: string): Record<string, unknown> {
  const marker = ';globalThis.__CL_GUARD_CONFIG__='
  const start = entryText.indexOf(marker)
  expect(start).toBeGreaterThan(-1)
  const end = entryText.indexOf(';\n;globalThis.__CL_REQUIRE_INTEGRITY_PROOF__', start)
  expect(end).toBeGreaterThan(start)
  return JSON.parse(entryText.slice(start + marker.length, end)) as Record<string, unknown>
}

const INJECTED_GLOBALS = [
  '__CL_GUARD_CONFIG__',
  '__CL_MANIFEST__',
  '__CL_ROOT_PINS__',
  '__CL_CHUNKS__',
  '__COPYLOCKER_K_BUILD__',
  '__COPYLOCKER_MANIFEST_ROOT__',
  '__CL_WASM_DIGESTS__',
  '__CL_WASM_DIGEST__',
  '__CL_GUARD_FN__',
  '__CL_GUARD_R__',
  '__CL_REQUIRE_INTEGRITY_PROOF__',
]

/**
 * Evaluate a patched entry chunk (prelude + bootstrap + original code) in
 * this realm with `fetch` pointed at the given dist bytes, then await the
 * guard root. Returns the published globals; cleans up fetch and globals.
 */
async function evalEntry(
  entryText: string,
  files: Map<string, Uint8Array>,
): Promise<{ R: Uint8Array; globals: Record<string, unknown> }> {
  const globals = globalThis as Record<string, unknown>
  const originalFetch = globals.fetch
  globals.fetch = distFetch(files)
  try {
    ;(0, eval)(entryText)
    const R = (await globals.__CL_GUARD_R__) as Uint8Array
    const published: Record<string, unknown> = {}
    for (const name of INJECTED_GLOBALS) published[name] = globals[name]
    return { R, globals: published }
  } finally {
    if (originalFetch === undefined) delete globals.fetch
    else globals.fetch = originalFetch
    for (const name of INJECTED_GLOBALS) delete globals[name]
  }
}

// ---------------------------------------------------------------------------
// Pipeline-level injection
// ---------------------------------------------------------------------------

describe('WASM_DIGEST injection (pipeline)', () => {
  it('injects the SHA-256 of a covered .wasm asset into the prelude config', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const wasmBytes = buildFixtureWasm()
      // the fixture is a real, compilable module
      await WebAssembly.compile(wasmBytes)

      const config = resolveConfig({ productId: 'test-app', signer: { kind: 'local', keyFile } })
      const inputs = wasmInputs(wasmBytes)
      const result = await runPipeline(inputs, config, IDENTITY, { warn: () => {} })

      const patched = result.patchedTexts.get('assets/index-aaa.js') as string
      const guardConfig = readGuardConfig(patched)
      expect(guardConfig.wasmDigests).toEqual({
        [WASM_FILE]: toHex(await sha256(wasmBytes)),
      })
    })
  })

  it('binds the RENAMED bytes when randomizeWasmExports is on', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const wasmBytes = buildFixtureWasm()
      const glue: PipelineInput = {
        fileName: 'assets/glue-bbb.js',
        kind: 'chunk',
        isEntry: false,
        text: fixtureGlue(),
      }
      const config = resolveConfig({
        productId: 'test-app',
        signer: { kind: 'local', keyFile },
        randomizeWasmExports: true,
      })
      const inputs = wasmInputs(wasmBytes, [glue])
      const result = await runPipeline(inputs, config, IDENTITY, { warn: () => {} })

      const renamed = result.patchedAssets.get(WASM_FILE)
      expect(renamed).toBeDefined()
      const guardConfig = readGuardConfig(result.patchedTexts.get('assets/index-aaa.js') as string)
      expect(guardConfig.wasmDigests).toEqual({ [WASM_FILE]: toHex(await sha256(renamed as Uint8Array)) })
      // …and that is NOT the digest of the pre-randomization bytes
      expect((guardConfig.wasmDigests as Record<string, string>)[WASM_FILE]).not.toBe(
        toHex(await sha256(wasmBytes)),
      )
    })
  })

  it('warns and injects an empty map when no covered .wasm asset exists', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const config = resolveConfig({ productId: 'test-app', signer: { kind: 'local', keyFile } })
      const inputs: PipelineInput[] = [
        { fileName: 'assets/index-aaa.js', kind: 'chunk', isEntry: true, text: 'console.log(1);\n' },
      ]
      const warnings: string[] = []
      const result = await runPipeline(inputs, config, IDENTITY, {
        warn: (m) => warnings.push(m),
      })
      expect(warnings.some((m) => m.includes('WASM_DIGEST was NOT injected'))).toBe(true)
      const guardConfig = readGuardConfig(result.patchedTexts.get('assets/index-aaa.js') as string)
      expect(guardConfig.wasmDigests).toEqual({})
    })
  })

  it('digests every covered .wasm asset when several are emitted', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const first = buildFixtureWasm()
      const second = new Uint8Array(first)
      second[second.byteLength - 1] = (second[second.byteLength - 1] as number) ^ 0xff
      const inputs = wasmInputs(first, [
        { fileName: 'assets/extra.wasm', kind: 'asset', isEntry: false, bytes: second },
      ])
      const config = resolveConfig({ productId: 'test-app', signer: { kind: 'local', keyFile } })
      const result = await runPipeline(inputs, config, IDENTITY, { warn: () => {} })

      const guardConfig = readGuardConfig(result.patchedTexts.get('assets/index-aaa.js') as string)
      expect(guardConfig.wasmDigests).toEqual({
        [WASM_FILE]: toHex(await sha256(first)),
        'assets/extra.wasm': toHex(await sha256(second)),
      })
    })
  })
})

// ---------------------------------------------------------------------------
// Runtime publishing (bootstrap evaluated against the real dist bytes)
// ---------------------------------------------------------------------------

describe('WASM_DIGEST injection (runtime publishing)', () => {
  it('publishes __CL_WASM_DIGEST__ matching the served wasm; a swap mismatches', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const wasmBytes = buildFixtureWasm()
      const config = resolveConfig({
        productId: 'test-app',
        signer: { kind: 'local', keyFile },
        guard: { strategy: 'sync' },
      })
      const inputs = wasmInputs(wasmBytes)
      const result = await runPipeline(inputs, config, IDENTITY, { warn: () => {} })
      const files = finalFiles(inputs, result)

      const patched = result.patchedTexts.get('assets/index-aaa.js') as string
      const { R, globals } = await evalEntry(patched, files)

      // the guard runtime accepted the dist (R == manifest root) …
      const root = decodeManifest(result.manifestBytes).manifest.root
      expect(toHex(R)).toBe(toHex(root))
      // …and the bootstrap published the design's constants
      const expectedHex = toHex(await sha256(wasmBytes))
      expect(globals.__CL_WASM_DIGEST__).toBe(expectedHex)
      expect(globals.__CL_WASM_DIGESTS__).toEqual({ [WASM_FILE]: expectedHex })

      // a swapped .wasm artifact digests differently → the runtime comparison
      // against the injected constant fails (the "replace the wasm" attack)
      const swapped = new Uint8Array(wasmBytes)
      swapped[10] = (swapped[10] as number) ^ 0xff
      expect(toHex(await sha256(swapped))).not.toBe(globals.__CL_WASM_DIGEST__)
    })
  })

  it('publishes only the map (no singular constant) for multi-wasm builds', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const first = buildFixtureWasm()
      const second = new Uint8Array(first)
      second[second.byteLength - 1] = (second[second.byteLength - 1] as number) ^ 0xff
      const config = resolveConfig({
        productId: 'test-app',
        signer: { kind: 'local', keyFile },
        guard: { strategy: 'sync' },
      })
      const inputs = wasmInputs(first, [
        { fileName: 'assets/extra.wasm', kind: 'asset', isEntry: false, bytes: second },
      ])
      const result = await runPipeline(inputs, config, IDENTITY, { warn: () => {} })
      const files = finalFiles(inputs, result)

      const patched = result.patchedTexts.get('assets/index-aaa.js') as string
      const { globals } = await evalEntry(patched, files)
      expect(globals.__CL_WASM_DIGEST__).toBeUndefined()
      expect(globals.__CL_WASM_DIGESTS__).toEqual({
        [WASM_FILE]: toHex(await sha256(first)),
        'assets/extra.wasm': toHex(await sha256(second)),
      })
    })
  })
})

// ---------------------------------------------------------------------------
// Real bundler build (vite adapter representative — the mechanism is the
// shared outdir pipeline every adapter feeds)
// ---------------------------------------------------------------------------

describe('WASM_DIGEST injection (vite adapter, real build)', () => {
  it('injects the digest of the .wasm asset vite emitted', async () => {
    await withTempDir(async (tmp) => {
      const { keyFile } = await makeLocalSigner(tmp)
      const fixtureDir = join(tmp, 'app')
      await mkdir(join(fixtureDir, 'src'), { recursive: true })
      const wasmBytes = buildFixtureWasm()
      await writeFile(join(fixtureDir, 'src', 'core.wasm'), wasmBytes)
      await writeFile(
        join(fixtureDir, 'src', 'main.js'),
        'export const wasmUrl = new URL("./core.wasm", import.meta.url).href\nconsole.log(wasmUrl)\n',
      )
      const outDir = join(tmp, 'dist')
      await build({
        root: fixtureDir,
        logLevel: 'silent',
        build: {
          outDir,
          emptyOutDir: true,
          // The fixture is far below the default inline limit; force the
          // wasm out as a real emitted asset instead of a data: URL.
          assetsInlineLimit: 0,
          rollupOptions: { input: join(fixtureDir, 'src', 'main.js') },
        },
        plugins: [copylocker({ productId: 'wasm-digest-app', signer: { kind: 'local', keyFile } })],
      })

      const inspection = await readDist(outDir)
      const wasmFile = [...inspection.files.keys()].find((name) => name.endsWith('.wasm'))
      expect(wasmFile).toBeDefined()
      // vite emitted the fixture verbatim
      expect(inspection.files.get(wasmFile as string)).toEqual(wasmBytes)

      const entryText = new TextDecoder().decode(inspection.files.get(inspection.entryFile))
      const guardConfig = readGuardConfig(entryText)
      expect(guardConfig.wasmDigests).toEqual({
        [wasmFile as string]: toHex(await sha256(wasmBytes)),
      })
    })
  }, 60_000)
})
