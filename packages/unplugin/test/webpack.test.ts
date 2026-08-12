import { describe, expect, it } from 'vitest'
import { cp, rm, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import webpack from 'webpack'
import copylocker from '../src/webpack.js'
import { makeLocalSigner, withTempDir } from './helpers.js'
import {
  expectRuntimeMatch,
  expectTamperDetected,
  expectVerifyOk,
  readDist,
} from './integration-checks.js'

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'app')

function runCompiler(compiler: webpack.Compiler): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    compiler.run((error, stats) => {
      if (error) return reject(error)
      if (stats?.hasErrors()) return reject(new Error(stats.toString({ errors: true })))
      compiler.close(() => resolvePromise())
    })
  })
}

describe('webpack integration (real build, afterEmit + outdir)', () => {
  it('injects the manifest and guard runtime; R matches; tamper is detected', async () => {
    await withTempDir(async (tmp) => {
      const { keyFile, publicKey } = await makeLocalSigner(tmp)
      const outDir = join(tmp, 'dist')
      const compiler = webpack({
        mode: 'production',
        target: 'web',
        context: fixtureDir,
        entry: join(fixtureDir, 'src', 'main.js'),
        output: {
          path: outDir,
          filename: '[name].js',
          chunkFilename: 'chunks/[name].js',
        },
        plugins: [
          copylocker({ productId: 'integration-app', signer: { kind: 'local', keyFile } }),
        ],
      })
      await runCompiler(compiler)

      const inspection = await readDist(outDir)
      const entryText = new TextDecoder().decode(inspection.files.get(inspection.entryFile))
      expect(entryText).toContain('__CL_GUARD_CONFIG__')
      expect(entryText).toContain('app.expensive') // guarded marker survived minification
      expect(inspection.signed.manifest.guarded.has('app.expensive')).toBe(true)
      // entry + async lazy chunk are both covered
      expect(inspection.signed.manifest.entries.size).toBeGreaterThanOrEqual(2)

      await expectRuntimeMatch(inspection, publicKey)
      await expectTamperDetected(inspection)
      await expectVerifyOk(outDir, publicKey)

      await rm(outDir, { recursive: true, force: true })
    })
  }, 60_000)

  it('watch mode rebuilds re-run the pipeline without crashing', async () => {
    await withTempDir(async (tmp) => {
      const { keyFile } = await makeLocalSigner(tmp)
      const src = join(tmp, 'src')
      await cp(join(fixtureDir, 'src'), src, { recursive: true })
      const outDir = join(tmp, 'dist')
      const compiler = webpack({
        mode: 'production',
        target: 'web',
        context: tmp,
        entry: join(src, 'plain.js'),
        output: { path: outDir, filename: '[name].js' },
        plugins: [
          copylocker({ productId: 'integration-app', signer: { kind: 'local', keyFile } }),
        ],
      })

      const builds: string[] = []
      const watching = await new Promise<webpack.Watching>((resolvePromise, reject) => {
        const w = compiler.watch({}, (error, stats) => {
          if (error) return reject(error)
          if (stats?.hasErrors()) return reject(new Error(stats.toString({ errors: true })))
          builds.push('done')
          resolvePromise(w)
        })
      })

      // first build produced a manifest
      const first = await readDist(outDir)
      expect(first.signed.manifest.entries.size).toBeGreaterThanOrEqual(1)

      // touch a source file → rebuild → pipeline runs again, manifest rewritten
      await writeFile(join(src, 'lib.js'), 'export function compute(x) { return x * 3 + 1 }\n')
      await new Promise<void>((resolvePromise, reject) => {
        compiler.hooks.done.tap('cl-watch-test', () => resolvePromise())
        setTimeout(() => reject(new Error('watch rebuild timed out')), 30_000)
      })
      const second = await readDist(outDir)
      expect(second.signed.manifest.entries.size).toBeGreaterThanOrEqual(1)
      expect(builds.length).toBeGreaterThanOrEqual(1)

      await new Promise<void>((resolvePromise) => watching.close(() => resolvePromise()))
    })
  }, 90_000)
})
