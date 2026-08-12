import { describe, expect, it } from 'vitest'
import { rm } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { rspack } from '@rspack/core'
import copylocker from '../src/rspack.js'
import { makeLocalSigner, withTempDir } from './helpers.js'
import {
  expectRuntimeMatch,
  expectTamperDetected,
  expectVerifyOk,
  readDist,
} from './integration-checks.js'

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'app')

describe('rspack integration (real build, afterEmit + outdir)', () => {
  it('injects the manifest and guard runtime; R matches; tamper is detected', async () => {
    await withTempDir(async (tmp) => {
      const { keyFile, publicKey } = await makeLocalSigner(tmp)
      const outDir = join(tmp, 'dist')
      const compiler = rspack({
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
      await new Promise<void>((resolvePromise, reject) => {
        compiler.run((error, stats) => {
          if (error) return reject(error)
          if (stats?.hasErrors()) return reject(new Error(stats.toString({ errors: true })))
          compiler.close(() => resolvePromise())
        })
      })

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
})
