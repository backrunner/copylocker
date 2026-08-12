import { describe, expect, it } from 'vitest'
import { rm } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { build } from '@farmfe/core'
import copylocker from '../src/farm.js'
import { makeLocalSigner, withTempDir } from './helpers.js'
import {
  expectRuntimeMatch,
  expectTamperDetected,
  expectVerifyOk,
  readDist,
} from './integration-checks.js'

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'app')

describe('farm integration (real build, finalizeResources)', () => {
  it('injects the manifest and guard runtime; R matches; tamper is detected', async () => {
    await withTempDir(async (tmp) => {
      const { keyFile, publicKey } = await makeLocalSigner(tmp)
      const outDir = join(tmp, 'dist')
      await build({
        root: fixtureDir,
        compilation: {
          input: { main: join(fixtureDir, 'src', 'main.js') },
          output: { path: outDir },
          minify: true,
          persistentCache: false,
        },
        plugins: [
          copylocker({
            productId: 'integration-app',
            // farm build() forces NODE_ENV=production in-process
            signer: { kind: 'local', keyFile, allowLocalInProduction: true },
          }),
        ],
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
