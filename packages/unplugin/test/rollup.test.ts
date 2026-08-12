import { describe, it } from 'vitest'
import { rm } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { rollup } from 'rollup'
import copylocker from '../src/rollup.js'
import { makeLocalSigner, withTempDir } from './helpers.js'
import {
  expectRuntimeMatch,
  expectTamperDetected,
  expectVerifyOk,
  readDist,
} from './integration-checks.js'

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'app')

describe('rollup integration (real build)', () => {
  it('injects the manifest and guard runtime; R matches; tamper is detected', async () => {
    await withTempDir(async (tmp) => {
      const { keyFile, publicKey } = await makeLocalSigner(tmp)
      const outDir = join(tmp, 'dist')
      const bundle = await rollup({
        input: join(fixtureDir, 'src', 'plain.js'),
        logLevel: 'silent',
        plugins: [copylocker({ productId: 'integration-app', signer: { kind: 'local', keyFile } })],
      })
      await bundle.write({ dir: outDir, format: 'es' })
      await bundle.close()

      const inspection = await readDist(outDir)
      await expectRuntimeMatch(inspection, publicKey)
      await expectTamperDetected(inspection)
      await expectVerifyOk(outDir, publicKey)

      await rm(outDir, { recursive: true, force: true })
    })
  }, 60_000)
})
