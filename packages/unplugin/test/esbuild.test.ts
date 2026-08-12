import { describe, expect, it } from 'vitest'
import { rm } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { build } from 'esbuild'
import copylocker from '../src/esbuild.js'
import { makeLocalSigner, withTempDir } from './helpers.js'
import {
  expectRuntimeMatch,
  expectTamperDetected,
  expectVerifyOk,
  readDist,
} from './integration-checks.js'

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'app')

describe('esbuild integration (real build, onEnd + outdir)', () => {
  it('injects the manifest and guard runtime; R matches; tamper is detected', async () => {
    await withTempDir(async (tmp) => {
      const { keyFile, publicKey } = await makeLocalSigner(tmp)
      const outDir = join(tmp, 'dist')
      await build({
        entryPoints: [join(fixtureDir, 'src', 'main.js')],
        bundle: true,
        splitting: true,
        format: 'esm',
        outdir: outDir,
        logLevel: 'silent',
        plugins: [
          copylocker({ productId: 'integration-app', signer: { kind: 'local', keyFile } }),
        ],
      })

      const inspection = await readDist(outDir)
      const entryText = new TextDecoder().decode(inspection.files.get(inspection.entryFile))
      expect(entryText).toContain('__CL_GUARD_CONFIG__')
      expect(entryText).toContain('app.expensive') // guarded marker survived
      expect(inspection.signed.manifest.guarded.has('app.expensive')).toBe(true)

      await expectRuntimeMatch(inspection, publicKey)
      await expectTamperDetected(inspection)
      await expectVerifyOk(outDir, publicKey)

      await rm(outDir, { recursive: true, force: true })
    })
  }, 60_000)
})
