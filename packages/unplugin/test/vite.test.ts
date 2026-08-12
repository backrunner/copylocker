import { describe, expect, it } from 'vitest'
import { rm } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { build } from 'vite'
import copylocker from '../src/vite.js'
import { makeLocalSigner, withTempDir } from './helpers.js'
import {
  expectRuntimeMatch,
  expectTamperDetected,
  expectVerifyOk,
  readDist,
} from './integration-checks.js'

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'app')

describe('vite integration (real build)', () => {
  it('injects the manifest and guard runtime; R matches; tamper is detected', async () => {
    await withTempDir(async (tmp) => {
      const { keyFile, publicKey } = await makeLocalSigner(tmp)
      const outDir = join(tmp, 'dist')
      await build({
        root: fixtureDir,
        logLevel: 'silent',
        build: {
          outDir,
          emptyOutDir: true,
          rollupOptions: { input: join(fixtureDir, 'src', 'main.js') },
        },
        plugins: [
          copylocker({
            productId: 'integration-app',
            signer: { kind: 'local', keyFile },
            splitConstants: 4,
          }),
        ],
      })

      const inspection = await readDist(outDir)
      const { signed, files } = inspection

      // two chunks (entry + lazy dynamic import), all covered
      const patterns = [...signed.manifest.entries.keys()]
      expect(patterns.some((p) => p.endsWith('.js'))).toBe(true)
      expect(patterns.length).toBeGreaterThanOrEqual(2)

      // the entry chunk carries the prelude: config + bootstrap + backfill
      const entryText = new TextDecoder().decode(files.get(inspection.entryFile))
      expect(entryText).toContain('__CL_GUARD_CONFIG__')
      expect(entryText).toContain('__CL_GUARD_R__')
      expect(entryText).toContain('"kbuild":["') // splitConstants: 4 shards

      // @guarded collection: marker survived minification, digest is in key 7
      expect(entryText).toMatch(/__CL_GUARD_FN__\(("|`)|__CL_GUARD_FN__\('/)
      expect(entryText).toContain('app.expensive')
      expect(signed.manifest.guarded.has('app.expensive')).toBe(true)

      // runtime recomputation over the real dist bytes
      await expectRuntimeMatch(inspection, publicKey)
      // one-byte tamper → R changes and verifyDist fails
      await expectTamperDetected(inspection)
      // CI gate: verifyDist passes on the clean build
      await expectVerifyOk(outDir, publicKey)

      await rm(outDir, { recursive: true, force: true })
    })
  }, 60_000)
})
