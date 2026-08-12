import { describe, expect, it } from 'vitest'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import {
  generateWrappingKey,
  getKek,
  hexEncode,
  loadRegistry,
  openSealedBytes,
  resolveWrappingKey,
} from '@copylocker/seal'
import { decodeManifest } from '@copylocker/guard'
import { resolveConfig } from '../src/config.js'
import { runPipeline, type BuildIdentity, type PipelineInput } from '../src/core.js'
import { makeLocalSigner, syntheticInputs, withTempDir } from './helpers.js'

const IDENTITY: BuildIdentity = {
  buildFingerprint: 'clb-test-nogit-0123456789abcdef',
  builtAt: 1_754_600_000,
  kbuild: 'ab'.repeat(32),
}

async function setupSealDir(dir: string): Promise<{ registryFile: string; wrappingKeyFile: string }> {
  const registryFile = join(dir, 'seal-registry.json')
  const wrappingKeyFile = join(dir, 'wrapping-key')
  await writeFile(wrappingKeyFile, hexEncode(generateWrappingKey()), { mode: 0o600 })
  return { registryFile, wrappingKeyFile }
}

describe('seal integration', () => {
  it('seal.assets seals globs into the out dir and registers manifest key 8', async () => {
    await withTempDir(async (dir) => {
      const { registryFile, wrappingKeyFile } = await setupSealDir(dir)
      await writeFile(join(dir, 'pro-data.json'), '{"level": 9}\n')
      const outDir = join(dir, 'dist')
      const { keyFile } = await makeLocalSigner(dir)
      const config = resolveConfig({
        productId: 'test-app',
        signer: { kind: 'local', keyFile },
        seal: {
          assets: [{ globs: ['pro-*.json'], feature: 'pro' }],
          registryFile,
          wrappingKeyFile,
          cwd: dir,
        },
      })
      const result = await runPipeline(syntheticInputs(), config, IDENTITY, {
        warn: () => {},
        outDir,
      })
      // sealed file landed in the out dir
      const sealedBytes = new Uint8Array(await readFile(join(outDir, 'pro-data.json.sealed')))
      expect(sealedBytes.byteLength).toBeGreaterThan(0)
      // manifest key 8 lists the asset id
      const signed = decodeManifest(result.manifestBytes)
      expect(signed.manifest.sealed).toContain('pro-data.json')
      // and the KEK from the persisted registry actually opens it
      const wrappingKey = await resolveWrappingKey({ keyFile: wrappingKeyFile })
      const registry = await loadRegistry({ path: registryFile, wrappingKey })
      const kek = getKek(registry, 'pro')
      expect(kek).toBeDefined()
      const opened = await openSealedBytes(kek as Uint8Array, sealedBytes, {
        productId: 'test-app',
        featureId: 'pro',
        assetId: 'pro-data.json',
      })
      expect(new TextDecoder().decode(opened)).toBe('{"level": 9}\n')
    })
  })

  it('seal.chunks replaces matched chunks with loader stubs (L3, opt-in)', async () => {
    await withTempDir(async (dir) => {
      const { registryFile, wrappingKeyFile } = await setupSealDir(dir)
      const { keyFile } = await makeLocalSigner(dir)
      const config = resolveConfig({
        productId: 'test-app',
        signer: { kind: 'local', keyFile },
        seal: {
          chunks: [{ match: /chunk-bbb/, feature: 'pro' }],
          registryFile,
          wrappingKeyFile,
          cwd: dir,
        },
      })
      const inputs: PipelineInput[] = syntheticInputs()
      const result = await runPipeline(inputs, config, IDENTITY, { warn: () => {} })

      // the chunk became a loader stub expecting globalThis.__cl
      const stub = result.patchedTexts.get('assets/chunk-bbb.js')
      expect(stub).toContain('__cl.loadSealed')
      expect(stub).toContain('assets/chunk-bbb.js.sealed')
      // the sealed payload is a new asset
      const payload = result.extraAssets.get('assets/chunk-bbb.js.sealed')
      expect(payload).toBeDefined()
      // manifest: sealed list contains the chunk assetId; the STUB is digested
      const signed = decodeManifest(result.manifestBytes)
      expect(signed.manifest.sealed).toContain('assets/chunk-bbb.js')
      expect([...signed.manifest.entries.keys()]).not.toContain('assets/chunk-bbb.js.sealed')
      // payload opens under the registry KEK
      const wrappingKey = await resolveWrappingKey({ keyFile: wrappingKeyFile })
      const registry = await loadRegistry({ path: registryFile, wrappingKey })
      const kek = getKek(registry, 'pro') as Uint8Array
      const opened = await openSealedBytes(kek, payload as Uint8Array, {
        productId: 'test-app',
        featureId: 'pro',
        assetId: 'assets/chunk-bbb.js',
      })
      expect(new TextDecoder().decode(opened)).toBe('export const answer = 42;\n')
    })
  })

  it('fails cleanly when the wrapping key is missing', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const config = resolveConfig({
        productId: 'test-app',
        signer: { kind: 'local', keyFile },
        seal: {
          assets: [{ globs: ['*.json'], feature: 'pro' }],
          registryFile: join(dir, 'reg.json'),
          wrappingKeyFile: join(dir, 'missing.key'),
          cwd: dir,
        },
      })
      await expect(
        runPipeline(syntheticInputs(), config, IDENTITY, { warn: () => {}, outDir: join(dir, 'dist') }),
      ).rejects.toThrow(/wrapping key/)
    })
  })
})
