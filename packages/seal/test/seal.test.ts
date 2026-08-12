import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { openSealedAsset as webOpen, sealAsset as webSeal } from '../../web/src/unseal.js'
import { decodeSealedAsset, openSealedBytes } from '../src/container.js'
import { chunkLoaderStub, sealAssets, sealChunk } from '../src/seal.js'

const kek = new Uint8Array(32).fill(21)

let dir: string

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'copylocker-seal-assets-'))
  await mkdir(join(dir, 'assets/pro'), { recursive: true })
  await writeFile(join(dir, 'assets/pro/presets.json'), '{"quality":"high"}')
  await writeFile(join(dir, 'assets/pro/model.bin'), Buffer.alloc(9000, 3))
  await writeFile(join(dir, 'assets/free.json'), '{"quality":"low"}')
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

describe('sealAssets', () => {
  it('dry-run (no outDir) writes nothing', async () => {
    const results = await sealAssets({
      cwd: dir,
      globs: ['assets/pro/*'],
      featureId: 'pro',
      productId: 'demo',
      kek,
    })
    expect(results.map((r) => r.source)).toEqual(['assets/pro/model.bin', 'assets/pro/presets.json'])
    for (const result of results) {
      expect(result.written).toBe(false)
      expect(result.output).toBe('<dry-run>')
      expect(result.sealedBytes).toBeGreaterThan(result.plaintextBytes)
    }
    await expect(readdir(join(dir, 'sealed'))).rejects.toThrow()
  })

  it('seals into outDir and the web runtime opens the products', async () => {
    const results = await sealAssets({
      cwd: dir,
      globs: ['assets/pro/**'],
      featureId: 'pro',
      productId: 'demo',
      kek,
      outDir: 'sealed',
      chunkSize: 4096,
    })
    expect(results.every((r) => r.written)).toBe(true)
    const chunked = results.find((r) => r.source === 'assets/pro/model.bin')
    expect(chunked?.chunking).toEqual({ chunkSize: 4096, chunkCount: 3 })

    const { readFile } = await import('node:fs/promises')
    for (const result of results) {
      const sealed = new Uint8Array(await readFile(join(dir, result.output)))
      // The exact runtime path: @copylocker/web opens the build-time product.
      const opened = await webOpen(kek, sealed, { productId: 'demo', featureId: 'pro' })
      const original = new Uint8Array(await readFile(join(dir, result.source)))
      expect(opened).toEqual(original)
    }
  })

  it('assetId override is bound into the container', async () => {
    const results = await sealAssets({
      cwd: dir,
      globs: ['assets/free.json'],
      featureId: 'free',
      productId: 'demo',
      kek,
      assetId: (source) => `/v1/${source}`,
    })
    expect(results[0]?.assetId).toBe('/v1/assets/free.json')
  })

  it('rejects missing product/feature ids', async () => {
    await expect(
      sealAssets({ cwd: dir, globs: ['x'], featureId: '', productId: 'demo', kek }),
    ).rejects.toMatchObject({ code: 'CONFIG' })
  })
})

describe('sealChunk (L3)', () => {
  it('seals a JS chunk and emits the §5.1 loader stub', async () => {
    const code = new TextEncoder().encode('export const answer = 42\n')
    const { sealed, stub, meta } = await sealChunk({
      code,
      featureId: 'pro',
      productId: 'demo',
      kek,
      assetId: 'chunks/pro-x7f2.js',
      sealedUrl: '/chunks/pro-x7f2.js.sealed',
    })
    expect(meta.assetId).toBe('chunks/pro-x7f2.js')
    expect(decodeSealedAsset(sealed).assetId).toBe('chunks/pro-x7f2.js')

    // Stub contract (design 60-instrumentation-guard.md §5.1).
    expect(stub).toContain('await __cl.loadSealed("/chunks/pro-x7f2.js.sealed", "pro")')
    expect(stub).toContain("new Blob([code], { type: 'text/javascript' })")
    expect(stub).toContain('URL.createObjectURL')
    expect(stub).toMatch(/export default async function load\(\)/)

    // The sealed chunk opens under the feature KEK.
    const opened = await openSealedBytes(kek, sealed, { productId: 'demo', featureId: 'pro' })
    expect(opened).toEqual(code)
  })

  it('stub template escapes backslashes and line terminators', () => {
    const stub = chunkLoaderStub('chunks\\dir\\a.js.sealed', 'pro')
    expect(stub).toContain('"chunks\\\\dir\\\\a.js.sealed"')
    // A single quote no longer breaks out of the emitted string literal.
    expect(chunkLoaderStub("/evil'.js", 'pro')).toContain('"/evil\'.js"')
    // A raw line terminator would leave an unterminated string literal; it
    // must be escaped within the emitted line.
    const line = chunkLoaderStub('/a\nb.js.sealed', 'pro')
      .split('\n')
      .find((l) => l.includes('loadSealed'))
    expect(line).toContain('"/a\\nb.js.sealed"')
  })

  it('the sealed chunk also opens via the web runtime', async () => {
    const code = new TextEncoder().encode('console.log(1)')
    const { sealed } = await sealChunk({
      code,
      featureId: 'pro',
      productId: 'demo',
      kek,
      assetId: 'chunks/a.js',
      sealedUrl: '/chunks/a.js.sealed',
    })
    const opened = await webOpen(kek, sealed, { productId: 'demo', featureId: 'pro' })
    expect(opened).toEqual(code)
    // And a web-produced container opens through the seal debug path.
    const webSealed = await webSeal(kek, {
      productId: 'demo',
      variantId: 0,
      featureId: 'pro',
      assetId: 'chunks/a.js',
    }, code)
    await expect(openSealedBytes(kek, webSealed)).resolves.toEqual(code)
  })
})
