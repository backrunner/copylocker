import { describe, expect, it } from 'vitest'
import { bootGuard, decodeManifest, zeroExcludedRanges } from '@copylocker/guard'
import { resolveConfig } from '../src/config.js'
import { runPipeline, type BuildIdentity, type PipelineResult } from '../src/core.js'
import { sha256, toHex } from '../src/hash.js'
import { makeLocalSigner, syntheticInputs, distFetch, withTempDir } from './helpers.js'

const IDENTITY: BuildIdentity = {
  buildFingerprint: 'clb-test-nogit-0123456789abcdef',
  builtAt: 1_754_600_000,
  kbuild: 'ab'.repeat(32),
}

async function buildOnce(options: Parameters<typeof resolveConfig>[0], identity = IDENTITY) {
  const config = resolveConfig(options)
  const inputs = syntheticInputs()
  const warnings: string[] = []
  const result = await runPipeline(inputs, config, identity, { warn: (m) => warnings.push(m) })
  return { config, inputs, result, warnings }
}

/** Final on-disk bytes for every covered output after patching. */
function finalFiles(inputs: ReturnType<typeof syntheticInputs>, result: PipelineResult) {
  const files = new Map<string, Uint8Array>()
  for (const input of inputs) {
    const patched = result.patchedTexts.get(input.fileName)
    if (patched !== undefined) files.set(input.fileName, new TextEncoder().encode(patched))
    else if (input.text !== undefined) files.set(input.fileName, new TextEncoder().encode(input.text))
    else files.set(input.fileName, input.bytes as Uint8Array)
  }
  for (const [name, bytes] of result.extraAssets) files.set(name, bytes)
  return files
}

describe('pipeline: two-round self-reference', () => {
  it('produces a manifest the guard runtime accepts; R equals the backfilled root', async () => {
    await withTempDir(async (dir) => {
      const { keyFile, publicKey } = await makeLocalSigner(dir)
      const { inputs, result } = await buildOnce({
        productId: 'test-app',
        signer: { kind: 'local', keyFile },
      })

      // covered: 2 js chunks + 1 css; the .map is excluded
      const signed = decodeManifest(result.manifestBytes)
      expect([...signed.manifest.entries.keys()].sort()).toEqual(
        ['assets/chunk-bbb.js', 'assets/index-aaa.js', 'assets/style-ccc.css'].sort(),
      )
      expect(signed.manifest.productId).toBe('test-app')
      expect(signed.manifest.buildFingerprint).toBe(IDENTITY.buildFingerprint)

      // entry chunk carries exactly the two placeholder spans
      const entry = signed.manifest.entries.get('assets/index-aaa.js')
      expect(entry?.excludedRanges).toHaveLength(2)
      expect(signed.manifest.entries.get('assets/chunk-bbb.js')?.excludedRanges).toEqual([])

      // backfill kept the chunk length stable: prelude + original code
      const patched = result.patchedTexts.get('assets/index-aaa.js') as string
      const original = inputs[0]?.text as string
      expect(patched.endsWith(original)).toBe(true)

      // round-1/round-2 equivalence: zeroing the manifest's excludedRanges on
      // the FINAL bytes reproduces the recorded digest
      const files = finalFiles(inputs, result)
      const entryBytes = files.get('assets/index-aaa.js') as Uint8Array
      const recomputed = await sha256(zeroExcludedRanges(entryBytes, entry?.excludedRanges ?? []))
      expect(toHex(recomputed)).toBe(toHex(entry?.digest as Uint8Array))

      // the manifest hex embedded in the chunk IS the manifest
      const manifestHex = patched.slice(
        entry?.excludedRanges[0]?.[0],
        entry?.excludedRanges[0]?.[1],
      )
      expect(manifestHex).toBe(toHex(result.manifestBytes))
      const rootHex = patched.slice(entry?.excludedRanges[1]?.[0], entry?.excludedRanges[1]?.[1])
      expect(rootHex).toBe(toHex(signed.manifest.root))

      // runtime: bootGuard over the dist bytes recomputes R == manifest.root
      const { R, report } = await bootGuard({
        manifest: result.manifestBytes,
        rootPins: [publicKey],
        chunks: [
          { url: 'assets/index-aaa.js', pattern: 'assets/index-aaa.js' },
          { url: 'assets/chunk-bbb.js', pattern: 'assets/chunk-bbb.js' },
          { url: 'assets/style-ccc.css', pattern: 'assets/style-ccc.css' },
        ],
        strategy: 'sync',
        fetchImpl: distFetch(files),
      })
      expect(report.signature).toBe('verified')
      expect(report.entries.every((e) => e.status === 'ok')).toBe(true)
      expect(toHex(R)).toBe(toHex(signed.manifest.root))
    })
  })

  it('a one-byte tamper in any chunk changes R', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const { inputs, result } = await buildOnce({
        productId: 'test-app',
        signer: { kind: 'local', keyFile },
      })
      const files = finalFiles(inputs, result)
      const tampered = new Map(files)
      const victim = new Uint8Array(files.get('assets/chunk-bbb.js') as Uint8Array)
      victim[5] = (victim[5] as number) ^ 0xff
      tampered.set('assets/chunk-bbb.js', victim)

      const { R, report } = await bootGuard({
        manifest: result.manifestBytes,
        chunks: [
          { url: 'assets/index-aaa.js', pattern: 'assets/index-aaa.js' },
          { url: 'assets/chunk-bbb.js', pattern: 'assets/chunk-bbb.js' },
          { url: 'assets/style-ccc.css', pattern: 'assets/style-ccc.css' },
        ],
        strategy: 'sync',
        fetchImpl: distFetch(tampered),
      })
      const root = decodeManifest(result.manifestBytes).manifest.root
      expect(toHex(R)).not.toBe(toHex(root))
      expect(report.entries.find((e) => e.pattern === 'assets/chunk-bbb.js')?.status).toBe(
        'mismatch',
      )
    })
  })

  it('writes inside the placeholder spans do NOT change the runtime digest', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const { inputs, result } = await buildOnce({
        productId: 'test-app',
        signer: { kind: 'local', keyFile },
      })
      const entry = decodeManifest(result.manifestBytes).manifest.entries.get(
        'assets/index-aaa.js',
      )
      const bytes = new Uint8Array(finalFiles(inputs, result).get('assets/index-aaa.js') as Uint8Array)
      const before = await sha256(zeroExcludedRanges(bytes, entry?.excludedRanges ?? []))
      // scribble inside the manifest hex span (runtime zeroes it anyway)
      const [s] = entry?.excludedRanges[0] ?? [0]
      bytes[s] = bytes[s] === 0x30 ? 0x31 : 0x30
      const after = await sha256(zeroExcludedRanges(bytes, entry?.excludedRanges ?? []))
      expect(toHex(after)).toBe(toHex(before))
    })
  })

  it('splitConstants injects N K_BUILD shards that reassemble to 32 bytes', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const { result } = await buildOnce(
        { productId: 'test-app', signer: { kind: 'local', keyFile }, splitConstants: 4 },
        { ...IDENTITY, kbuild: ['00'.repeat(8), '11'.repeat(8), '22'.repeat(8), '33'.repeat(8)] },
      )
      const patched = result.patchedTexts.get('assets/index-aaa.js') as string
      expect(patched).toContain('"kbuild":["0000000000000000"')
      const match = /"kbuild":\[("[0-9a-f]*"(?:,"[0-9a-f]*")*)\]/.exec(patched)
      expect(match).not.toBeNull()
      const shards = JSON.parse(`[${match?.[1] as string}]`) as string[]
      expect(shards).toHaveLength(4)
      expect(shards.join('')).toMatch(/^[0-9a-f]{64}$/)
    })
  })
})

describe('pipeline: config validation', () => {
  it('rejects blake3 in M4-A (the guard runtime computes sha256)', () => {
    expect(() => resolveConfig({ productId: 'x', hasher: 'blake3' })).toThrow(/blake3/)
  })

  it('rejects bad rootPins and suiteId', () => {
    expect(() => resolveConfig({ productId: 'x', rootPins: ['zz'] })).toThrow(/rootPins/)
    expect(() => resolveConfig({ productId: 'x', suiteId: '0102' })).toThrow(/suiteId/)
  })

  it('labels the default hasher as sha256, not custom', () => {
    expect(resolveConfig({ productId: 'x' }).hashAlg).toBe('sha256')
    expect(resolveConfig({ productId: 'x', hasher: 'sha256' }).hashAlg).toBe('sha256')
    expect(resolveConfig({ productId: 'x', hasher: async (b) => b }).hashAlg).toBe('custom')
  })

  it('rejects an invalid seal.chunks regex string as a ConfigError', () => {
    expect(() =>
      resolveConfig({ productId: 'x', seal: { chunks: [{ match: '([', feature: 'p' }] } }),
    ).toThrow(/not a valid regular expression/)
  })
})

describe('verifyDist provenance gate', () => {
  it('an unsigned dist FAILS when public keys are given; passes integrity-only without', async () => {
    const { mkdir, writeFile } = await import('node:fs/promises')
    const { dirname, join } = await import('node:path')
    const { verifyDist } = await import('../src/verify.js')
    await withTempDir(async (dir) => {
      const { inputs, result } = await buildOnce({ productId: 'test-app' }) // no signer → unsigned
      for (const [name, bytes] of finalFiles(inputs, result)) {
        const target = join(dir, ...name.split('/'))
        await mkdir(dirname(target), { recursive: true })
        await writeFile(target, bytes)
      }
      await mkdir(join(dir, '.copylocker'), { recursive: true })
      await writeFile(join(dir, '.copylocker', 'manifest.cbor'), result.manifestBytes)

      const { publicKey } = await makeLocalSigner(dir)
      const pub = new Uint8Array(32)
      for (let i = 0; i < 32; i += 1) pub[i] = Number.parseInt(publicKey.slice(i * 2, i * 2 + 2), 16)

      const withKeys = await verifyDist({ distDir: dir, publicKeys: [pub] })
      expect(withKeys.signature).toBe('unsigned')
      expect(withKeys.ok).toBe(false)

      const withoutKeys = await verifyDist({ distDir: dir })
      expect(withoutKeys.signature).toBe('skipped')
      expect(withoutKeys.ok).toBe(true)
    })
  })

  it('rejects entry-chunk sealing', async () => {
    await withTempDir(async (dir) => {
      const { keyFile } = await makeLocalSigner(dir)
      const { generateWrappingKey, hexEncode } = await import('@copylocker/seal')
      const { writeFile } = await import('node:fs/promises')
      await writeFile(`${dir}/wrap.key`, hexEncode(generateWrappingKey()), { mode: 0o600 })
      const config = resolveConfig({
        productId: 'test-app',
        signer: { kind: 'local', keyFile },
        seal: {
          chunks: [{ match: /index-aaa/, feature: 'pro' }],
          registryFile: `${dir}/reg.json`,
          wrappingKeyFile: `${dir}/wrap.key`,
          cwd: dir,
        },
      })
      await expect(
        runPipeline(syntheticInputs(), config, IDENTITY, { warn: () => {} }),
      ).rejects.toThrow(/entry chunk/)
    })
  })
})
