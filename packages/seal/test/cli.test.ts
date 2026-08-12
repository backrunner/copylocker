import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { deriveFinalKey as webDeriveFinalKey } from '../../web/src/derive.js'
import { openSealedAsset as webOpen } from '../../web/src/unseal.js'
import { main } from '../src/cli.js'
import { getKek, hexEncode, loadRegistry, resolveWrappingKey } from '../src/keystore.js'

let dir: string
let previousCwd: string

interface Captured {
  code: number
  stdout: string
  stderr: string
}

async function run(argv: string[]): Promise<Captured> {
  let stdout = ''
  let stderr = ''
  const outWrite = process.stdout.write.bind(process.stdout)
  const errWrite = process.stderr.write.bind(process.stderr)
  process.stdout.write = ((chunk: unknown) => {
    stdout += String(chunk)
    return true
  }) as typeof process.stdout.write
  process.stderr.write = ((chunk: unknown) => {
    stderr += String(chunk)
    return true
  }) as typeof process.stderr.write
  try {
    const code = await main(argv)
    return { code, stdout, stderr }
  } finally {
    process.stdout.write = outWrite
    process.stderr.write = errWrite
  }
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'copylocker-seal-cli-'))
  previousCwd = process.cwd()
  process.chdir(dir)
})

afterEach(async () => {
  process.chdir(previousCwd)
  await rm(dir, { recursive: true, force: true })
})

describe('cli: init', () => {
  it('creates the wrapping key (0600) and gitignores key material', async () => {
    const result = await run(['init'])
    expect(result.code).toBe(0)
    const keyInfo = await stat('.copylocker/wrapping-key')
    expect(keyInfo.mode & 0o777).toBe(0o600)
    const gitignore = await readFile('.gitignore', 'utf8')
    expect(gitignore).toContain('.copylocker/seal-registry.json')
    expect(gitignore).toContain('.copylocker/wrapping-key')
    // Idempotent: second run keeps the same key.
    const keyHex = await readFile('.copylocker/wrapping-key', 'utf8')
    const again = await run(['init'])
    expect(again.code).toBe(0)
    expect(again.stdout).toContain('already exists')
    expect(await readFile('.copylocker/wrapping-key', 'utf8')).toBe(keyHex)
  })

  it('init --dir gitignores the ACTUAL directory, not the default', async () => {
    const result = await run(['init', '--dir', 'secrets'])
    expect(result.code).toBe(0)
    await stat('secrets/wrapping-key')
    const gitignore = await readFile('.gitignore', 'utf8')
    expect(gitignore).toContain('secrets/seal-registry.json')
    expect(gitignore).toContain('secrets/wrapping-key')
  })
})

describe('cli: seal + registry', () => {
  beforeEach(async () => {
    await run(['init'])
    await writeFile('presets.json', '{"a":1}')
  })

  it('seal without --out is a dry-run and writes no .sealed files', async () => {
    const result = await run(['seal', 'presets.json', '--feature', 'pro', '--product-id', 'demo'])
    expect(result.code).toBe(0)
    expect(result.stdout).toContain('dry-run')
    expect(result.stdout).toContain('presets.json')
    await expect(stat('presets.json.sealed')).rejects.toThrow()
    // The KEK is still registered (encrypted registry) so runs are stable.
    expect(result.stdout).toContain('registry updated')
  })

  it('seal --out writes containers; registry list shows only fingerprints', async () => {
    const dry = await run(['seal', 'presets.json', '--feature', 'pro', '--product-id', 'demo'])
    expect(dry.code).toBe(0)
    const sealed = await run([
      'seal',
      'presets.json',
      '--feature',
      'pro',
      '--product-id',
      'demo',
      '--out',
      'sealed',
    ])
    expect(sealed.code).toBe(0)
    await stat(join('sealed', 'presets.json.sealed'))

    const list = await run(['registry', 'list'])
    expect(list.code).toBe(0)
    expect(list.stdout).toContain('pro')
    expect(list.stdout).toMatch(/kek-sha256:[0-9a-f]{16}/)

    // Key bytes never appear in any CLI output.
    const wrappingKey = await resolveWrappingKey({ keyFile: '.copylocker/wrapping-key' })
    const registry = await loadRegistry({ path: '.copylocker/seal-registry.json', wrappingKey })
    const kekHex = hexEncode(getKek(registry, 'pro') as Uint8Array)
    for (const output of [dry, sealed, list]) {
      expect(output.stdout).not.toContain(kekHex)
      expect(output.stderr).not.toContain(kekHex)
    }
  })

  it('requires --product-id', async () => {
    const result = await run(['seal', 'presets.json', '--feature', 'pro'])
    expect(result.code).toBe(2)
    expect(result.stderr).toContain('--product-id')
  })

  it('supports the --flag=value form (no silent dry-run)', async () => {
    const result = await run([
      'seal',
      'presets.json',
      '--feature=pro',
      '--product-id=demo',
      '--out=sealed',
    ])
    expect(result.code).toBe(0)
    await stat(join('sealed', 'presets.json.sealed'))
  })

  it('re-sealing with --out inside the glob scope does not seal its own output', async () => {
    const first = await run([
      'seal',
      '**',
      '--feature',
      'pro',
      '--product-id',
      'demo',
      '--out',
      'sealed',
    ])
    expect(first.code).toBe(0)
    const second = await run([
      'seal',
      '**',
      '--feature',
      'pro',
      '--product-id',
      'demo',
      '--out',
      'sealed',
    ])
    expect(second.code).toBe(0)
    expect(second.stdout).not.toContain('.sealed.sealed')
  })

  it('rejects a variant-id that is not a non-negative integer', async () => {
    const result = await run([
      'seal',
      'presets.json',
      '--feature',
      'pro',
      '--product-id',
      'demo',
      '--variant-id',
      'abc',
    ])
    expect(result.code).toBe(2)
    expect(result.stderr).toContain('--variant-id')
  })
})

describe('cli: derive-final-key + wrap-kek development bridge', () => {
  const m = hexEncode(new Uint8Array(32).fill(1))
  const kBuild = hexEncode(new Uint8Array(32).fill(2))
  const manifestRoot = hexEncode(new Uint8Array(32).fill(3))
  const wasmDigest = hexEncode(new Uint8Array(32).fill(4))

  it('derive-final-key matches @copylocker/web byte for byte', async () => {
    const result = await run([
      'derive-final-key',
      '--m',
      m,
      '--k-build',
      kBuild,
      '--manifest-root',
      manifestRoot,
      '--wasm-digest',
      wasmDigest,
    ])
    expect(result.code).toBe(0)
    const expected = await webDeriveFinalKey(new Uint8Array(32).fill(1), {
      kBuild: new Uint8Array(32).fill(2),
      manifestRoot: new Uint8Array(32).fill(3),
    }, new Uint8Array(32).fill(4))
    expect(result.stdout.trim()).toBe(hexEncode(expected))
  })

  it('wrap-kek is dry-run by default and bridges the full unseal chain', async () => {
    await run(['init'])
    const original = Buffer.alloc(100, 9)
    await writeFile('model.bin', original)
    await run([
      'seal',
      'model.bin',
      '--feature',
      'pro',
      '--product-id',
      'demo',
      '--out',
      'sealed',
    ])

    const finalKey = await webDeriveFinalKey(new Uint8Array(32).fill(1), {
      kBuild: new Uint8Array(32).fill(2),
      manifestRoot: new Uint8Array(32).fill(3),
    }, new Uint8Array(32).fill(4))
    const finalKeyHex = hexEncode(finalKey)

    const dry = await run([
      'wrap-kek',
      '--feature',
      'pro',
      '--product-id',
      'demo',
      '--final-key',
      finalKeyHex,
    ])
    expect(dry.code).toBe(0)
    expect(dry.stdout).toContain('dry-run')
    await expect(stat('wrapped-kek.bin')).rejects.toThrow()

    const written = await run([
      'wrap-kek',
      '--feature',
      'pro',
      '--product-id',
      'demo',
      '--final-key',
      finalKeyHex,
      '--out',
      'wrapped-kek.bin',
    ])
    expect(written.code).toBe(0)
    expect((await stat('wrapped-kek.bin')).mode & 0o777).toBe(0o600)

    // The M4-A bridge loop, exactly as a page would run it:
    // cl.unseal(feature, wrappedKek) → KEK → openSealedAsset(KEK, asset).
    const wrapped = new Uint8Array(await readFile('wrapped-kek.bin'))
    const kek = await webOpen(finalKey, wrapped, { productId: 'demo', featureId: 'pro' })
    expect(kek.byteLength).toBe(32)
    const sealedAsset = new Uint8Array(await readFile(join('sealed', 'model.bin.sealed')))
    const opened = await webOpen(kek, sealedAsset, { productId: 'demo', featureId: 'pro' })
    expect(opened).toEqual(new Uint8Array(original))

    // The final key never appears in CLI output beyond what the caller passed in.
    const wrappingKeyHex = await readFile('.copylocker/wrapping-key', 'utf8')
    expect(dry.stdout).not.toContain(wrappingKeyHex.trim())
  })

  it('wrap-kek fails for an unregistered feature without leaking why in key material', async () => {
    await run(['init'])
    const result = await run([
      'wrap-kek',
      '--feature',
      'ghost',
      '--product-id',
      'demo',
      '--final-key',
      hexEncode(new Uint8Array(32)),
    ])
    expect(result.code).toBe(2)
    expect(result.stderr).toContain('no KEK registered')
  })
})
