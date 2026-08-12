import { mkdtemp, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  emptyRegistry,
  generateWrappingKey,
  getKek,
  getOrCreateKek,
  hexDecode,
  hexEncode,
  kekFingerprint,
  loadRegistry,
  resolveWrappingKey,
  saveRegistry,
} from '../src/keystore.js'

let dir: string

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'copylocker-seal-keystore-'))
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

describe('keystore: encrypted KEK registry', () => {
  it('round-trips an encrypted registry', async () => {
    const wrappingKey = generateWrappingKey()
    const path = join(dir, 'registry.json')
    const registry = emptyRegistry()
    const { kek, created } = getOrCreateKek(registry, 'pro')
    expect(created).toBe(true)
    expect(kek.byteLength).toBe(32)
    await saveRegistry({ path, wrappingKey, registry })

    const loaded = await loadRegistry({ path, wrappingKey })
    expect(Object.keys(loaded.features)).toEqual(['pro'])
    expect(getKek(loaded, 'pro')).toEqual(kek)

    // Same feature never rotates its KEK.
    const again = getOrCreateKek(loaded, 'pro')
    expect(again.created).toBe(false)
    expect(again.kek).toEqual(kek)
  })

  it('never stores plaintext KEKs on disk', async () => {
    const wrappingKey = generateWrappingKey()
    const path = join(dir, 'registry.json')
    const registry = emptyRegistry()
    const { kek } = getOrCreateKek(registry, 'pro')
    await saveRegistry({ path, wrappingKey, registry })

    const { readFile } = await import('node:fs/promises')
    const raw = await readFile(path, 'utf8')
    expect(raw).not.toContain(hexEncode(kek))
    const envelope = JSON.parse(raw) as Record<string, unknown>
    expect(envelope.v).toBe(1)
    expect(envelope.alg).toBe('AES-256-GCM')
    expect(typeof envelope.nonce).toBe('string')
    expect(typeof envelope.ct).toBe('string')
  })

  it('writes the registry with mode 0600', async () => {
    const wrappingKey = generateWrappingKey()
    const path = join(dir, 'registry.json')
    await saveRegistry({ path, wrappingKey, registry: emptyRegistry() })
    const info = await stat(path)
    expect(info.mode & 0o777).toBe(0o600)
  })

  it('rejects the wrong wrapping key (NOT_ENTITLED, not a parse error)', async () => {
    const path = join(dir, 'registry.json')
    const registry = emptyRegistry()
    getOrCreateKek(registry, 'pro')
    await saveRegistry({ path, wrappingKey: generateWrappingKey(), registry })
    await expect(
      loadRegistry({ path, wrappingKey: generateWrappingKey() }),
    ).rejects.toMatchObject({ code: 'NOT_ENTITLED' })
  })

  it('rejects a tampered registry', async () => {
    const wrappingKey = generateWrappingKey()
    const path = join(dir, 'registry.json')
    const registry = emptyRegistry()
    getOrCreateKek(registry, 'pro')
    await saveRegistry({ path, wrappingKey, registry })
    const { readFile, writeFile } = await import('node:fs/promises')
    const raw = await readFile(path, 'utf8')
    const envelope = JSON.parse(raw) as { ct: string }
    envelope.ct = envelope.ct.slice(0, -4) + 'AAAA'
    await writeFile(path, JSON.stringify(envelope))
    await expect(loadRegistry({ path, wrappingKey })).rejects.toMatchObject({
      code: 'NOT_ENTITLED',
    })
  })

  it('a missing registry file loads as empty', async () => {
    const loaded = await loadRegistry({
      path: join(dir, 'absent.json'),
      wrappingKey: generateWrappingKey(),
    })
    expect(loaded.features).toEqual({})
  })

  it('resolves the wrapping key from env, file, or explicit bytes', async () => {
    const explicit = generateWrappingKey()
    await expect(resolveWrappingKey({ key: explicit })).resolves.toEqual(explicit)

    const fromEnv = generateWrappingKey()
    await expect(
      resolveWrappingKey({ env: { COPYLOCKER_SEAL_WRAPPING_KEY: hexEncode(fromEnv) } }),
    ).resolves.toEqual(fromEnv)

    const { writeFile } = await import('node:fs/promises')
    const keyFile = join(dir, 'wrapping-key')
    const fromFile = generateWrappingKey()
    await writeFile(keyFile, hexEncode(fromFile))
    await expect(resolveWrappingKey({ keyFile, env: {} })).resolves.toEqual(fromFile)

    await expect(resolveWrappingKey({ env: {} })).rejects.toMatchObject({ code: 'CONFIG' })
    await expect(
      resolveWrappingKey({ env: { COPYLOCKER_SEAL_WRAPPING_KEY: 'zz' } }),
    ).rejects.toMatchObject({ code: 'CONFIG' })
  })

  it('fingerprint is stable, short, and never equal to key material', async () => {
    const kek = hexDecode('ab'.repeat(32), 'test kek')
    const fp = await kekFingerprint(kek)
    expect(fp).toMatch(/^[0-9a-f]{16}$/)
    expect(hexEncode(kek)).not.toContain(fp)
    expect(await kekFingerprint(kek)).toBe(fp)
  })
})
