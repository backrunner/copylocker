import { describe, expect, it } from 'vitest'
import { readFile, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { decodeManifest, verifyManifestSignature } from '@copylocker/guard'
import { encodeContainer, encodeTbs } from '../src/manifest.js'
import { generateLocalKeyFile, resolveSigner, SignerError } from '../src/signer.js'
import { withTempDir } from './helpers.js'
import type { ManifestInput } from '../src/manifest.js'

function tbsBytes(): Uint8Array {
  const input: ManifestInput = {
    suiteId: new Uint8Array([1, 0, 0, 1]),
    productId: 'test-app',
    buildFingerprint: 'clb-test',
    builtAt: 1_754_600_000,
    hashAlg: 'sha256',
    entries: new Map([['a.js', { digest: new Uint8Array(32).fill(1), excludedRanges: [] }]]),
    guarded: new Map(),
    sealed: [],
    root: new Uint8Array(32).fill(9),
  }
  return encodeTbs(input)
}

describe('signer: local', () => {
  it('keygen writes a 0600 JWK and the signature verifies via the guard runtime', async () => {
    await withTempDir(async (dir) => {
      const keyFile = join(dir, 'key.json')
      const publicHex = await generateLocalKeyFile(keyFile)
      expect(publicHex).toMatch(/^[0-9a-f]{64}$/)
      expect((await stat(keyFile)).mode & 0o777).toBe(0o600)
      const jwk = JSON.parse(await readFile(keyFile, 'utf8')) as { kty: string; crv: string }
      expect(jwk.kty).toBe('OKP')
      expect(jwk.crv).toBe('Ed25519')

      const pins: Uint8Array[] = []
      const signer = await resolveSigner({ kind: 'local', keyFile }, pins, { env: {} })
      expect(signer).toBeDefined()
      expect(pins).toHaveLength(1)
      const tbs = tbsBytes()
      const signature = await (signer as NonNullable<typeof signer>).sign(tbs)
      expect(signature).toHaveLength(64)
      const container = encodeContainer(tbs, signature)
      const status = await verifyManifestSignature(decodeManifest(container), pins)
      expect(status).toBe('verified')
    })
  })

  it('is an error under NODE_ENV=production without the override', async () => {
    await withTempDir(async (dir) => {
      const keyFile = join(dir, 'key.json')
      await generateLocalKeyFile(keyFile)
      await expect(
        resolveSigner({ kind: 'local', keyFile }, [], { env: { NODE_ENV: 'production' } }),
      ).rejects.toThrow(SignerError)
    })
  })

  it('warns but proceeds under production with allowLocalInProduction', async () => {
    await withTempDir(async (dir) => {
      const keyFile = join(dir, 'key.json')
      await generateLocalKeyFile(keyFile)
      const warnings: string[] = []
      const signer = await resolveSigner(
        { kind: 'local', keyFile, allowLocalInProduction: true },
        [],
        { env: { NODE_ENV: 'production' }, warn: (m) => warnings.push(m) },
      )
      expect(signer).toBeDefined()
      expect(warnings.some((w) => w.includes('allowLocalInProduction'))).toBe(true)
    })
  })
})

describe('signer: remote', () => {
  const tbs = tbsBytes()

  it('POSTs the tbs with a bearer token and returns the 64-byte signature', async () => {
    const calls: { url: string; auth: string; body: Uint8Array }[] = []
    const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
      calls.push({
        url: String(url),
        auth: String((init?.headers as Record<string, string>).authorization),
        body: new Uint8Array(init?.body as Uint8Array),
      })
      return new Response(new Uint8Array(64).fill(5), { status: 200 })
    }) as typeof fetch
    const signer = await resolveSigner(
      { kind: 'remote', endpoint: 'https://sign.example.com/tbs', token: 'tok' },
      [],
      { fetchImpl },
    )
    const signature = await (signer as NonNullable<typeof signer>).sign(tbs)
    expect(signature).toEqual(new Uint8Array(64).fill(5))
    expect(calls[0]?.auth).toBe('Bearer tok')
    expect(calls[0]?.body).toEqual(tbs)
  })

  it('classifies HTTP errors', async () => {
    const fetchImpl = (async () => new Response('nope', { status: 503 })) as typeof fetch
    const signer = await resolveSigner(
      { kind: 'remote', endpoint: 'https://sign.example.com', token: 't' },
      [],
      { fetchImpl },
    )
    const error = await (signer as NonNullable<typeof signer>).sign(tbs).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(SignerError)
    expect((error as SignerError).code).toBe('http')
  })

  it('classifies timeouts', async () => {
    const fetchImpl = ((_url: string | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () =>
          reject(new DOMException('aborted', 'TimeoutError')),
        )
      })) as typeof fetch
    const signer = await resolveSigner(
      { kind: 'remote', endpoint: 'https://sign.example.com', token: 't', timeoutMs: 10 },
      [],
      { fetchImpl },
    )
    const error = await (signer as NonNullable<typeof signer>).sign(tbs).catch((e: unknown) => e)
    expect((error as SignerError).code).toBe('timeout')
  })

  it('rejects malformed signature responses', async () => {
    const fetchImpl = (async () => new Response(new Uint8Array(10), { status: 200 })) as typeof fetch
    const signer = await resolveSigner(
      { kind: 'remote', endpoint: 'https://sign.example.com', token: 't' },
      [],
      { fetchImpl },
    )
    const error = await (signer as NonNullable<typeof signer>).sign(tbs).catch((e: unknown) => e)
    expect((error as SignerError).code).toBe('bad-response')
  })
})

describe('signer: custom and unsigned', () => {
  it('custom function receives the raw tbs and must return 64 bytes', async () => {
    let seen: Uint8Array | undefined
    const signer = await resolveSigner(
      async (tbs: Uint8Array) => {
        seen = tbs
        return new Uint8Array(64).fill(3)
      },
      [],
      { env: {} },
    )
    const tbs = tbsBytes()
    await (signer as NonNullable<typeof signer>).sign(tbs)
    expect(seen).toEqual(tbs)
    const bad = await resolveSigner(async () => new Uint8Array(8), [], { env: {} })
    await expect((bad as NonNullable<typeof bad>).sign(tbs)).rejects.toThrow(SignerError)
  })

  it('no signer → unsigned development build (warned)', async () => {
    const warnings: string[] = []
    const signer = await resolveSigner(undefined, [], { env: {}, warn: (m) => warnings.push(m) })
    expect(signer).toBeUndefined()
    expect(warnings.some((w) => w.includes('UNSIGNED'))).toBe(true)
  })
})
