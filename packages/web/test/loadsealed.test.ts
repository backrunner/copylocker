import { describe, expect, it } from 'vitest'
import { IDBFactory } from 'fake-indexeddb'
import { CopyLocker, NotEntitledError, TransportError, UnsealError } from '../src/index.js'
import { sealAsset } from '../src/unseal.js'
import { MockSessionDriver, mockWorkerFetch, TEST_ROOT_PIN } from './helpers/mockSession.js'

function memoryStorage(): Storage {
  const backing = new Map<string, string>()
  return {
    getItem: (k: string) => backing.get(k) ?? null,
    setItem: (k: string, v: string) => void backing.set(k, v),
  } as unknown as Storage
}

interface Fixture {
  driver: MockSessionDriver
  fetchLog: string[]
  factory: IDBFactory
}

const meta = { productId: 'demo', variantId: 0, featureId: 'pro', assetId: 'presets.json' }
const plaintext = new TextEncoder().encode('{"presets":["a","b"]}')

/** fetch stub: the sealed asset at /presets.json.sealed, Worker endpoints canned. */
function fetchWithAsset(log: string[], sealed: Uint8Array | null): typeof fetch {
  const inner = mockWorkerFetch(log)
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/presets.json.sealed')) {
      if (sealed === null) return new Response('not found', { status: 404 })
      return new Response(sealed as unknown as ArrayBuffer, {
        status: 200,
        headers: { 'Content-Type': 'application/octet-stream' },
      })
    }
    return inner(input, init)
  }) as typeof fetch
}

async function makeClient(fixture: Fixture, sealed: Uint8Array | null, extra?: object) {
  return CopyLocker.create({
    serverUrl: 'https://license.example.test',
    productId: 'demo',
    rootPins: [TEST_ROOT_PIN],
    sessionDriver: fixture.driver,
    fetchFn: fetchWithAsset(fixture.fetchLog, sealed),
    indexedDB: fixture.factory,
    localStorage: memoryStorage(),
    schedulerIntervalMs: 3_600_000,
    ...extra,
  })
}

function fixture(entitled: string[]): Fixture {
  return { driver: new MockSessionDriver({ entitled }), fetchLog: [], factory: new IDBFactory() }
}

describe('CopyLocker.loadSealed (@copylocker/seal KEK path)', () => {
  it('fetches and opens an asset sealed under the feature KEK', async () => {
    const fx = fixture(['pro'])
    const cl = await makeClient(fx, await sealAsset(fx.driver.kek, meta, plaintext))
    await cl.activate('CL-TEST-KEY')

    const opened = await cl.loadSealed('/presets.json.sealed', 'pro')
    expect(opened).toEqual(plaintext)
    // The KEK came from the unseal-asset op, not the derive-m path.
    expect(fx.driver.ops).toContain(13)
    cl.dispose()
  })

  it('rejects with the indistinguishable error for an unentitled feature', async () => {
    const fx = fixture(['pro'])
    const cl = await makeClient(fx, await sealAsset(fx.driver.kek, meta, plaintext))
    await cl.activate('CL-TEST-KEY')
    await expect(cl.loadSealed('/presets.json.sealed', 'nope')).rejects.toThrow(NotEntitledError)
    cl.dispose()
  })

  it('rejects with the indistinguishable error when no credential is installed', async () => {
    const fx = fixture(['pro'])
    const cl = await makeClient(fx, await sealAsset(fx.driver.kek, meta, plaintext))
    await expect(cl.loadSealed('/presets.json.sealed', 'pro')).rejects.toThrow(NotEntitledError)
    cl.dispose()
  })

  it('rejects UnsealError when the container was sealed under a different KEK', async () => {
    const fx = fixture(['pro'])
    const wrongKek = new Uint8Array(32).fill(0x42)
    const cl = await makeClient(fx, await sealAsset(wrongKek, meta, plaintext))
    await cl.activate('CL-TEST-KEY')
    await expect(cl.loadSealed('/presets.json.sealed', 'pro')).rejects.toThrow(UnsealError)
    cl.dispose()
  })

  it('surfaces a fetch failure as TransportError', async () => {
    const fx = fixture(['pro'])
    const cl = await makeClient(fx, null)
    await cl.activate('CL-TEST-KEY')
    await expect(cl.loadSealed('/presets.json.sealed', 'pro')).rejects.toThrow(TransportError)
    cl.dispose()
  })

  it('fails closed when requireIntegrityProof is set and no guard produced R', async () => {
    const fx = fixture(['pro'])
    const cl = await makeClient(fx, await sealAsset(fx.driver.kek, meta, plaintext), {
      requireIntegrityProof: true,
    })
    await cl.activate('CL-TEST-KEY')
    await expect(cl.loadSealed('/presets.json.sealed', 'pro')).rejects.toMatchObject({
      name: 'NotEntitledError',
      code: 17,
    })
    // The asset is never fetched and the op never runs without the integrity proof.
    expect(fx.fetchLog.some((entry) => entry.includes('/presets.json.sealed'))).toBe(false)
    expect(fx.driver.ops).not.toContain(13)
    cl.dispose()
  })
})
