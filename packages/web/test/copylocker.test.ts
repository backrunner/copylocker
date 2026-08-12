import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'
import { IDBFactory } from 'fake-indexeddb'
import { CopyLocker, NotEntitledError, UnsealError } from '../src/index.js'
import { deriveFinalKey, resolveBuildConstants } from '../src/derive.js'
import { sealAsset } from '../src/unseal.js'
import { MockSessionDriver, mockWorkerFetch, TEST_ROOT_PIN } from './helpers/mockSession.js'

const srcDir = dirname(dirname(fileURLToPath(import.meta.url)))

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

function makeOptions(fixture: Fixture) {
  return {
    serverUrl: 'https://license.example.test',
    productId: 'demo',
    rootPins: [TEST_ROOT_PIN],
    sessionDriver: fixture.driver,
    fetchFn: mockWorkerFetch(fixture.fetchLog) as typeof fetch,
    indexedDB: fixture.factory,
    localStorage: memoryStorage(),
    schedulerIntervalMs: 3_600_000,
  }
}

async function finalKeyFor(driver: MockSessionDriver, wasmDigest = new Uint8Array(32)) {
  return deriveFinalKey(driver.m, resolveBuildConstants(), wasmDigest)
}

const meta = { productId: 'demo', variantId: 0, featureId: 'pro', assetId: 'chunk.bin' }
const plaintext = new Uint8Array([10, 20, 30])

describe('CopyLocker (mock session)', () => {
  it('activates and unseals an entitled feature', async () => {
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    const cl = await CopyLocker.create(makeOptions(fixture))
    expect(cl.state).toBe('unlicensed')

    await cl.activate('CL-TEST-KEY')
    expect(cl.state).toBe('active')
    expect(fixture.fetchLog).toEqual([
      'GET https://license.example.test/v1/keys',
      'POST https://license.example.test/v1/activate',
    ])

    const sealed = await sealAsset(await finalKeyFor(fixture.driver), meta, plaintext)
    const opened = await cl.unseal('pro', sealed)
    expect(opened).toEqual(plaintext)
    cl.dispose()
  })

  it('rejects unseal for an unentitled feature with the indistinguishable error', async () => {
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    const cl = await CopyLocker.create(makeOptions(fixture))
    await cl.activate('CL-TEST-KEY')
    const sealed = await sealAsset(await finalKeyFor(fixture.driver), meta, plaintext)
    await expect(cl.unseal('nope', sealed)).rejects.toThrow(NotEntitledError)
    cl.dispose()
  })

  it('rejects unseal when a build constant is swapped (FR-WEB-003/005)', async () => {
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    const cl = await CopyLocker.create({
      ...makeOptions(fixture),
      buildConstants: { kBuild: new Uint8Array(32).fill(0xaa) },
    })
    await cl.activate('CL-TEST-KEY')
    // Sealed with the all-zeros constant; the client derives with 0xaa…
    const sealed = await sealAsset(await finalKeyFor(fixture.driver), meta, plaintext)
    await expect(cl.unseal('pro', sealed)).rejects.toThrow(UnsealError)
    cl.dispose()
  })

  it('falls back to the offline session root when no online root is armed', async () => {
    const fixture: Fixture = {
      driver: new MockSessionDriver({ entitled: ['pro'], onlineRoot: false }),
      fetchLog: [],
      factory: new IDBFactory(),
    }
    const cl = await CopyLocker.create(makeOptions(fixture))
    await cl.activate('CL-TEST-KEY')
    const sealed = await sealAsset(await finalKeyFor(fixture.driver), meta, plaintext)
    expect(await cl.unseal('pro', sealed)).toEqual(plaintext)
    cl.dispose()
  })

  it('triggers a background validation from unseal when the check is due', async () => {
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    const cl = await CopyLocker.create(makeOptions(fixture))
    await cl.activate('CL-TEST-KEY')
    // Force the next check into the past.
    fixture.driver.refreshAfter = 1
    ;(cl as unknown as { nextCheckAt: number }).nextCheckAt = 1
    const sealed = await sealAsset(await finalKeyFor(fixture.driver), meta, plaintext)
    await cl.unseal('pro', sealed)
    await vi.waitFor(() => {
      expect(fixture.fetchLog).toContain('POST https://license.example.test/v1/validate')
    })
    cl.dispose()
  })

  it('restores an activated session from IndexedDB without network calls', async () => {
    const factory = new IDBFactory()
    const first: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory }
    const cl1 = await CopyLocker.create(makeOptions(first))
    await cl1.activate('CL-TEST-KEY')
    cl1.dispose()
    await new Promise((resolve) => setTimeout(resolve, 20)) // let persistSnapshot land

    const second: Fixture = { driver: new MockSessionDriver({ entitled: [] }), fetchLog: [], factory }
    const cl2 = await CopyLocker.create(makeOptions(second))
    expect(cl2.state).toBe('active')
    expect(second.fetchLog).toEqual([])
    cl2.dispose()
  })

  it('requires re-activation after the IndexedDB store is wiped', async () => {
    const first: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    const cl1 = await CopyLocker.create(makeOptions(first))
    await cl1.activate('CL-TEST-KEY')
    cl1.dispose()
    await new Promise((resolve) => setTimeout(resolve, 20))

    const second: Fixture = { driver: new MockSessionDriver({ entitled: [] }), fetchLog: [], factory: new IDBFactory() }
    const cl2 = await CopyLocker.create(makeOptions(second))
    expect(cl2.state).toBe('unlicensed')
    cl2.dispose()
  })

  it('deactivates: server first, then local wipe', async () => {
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    const cl = await CopyLocker.create(makeOptions(fixture))
    await cl.activate('CL-TEST-KEY')
    await cl.deactivate()
    expect(cl.state).toBe('unlicensed')
    expect(fixture.fetchLog.at(-1)).toBe('POST https://license.example.test/v1/deactivate')
    expect(fixture.driver.activated).toBe(false)
    cl.dispose()
  })

  it('notifies state listeners', async () => {
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    const states: string[] = []
    const cl = await CopyLocker.create({ ...makeOptions(fixture), onStateChange: (s) => states.push(s) })
    await cl.activate('CL-TEST-KEY')
    expect(states).toEqual(['active'])
    cl.dispose()
  })

  it('unseal accepts DataView and non-byte typed-array BufferSources', async () => {
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    const cl = await CopyLocker.create(makeOptions(fixture))
    await cl.activate('CL-TEST-KEY')
    const sealed = await sealAsset(await finalKeyFor(fixture.driver), meta, plaintext)
    const buffer = sealed.slice().buffer as ArrayBuffer
    expect(await cl.unseal('pro', new DataView(buffer))).toEqual(plaintext)
    expect(await cl.unseal('pro', new Int8Array(buffer))).toEqual(plaintext)
    // A view window must be respected, not the whole backing buffer.
    const padded = new Uint8Array(sealed.byteLength + 4)
    padded.set(sealed, 2)
    const window2 = new Uint8Array(padded.buffer, 2, sealed.byteLength)
    expect(await cl.unseal('pro', window2)).toEqual(plaintext)
    cl.dispose()
  })

  it('a fatal background validation error is swallowed (no unhandled rejection)', async () => {
    const fixture: Fixture = {
      driver: new MockSessionDriver({ entitled: ['pro'], fatalValidateCode: 100 }),
      fetchLog: [],
      factory: new IDBFactory(),
    }
    const cl = await CopyLocker.create(makeOptions(fixture))
    await cl.activate('CL-TEST-KEY')
    ;(cl as unknown as { nextCheckAt: number }).nextCheckAt = 1 // force a due revalidation
    const sealed = await sealAsset(await finalKeyFor(fixture.driver), meta, plaintext)
    await cl.unseal('pro', sealed) // fires the fatal background validation
    // vitest fails the run on any unhandled rejection — reaching this point
    // after the background settle is the assertion.
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(fixture.fetchLog).toContain('POST https://license.example.test/v1/validate')
    cl.dispose()
  })

  it('fails closed (fresh device) when the stored snapshot cannot be decrypted', async () => {
    const factory = new IDBFactory()
    // Pre-seed IDB with an undecryptable snapshot — as left behind by a
    // memory-only wrap key that did not survive the reload.
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = factory.open('copylocker-web', 1)
      request.onupgradeneeded = () => request.result.createObjectStore('kv')
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('kv', 'readwrite')
      tx.objectStore('kv').put(new Uint8Array(64).fill(9), 'snapshot-v1')
      tx.oncomplete = () => resolve()
      tx.onerror = () => reject(tx.error)
    })
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: [] }), fetchLog: [], factory }
    const cl = await CopyLocker.create(makeOptions(fixture)) // must not reject
    expect(cl.state).toBe('unlicensed')
    cl.dispose()
  })

  it('has no gating API surface (API red line)', () => {
    const proto = CopyLocker.prototype as unknown as Record<string, unknown>
    expect(proto['isLicensed']).toBeUndefined()
    expect(proto['check']).toBeUndefined()
  })

  it('marks `state` as advisory-only in the shipped TSDoc', () => {
    const source = readFileSync(join(srcDir, 'src', 'index.ts'), 'utf8')
    expect(source).toContain('@deprecated for gating — advisory only')
  })
})

describe('CopyLocker (WASM_DIGEST comparison, 40-web-sdk-wasm-ts.md §5)', () => {
  const globals = globalThis as Record<string, unknown>

  it('fails closed at create() when the loaded wasm digest mismatches the injected constant', async () => {
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    // The mock session digests to all zeros; the build-time constant says otherwise.
    globals.__CL_WASM_DIGEST__ = 'ab'.repeat(32)
    try {
      await expect(CopyLocker.create(makeOptions(fixture))).rejects.toMatchObject({
        name: 'NotEntitledError',
        code: 17, // indistinguishable derivation error (NFR-SEC-011)
      })
    } finally {
      delete globals.__CL_WASM_DIGEST__
    }
  })

  it('creates normally when the loaded wasm digest matches the injected constant', async () => {
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    globals.__CL_WASM_DIGEST__ = '00'.repeat(32) // the mock session's all-zeros digest
    try {
      const cl = await CopyLocker.create(makeOptions(fixture))
      cl.dispose()
    } finally {
      delete globals.__CL_WASM_DIGEST__
    }
  })

  it('compares against the sessionDriver wasmDigest option when provided', async () => {
    const fixture: Fixture = { driver: new MockSessionDriver({ entitled: ['pro'] }), fetchLog: [], factory: new IDBFactory() }
    globals.__CL_WASM_DIGEST__ = '07'.repeat(32)
    try {
      const cl = await CopyLocker.create({
        ...makeOptions(fixture),
        wasmDigest: new Uint8Array(32).fill(7),
      })
      cl.dispose()
      await expect(CopyLocker.create(makeOptions(fixture))).rejects.toMatchObject({ code: 17 })
    } finally {
      delete globals.__CL_WASM_DIGEST__
    }
  })
})
