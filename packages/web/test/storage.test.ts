import { describe, expect, it } from 'vitest'
import { IDBFactory } from 'fake-indexeddb'
import { createSnapshotStore, getPersistentDeviceId } from '../src/storage.js'

const freshIndexedDB = (): IDBFactory => new IDBFactory()

describe('storage', () => {
  it('encrypts and round-trips the snapshot blob through IndexedDB', async () => {
    const factory = freshIndexedDB()
    const store = createSnapshotStore({ indexedDB: factory })
    expect(store.degraded).toBe(false)
    const blob = new Uint8Array([1, 2, 3, 250])
    await store.save(blob)
    expect(await store.load()).toEqual(blob)

    // The ciphertext at rest must not contain the plaintext.
    const raw = await new Promise<unknown>((resolve, reject) => {
      const request = factory.open('copylocker-web', 1)
      request.onsuccess = () => {
        const tx = request.result.transaction('kv').objectStore('kv').get('snapshot-v1')
        tx.onsuccess = () => resolve(tx.result)
        tx.onerror = () => reject(tx.error)
      }
    })
    expect(raw).toBeInstanceOf(Uint8Array)
    expect([...(raw as Uint8Array)]).not.toEqual([...blob])
  })

  it('persists across store instances (wrap key survives in IndexedDB)', async () => {
    const factory = freshIndexedDB()
    const first = createSnapshotStore({ indexedDB: factory })
    await first.save(new Uint8Array([9, 9, 9]))
    const second = createSnapshotStore({ indexedDB: factory })
    expect(await second.load()).toEqual(new Uint8Array([9, 9, 9]))
  })

  it('returns null after clear() — a wiped store forces re-activation', async () => {
    const factory = freshIndexedDB()
    const store = createSnapshotStore({ indexedDB: factory })
    await store.save(new Uint8Array([1]))
    await store.clear()
    expect(await store.load()).toBeNull()
  })

  it('a fresh IndexedDB (cleared browser data) has no snapshot', async () => {
    const factory = freshIndexedDB()
    await createSnapshotStore({ indexedDB: factory }).save(new Uint8Array([1]))
    const wiped = createSnapshotStore({ indexedDB: freshIndexedDB() })
    expect(await wiped.load()).toBeNull()
  })

  it('degrades to memory when IndexedDB is unavailable', async () => {
    const store = createSnapshotStore({ indexedDB: undefined })
    // Node has no global indexedDB, so this exercises the degradation path.
    expect(store.degraded).toBe(true)
    await store.save(new Uint8Array([5]))
    expect(await store.load()).toEqual(new Uint8Array([5]))
    // A new memory store starts empty: every cold start re-activates.
    expect(await createSnapshotStore({ storage: 'memory' }).load()).toBeNull()
  })

  it('keeps only the non-sensitive device id in the storage backend', () => {
    const backing = new Map<string, string>()
    const storage = {
      getItem: (k: string) => backing.get(k) ?? null,
      setItem: (k: string, v: string) => void backing.set(k, v),
    } as unknown as Storage
    const a = getPersistentDeviceId(storage)
    expect(a).toMatch(/^[0-9a-f]{32}$/)
    expect(getPersistentDeviceId(storage)).toBe(a)
    expect(backing.size).toBe(1)
  })
})
