/**
 * Persistent storage (design §4.4, FR-WEB-007).
 *
 * The opaque session snapshot — which contains the credential envelope and
 * the device KEM/Signing key material — is encrypted with a **non-extractable
 * AES-GCM CryptoKey** before it touches IndexedDB. The CryptoKey itself is
 * stored in IndexedDB too (structured clone supports CryptoKey), so its raw
 * bytes never exist in page-reachable memory.
 *
 * Honest weakness (design §4.4): the ML-KEM part of the device private key is
 * software-custodied inside the snapshot. WebCrypto cannot hold ML-KEM keys,
 * so a same-origin attacker with full script execution can drive the API.
 * This is inherent to the web platform and declared in the README.
 *
 * `localStorage` is used only for the non-sensitive `device_id` redundancy
 * (see {@link getPersistentDeviceId}). IndexedDB is cleared or unavailable →
 * the store degrades to memory and every cold start requires reactivation.
 */

const DB_NAME = 'copylocker-web'
const DB_VERSION = 1
const STORE = 'kv'
const WRAP_KEY = 'snapshot-wrap-key-v1'
const SNAPSHOT_KEY = 'snapshot-v1'
const NONCE_BYTES = 12

export interface SnapshotStore {
  /** True when persistence is unavailable and everything lives in memory. */
  readonly degraded: boolean
  /** The stored (decrypted) snapshot, or null when none / wiped. */
  load(): Promise<Uint8Array | null>
  /** Encrypt and persist the snapshot. */
  save(blob: Uint8Array): Promise<void>
  /** Wipe the stored snapshot (the wrap key is kept). */
  clear(): Promise<void>
}

function subtleOrThrow(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('CopyLocker: WebCrypto SubtleCrypto is required (secure context)')
  }
  return subtle
}

async function seal(key: CryptoKey, blob: Uint8Array): Promise<Uint8Array> {
  const subtle = subtleOrThrow()
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  const body = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as unknown as ArrayBuffer },
      key,
      blob as unknown as ArrayBuffer,
    ),
  )
  const out = new Uint8Array(NONCE_BYTES + body.byteLength)
  out.set(nonce, 0)
  out.set(body, NONCE_BYTES)
  return out
}

async function open(key: CryptoKey, blob: Uint8Array): Promise<Uint8Array> {
  const subtle = subtleOrThrow()
  const nonce = blob.subarray(0, NONCE_BYTES)
  const body = blob.subarray(NONCE_BYTES)
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv: nonce as unknown as ArrayBuffer },
    key,
    body as unknown as ArrayBuffer,
  )
  return new Uint8Array(plaintext)
}

class MemoryStore implements SnapshotStore {
  readonly degraded = true
  private key: CryptoKey | null = null
  private blob: Uint8Array | null = null

  private async wrapKey(): Promise<CryptoKey> {
    this.key ??= await subtleOrThrow().generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ])
    return this.key
  }

  async load(): Promise<Uint8Array | null> {
    if (!this.blob) return null
    return open(await this.wrapKey(), this.blob)
  }

  async save(blob: Uint8Array): Promise<void> {
    this.blob = await seal(await this.wrapKey(), blob)
  }

  async clear(): Promise<void> {
    this.blob = null
  }
}

function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'))
  })
}

class IndexedDbStore implements SnapshotStore {
  readonly degraded = false
  private db: IDBDatabase | null = null
  /** In-memory key fallback when the CryptoKey cannot be structured-cloned. */
  private memoryKey: CryptoKey | null = null

  constructor(private readonly factory: IDBFactory) {}

  private async database(): Promise<IDBDatabase> {
    if (this.db) return this.db
    this.db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = this.factory.open(DB_NAME, DB_VERSION)
      request.onupgradeneeded = () => {
        request.result.createObjectStore(STORE)
      }
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error('IndexedDB open failed'))
    })
    return this.db
  }

  private async tx(mode: IDBTransactionMode): Promise<IDBObjectStore> {
    const db = await this.database()
    return db.transaction(STORE, mode).objectStore(STORE)
  }

  private async wrapKey(): Promise<CryptoKey> {
    if (this.memoryKey) return this.memoryKey
    const store = await this.tx('readonly')
    const existing = await requestToPromise(store.get(WRAP_KEY))
    if (existing instanceof CryptoKey) {
      this.memoryKey = existing
      return existing
    }
    const key = await subtleOrThrow().generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ])
    this.memoryKey = key
    try {
      const write = await this.tx('readwrite')
      await requestToPromise(write.put(key, WRAP_KEY))
    } catch {
      // The CryptoKey could not be structured-cloned into IndexedDB: keep it
      // in memory for this page session. The snapshot ciphertext is still
      // unreadable after a reload, which fails closed (re-activation).
    }
    return key
  }

  async load(): Promise<Uint8Array | null> {
    const store = await this.tx('readonly')
    const blob = await requestToPromise(store.get(SNAPSHOT_KEY))
    if (!(blob instanceof Uint8Array)) return null
    return open(await this.wrapKey(), blob)
  }

  async save(blob: Uint8Array): Promise<void> {
    const sealed = await seal(await this.wrapKey(), blob)
    const store = await this.tx('readwrite')
    await requestToPromise(store.put(sealed, SNAPSHOT_KEY))
  }

  async clear(): Promise<void> {
    const store = await this.tx('readwrite')
    await requestToPromise(store.delete(SNAPSHOT_KEY))
  }
}

export interface StorageOptions {
  /** 'indexeddb' (default) or 'memory'. */
  storage?: 'indexeddb' | 'memory'
  /** Injectable for tests; defaults to the global `indexedDB`. */
  indexedDB?: IDBFactory
}

/** Create the snapshot store, degrading to memory when IndexedDB is absent. */
export function createSnapshotStore(options: StorageOptions = {}): SnapshotStore {
  const factory = options.indexedDB ?? globalThis.indexedDB
  if (options.storage === 'memory' || !factory) {
    return new MemoryStore()
  }
  return new IndexedDbStore(factory)
}

const DEVICE_ID_KEY = 'copylocker:device-id'

/**
 * The non-sensitive device identifier, redundantly kept in `localStorage` so
 * the fingerprint survives an IndexedDB wipe. Nothing secret ever goes here.
 */
export function getPersistentDeviceId(storage?: Storage): string {
  const backend = storage ?? safeLocalStorage()
  const existing = backend?.getItem(DEVICE_ID_KEY)
  if (existing && /^[0-9a-f]{32}$/.test(existing)) return existing
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16))
  const id = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  try {
    backend?.setItem(DEVICE_ID_KEY, id)
  } catch {
    // Quota or privacy-mode rejection: the id stays session-scoped.
  }
  return id
}

function safeLocalStorage(): Storage | null {
  try {
    return globalThis.localStorage ?? null
  } catch {
    return null
  }
}
