import { describe, expect, it } from 'vitest'
import { IDBFactory } from 'fake-indexeddb'
import { CopyLocker, NotEntitledError } from '../src/index.js'
import { deriveFinalKey, resolveBuildConstants } from '../src/derive.js'
import { SessionOps } from '../src/session.js'
import { sealAsset } from '../src/unseal.js'
import { WorkerSessionClient, type WorkerPortLike } from '../src/worker/client.js'
import { createMessageHandler } from '../src/worker/entry.js'
import {
  OP_INIT,
  OP_STEP,
  STATUS_CORE_ERROR,
  STATUS_HOST_ERROR,
  STATUS_OK,
  decodeCoreError,
  decodeRequest,
  decodeResponse,
  encodeInit,
  encodeRequest,
} from '../src/worker/protocol.js'
import { MockSessionDriver, mockWorkerFetch, TEST_ROOT_PIN } from './helpers/mockSession.js'

/** In-process Worker stand-in: ferries frames to the entry handler. */
class FakeWorkerPort implements WorkerPortLike {
  private readonly listeners = new Map<string, ((event: { data?: unknown }) => void)[]>()
  terminated = false

  constructor(private readonly handler: (frame: Uint8Array) => Promise<Uint8Array>) {}

  postMessage(message: Uint8Array): void {
    // Copy, as a real transfer would detach the sender's buffer.
    const frame = new Uint8Array(message)
    queueMicrotask(async () => {
      const out = await this.handler(frame)
      for (const listener of this.listeners.get('message') ?? []) {
        listener({ data: out })
      }
    })
  }

  addEventListener(type: string, listener: (event: { data?: unknown }) => void): void {
    const list = this.listeners.get(type) ?? []
    list.push(listener)
    this.listeners.set(type, list)
  }

  terminate(): void {
    this.terminated = true
  }
}

function memoryStorage(): Storage {
  const backing = new Map<string, string>()
  return {
    getItem: (k: string) => backing.get(k) ?? null,
    setItem: (k: string, v: string) => void backing.set(k, v),
  } as unknown as Storage
}

const INIT_PAYLOAD = encodeInit({ wasmBytes: new Uint8Array([1]), cfg: new Uint8Array([2]) })

describe('worker protocol', () => {
  it('round-trips init and step frames', async () => {
    const driver = new MockSessionDriver({ entitled: ['pro'] })
    const port = new FakeWorkerPort(createMessageHandler(() => driver))
    const client = new WorkerSessionClient(port, new Uint8Array(32))
    await client.init({ wasmBytes: new Uint8Array([1]), cfg: new Uint8Array([2]) })

    const ops = new SessionOps(client)
    const result = await ops.deviceKeygen()
    expect(result.summary.state).toBe(0)
    expect(driver.ops).toContain(1)
  })

  it('resolves concurrent steps by id even when responses arrive out of order', async () => {
    const driver = new MockSessionDriver({})
    const base = createMessageHandler(() => driver)
    let stepSeen = 0
    let releaseFirst!: () => void
    const gate = new Promise<void>((resolve) => {
      releaseFirst = resolve
    })
    const handler = async (frame: Uint8Array): Promise<Uint8Array> => {
      const request = decodeRequest(frame)
      if (request.op === OP_STEP) {
        stepSeen += 1
        if (stepSeen === 1) await gate // hold the first step's response
      }
      return base(frame)
    }
    const port = new FakeWorkerPort(handler)
    const client = new WorkerSessionClient(port, new Uint8Array(32))
    await client.init({ wasmBytes: new Uint8Array([1]), cfg: new Uint8Array([2]) })

    const order: string[] = []
    const ops = new SessionOps(client)
    const first = ops.stateQuery().then(() => order.push('first'))
    const second = ops.stateQuery().then(() => order.push('second'))
    await second
    expect(order).toEqual(['second']) // id correlation, not arrival order
    releaseFirst()
    await first
    expect(order).toEqual(['second', 'first'])
  })

  it('encodes core errors as bare numeric codes on the wire', async () => {
    const driver = new MockSessionDriver({ entitled: [] })
    const handler = createMessageHandler(() => driver)
    const initOut = await handler(encodeRequest(1, OP_INIT, INIT_PAYLOAD))
    expect(decodeResponse(initOut).status).toBe(STATUS_OK)

    // A failing derive (op 9: feature "nope", kind 0): the wire response must
    // be STATUS_CORE_ERROR with the numeric code as its only payload.
    const request = encodeRequest(2, OP_STEP, deriveRequestBytes())
    const response = decodeResponse(await handler(request))
    expect(response.status).toBe(STATUS_CORE_ERROR)
    expect(decodeCoreError(response.payload)).toBe(13)
  })

  it('rejects steps before init with a host error', async () => {
    const handler = createMessageHandler(() => new MockSessionDriver({}))
    const response = decodeResponse(await handler(encodeRequest(7, OP_STEP, deriveRequestBytes())))
    expect(response.status).toBe(STATUS_HOST_ERROR)
  })

  it('maps wire error codes back onto typed errors in SessionOps', async () => {
    const driver = new MockSessionDriver({ entitled: [] })
    const port = new FakeWorkerPort(createMessageHandler(() => driver))
    const client = new WorkerSessionClient(port, new Uint8Array(32))
    await client.init({ wasmBytes: new Uint8Array([1]), cfg: new Uint8Array([2]) })

    const ops = new SessionOps(client)
    const failure = await ops.deriveM('nope', 0, 1000).catch((error: unknown) => error)
    expect(failure).toBeInstanceOf(NotEntitledError)
    expect((failure as NotEntitledError).code).toBe(13)
  })
})

/** op-9 (derive-m) request bytes: {0: 9, 1: "nope", 2: 0, 3: 1000}. */
function deriveRequestBytes(): Uint8Array {
  // Encoded through a SessionOps over a capturing driver to reuse the exact
  // production encoding path.
  let captured: Uint8Array | null = null
  const ops = new SessionOps({
    step(input: Uint8Array): Uint8Array {
      captured = input
      throw 13
    },
  })
  void ops.deriveM('nope', 0, 1000).catch(() => {})
  if (!captured) throw new Error('capture failed')
  return captured
}

describe('CopyLocker worker isolation (FR-WEB-008)', () => {
  const wasmBytes = new Uint8Array([9, 8, 7, 6, 5])

  async function wasmDigest(): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', wasmBytes))
  }

  function makeFetch(log: string[]): typeof fetch {
    const inner = mockWorkerFetch(log)
    return (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('copylocker_wasm_bg.wasm')) {
        log.push(`${init?.method ?? 'GET'} ${url}`)
        return new Response(wasmBytes.slice().buffer, { status: 200 })
      }
      return inner(input, init)
    }) as typeof fetch
  }

  it('runs the full activate → unseal flow through the Worker bridge', async () => {
    const driver = new MockSessionDriver({ entitled: ['pro'] })
    const port = new FakeWorkerPort(createMessageHandler(() => driver))
    const log: string[] = []
    const cl = await CopyLocker.create({
      serverUrl: 'https://license.example.test',
      productId: 'demo',
      rootPins: [TEST_ROOT_PIN],
      glueBaseUrl: 'https://license.example.test/wasm/',
      workerFactory: () => port,
      fetchFn: makeFetch(log),
      indexedDB: new IDBFactory(),
      localStorage: memoryStorage(),
      schedulerIntervalMs: 3_600_000,
    })
    expect(cl.degradedFlags.worker).toBe(false)
    expect(log).toContain('GET https://license.example.test/wasm/copylocker_wasm_bg.wasm')

    await cl.activate('CL-TEST-KEY')
    expect(cl.state).toBe('active')

    const digest = await wasmDigest()
    const finalKey = await deriveFinalKey(driver.m, resolveBuildConstants(), digest)
    const sealed = await sealAsset(
      finalKey,
      { productId: 'demo', variantId: 0, featureId: 'pro', assetId: 'chunk.bin' },
      new Uint8Array([10, 20, 30]),
    )
    expect(await cl.unseal('pro', sealed)).toEqual(new Uint8Array([10, 20, 30]))

    cl.dispose()
    expect(port.terminated).toBe(true)
  })

  it('falls back and flags the degradation when Worker construction throws', async () => {
    const driver = new MockSessionDriver({ entitled: ['pro'] })
    const log: string[] = []
    const cl = await CopyLocker.create({
      serverUrl: 'https://license.example.test',
      productId: 'demo',
      rootPins: [TEST_ROOT_PIN],
      glueBaseUrl: 'https://license.example.test/wasm/',
      workerFactory: () => {
        throw new Error('no workers here')
      },
      sessionDriver: driver,
      fetchFn: makeFetch(log),
      indexedDB: new IDBFactory(),
      localStorage: memoryStorage(),
      schedulerIntervalMs: 3_600_000,
    })
    expect(cl.degradedFlags.worker).toBe(true)
    await cl.activate('CL-TEST-KEY')
    expect(cl.state).toBe('active')
    cl.dispose()
  })

  it('flags the degradation when no Worker global exists (Node)', async () => {
    expect(typeof (globalThis as Record<string, unknown>)['Worker']).toBe('undefined')
    const driver = new MockSessionDriver({})
    const cl = await CopyLocker.create({
      serverUrl: 'https://license.example.test',
      productId: 'demo',
      rootPins: [TEST_ROOT_PIN],
      sessionDriver: driver,
      fetchFn: mockWorkerFetch([]) as typeof fetch,
      indexedDB: new IDBFactory(),
      localStorage: memoryStorage(),
      schedulerIntervalMs: 3_600_000,
    })
    expect(cl.degradedFlags.worker).toBe(true)
    cl.dispose()
  })

  it('reports no degradation when worker isolation is explicitly disabled', async () => {
    const driver = new MockSessionDriver({})
    const cl = await CopyLocker.create({
      serverUrl: 'https://license.example.test',
      productId: 'demo',
      rootPins: [TEST_ROOT_PIN],
      worker: false,
      sessionDriver: driver,
      fetchFn: mockWorkerFetch([]) as typeof fetch,
      indexedDB: new IDBFactory(),
      localStorage: memoryStorage(),
      schedulerIntervalMs: 3_600_000,
    })
    expect(cl.degradedFlags.worker).toBe(false)
    cl.dispose()
  })
})
