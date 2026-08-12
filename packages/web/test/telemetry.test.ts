import { describe, expect, it } from 'vitest'
import { IDBFactory } from 'fake-indexeddb'
import { CopyLocker } from '../src/index.js'
import { decode, encode, mapGet, type CborValue } from '../src/cbor.js'
import { MockSessionDriver, TEST_ROOT_PIN } from './helpers/mockSession.js'

/** A canonical telemetry_block as `@copylocker/telemetry` would encode it. */
function sampleBlock(): Uint8Array {
  return encode(
    new Map<number, CborValue>([
      [0, 3],
      [1, 360_000],
      [2, 4],
      [3, [1, 1, 1, 1]],
      [4, new Map<string, CborValue>([['export', 2]])],
      [5, 1],
    ]),
  )
}

interface Fixture {
  driver: MockSessionDriver
  /** Raw bodies POSTed to /v1/validate. */
  validateBodies: Uint8Array[]
}

function makeFetch(fixture: Fixture): typeof fetch {
  const ok = (body: Uint8Array) =>
    new Response(body as unknown as ArrayBuffer, {
      status: 200,
      headers: { 'Content-Type': 'application/cbor' },
    })
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/v1/keys')) return ok(encode(new Map([[0, 'keyset']])))
    if (url.endsWith('/v1/activate')) return ok(encode(new Map([[0, 'credential']])))
    if (url.endsWith('/v1/validate')) {
      fixture.validateBodies.push(new Uint8Array(init?.body as ArrayBuffer))
      return ok(encode(new Map([[0, 'ticket']])))
    }
    return new Response('not found', { status: 404 })
  }) as typeof fetch
}

async function createClient(telemetry?: { buildBlock(now: number): Uint8Array | undefined }) {
  const fixture: Fixture = { driver: new MockSessionDriver(), validateBodies: [] }
  const cl = await CopyLocker.create({
    serverUrl: 'https://license.example.test',
    productId: 'demo',
    rootPins: [TEST_ROOT_PIN],
    sessionDriver: fixture.driver,
    fetchFn: makeFetch(fixture),
    indexedDB: new IDBFactory(),
    schedulerIntervalMs: 3_600_000,
    telemetry,
  })
  await cl.activate('CL-TEST-KEY')
  return { cl, fixture }
}

async function validateOnce(cl: CopyLocker): Promise<void> {
  await (cl as unknown as { validateNow(): Promise<void> }).validateNow()
}

describe('telemetry wiring (proto key 11 on /v1/validate)', () => {
  it('sends no telemetry by default', async () => {
    const { cl, fixture } = await createClient()
    await validateOnce(cl)
    expect(fixture.validateBodies).toHaveLength(1)
    const request = decode(fixture.validateBodies[0] as Uint8Array)
    expect(mapGet(request, 11)).toBeUndefined()
    expect(fixture.driver.lastValidateTelemetry).toBeUndefined()
    cl.dispose()
  })

  it('hands the hook-built block to the signing op; the built request carries it at key 11', async () => {
    const block = sampleBlock()
    const { cl, fixture } = await createClient({ buildBlock: () => block })
    await validateOnce(cl)
    // The exact hook bytes reached the build-validate-request op input, so
    // the core embeds and signs them (no post-signing attach).
    expect(fixture.driver.lastValidateTelemetry).toBeInstanceOf(Uint8Array)
    expect([...(fixture.driver.lastValidateTelemetry as Uint8Array)]).toEqual([...block])
    const request = decode(fixture.validateBodies[0] as Uint8Array)
    // The mock core's own field survives alongside the embedded block.
    expect(mapGet(request, 1)).toBe('validate-request')
    const embedded = mapGet(request, 11)
    expect(embedded).toBeInstanceOf(Map)
    expect(mapGet(embedded as CborValue, 0)).toBe(3) // consent_version
    expect(mapGet(embedded as CborValue, 1)).toBe(360_000) // window_start
    expect(mapGet(embedded as CborValue, 2)).toBe(4) // session_count
    expect(mapGet(embedded as CborValue, 3)).toEqual([1, 1, 1, 1]) // histogram
    expect(mapGet(embedded as CborValue, 5)).toBe(1) // days_active
    const features = mapGet(embedded as CborValue, 4)
    expect(features).toBeInstanceOf(Map)
    expect((features as Map<CborValue, CborValue>).get('export')).toBe(2)
    cl.dispose()
  })

  it('omits key 11 when the hook returns undefined (no consent / empty window)', async () => {
    const { cl, fixture } = await createClient({ buildBlock: () => undefined })
    await validateOnce(cl)
    expect(fixture.driver.lastValidateTelemetry).toBeUndefined()
    expect(mapGet(decode(fixture.validateBodies[0] as Uint8Array), 11)).toBeUndefined()
    cl.dispose()
  })

  it('never breaks validation: a throwing hook validates without a block', async () => {
    const { cl, fixture } = await createClient({
      buildBlock: () => {
        throw new Error('telemetry exploded')
      },
    })
    await validateOnce(cl)
    expect(fixture.validateBodies).toHaveLength(1)
    const request = decode(fixture.validateBodies[0] as Uint8Array)
    expect(mapGet(request, 1)).toBe('validate-request')
    expect(mapGet(request, 11)).toBeUndefined()
    expect(fixture.driver.lastValidateTelemetry).toBeUndefined()
    expect(cl.state).toBe('active')
    cl.dispose()
  })

  it('never breaks validation: a hook returning non-CBOR garbage validates without a block', async () => {
    const { cl, fixture } = await createClient({ buildBlock: () => new Uint8Array([0xff, 0xff]) })
    await validateOnce(cl)
    expect(mapGet(decode(fixture.validateBodies[0] as Uint8Array), 11)).toBeUndefined()
    // Garbage is dropped before it reaches the op, so the core never rejects.
    expect(fixture.driver.lastValidateTelemetry).toBeUndefined()
    expect(cl.state).toBe('active')
    cl.dispose()
  })

  it('drops hook output over the 512-byte cap before it reaches the op', async () => {
    const oversized = new Uint8Array(513)
    oversized[0] = 0xa0
    const { cl, fixture } = await createClient({ buildBlock: () => oversized })
    await validateOnce(cl)
    expect(fixture.driver.lastValidateTelemetry).toBeUndefined()
    expect(mapGet(decode(fixture.validateBodies[0] as Uint8Array), 11)).toBeUndefined()
    expect(cl.state).toBe('active')
    cl.dispose()
  })

  it('drops hook output that decodes to a non-map value', async () => {
    const { cl, fixture } = await createClient({ buildBlock: () => encode(42) })
    await validateOnce(cl)
    expect(fixture.driver.lastValidateTelemetry).toBeUndefined()
    expect(mapGet(decode(fixture.validateBodies[0] as Uint8Array), 11)).toBeUndefined()
    expect(cl.state).toBe('active')
    cl.dispose()
  })
})
