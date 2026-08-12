import { describe, expect, it, vi } from 'vitest'
import { Transport, TransportError } from '../src/transport.js'

function jsonResponse(status: number, body: Uint8Array = new Uint8Array([1, 2, 3])): Response {
  return new Response(status === 204 ? null : (body as unknown as ArrayBuffer), { status })
}

function harness(fetchImpl: ReturnType<typeof vi.fn>) {
  const sleeps: number[] = []
  const transport = new Transport('https://license.example.test/', {
    fetchFn: fetchImpl as unknown as typeof fetch,
    baseDelayMs: 500,
    sleepFn: async (ms) => {
      sleeps.push(ms)
    },
    randomFn: () => 0,
  })
  return { transport, sleeps }
}

describe('transport', () => {
  it('POSTs CBOR bytes with the application/cbor content type', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(200))
    const { transport } = harness(fetchImpl)
    const body = new Uint8Array([0xa1, 0x00, 0x01])
    const result = await transport.activate(body)
    expect([...result]).toEqual([1, 2, 3])
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('https://license.example.test/v1/activate')
    expect(init.method).toBe('POST')
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/cbor')
    expect(new Uint8Array(init.body as ArrayBuffer)).toEqual(body)
  })

  it('sends the protocol headers the Worker requires, with one Idempotency-Key per activation', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(200))
    const { transport } = harness(fetchImpl)
    await transport.getKeyset()
    let headers = fetchImpl.mock.calls[0]?.[1]?.headers as Record<string, string>
    expect(headers['X-CL-Proto']).toBe('1')
    expect(headers['Accept']).toBe('application/cbor')
    expect(headers['Idempotency-Key']).toBeUndefined()

    await transport.activate(new Uint8Array([1]))
    await transport.activate(new Uint8Array([1]))
    const first = fetchImpl.mock.calls[1]?.[1]?.headers as Record<string, string>
    const second = fetchImpl.mock.calls[2]?.[1]?.headers as Record<string, string>
    expect(first['X-CL-Proto']).toBe('1')
    expect(first['Idempotency-Key']).toBeTruthy()
    expect(second['Idempotency-Key']).toBeTruthy()
    expect(first['Idempotency-Key']).not.toBe(second['Idempotency-Key'])
  })

  it('GETs the keyset without a body', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(200))
    const { transport } = harness(fetchImpl)
    await transport.getKeyset()
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('https://license.example.test/v1/keys')
    expect(init.method).toBe('GET')
    expect(init.body).toBeUndefined()
  })

  it('never retries 4xx responses', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(403))
    const { transport, sleeps } = harness(fetchImpl)
    await expect(transport.validate(new Uint8Array([1]))).rejects.toThrow(TransportError)
    expect(fetchImpl).toHaveBeenCalledOnce()
    expect(sleeps).toEqual([])
    const error = await transport.validate(new Uint8Array([1])).catch((e: unknown) => e)
    expect((error as TransportError).status).toBe(403)
  })

  it('retries 5xx with exponential backoff', async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(500))
      .mockResolvedValueOnce(jsonResponse(502))
      .mockResolvedValueOnce(jsonResponse(200))
    const { transport, sleeps } = harness(fetchImpl)
    const result = await transport.validate(new Uint8Array([1]))
    expect([...result]).toEqual([1, 2, 3])
    expect(fetchImpl).toHaveBeenCalledTimes(3)
    expect(sleeps).toEqual([500, 1000])
  })

  it('retries network errors and eventually gives up', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError('fetch failed')
    })
    const { transport, sleeps } = harness(fetchImpl)
    await expect(transport.deactivate(new Uint8Array([1]))).rejects.toThrow(TransportError)
    expect(fetchImpl).toHaveBeenCalledTimes(4) // default maxAttempts
    expect(sleeps).toEqual([500, 1000, 2000])
    const error = await transport.deactivate(new Uint8Array([1])).catch((e: unknown) => e)
    expect((error as TransportError).status).toBe(0)
  })

  it('rejects a relative server URL', () => {
    expect(() => new Transport('license.example.test')).toThrow(TypeError)
  })
})
