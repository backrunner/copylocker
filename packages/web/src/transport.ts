/**
 * Transport to the CopyLocker Worker (`crates/copylocker-worker`).
 *
 * Routes (see `crates/copylocker-worker/src/router.rs`):
 * - `GET  /v1/keys`        — keyset fetch
 * - `POST /v1/activate`    — body is the CBOR request built by the core
 * - `POST /v1/validate`
 * - `POST /v1/deactivate`
 *
 * Bodies are `application/cbor` bytes; responses are `application/cbor`.
 * Retry policy: exponential backoff with jitter for 5xx and network errors;
 * 4xx is a definitive protocol answer and is never retried.
 */

export class TransportError extends Error {
  /** HTTP status when the failure came from a response, else 0 (network). */
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'TransportError'
    this.status = status
  }
}

export interface TransportOptions {
  /** Injectable fetch (defaults to the global). */
  fetchFn?: typeof fetch
  /** Maximum attempts per request, including the first (default 4). */
  maxAttempts?: number
  /** Base backoff in milliseconds; attempt n waits base * 2^(n-1) + jitter. */
  baseDelayMs?: number
  /** Sleep override for tests. */
  sleepFn?: (ms: number) => Promise<void>
  /** Random source for jitter (tests inject determinism). */
  randomFn?: () => number
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export class Transport {
  private readonly baseUrl: string
  private readonly fetchFn: typeof fetch
  private readonly maxAttempts: number
  private readonly baseDelayMs: number
  private readonly sleepFn: (ms: number) => Promise<void>
  private readonly randomFn: () => number

  constructor(serverUrl: string, options: TransportOptions = {}) {
    if (!/^https?:\/\//.test(serverUrl)) {
      throw new TypeError('CopyLocker: serverUrl must be an absolute http(s) URL')
    }
    this.baseUrl = serverUrl.replace(/\/+$/, '')
    const fetchFn = options.fetchFn ?? globalThis.fetch
    if (!fetchFn) throw new Error('CopyLocker: fetch is required')
    this.fetchFn = fetchFn.bind(globalThis)
    this.maxAttempts = options.maxAttempts ?? 4
    this.baseDelayMs = options.baseDelayMs ?? 500
    this.sleepFn = options.sleepFn ?? defaultSleep
    this.randomFn = options.randomFn ?? Math.random
  }

  /** `GET /v1/keys` — the keyset bytes. */
  async getKeyset(): Promise<Uint8Array> {
    return this.request('GET', '/v1/keys')
  }

  /** `POST /v1/activate` with a core-built request body. */
  async activate(body: Uint8Array): Promise<Uint8Array> {
    // The server requires an Idempotency-Key on activation (one per caller
    // intent; every retry of this request reuses it).
    return this.request('POST', '/v1/activate', body, {
      'Idempotency-Key': globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`,
    })
  }

  /** `POST /v1/validate` with a core-built request body. */
  async validate(body: Uint8Array): Promise<Uint8Array> {
    return this.request('POST', '/v1/validate', body)
  }

  /** `POST /v1/deactivate` with a core-built request body. */
  async deactivate(body: Uint8Array): Promise<Uint8Array> {
    return this.request('POST', '/v1/deactivate', body)
  }

  private async request(
    method: 'GET' | 'POST',
    path: string,
    body?: Uint8Array,
    extraHeaders?: Record<string, string>,
  ): Promise<Uint8Array> {
    // Protocol headers mirror the native client (`X-CL-Proto` is mandatory —
    // the Worker rejects protocol requests without it with 426).
    const headers: Record<string, string> = {
      Accept: 'application/cbor',
      'X-CL-Proto': '1',
      ...extraHeaders,
    }
    if (body) headers['Content-Type'] = 'application/cbor'
    let lastError: TransportError | null = null
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      try {
        const response = await this.fetchFn(`${this.baseUrl}${path}`, {
          method,
          headers,
          body: body ? (body as unknown as ArrayBuffer) : undefined,
        })
        if (response.ok) {
          return new Uint8Array(await response.arrayBuffer())
        }
        // 4xx is a definitive protocol answer: never retried.
        if (response.status >= 400 && response.status < 500) {
          throw new TransportError(response.status, `CopyLocker: server rejected the request (${response.status})`)
        }
        lastError = new TransportError(response.status, `CopyLocker: server error (${response.status})`)
      } catch (error) {
        if (error instanceof TransportError && error.status >= 400 && error.status < 500) {
          throw error
        }
        lastError =
          error instanceof TransportError
            ? error
            : new TransportError(0, 'CopyLocker: network request failed')
      }
      if (attempt < this.maxAttempts) {
        const backoff = this.baseDelayMs * 2 ** (attempt - 1)
        const jitter = Math.floor(this.randomFn() * this.baseDelayMs)
        await this.sleepFn(backoff + jitter)
      }
    }
    throw lastError ?? new TransportError(0, 'CopyLocker: network request failed')
  }
}
