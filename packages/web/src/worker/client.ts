/**
 * Main-thread side of the Worker session bridge (FR-WEB-008, design §4.2).
 *
 * {@link WorkerSessionClient} is an `AsyncSessionDriver`: every `step` call
 * is framed (`worker/protocol.ts`), posted to the Worker with its buffer
 * transferred, and resolved when the response with the matching id arrives.
 * Numeric core error codes are re-thrown as bare numbers so `SessionOps`
 * maps them onto typed errors exactly like the main-thread driver does.
 *
 * {@link openWorkerSession} owns startup: fetch the raw wasm bytes (their
 * SHA-256 feeds both the constructor configuration and the two-stage key
 * transform, so the digest is computed here on the main thread), spawn the
 * Worker, and handshake with INIT. The Worker entry chunk is referenced with
 * the bundler-recognized `new Worker(new URL(..., import.meta.url))` pattern.
 */

import { packageGlueBase, type AsyncSessionDriver } from '../session.js'
import {
  OP_INIT,
  OP_STEP,
  STATUS_CORE_ERROR,
  STATUS_HOST_ERROR,
  STATUS_OK,
  decodeCoreError,
  decodeResponse,
  encodeInit,
  encodeRequest,
  messageBytes,
  type WorkerInit,
} from './protocol.js'

/**
 * The minimal Worker surface the client drives. Structurally matches the
 * DOM `Worker`; tests substitute a fake port wired to the entry handler.
 */
export interface WorkerPortLike {
  postMessage(message: Uint8Array, transfer?: Transferable[]): void
  addEventListener(type: 'message' | 'error', listener: (event: { data?: unknown }) => void): void
  terminate(): void
}

/** Testing/advanced seam overriding Worker construction. */
export type WorkerFactory = () => WorkerPortLike

interface PendingRequest {
  resolve(payload: Uint8Array): void
  reject(error: unknown): void
}

export class WorkerSessionClient implements AsyncSessionDriver {
  private nextId = 1
  private readonly pending = new Map<number, PendingRequest>()
  private failure: Error | null = null

  constructor(
    private readonly port: WorkerPortLike,
    /** SHA-256 of the raw `.wasm` bytes; feeds the two-stage transform. */
    readonly wasmDigest: Uint8Array,
  ) {
    port.addEventListener('message', (event) => this.onMessage(event.data))
    port.addEventListener('error', () =>
      this.failAll(new Error('CopyLocker: worker session failed')),
    )
  }

  /** Handshake: ship the wasm bytes and constructor config to the Worker. */
  async init(init: WorkerInit): Promise<void> {
    await this.request(OP_INIT, encodeInit(init))
  }

  step(input: Uint8Array): Promise<Uint8Array> {
    return this.request(OP_STEP, input)
  }

  /** Terminate the Worker and reject everything still in flight. */
  dispose(): void {
    this.failAll(new Error('CopyLocker: worker session disposed'))
    this.port.terminate()
  }

  private request(op: number, payload: Uint8Array): Promise<Uint8Array> {
    if (this.failure) return Promise.reject(this.failure)
    const id = this.nextId
    this.nextId = (this.nextId + 1) >>> 0 || 1
    const frame = encodeRequest(id, op, payload)
    return new Promise<Uint8Array>((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      try {
        this.port.postMessage(frame, [frame.buffer as ArrayBuffer])
      } catch (error) {
        this.pending.delete(id)
        reject(error)
      }
    })
  }

  private onMessage(data: unknown): void {
    const frame = messageBytes(data)
    if (!frame) return
    let response
    try {
      response = decodeResponse(frame)
    } catch {
      return
    }
    const request = this.pending.get(response.id)
    if (!request) return
    this.pending.delete(response.id)
    switch (response.status) {
      case STATUS_OK:
        request.resolve(response.payload)
        return
      case STATUS_CORE_ERROR:
        // Bare numeric code, mirroring `ClSession.step` rejections.
        request.reject(decodeCoreError(response.payload))
        return
      case STATUS_HOST_ERROR:
        request.reject(
          new Error(`CopyLocker: worker session error — ${new TextDecoder().decode(response.payload)}`),
        )
        return
      default:
        request.reject(new Error('CopyLocker: worker protocol violation'))
    }
  }

  private failAll(error: Error): void {
    this.failure ??= error
    for (const request of this.pending.values()) request.reject(this.failure)
    this.pending.clear()
  }
}

export interface OpenWorkerSessionOptions {
  /** Base URL the glue and `.wasm` are served from (defaults to `dist/wasm/`). */
  glueBaseUrl?: string | URL
  /** Fetch implementation (defaults to the global `fetch`). */
  fetchFn?: typeof fetch
  /** Overrides Worker construction (tests); defaults to the bundled entry. */
  workerFactory?: WorkerFactory
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('CopyLocker: WebCrypto SubtleCrypto is required (secure context)')
  }
  return new Uint8Array(await subtle.digest('SHA-256', bytes as unknown as ArrayBuffer))
}

/**
 * Fetch the wasm bytes, spawn the Worker, and open the session inside it.
 * Throws when the Worker cannot be constructed or the handshake fails — the
 * caller (`CopyLocker.create`) catches this and degrades to the main thread.
 */
export async function openWorkerSession(
  cfg: (wasmDigest: Uint8Array) => Uint8Array,
  options: OpenWorkerSessionOptions = {},
): Promise<WorkerSessionClient> {
  // `packageGlueBase` keeps bundlers from turning the directory default
  // into a (broken) static asset reference.
  const base = options.glueBaseUrl ?? packageGlueBase('../wasm/', import.meta.url)
  const wasmUrl = new URL('copylocker_wasm_bg.wasm', base).href
  const glueUrl = new URL('copylocker_wasm.js', base).href

  const fetchFn = options.fetchFn ?? globalThis.fetch
  if (!fetchFn) throw new Error('CopyLocker: fetch is required to load the wasm module')
  const response = await fetchFn(wasmUrl)
  if (!response.ok) {
    throw new Error('CopyLocker: wasm module not found — run `npm run build:wasm` first')
  }
  const wasmBytes = new Uint8Array(await response.arrayBuffer())
  const wasmDigest = await sha256(wasmBytes)

  const port = options.workerFactory
    ? options.workerFactory()
    : new Worker(new URL('./entry.js', import.meta.url), { type: 'module' })

  const client = new WorkerSessionClient(port, wasmDigest)
  try {
    await client.init({ wasmBytes, cfg: cfg(wasmDigest), glueUrl })
  } catch (error) {
    client.dispose()
    throw error
  }
  return client
}
