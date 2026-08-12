/**
 * Worker-side entry point for session isolation (FR-WEB-008, design §4.2).
 *
 * This module is loaded as a dedicated Worker chunk
 * (`new Worker(new URL('./worker/entry.js', import.meta.url), { type: 'module' })`
 * on the main thread). It receives the wasm bytes plus the constructor
 * configuration in an INIT frame, builds the `ClSession` inside the Worker,
 * and from then on shuttles opaque STEP request/response bytes between the
 * main thread and the core. Core failures go back as bare numeric codes —
 * the same contract `ClSession.step` has on the main thread (NFR-SEC-011).
 *
 * The message handler is exported separately from the Worker bootstrap so
 * tests can drive the protocol over a fake port without a real Worker.
 */

import { isErrorCode } from '../errors.js'
import type { SessionDriver } from '../session.js'
import {
  OP_INIT,
  OP_STEP,
  STATUS_CORE_ERROR,
  STATUS_HOST_ERROR,
  STATUS_OK,
  decodeInit,
  decodeRequest,
  encodeCoreError,
  encodeResponse,
  messageBytes,
  type WorkerInit,
} from './protocol.js'

const EMPTY = new Uint8Array(0)

/** Build the in-Worker session from the INIT payload. */
export type WorkerSessionFactory = (init: WorkerInit) => SessionDriver | Promise<SessionDriver>

interface WasmGlue {
  default: (input: { module_or_path: BufferSource }) => Promise<unknown>
  ClSession: new (cfg: Uint8Array) => SessionDriver
}

/**
 * The production factory: import the wasm-bindgen glue, instantiate from the
 * transferred bytes, and open the session. The glue URL is resolved by the
 * main thread (it owns the `glueBaseUrl` option); the fallback matches the
 * package layout (`dist/worker/entry.js` → `dist/wasm/`).
 */
export async function defaultSessionFactory(init: WorkerInit): Promise<SessionDriver> {
  const glueUrl = init.glueUrl ?? new URL('../wasm/copylocker_wasm.js', import.meta.url).href
  let glue: WasmGlue
  try {
    glue = (await import(/* @vite-ignore */ glueUrl)) as WasmGlue
  } catch {
    throw new Error('CopyLocker: wasm glue not found — run `npm run build:wasm` first')
  }
  await glue.default({ module_or_path: init.wasmBytes as unknown as ArrayBuffer })
  return new glue.ClSession(init.cfg)
}

/**
 * Create the request handler for one Worker instance. Pure protocol: bytes
 * in, bytes out; the transport (Worker scope or a test fake) is the caller's
 * concern.
 */
export function createMessageHandler(
  factory: WorkerSessionFactory,
): (frame: Uint8Array) => Promise<Uint8Array> {
  let session: SessionDriver | null = null
  return async (frame) => {
    let id = 0
    try {
      const request = decodeRequest(frame)
      id = request.id
      switch (request.op) {
        case OP_INIT: {
          session = await factory(decodeInit(request.payload))
          return encodeResponse(id, STATUS_OK, EMPTY)
        }
        case OP_STEP: {
          if (!session) {
            return encodeResponse(id, STATUS_HOST_ERROR, utf8('session not initialized'))
          }
          try {
            return encodeResponse(id, STATUS_OK, session.step(request.payload))
          } catch (error) {
            if (isErrorCode(error)) return encodeResponse(id, STATUS_CORE_ERROR, encodeCoreError(error))
            throw error
          }
        }
        default:
          return encodeResponse(id, STATUS_HOST_ERROR, utf8('unknown op'))
      }
    } catch (error) {
      return encodeResponse(id, STATUS_HOST_ERROR, utf8(errorMessage(error)))
    }
  }
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown failure'
}

// --- Worker bootstrap -------------------------------------------------------
//
// Only arms the message listener when running inside a Worker global scope:
// `postMessage` exists on both `window` and the Worker scope, so the
// `window` check is what keeps the main thread (and Node, which has neither)
// from installing anything. Importing this module outside a Worker is a
// no-op.

interface WorkerScope {
  postMessage?: (message: Uint8Array, transfer: Transferable[]) => void
  onmessage?: ((event: { data?: unknown }) => void) | null
}

const scope = globalThis as unknown as WorkerScope
if (typeof window === 'undefined' && typeof scope.postMessage === 'function') {
  const handle = createMessageHandler(defaultSessionFactory)
  scope.onmessage = (event) => {
    const frame = messageBytes(event.data)
    if (!frame) return
    void handle(frame).then((out) => {
      scope.postMessage?.(out, [out.buffer as ArrayBuffer])
    })
  }
}
