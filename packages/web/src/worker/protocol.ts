/**
 * Wire protocol between the main thread and the session Worker
 * (`40-web-sdk-wasm-ts.md §4.2`, FR-WEB-008).
 *
 * Every message is a single opaque byte frame, transferred as an
 * `ArrayBuffer` via `postMessage`. Nothing semantic (op names, feature ids,
 * state) appears in the frame header — the payloads are the same opaque CBOR
 * blobs the main-thread driver would hand to the wasm core directly.
 *
 * Frame layout (all integers little-endian):
 *
 * ```text
 * request:  u32 id ‖ u8 op      ‖ payload
 * response: u32 id ‖ u8 status  ‖ payload
 * ```
 *
 * - `op`     — {@link OP_INIT} (payload: CBOR `{1: wasmBytes, 2: cfgBytes,
 *   3?: glueUrl}`) or {@link OP_STEP} (payload: opaque session request bytes).
 * - `status` — {@link STATUS_OK} (payload: response bytes; empty for INIT),
 *   {@link STATUS_CORE_ERROR} (payload: u32 numeric core error code, mirrored
 *   to the numeric rejection contract of `ClSession.step`), or
 *   {@link STATUS_HOST_ERROR} (payload: UTF-8 host-side diagnostic).
 *
 * `id` correlates responses to requests so concurrent `step` calls can be
 * in flight; ids wrap at 2^32.
 */

import { decode, encode, mapGet, type CborValue } from '../cbor.js'

export const OP_INIT = 1
export const OP_STEP = 2

export const STATUS_OK = 0
export const STATUS_CORE_ERROR = 1
export const STATUS_HOST_ERROR = 2

const HEADER_BYTES = 5

export interface WorkerRequest {
  id: number
  op: number
  payload: Uint8Array
}

export interface WorkerResponse {
  id: number
  status: number
  payload: Uint8Array
}

function writeHeader(id: number, kind: number, payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(HEADER_BYTES + payload.byteLength)
  const view = new DataView(frame.buffer)
  view.setUint32(0, id >>> 0, true)
  frame[4] = kind
  frame.set(payload, HEADER_BYTES)
  return frame
}

function readHeader(frame: Uint8Array): { id: number; kind: number; payload: Uint8Array } {
  if (frame.byteLength < HEADER_BYTES) {
    throw new TypeError('worker protocol: truncated frame')
  }
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength)
  return {
    id: view.getUint32(0, true),
    kind: frame[4] as number,
    payload: frame.subarray(HEADER_BYTES),
  }
}

export function encodeRequest(id: number, op: number, payload: Uint8Array): Uint8Array {
  return writeHeader(id, op, payload)
}

export function decodeRequest(frame: Uint8Array): WorkerRequest {
  const { id, kind, payload } = readHeader(frame)
  return { id, op: kind, payload }
}

export function encodeResponse(id: number, status: number, payload: Uint8Array): Uint8Array {
  return writeHeader(id, status, payload)
}

export function decodeResponse(frame: Uint8Array): WorkerResponse {
  const { id, kind, payload } = readHeader(frame)
  return { id, status: kind, payload }
}

/** Payload codec for {@link STATUS_CORE_ERROR}: the bare numeric code. */
export function encodeCoreError(code: number): Uint8Array {
  const payload = new Uint8Array(4)
  new DataView(payload.buffer).setUint32(0, code >>> 0, true)
  return payload
}

export function decodeCoreError(payload: Uint8Array): number {
  if (payload.byteLength !== 4) throw new TypeError('worker protocol: bad error payload')
  return new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(0, true)
}

/** Everything the Worker needs to open a session (op {@link OP_INIT}). */
export interface WorkerInit {
  /** Raw `.wasm` bytes (transferred; the Worker instantiates from bytes). */
  wasmBytes: Uint8Array
  /** Constructor configuration CBOR (`Session::new` schema 1). */
  cfg: Uint8Array
  /** Absolute URL of the wasm-bindgen glue module, resolved by the caller. */
  glueUrl?: string
}

export function encodeInit(init: WorkerInit): Uint8Array {
  const map = new Map<number, CborValue>([
    [1, init.wasmBytes],
    [2, init.cfg],
  ])
  if (init.glueUrl !== undefined) map.set(3, init.glueUrl)
  return encode(map)
}

export function decodeInit(payload: Uint8Array): WorkerInit {
  const value = decode(payload)
  const wasmBytes = mapGet(value, 1)
  const cfg = mapGet(value, 2)
  const glueUrl = mapGet(value, 3)
  if (!(wasmBytes instanceof Uint8Array) || !(cfg instanceof Uint8Array)) {
    throw new TypeError('worker protocol: malformed init payload')
  }
  if (glueUrl !== undefined && typeof glueUrl !== 'string') {
    throw new TypeError('worker protocol: malformed init payload')
  }
  return { wasmBytes, cfg, glueUrl: glueUrl as string | undefined }
}

/** Normalize a `postMessage` payload (`ArrayBuffer` or view) to bytes. */
export function messageBytes(data: unknown): Uint8Array | null {
  if (data instanceof Uint8Array) return data
  if (data instanceof ArrayBuffer) return new Uint8Array(data)
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
  }
  return null
}
