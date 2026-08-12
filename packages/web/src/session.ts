/**
 * Host-side wrapper for the opaque `ClSession` wasm-bindgen surface
 * (`40-web-sdk-wasm-ts.md §3`). The wasm module exposes exactly one generic
 * entry point — `step(cbor) -> cbor | number` — and this module encodes the
 * op maps, decodes the advisory summaries, and turns numeric rejections into
 * typed errors.
 */

import { encode, decode, mapGet, type CborValue } from './cbor.js'
import { errorFromCode, isErrorCode } from './errors.js'

// --- op codes (request map key 0), mirroring copylocker-wasm codes.rs ---

export const OP_DEVICE_KEYGEN = 1
export const OP_SNAPSHOT_EXPORT = 2
export const OP_SNAPSHOT_IMPORT = 3
export const OP_BUILD_ACTIVATE_REQUEST = 4
export const OP_INGEST_KEYSET = 5
export const OP_INGEST_ACTIVATE_RESPONSE = 6
export const OP_BUILD_VALIDATE_REQUEST = 7
export const OP_INGEST_VALIDATE_RESPONSE = 8
export const OP_DERIVE_M = 9
export const OP_EVENT = 10
export const OP_STATE_QUERY = 11
export const OP_BUILD_DEACTIVATE_REQUEST = 12
export const OP_UNSEAL_ASSET = 13

// --- event kinds (op 10, key 1) ---

export const EVENT_TICK = 1
export const EVENT_NETWORK_AVAILABLE = 2
export const EVENT_APP_RESUMED = 3
export const EVENT_NETWORK_FAILED = 4
export const EVENT_USER_DEACTIVATE = 5

// --- effect codes (response key 90) ---

export const EFFECT_PERSIST = 1
export const EFFECT_SEND_VALIDATION = 2
export const EFFECT_WIPE_ALL = 3
export const EFFECT_STATE_CHANGED = 4
export const EFFECT_SCHEDULE_WAKE = 5

/** `SessionKind` for op 9: 0 = offline, 1 = online (see session.rs). */
export const SESSION_OFFLINE = 0
export const SESSION_ONLINE = 1

/**
 * The minimal surface the TS shell needs from a session backend. The real
 * implementation is the wasm-bindgen `ClSession`; tests inject an in-memory
 * mock. `step` throws the numeric error code on failure.
 */
export interface SessionDriver {
  step(input: Uint8Array): Uint8Array
}

/**
 * The async counterpart of {@link SessionDriver}, implemented by the Worker
 * bridge (`worker/client.ts`, FR-WEB-008): the same opaque request bytes are
 * ferried to the Worker over `postMessage` and the response bytes (or the
 * numeric error code) come back asynchronously.
 */
export interface AsyncSessionDriver {
  step(input: Uint8Array): Promise<Uint8Array>
}

/** The advisory summary map every op response carries. Never usable for gating. */
export interface Summary {
  /** Numeric state code (response key 1). */
  state: number
  /** Numeric reason code (response key 2); 0 means "no transition". */
  reason: number
  /** Unix seconds after which the host should revalidate (key 3). */
  refreshAfter: number
  /** Unix seconds when the grace window closes (key 4). */
  graceDeadline: number
  /** Unix seconds when the credential expires; 0 = no expiry (key 5). */
  notAfter: number
  /** Whether a credential is installed (key 6). */
  hasCredential: boolean
  /** Validation verdict or kill reason, when present (key 7). */
  verdict?: number
  /** Effect codes the host must act on (key 90). */
  effects: number[]
  /** Unix seconds the host should wake the session at, when present (key 91). */
  wakeAt?: number
}

export interface OpResult {
  summary: Summary
  /** Payload bytes from response key 8 (request bodies, snapshots, `M`). */
  payload?: Uint8Array
}

function requireNumber(value: CborValue | undefined, key: number): number {
  if (typeof value !== 'number') throw new TypeError(`session response: bad field ${key}`)
  return value
}

function optionalNumber(value: CborValue | undefined): number | undefined {
  return typeof value === 'number' ? value : undefined
}

function decodeSummary(value: CborValue): Summary {
  return {
    state: requireNumber(mapGet(value, 1), 1),
    reason: requireNumber(mapGet(value, 2), 2),
    refreshAfter: requireNumber(mapGet(value, 3), 3),
    graceDeadline: requireNumber(mapGet(value, 4), 4),
    notAfter: requireNumber(mapGet(value, 5), 5),
    hasCredential: requireNumber(mapGet(value, 6), 6) !== 0,
    verdict: optionalNumber(mapGet(value, 7)),
    effects: (mapGet(value, 90) as CborValue[] | undefined)?.map((item) =>
      requireNumber(item, 90),
    ) ?? [],
    wakeAt: optionalNumber(mapGet(value, 91)),
  }
}

function decodeResult(bytes: Uint8Array): OpResult {
  const value = decode(bytes)
  const payload = mapGet(value, 8)
  return {
    summary: decodeSummary(value),
    payload: payload instanceof Uint8Array ? payload : undefined,
  }
}

function request(fields: Map<number, CborValue>): Uint8Array {
  const map = new Map<CborValue, CborValue>()
  for (const [key, value] of fields) map.set(key, value)
  return encode(map)
}

/** Typed op interface over a {@link SessionDriver} or {@link AsyncSessionDriver}. */
export class SessionOps {
  constructor(private readonly driver: SessionDriver | AsyncSessionDriver) {}

  private async call(fields: Map<number, CborValue>): Promise<OpResult> {
    let output: Uint8Array
    try {
      output = await this.driver.step(request(fields))
    } catch (error) {
      if (isErrorCode(error)) throw errorFromCode(error)
      throw error
    }
    return decodeResult(output)
  }

  private static op(op: number, fields: [number, CborValue][] = []): Map<number, CborValue> {
    return new Map<number, CborValue>([[0, op], ...fields])
  }

  /** Generate (or confirm) the device key pair. Idempotent. */
  async deviceKeygen(): Promise<OpResult> {
    return this.call(SessionOps.op(OP_DEVICE_KEYGEN))
  }

  /** Export the opaque session snapshot for encrypted persistence. */
  async snapshotExport(): Promise<Uint8Array> {
    const payload = (await this.call(SessionOps.op(OP_SNAPSHOT_EXPORT))).payload
    if (!payload) throw new TypeError('session response: missing snapshot payload')
    return payload
  }

  /** Import a previously exported snapshot; rebuilds all verified state. */
  async snapshotImport(blob: Uint8Array, now: number): Promise<OpResult> {
    return this.call(SessionOps.op(OP_SNAPSHOT_IMPORT, [
      [1, blob],
      [2, now],
    ]))
  }

  /** Build a `/v1/activate` request body for a license key or account token. */
  async buildActivateRequest(
    credential: { licenseKey: string } | { accountToken: Uint8Array },
    now: number,
  ): Promise<Uint8Array> {
    const fields: [number, CborValue][] =
      'licenseKey' in credential
        ? [[1, credential.licenseKey]]
        : [[3, credential.accountToken]]
    fields.push([2, now])
    const payload = (await this.call(SessionOps.op(OP_BUILD_ACTIVATE_REQUEST, fields))).payload
    if (!payload) throw new TypeError('session response: missing request payload')
    return payload
  }

  /** Ingest a `/v1/keys` keyset. */
  async ingestKeyset(keyset: Uint8Array, now: number): Promise<OpResult> {
    return this.call(SessionOps.op(OP_INGEST_KEYSET, [
      [1, keyset],
      [2, now],
    ]))
  }

  /** Ingest a `/v1/activate` response envelope. */
  async ingestActivateResponse(envelope: Uint8Array, now: number): Promise<OpResult> {
    return this.call(SessionOps.op(OP_INGEST_ACTIVATE_RESPONSE, [
      [1, envelope],
      [2, now],
    ]))
  }

  /**
   * Build a `/v1/validate` request body. `telemetryBlock`, when given, is the
   * canonical-CBOR `telemetry_block` the core embeds at proto key 11 *before*
   * signing, so the device proof covers it.
   */
  async buildValidateRequest(now: number, telemetryBlock?: Uint8Array): Promise<Uint8Array> {
    const fields: [number, CborValue][] = [[2, now]]
    if (telemetryBlock) fields.push([1, telemetryBlock])
    const payload = (await this.call(SessionOps.op(OP_BUILD_VALIDATE_REQUEST, fields))).payload
    if (!payload) throw new TypeError('session response: missing request payload')
    return payload
  }

  /** Ingest a `/v1/validate` response (validation ticket or kill order). */
  async ingestValidateResponse(envelope: Uint8Array, now: number): Promise<OpResult> {
    return this.call(SessionOps.op(OP_INGEST_VALIDATE_RESPONSE, [
      [1, envelope],
      [2, now],
    ]))
  }

  /** Derive the 32-byte half-baked material `M` for an entitled feature. */
  async deriveM(featureId: string, kind: number, now: number): Promise<OpResult> {
    return this.call(SessionOps.op(OP_DERIVE_M, [
      [1, featureId],
      [2, kind],
      [3, now],
    ]))
  }

  /** Drive the state machine with a host event. */
  async event(kind: number, now: number, gapMs?: number): Promise<OpResult> {
    const fields: [number, CborValue][] = [
      [1, kind],
      [2, now],
    ]
    if (gapMs !== undefined) fields.push([3, gapMs])
    return this.call(SessionOps.op(OP_EVENT, fields))
  }

  /** Advisory state query. Never usable for gating (ADR-0004). */
  async stateQuery(): Promise<OpResult> {
    return this.call(SessionOps.op(OP_STATE_QUERY))
  }

  /** Build a `/v1/deactivate` request body. */
  async buildDeactivateRequest(now: number): Promise<Uint8Array> {
    const payload = (await this.call(SessionOps.op(OP_BUILD_DEACTIVATE_REQUEST, [[2, now]]))).payload
    if (!payload) throw new TypeError('session response: missing request payload')
    return payload
  }

  /**
   * Unwrap an entitled feature's 32-byte asset KEK from the credential's or the
   * latest ticket's wrapped KEKs (response key 8). The core runs the clock
   * guard and the entitlement chain; every failure is the indistinguishable
   * `ERR_NOT_ENTITLED` (or `ERR_NO_CREDENTIAL` before activation).
   */
  async unsealAsset(featureId: string, now: number): Promise<OpResult> {
    return this.call(SessionOps.op(OP_UNSEAL_ASSET, [
      [1, featureId],
      [2, now],
    ]))
  }
}

// --- constructor configuration (Session::new schema) ---

export interface SessionConfigFields {
  productId: string
  /** Pinned current root verifying key bytes. */
  rootCurrent: Uint8Array
  /** Pinned successor root verifying key bytes, when known. */
  rootNext?: Uint8Array
  /** Device fingerprint digest collected by the TS shell. */
  fingerprint: Uint8Array
  /** Build-time variant constant (32 bytes). */
  variantConst: Uint8Array
  /** Wasm build digest evidence (32 bytes). */
  moduleDigest: Uint8Array
  /** Build fingerprint string (== evidence). */
  buildFingerprint: string
  appVersion: string
  sdkVersion: string
  os: string
  arch: string
  releaseId: string
  variantId: number
  supportedSuites?: Uint8Array[]
  supportedVariants?: number[]
  rollbackThreshold?: number
  minValidationIntervalSecs?: number
  /** Host wall clock, unix seconds. */
  now: number
}

/** Encode the constructor configuration map (`Session::new` CDDL, schema 1). */
export function encodeSessionConfig(fields: SessionConfigFields): Uint8Array {
  const map = new Map<number, CborValue>([
    [0, 1],
    [1, fields.productId],
    [2, fields.rootCurrent],
    [4, fields.fingerprint],
    [5, fields.variantConst],
    [6, fields.moduleDigest],
    [7, fields.buildFingerprint],
    [8, fields.appVersion],
    [9, fields.sdkVersion],
    [10, fields.os],
    [11, fields.arch],
    [12, fields.releaseId],
    [13, fields.variantId],
    [18, fields.now],
  ])
  if (fields.rootNext) map.set(3, fields.rootNext)
  if (fields.supportedSuites) map.set(14, fields.supportedSuites.slice())
  if (fields.supportedVariants) map.set(15, fields.supportedVariants.slice())
  if (fields.rollbackThreshold !== undefined) map.set(16, fields.rollbackThreshold)
  if (fields.minValidationIntervalSecs !== undefined) map.set(17, fields.minValidationIntervalSecs)
  return encode(map)
}

// --- wasm loading ---

export interface WasmSessionResources {
  ops: SessionOps
  /** SHA-256 of the raw `.wasm` bytes; feeds the two-stage transform. */
  wasmDigest: Uint8Array
}

export interface WasmLoadOptions {
  /**
   * Base URL the generated glue and `.wasm` are served from. Defaults to the
   * package's own `dist/wasm/` (or `src/wasm/` in development) relative to
   * this module.
   */
  glueBaseUrl?: string | URL
  /** Fetch implementation (defaults to the global `fetch`). */
  fetchFn?: typeof fetch
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('CopyLocker: WebCrypto SubtleCrypto is required (secure context)')
  }
  return new Uint8Array(await subtle.digest('SHA-256', bytes as unknown as ArrayBuffer))
}

/**
 * Default glue/wasm location resolved lazily through non-literal arguments
 * on purpose: bundlers statically rewrite `new URL('<dir>', import.meta.url)`
 * into an asset reference, and a *directory* URL breaks webpack/Turbopack
 * builds. Only used when the caller leaves `glueBaseUrl` unset. `moduleUrl`
 * is the calling module's `import.meta.url`.
 */
export function packageGlueBase(relativeBase: string, moduleUrl: string | URL): URL {
  return new URL(relativeBase, moduleUrl)
}

/**
 * Load the wasm-bindgen glue, instantiate the module, hash the raw bytes for
 * the two-stage transform, and open a session.
 *
 * The glue is generated by `npm run build:wasm` into `src/wasm/` and copied to
 * `dist/wasm/` by `npm run build`. The import specifier is computed at
 * runtime so the TypeScript layer compiles and tests run without the artifact.
 *
 * `cfg` may be a function of the wasm digest: the constructor configuration
 * embeds the module digest as evidence, which is only known once the bytes
 * are fetched.
 */
export async function loadWasmSession(
  cfg: Uint8Array | ((wasmDigest: Uint8Array) => Uint8Array),
  options: WasmLoadOptions = {},
): Promise<WasmSessionResources> {
  const base = options.glueBaseUrl ?? packageGlueBase('./wasm/', import.meta.url)
  const glueUrl = new URL('copylocker_wasm.js', base).href
  const wasmUrl = new URL('copylocker_wasm_bg.wasm', base).href

  const fetchFn = options.fetchFn ?? globalThis.fetch
  if (!fetchFn) throw new Error('CopyLocker: fetch is required to load the wasm module')
  const response = await fetchFn(wasmUrl)
  if (!response.ok) {
    throw new Error('CopyLocker: wasm module not found — run `npm run build:wasm` first')
  }
  const wasmBytes = new Uint8Array(await response.arrayBuffer())
  const wasmDigest = await sha256(wasmBytes)
  const cfgBytes = typeof cfg === 'function' ? cfg(wasmDigest) : cfg

  interface Glue {
    default: (input: { module_or_path: BufferSource }) => Promise<unknown>
    ClSession: new (cfg: Uint8Array) => SessionDriver
  }
  let glue: Glue
  try {
    glue = (await import(/* @vite-ignore */ glueUrl)) as Glue
  } catch {
    throw new Error('CopyLocker: wasm glue not found — run `npm run build:wasm` first')
  }
  await glue.default({ module_or_path: wasmBytes })

  let session: SessionDriver
  try {
    session = new glue.ClSession(cfgBytes)
  } catch (error) {
    if (isErrorCode(error)) throw errorFromCode(error)
    throw error
  }
  return { ops: new SessionOps(session), wasmDigest }
}
