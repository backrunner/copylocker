/**
 * `@copylocker/web` — the CopyLocker Web SDK (M3).
 *
 * The TypeScript shell over the `copylocker-wasm` core: it owns scheduling,
 * transport, storage, environment probes, the second stage of the key
 * transform, and asset unsealing (design `40-web-sdk-wasm-ts.md §2/§4`).
 *
 * There is deliberately **no** `isLicensed()` / `check(): boolean` surface.
 * The only "use the license" entry point is {@link CopyLocker.unseal}.
 */

import {
  resolveBuildConstants,
  resolveExpectedWasmDigest,
  resolveManifestRoot,
  resolveRequireIntegrityProof,
  deriveFinalKey,
  type BuildConstants,
  type IntegrityHooks,
} from './derive.js'
import { decode } from './cbor.js'
import { CopyLockerError, errorFromCode, isErrorCode, ERR_DERIVATION, ERR_NO_CREDENTIAL, ERR_NOT_ENTITLED } from './errors.js'
import { collectFingerprint, type FingerprintNavigator } from './fingerprint.js'
import { Scheduler, type TriggerReason } from './scheduler.js'
import {
  EFFECT_PERSIST,
  EFFECT_SCHEDULE_WAKE,
  EFFECT_SEND_VALIDATION,
  EFFECT_STATE_CHANGED,
  EFFECT_WIPE_ALL,
  EVENT_APP_RESUMED,
  EVENT_NETWORK_AVAILABLE,
  EVENT_NETWORK_FAILED,
  EVENT_TICK,
  EVENT_USER_DEACTIVATE,
  SESSION_OFFLINE,
  SESSION_ONLINE,
  encodeSessionConfig,
  loadWasmSession,
  SessionOps,
  type SessionDriver,
  type Summary,
} from './session.js'
import { createSnapshotStore, type SnapshotStore } from './storage.js'
import { Transport, TransportError } from './transport.js'
import { openSealedAsset } from './unseal.js'
import {
  openWorkerSession,
  type WorkerFactory,
  type WorkerSessionClient,
} from './worker/client.js'

export { CopyLockerError, errorFromCode } from './errors.js'
export type { ErrorKind } from './errors.js'
export {
  MalformedError,
  ConfigError,
  EntropyError,
  LifecycleError,
  NotEntitledError,
  FatalLicenseError,
} from './errors.js'
export { wrapFetch } from './scheduler.js'
export { TransportError } from './transport.js'
export { UnsealError, sealAsset, openSealedAsset, decodeSealedAsset } from './unseal.js'
export type { Chunking, SealedAssetMeta } from './unseal.js'
export type { BuildConstants, IntegrityHooks } from './derive.js'
export type { AsyncSessionDriver, SessionDriver } from './session.js'
export type { WorkerFactory, WorkerPortLike } from './worker/client.js'

/**
 * Optional T1 aggregate telemetry hook (M6; `90-analytics-telemetry.md` §6).
 * Implementations come from `@copylocker/telemetry` (`createTelemetryHook`),
 * but the shape is structural so the dependency stays optional. When no
 * hook is configured, validate requests carry no telemetry at all.
 */
export interface TelemetryHooks {
  /**
   * Called immediately before each `/v1/validate`. Return the canonical CBOR
   * `telemetry_block` or `undefined` to send none. The block is passed into
   * the `build-validate-request` op and embedded at proto key 11 *before*
   * the request is signed, so the device proof covers it. Telemetry is
   * best-effort: a throwing or malformed hook never breaks validation — the
   * request goes out without the block.
   */
  buildBlock(now: number): Uint8Array | undefined
}

/** Advisory license state names, mirroring the wasm numeric state codes. */
export type LicenseState =
  | 'unlicensed'
  | 'activating'
  | 'active'
  | 'needs-revalidation'
  | 'grace'
  | 'locked'
  | 'revoked'
  | 'tampered'

const STATE_NAMES: readonly LicenseState[] = [
  'unlicensed',
  'activating',
  'active',
  'needs-revalidation',
  'grace',
  'locked',
  'revoked',
  'tampered',
]

const SDK_VERSION = '0.1.0'
/**
 * Maximum telemetry_block byte length (`90-analytics-telemetry.md §2.6`,
 * `MAX_TELEMETRY_BLOCK_BYTES` in copylocker-proto). Larger hook output is
 * dropped before it reaches the signing core.
 */
const MAX_TELEMETRY_BLOCK_BYTES = 512
/** CL-STD-1 suite id (`copylocker-suite-std::CL_STD_1_SUITE_ID`, big-endian 0x01000001). */
const CL_STD_1 = new Uint8Array([0x01, 0x00, 0x00, 0x01])

function unixNow(): number {
  return Math.floor(Date.now() / 1000)
}

function decodeHex(value: string, field: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(value)) {
    throw new TypeError(`CopyLocker: ${field} must be hex-encoded`)
  }
  const bytes = new Uint8Array(value.length / 2)
  for (let i = 0; i < bytes.byteLength; i += 1) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

export interface CopyLockerOptions {
  /** Base URL of the CopyLocker Worker, e.g. `https://license.example.com`. */
  serverUrl: string
  productId: string
  /**
   * Pinned root verifying keys, hex-encoded, build-time injected. The first
   * entry is the current root; an optional second entry pins the successor.
   */
  rootPins: string[]
  storage?: 'indexeddb' | 'memory'
  /**
   * Worker isolation (FR-WEB-008), default true: the wasm core runs inside a
   * dedicated Web Worker and the main thread talks to it in opaque byte
   * frames. When no Worker is available (or construction fails) the core
   * falls back to the main thread and `degradedFlags.worker` is set.
   */
  worker?: boolean
  privacy?: {
    /** Reserved; the web shell never reports raw device attributes. */
    reportAttrs?: boolean
    /** Canvas/WebGL probing. Default false (FR-WEB-006). */
    canvasFingerprint?: boolean
  }
  onStateChange?: (s: LicenseState) => void

  /**
   * T1 aggregate telemetry hook (`@copylocker/telemetry`). When provided, the
   * block it builds is attached to `/v1/validate` requests at proto key 11 —
   * piggybacked, no extra request. Default: no telemetry.
   */
  telemetry?: TelemetryHooks

  /** Build-constant override (defaults to the M4 injection points, then zeros). */
  buildConstants?: Partial<BuildConstants>
  /**
   * M4 runtime integrity hook (`@copylocker/guard`). When `manifestRoot` is
   * provided, its actually-computed root `R` is used for key derivation in
   * place of the injected `MANIFEST_ROOT` constant — so a tampered bundle
   * derives a different `FinalKey` and sealed assets fail to open.
   */
  integrity?: IntegrityHooks
  /**
   * Fail-closed integrity proof (M4-A). When true, key derivation REQUIRES
   * the actually-computed guard root `R`: if `integrity.manifestRoot` is not
   * configured or yields `undefined` (the guard bootstrap was deleted or
   * never ran), derivation throws instead of falling back to the injected
   * `MANIFEST_ROOT` constant. Defaults to the `__CL_REQUIRE_INTEGRITY_PROOF__`
   * build constant injected by `@copylocker/unplugin` (true when the guard
   * bootstrap is part of the build), so unplugin-built apps get the strict
   * semantics without setting anything.
   */
  requireIntegrityProof?: boolean
  /** 32-byte build-time variant constant (defaults to all zeros). */
  variantConst?: Uint8Array
  /** Build fingerprint string (== evidence), build-time injected. */
  buildFingerprint?: string
  appVersion?: string
  releaseId?: string
  variantId?: number
  minValidationIntervalSecs?: number

  /** Base URL the wasm glue is served from (defaults to the bundled copy). */
  glueBaseUrl?: string | URL
  /**
   * Testing/advanced seam: override Worker construction for `worker: true`
   * (e.g. a fake port wired to the entry handler). Defaults to
   * `new Worker(new URL('./worker/entry.js', import.meta.url), { type: 'module' })`.
   */
  workerFactory?: WorkerFactory
  /** Testing seam: skip wasm loading and drive a mock session. */
  sessionDriver?: SessionDriver
  /** Wasm digest to use with `sessionDriver` (defaults to all zeros). */
  wasmDigest?: Uint8Array
  fetchFn?: typeof fetch
  indexedDB?: IDBFactory
  navigatorObj?: FingerprintNavigator
  localStorage?: Storage
  /** Periodic scheduler tick in milliseconds (default 60s). */
  schedulerIntervalMs?: number
}

/** Environment degradations recorded at create() time. */
export interface DegradedFlags {
  /** IndexedDB unavailable (or `storage: 'memory'`): re-activation per load. */
  storage: boolean
  /** Worker isolation requested but not active (main-thread/mock fallback). */
  worker: boolean
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false
  let diff = 0
  for (let i = 0; i < a.byteLength; i += 1) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}

export class CopyLocker {
  private readonly ops: SessionOps
  private readonly transport: Transport
  private readonly store: SnapshotStore
  private readonly scheduler: Scheduler
  private readonly constants: BuildConstants
  private readonly integrity: IntegrityHooks | undefined
  private readonly telemetry: TelemetryHooks | undefined
  private readonly requireIntegrityProof: boolean
  private readonly wasmDigest: Uint8Array
  private readonly productId: string
  private readonly fetchFn: typeof fetch | undefined
  private readonly listeners = new Set<(s: LicenseState) => void>()
  private advisoryState: LicenseState = 'unlicensed'
  private nextCheckAt = 0
  private validating: Promise<void> | null = null
  private stopped = false
  private readonly workerClient: WorkerSessionClient | null

  readonly degradedFlags: DegradedFlags

  private constructor(
    options: CopyLockerOptions,
    ops: SessionOps,
    wasmDigest: Uint8Array,
    store: SnapshotStore,
    workerClient: WorkerSessionClient | null,
  ) {
    this.ops = ops
    this.wasmDigest = wasmDigest
    this.store = store
    this.workerClient = workerClient
    this.productId = options.productId
    this.fetchFn = options.fetchFn
    this.transport = new Transport(options.serverUrl, { fetchFn: options.fetchFn })
    this.constants = resolveBuildConstants(options.buildConstants)
    this.integrity = options.integrity
    this.telemetry = options.telemetry
    this.requireIntegrityProof = resolveRequireIntegrityProof(options.requireIntegrityProof)
    this.degradedFlags = {
      storage: store.degraded,
      worker: options.worker !== false && workerClient === null,
    }
    this.scheduler = new Scheduler(
      { onTrigger: (reason) => void this.onTrigger(reason) },
      { intervalMs: options.schedulerIntervalMs },
    )
    if (options.onStateChange) this.listeners.add(options.onStateChange)
  }

  /**
   * Create a client-side instance. Requires a browser environment — during
   * SSR import `@copylocker/web/ssr` instead and only call this on the
   * client (see README "SSR").
   */
  static async create(options: CopyLockerOptions): Promise<CopyLocker> {
    if (!options.serverUrl || !options.productId || options.rootPins.length === 0) {
      throw new TypeError('CopyLocker: serverUrl, productId and rootPins are required')
    }
    if (
      options.sessionDriver === undefined &&
      options.workerFactory === undefined &&
      typeof window === 'undefined'
    ) {
      throw new Error(
        'CopyLocker: create() requires a browser environment — during SSR import `@copylocker/web/ssr` and call create() on the client only',
      )
    }
    const fingerprint = await collectFingerprint({
      navigator: options.navigatorObj,
      storage: options.localStorage,
      privacy: options.privacy,
    })
    const store = createSnapshotStore({
      storage: options.storage,
      indexedDB: options.indexedDB,
    })

    const cfgFor = (moduleDigest: Uint8Array): Uint8Array =>
      encodeSessionConfig({
        productId: options.productId,
        rootCurrent: decodeHex(options.rootPins[0] as string, 'rootPins[0]'),
        rootNext:
          options.rootPins.length > 1
            ? decodeHex(options.rootPins[1] as string, 'rootPins[1]')
            : undefined,
        fingerprint: fingerprint.digest,
        variantConst: options.variantConst ?? new Uint8Array(32),
        moduleDigest,
        buildFingerprint: options.buildFingerprint ?? 'dev',
        appVersion: options.appVersion ?? '0.0.0',
        sdkVersion: SDK_VERSION,
        os: 'web',
        arch: 'wasm32',
        releaseId: options.releaseId ?? 'dev',
        variantId: options.variantId ?? 0,
        supportedSuites: [CL_STD_1],
        minValidationIntervalSecs: options.minValidationIntervalSecs,
        now: unixNow(),
      })

    let ops: SessionOps
    let wasmDigest: Uint8Array
    let workerClient: WorkerSessionClient | null = null
    // Worker isolation (FR-WEB-008), default on. A `sessionDriver` testing
    // seam replaces the backend outright, so the Worker is only attempted
    // for real wasm sessions (or when a test injects its own workerFactory).
    const attemptWorker =
      options.worker !== false &&
      (options.workerFactory !== undefined ||
        (options.sessionDriver === undefined && typeof Worker !== 'undefined'))
    if (attemptWorker) {
      try {
        workerClient = await openWorkerSession(cfgFor, {
          glueBaseUrl: options.glueBaseUrl,
          fetchFn: options.fetchFn,
          workerFactory: options.workerFactory,
        })
      } catch {
        // Degrade to the main thread (design §4.2); flagged in degradedFlags.
        workerClient = null
      }
    }
    if (workerClient) {
      ops = new SessionOps(workerClient)
      wasmDigest = workerClient.wasmDigest
    } else if (options.sessionDriver) {
      ops = new SessionOps(options.sessionDriver)
      wasmDigest = options.wasmDigest ?? new Uint8Array(32)
      // The constructor configuration still runs through the mock so tests
      // exercise the same encoding path.
      options.sessionDriver.step(cfgFor(wasmDigest))
    } else {
      const loaded = await loadWasmSession(cfgFor, {
        glueBaseUrl: options.glueBaseUrl,
        fetchFn: options.fetchFn,
      })
      ops = loaded.ops
      wasmDigest = loaded.wasmDigest
    }

    // WASM_DIGEST comparison (`40-web-sdk-wasm-ts.md §5`): when the unplugin
    // injected the build-time digest of the .wasm artifact, the bytes that
    // were actually loaded must match it. A swapped or patched wasm fails
    // closed here with the same indistinguishable error the wasm core uses
    // for forbidden derivations (NFR-SEC-011) — before any key material
    // exists. No injected constant (dev build) → no comparison.
    const expectedWasmDigest = resolveExpectedWasmDigest()
    if (expectedWasmDigest !== undefined && !bytesEqual(expectedWasmDigest, wasmDigest)) {
      workerClient?.dispose() // do not leak the spawned Worker on the way out
      throw errorFromCode(ERR_DERIVATION)
    }

    const client = new CopyLocker(options, ops, wasmDigest, store, workerClient)
    try {
      await client.restore()
    } catch (error) {
      workerClient?.dispose()
      throw error
    }
    client.scheduler.start()
    return client
  }

  /** Restore the persisted snapshot, or start a fresh device. */
  private async restore(): Promise<void> {
    const now = unixNow()
    let summary: Summary
    let blob: Uint8Array | null = null
    try {
      blob = await this.store.load()
    } catch {
      // A snapshot that cannot even be loaded (undecryptable ciphertext from a
      // previous session's memory-only wrap key, tampered IDB contents, or a
      // failing store) is no snapshot: fail closed — wipe, start fresh.
      await this.store.clear().catch(() => {})
    }
    if (blob) {
      try {
        summary = (await this.ops.snapshotImport(blob, now)).summary
      } catch {
        // Unusable snapshot: fail closed, wipe, start fresh.
        await this.store.clear()
        summary = await this.freshDevice(now)
      }
    } else {
      summary = await this.freshDevice(now)
    }
    this.adopt(summary)
  }

  private async freshDevice(now: number): Promise<Summary> {
    const summary = (await this.ops.deviceKeygen()).summary
    void this.persistSnapshot()
    return summary
  }

  /** Activate with a license key. */
  async activate(key: string): Promise<void> {
    if (!key) throw new TypeError('CopyLocker: license key is required')
    await this.activateWith({ licenseKey: key })
  }

  /** Activate with an account token. */
  async activateWithAccount(token: string): Promise<void> {
    if (!token) throw new TypeError('CopyLocker: account token is required')
    await this.activateWith({ accountToken: new TextEncoder().encode(token) })
  }

  private async activateWith(
    credential: { licenseKey: string } | { accountToken: Uint8Array },
  ): Promise<void> {
    const now = unixNow()
    this.adopt((await this.ops.ingestKeyset(await this.transport.getKeyset(), now)).summary)
    const body = await this.ops.buildActivateRequest(credential, now)
    const response = await this.transport.activate(body)
    this.adopt((await this.ops.ingestActivateResponse(response, unixNow())).summary)
    // The core never emits EFFECT_PERSIST (host-owned store, as in the
    // native client): persist the newly credentialed session explicitly, or a
    // reload would silently fall back to unlicensed.
    await this.persistSnapshot()
  }

  /** Deactivate: server acknowledgement first, then the local wipe. */
  async deactivate(): Promise<void> {
    const now = unixNow()
    const body = await this.ops.buildDeactivateRequest(now)
    await this.transport.deactivate(body)
    this.adopt((await this.ops.event(EVENT_USER_DEACTIVATE, unixNow())).summary)
  }

  /**
   * The only "use the license" entry point: derive `M` inside the core,
   * complete the two-stage transform, and open the sealed asset. Throws
   * `NotEntitledError` when the feature is not available, and `UnsealError`
   * when the container does not authenticate.
   */
  async unseal(featureId: string, sealed: BufferSource): Promise<Uint8Array> {
    if (!featureId) throw new TypeError('CopyLocker: featureId is required')
    // BufferSource includes DataView and non-byte typed arrays: respect the
    // view's byte window — `new Uint8Array(view)` would silently produce an
    // empty (DataView) or element-wise truncated (Int16Array) copy.
    const bytes =
      sealed instanceof Uint8Array
        ? sealed
        : ArrayBuffer.isView(sealed)
          ? new Uint8Array(sealed.buffer, sealed.byteOffset, sealed.byteLength)
          : new Uint8Array(sealed)
    const now = unixNow()
    // Instrumentation trigger (design §4.3): a stale session revalidates in
    // the background; unseal itself is never blocked by the network.
    if (this.nextCheckAt > 0 && now >= this.nextCheckAt) {
      this.validateInBackground()
    }
    const m = await this.deriveMaterial(featureId, now)
    // The guard's actually-computed R wins over the injected constant when
    // the M4 integrity hook is configured (design §6: removing the guard
    // removes R, and without R nothing unseals). With requireIntegrityProof
    // (the unplugin default) a missing R fails closed instead of falling back.
    const manifestRoot = await resolveManifestRoot(
      this.integrity,
      this.constants.manifestRoot,
      this.requireIntegrityProof,
    )
    const finalKey = await deriveFinalKey(m, { ...this.constants, manifestRoot }, this.wasmDigest)
    return openSealedAsset(finalKey, bytes, { productId: this.productId, featureId })
  }

  /**
   * Fetch and unseal an asset processed by `@copylocker/seal` (design §4.1).
   *
   * The per-feature asset KEK is unwrapped inside the core from the
   * credential's or the latest ticket's `wrapped_keks` (the `unseal-asset` op
   * — the web half of the desktop `CopyLockerClient::unseal`); the web v1
   * container is then opened with it here. The wrap itself binds the release's
   * variant, build fingerprint, and wasm-digest evidence, so a build the KEK
   * was not wrapped for unwraps nothing. Use {@link CopyLocker.unseal} for
   * assets sealed against a session `FinalKey` (the two-stage transform).
   *
   * Throws `NotEntitledError` when the feature is not available (or no
   * credential is installed), `TransportError` when the fetch fails, and
   * `UnsealError` when the container does not authenticate.
   */
  async loadSealed(url: string, featureId: string): Promise<Uint8Array> {
    if (!featureId) throw new TypeError('CopyLocker: featureId is required')
    const fetchFn = this.fetchFn ?? globalThis.fetch
    if (!fetchFn) throw new Error('CopyLocker: fetch is required')
    const now = unixNow()
    // Instrumentation trigger (design §4.3), same as unseal().
    if (this.nextCheckAt > 0 && now >= this.nextCheckAt) {
      this.validateInBackground()
    }
    // The same fail-closed integrity gate as unseal(): when the build requires
    // the guard's proof (`requireIntegrityProof`), a missing R kills the KEK
    // path too — deleting the guard cannot turn loadSealed into an oracle.
    await resolveManifestRoot(
      this.integrity,
      this.constants.manifestRoot,
      this.requireIntegrityProof,
    )
    const kek = await this.unwrapAssetKek(featureId, now)
    const response = await fetchFn(url)
    if (!response.ok) throw new TransportError(response.status, 'CopyLocker: asset fetch failed')
    const sealed = new Uint8Array(await response.arrayBuffer())
    return openSealedAsset(kek, sealed, {
      productId: this.productId,
      featureId,
    })
  }

  /**
   * @deprecated for gating — advisory only
   *
   * The last known advisory state, for UI display. It can be stale, spoofed,
   * or bypassed; never branch entitlement logic on it (ADR-0004).
   */
  get state(): LicenseState {
    return this.advisoryState
  }

  /** Subscribe to advisory state changes. Returns an unsubscribe function. */
  onStateChange(listener: (s: LicenseState) => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  /** Report connectivity; schedules a validation when one is due. */
  hintOnline(): void {
    this.scheduler.hintOnline()
  }

  /** Stop the scheduler and terminate the session Worker, when one runs. */
  dispose(): void {
    this.stopped = true
    this.scheduler.stop()
    this.workerClient?.dispose()
  }

  // --- internals -------------------------------------------------------------

  /**
   * Unwrap the per-feature asset KEK inside the core (the `unseal-asset` op).
   * No credential, an unentitled feature, and a failed unwrap collapse onto
   * the same indistinguishable `NotEntitledError` (mirrors `unseal()`).
   */
  private async unwrapAssetKek(featureId: string, now: number): Promise<Uint8Array> {
    try {
      const result = await this.ops.unsealAsset(featureId, now)
      this.adopt(result.summary)
      if (!result.payload || result.payload.byteLength !== 32) {
        throw new TypeError('CopyLocker: invalid unseal result')
      }
      return result.payload
    } catch (error) {
      if (
        error instanceof CopyLockerError &&
        (error.code === ERR_DERIVATION ||
          error.code === ERR_NO_CREDENTIAL ||
          error.code === ERR_NOT_ENTITLED)
      ) {
        throw errorFromCode(ERR_NOT_ENTITLED)
      }
      throw error
    }
  }

  private async deriveMaterial(featureId: string, now: number): Promise<Uint8Array> {
    // Prefer the online session root; fall back to offline when no online
    // root is armed. Both failures surface the same indistinguishable error.
    for (const kind of [SESSION_ONLINE, SESSION_OFFLINE]) {
      try {
        const result = await this.ops.deriveM(featureId, kind, now)
        this.adopt(result.summary)
        if (!result.payload || result.payload.byteLength !== 32) {
          throw new TypeError('CopyLocker: invalid derivation result')
        }
        return result.payload
      } catch (error) {
        // No credential at all (ERR_NO_CREDENTIAL), an unentitled feature
        // (ERR_NOT_ENTITLED), and a missing session root (ERR_DERIVATION)
        // must surface as the same indistinguishable NotEntitledError.
        if (
          error instanceof CopyLockerError &&
          (error.code === ERR_DERIVATION ||
            error.code === ERR_NO_CREDENTIAL ||
            error.code === ERR_NOT_ENTITLED)
        ) {
          continue
        }
        throw error
      }
    }
    throw errorFromCode(ERR_DERIVATION)
  }

  private async validateNow(): Promise<void> {
    if (this.validating || this.stopped) return this.validating ?? undefined
    this.validating = (async () => {
      const now = unixNow()
      try {
        const body = await this.ops.buildValidateRequest(now, this.buildTelemetryBlock(now))
        const response = await this.transport.validate(body)
        this.adopt((await this.ops.ingestValidateResponse(response, unixNow())).summary)
        // A fresh ticket moves the deadlines and watermarks; keep the stored
        // snapshot in step (the core does not emit EFFECT_PERSIST itself).
        void this.persistSnapshot()
      } catch (error) {
        if (error instanceof TransportError) {
          this.adopt((await this.ops.event(EVENT_NETWORK_FAILED, unixNow())).summary)
        } else if (isErrorCode(error)) {
          // Lifecycle errors (e.g. no credential yet) are routine here.
          if (error >= 100) throw errorFromCode(error)
        } else {
          throw error
        }
      }
    })().finally(() => {
      this.validating = null
    })
    return this.validating
  }

  /**
   * Fire-and-forget validation (instrumentation triggers, EFFECT_SEND_VALIDATION).
   * A fatal core error is deliberately swallowed here: the rejection would
   * otherwise be an unhandled promise rejection, and the state machine has
   * already recorded everything actionable.
   */
  private validateInBackground(): void {
    void this.validateNow()?.catch(() => {})
  }

  /**
   * Build the T1 telemetry block handed to the `build-validate-request` op,
   * so the core embeds it at proto key 11 *before* signing. Best-effort: any
   * hook or decoding failure yields `undefined` — telemetry must never break
   * licensing. Oversized blocks and blocks that are not a canonical CBOR map
   * are dropped here too, so the core never rejects the request over
   * telemetry.
   */
  private buildTelemetryBlock(now: number): Uint8Array | undefined {
    if (!this.telemetry) return undefined
    try {
      const block = this.telemetry.buildBlock(now)
      if (!block || block.byteLength === 0 || block.byteLength > MAX_TELEMETRY_BLOCK_BYTES) {
        return undefined
      }
      if (!(decode(block) instanceof Map)) return undefined
      return block
    } catch {
      return undefined
    }
  }

  private async onTrigger(reason: TriggerReason): Promise<void> {
    if (this.stopped) return
    const now = unixNow()
    try {
      switch (reason) {
        case 'network':
        case 'hint':
          this.adopt((await this.ops.event(EVENT_NETWORK_AVAILABLE, now)).summary)
          break
        case 'resume':
          this.adopt((await this.ops.event(EVENT_APP_RESUMED, now, this.scheduler.resumeGapMs())).summary)
          break
        case 'wake':
        case 'tick':
          this.adopt((await this.ops.event(EVENT_TICK, now)).summary)
          break
      }
    } catch {
      // Event driving is advisory; the core throttles and gates itself.
    }
  }

  /** Adopt an op summary: act on effects, update the advisory state. */
  private adopt(summary: Summary): void {
    this.nextCheckAt = summary.refreshAfter
    const next = STATE_NAMES[summary.state] ?? 'unlicensed'
    if (next !== this.advisoryState) {
      this.advisoryState = next
      for (const listener of this.listeners) {
        try {
          listener(next)
        } catch {
          // Listener failures must not break the licensing path.
        }
      }
    }
    for (const effect of summary.effects) {
      switch (effect) {
        case EFFECT_PERSIST:
          void this.persistSnapshot()
          break
        case EFFECT_SEND_VALIDATION:
          this.validateInBackground()
          break
        case EFFECT_WIPE_ALL:
          void this.enqueueStoreWrite(async () => {
            try {
              await this.store.clear()
            } catch {
              // A failing wipe degrades to "stale snapshot next load"; the
              // restore path fails closed on anything undecryptable.
            }
          })
          break
        case EFFECT_SCHEDULE_WAKE:
          if (summary.wakeAt !== undefined) {
            this.scheduler.scheduleWake(summary.wakeAt, unixNow())
          }
          break
        case EFFECT_STATE_CHANGED:
          break
        default:
          break
      }
    }
  }

  /**
   * Snapshot writes and wipes are fire-and-forget but must never land out of
   * order (a slow earlier write clobbering a later credentialed snapshot, or
   * resurrecting one after a deactivate wipe). Every store mutation is
   * serialized through this queue.
   */
  private writeQueue: Promise<void> = Promise.resolve()

  private enqueueStoreWrite(task: () => Promise<void>): Promise<void> {
    const run = this.writeQueue.then(task)
    this.writeQueue = run.catch(() => {})
    return run
  }

  private persistSnapshot(): Promise<void> {
    return this.enqueueStoreWrite(async () => {
      try {
        await this.store.save(await this.ops.snapshotExport())
      } catch {
        // Persistence failure degrades to "re-activate next load"; never fatal.
      }
    })
  }
}
