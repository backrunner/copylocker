import { isAbsolute } from 'node:path'

import {
  CopyLockerCommandError,
  HOST_INVALID_ARGUMENT,
  HOST_NOT_ENTITLED,
  HOST_TRANSIENT,
  IPC_CHANNELS,
  requireBytes,
  requireText,
  stableErrorCode,
  type IpcResult,
  type NativeState,
} from '../shared'

const MAX_KEY_BYTES = 4 * 1024
const MAX_FEATURE_BYTES = 1024
const MAX_ASSET_BYTES = 64 * 1024 * 1024
const MAX_CHALLENGE_BYTES = 64 * 1024
const MAX_OFFLINE_RESPONSE_BYTES = 1024 * 1024
const MAX_ARMORED_OLK_BYTES = 2 * 1024 * 1024
const MAX_ROOT_KEY_BYTES = 64 * 1024
const MAX_FINGERPRINT_SALT_BYTES = 64 * 1024
const MAX_PATH_BYTES = 16 * 1024

interface NativeEvidenceOptions {
  modulePath: string
  asarPath?: string
  expectedModuleDigest: Buffer
}

interface NativeConfig {
  serverUrl: string
  appId: string
  productId: string
  appVersion: string
  releaseId: string
  buildFingerprint: string
  currentRootKey: Buffer
  nextRootKey?: Buffer
  fingerprintSalt: Buffer
  variantId: number
  variantConst: Buffer
  evidence: NativeEvidenceOptions
  allowUnboundOlk?: boolean
  allowInsecureLocalhost?: boolean
}

export interface NativeClientLike {
  activate(key: string): Promise<void>
  deactivate(): Promise<void>
  state(): NativeState
  unseal(feature: string, data: Buffer): Promise<Buffer>
  challenge(input: Buffer): Promise<Buffer>
  offlineRequest(key: string): Promise<Buffer>
  offlineImport(data: Buffer): Promise<void>
  importOlk(data: string): Promise<void>
}

export interface NativeModuleLike {
  CopyLockerNative: {
    create(config: NativeConfig): Promise<NativeClientLike>
  }
  nativeBindingPath: string
}

export interface WebPreferencesLike {
  contextIsolation?: boolean
  nodeIntegration?: boolean
  sandbox?: boolean
}

export interface WebContentsLike {
  getLastWebPreferences(): WebPreferencesLike
  destroy?(): void
}

export interface FrameLike {
  parent: FrameLike | null
}

export interface InvokeEventLike {
  sender: WebContentsLike
  senderFrame: FrameLike | null
}

type IpcHandler = (event: InvokeEventLike, ...args: unknown[]) => unknown

export interface ElectronMainLike {
  app: {
    getAppPath(): string
    on(event: 'web-contents-created', listener: WebContentsCreatedListener): void
    removeListener(event: 'web-contents-created', listener: WebContentsCreatedListener): void
  }
  ipcMain: {
    handle(channel: string, handler: IpcHandler): void
    removeHandler(channel: string): void
  }
  BrowserWindow: {
    getAllWindows(): Array<{ webContents: WebContentsLike }>
  }
}

type WebContentsCreatedListener = (event: unknown, contents: WebContentsLike) => void

export interface CopyLockerConfig {
  serverUrl: string
  appId: string
  productId: string
  appVersion: string
  releaseId: string
  buildFingerprint: string
  currentRootKey: Uint8Array
  nextRootKey?: Uint8Array
  fingerprintSalt: Uint8Array
  variantId: number
  variantConst: Uint8Array
  expectedModuleDigest: Uint8Array
  modulePath?: string
  asarPath?: string
  allowUnboundOlk?: boolean
  allowInsecureLocalhost?: boolean
}

export interface RateLimitPolicy {
  windowMs?: number
  maxRequests?: number
  maxBytes?: number
}

export interface IpcPolicy {
  /** Enable activation, deactivation, and offline credential management. Defaults to true. */
  allowActivation?: boolean
  /** Features that renderer processes may unseal. Empty by default. */
  allowedFeatures?: readonly string[]
  /** Challenge is opaque and cannot be feature-filtered, so it is disabled by default. */
  allowChallenge?: boolean
  rateLimit?: RateLimitPolicy
}

export interface CopyLockerDependencies {
  native?: NativeModuleLike
  electron?: ElectronMainLike
  now?: () => number
}

interface NormalizedPolicy {
  allowActivation: boolean
  allowedFeatures: ReadonlySet<string>
  allowChallenge: boolean
  windowMs: number
  maxRequests: number
  maxBytes: number
}

interface RateBucket {
  startedAt: number
  requests: number
  bytes: number
}

class HostBoundaryError extends Error {
  readonly code: number

  constructor(code: number) {
    super(`CL:${code}`)
    this.code = code
  }
}

export class SecurityConfigurationError extends Error {
  readonly code = HOST_NOT_ENTITLED

  constructor() {
    super(
      'CopyLocker requires contextIsolation=true, nodeIntegration=false, and sandbox=true',
    )
    this.name = 'SecurityConfigurationError'
  }
}

class RateLimiter {
  readonly #policy: NormalizedPolicy
  readonly #now: () => number
  readonly #buckets = new WeakMap<object, RateBucket>()

  constructor(policy: NormalizedPolicy, now: () => number) {
    this.#policy = policy
    this.#now = now
  }

  consume(sender: object, bytes: number): void {
    const now = this.#now()
    let bucket = this.#buckets.get(sender)
    if (!bucket || now - bucket.startedAt >= this.#policy.windowMs) {
      bucket = { startedAt: now, requests: 0, bytes: 0 }
      this.#buckets.set(sender, bucket)
    }
    if (
      bucket.requests >= this.#policy.maxRequests ||
      bytes > this.#policy.maxBytes - bucket.bytes
    ) {
      throw new HostBoundaryError(HOST_TRANSIENT)
    }
    bucket.requests += 1
    bucket.bytes += bytes
  }
}

export class CopyLocker {
  readonly #native: NativeClientLike
  readonly #electron: ElectronMainLike
  readonly #now: () => number
  #detachIpc: (() => void) | undefined

  private constructor(
    native: NativeClientLike,
    electron: ElectronMainLike,
    now: () => number,
  ) {
    this.#native = native
    this.#electron = electron
    this.#now = now
  }

  static async create(
    config: CopyLockerConfig,
    dependencies: CopyLockerDependencies = {},
  ): Promise<CopyLocker> {
    const nativeModule = dependencies.native ?? loadNativeModule()
    const electron = dependencies.electron ?? loadElectron()
    const nativeConfig = buildNativeConfig(config, nativeModule, electron)
    try {
      const native = await nativeModule.CopyLockerNative.create(nativeConfig)
      return new CopyLocker(native, electron, dependencies.now ?? Date.now)
    } catch (error) {
      throw new CopyLockerCommandError(stableErrorCode(error))
    }
  }

  /** Register the fixed IPC surface. Returns an idempotent detach callback. */
  attachIpc(policy: IpcPolicy = {}): () => void {
    if (this.#detachIpc) {
      throw new Error('CopyLocker IPC is already attached')
    }
    const normalized = normalizePolicy(policy)
    const limiter = new RateLimiter(normalized, this.#now)
    for (const window of this.#electron.BrowserWindow.getAllWindows()) {
      assertSecureWebContents(window.webContents)
    }

    const onWebContentsCreated: WebContentsCreatedListener = (_event, contents) => {
      try {
        assertSecureWebContents(contents)
      } catch (error) {
        contents.destroy?.()
        throw error
      }
    }
    this.#electron.app.on('web-contents-created', onWebContentsCreated)

    const handlers = this.#handlers(normalized, limiter)
    const registered: string[] = []
    const detach = (): void => {
      for (const channel of registered.splice(0)) {
        this.#electron.ipcMain.removeHandler(channel)
      }
      this.#electron.app.removeListener('web-contents-created', onWebContentsCreated)
      if (this.#detachIpc === detach) this.#detachIpc = undefined
    }

    try {
      for (const [channel, handler] of handlers) {
        this.#electron.ipcMain.handle(channel, handler)
        registered.push(channel)
      }
    } catch (error) {
      detach()
      throw error
    }
    this.#detachIpc = detach
    return detach
  }

  #handlers(policy: NormalizedPolicy, limiter: RateLimiter): Array<[string, IpcHandler]> {
    return [
      [
        IPC_CHANNELS.state,
        (event) => this.#invoke(event, limiter, 0, () => this.#native.state()),
      ],
      [
        IPC_CHANNELS.activate,
        (event, key) =>
          this.#invoke(event, limiter, inputSize(key), async () => {
            requireActivation(policy)
            await this.#native.activate(requireText(key, MAX_KEY_BYTES, 'activation key'))
          }),
      ],
      [
        IPC_CHANNELS.deactivate,
        (event) =>
          this.#invoke(event, limiter, 0, async () => {
            requireActivation(policy)
            await this.#native.deactivate()
          }),
      ],
      [
        IPC_CHANNELS.unseal,
        (event, feature, data) =>
          this.#invoke(event, limiter, inputSize(feature) + inputSize(data), async () => {
            const safeFeature = requireText(feature, MAX_FEATURE_BYTES, 'feature')
            if (!policy.allowedFeatures.has(safeFeature)) {
              throw new HostBoundaryError(HOST_NOT_ENTITLED)
            }
            const safeData = requireBytes(data, MAX_ASSET_BYTES, 'sealed asset')
            return Uint8Array.from(
              await this.#native.unseal(safeFeature, Buffer.from(safeData)),
            )
          }),
      ],
      [
        IPC_CHANNELS.challenge,
        (event, input) =>
          this.#invoke(event, limiter, inputSize(input), async () => {
            if (!policy.allowChallenge) throw new HostBoundaryError(HOST_NOT_ENTITLED)
            const safeInput = requireBytes(input, MAX_CHALLENGE_BYTES, 'challenge')
            return Uint8Array.from(await this.#native.challenge(Buffer.from(safeInput)))
          }),
      ],
      [
        IPC_CHANNELS.offlineRequest,
        (event, key) =>
          this.#invoke(event, limiter, inputSize(key), async () => {
            requireActivation(policy)
            return Uint8Array.from(
              await this.#native.offlineRequest(
                requireText(key, MAX_KEY_BYTES, 'activation key'),
              ),
            )
          }),
      ],
      [
        IPC_CHANNELS.offlineImport,
        (event, data) =>
          this.#invoke(event, limiter, inputSize(data), async () => {
            requireActivation(policy)
            const safeData = requireBytes(data, MAX_OFFLINE_RESPONSE_BYTES, 'offline response')
            await this.#native.offlineImport(Buffer.from(safeData))
          }),
      ],
      [
        IPC_CHANNELS.importOlk,
        (event, data) =>
          this.#invoke(event, limiter, inputSize(data), async () => {
            requireActivation(policy)
            await this.#native.importOlk(
              requireText(data, MAX_ARMORED_OLK_BYTES, 'offline license key'),
            )
          }),
      ],
    ]
  }

  async #invoke<T>(
    event: InvokeEventLike,
    limiter: RateLimiter,
    bytes: number,
    operation: () => T | Promise<T>,
  ): Promise<IpcResult<T>> {
    try {
      authorizeSender(event)
      limiter.consume(event.sender, bytes)
      return { ok: true, value: await operation() }
    } catch (error) {
      return {
        ok: false,
        error: {
          code: error instanceof TypeError ? HOST_INVALID_ARGUMENT : stableErrorCode(error),
        },
      }
    }
  }
}

export function assertSecureWebContents(contents: WebContentsLike): void {
  const preferences = contents.getLastWebPreferences()
  if (
    preferences.contextIsolation !== true ||
    preferences.nodeIntegration !== false ||
    preferences.sandbox !== true
  ) {
    throw new SecurityConfigurationError()
  }
}

function authorizeSender(event: InvokeEventLike): void {
  assertSecureWebContents(event.sender)
  if (!event.senderFrame || event.senderFrame.parent !== null) {
    throw new HostBoundaryError(HOST_NOT_ENTITLED)
  }
}

function requireActivation(policy: NormalizedPolicy): void {
  if (!policy.allowActivation) throw new HostBoundaryError(HOST_NOT_ENTITLED)
}

function normalizePolicy(policy: IpcPolicy): NormalizedPolicy {
  const allowedFeatures = new Set<string>()
  for (const feature of policy.allowedFeatures ?? []) {
    allowedFeatures.add(requireText(feature, MAX_FEATURE_BYTES, 'allowed feature'))
  }
  return {
    allowActivation: policy.allowActivation ?? true,
    allowedFeatures,
    allowChallenge: policy.allowChallenge ?? false,
    windowMs: positiveInteger(policy.rateLimit?.windowMs ?? 60_000, 'rate window'),
    maxRequests: positiveInteger(policy.rateLimit?.maxRequests ?? 120, 'request limit'),
    maxBytes: positiveInteger(policy.rateLimit?.maxBytes ?? 8 * 1024 * 1024, 'byte limit'),
  }
}

function positiveInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`Invalid ${field}`)
  return value
}

function inputSize(value: unknown): number {
  if (typeof value === 'string') return new TextEncoder().encode(value).byteLength
  if (value instanceof Uint8Array) return value.byteLength
  return 0
}

function buildNativeConfig(
  config: CopyLockerConfig,
  nativeModule: NativeModuleLike,
  electron: ElectronMainLike,
): NativeConfig {
  const serverUrl = requireText(config.serverUrl, 4 * 1024, 'server URL')
  const appId = requireText(config.appId, 128, 'application ID')
  const productId = requireText(config.productId, 128, 'product ID')
  const appVersion = requireText(config.appVersion, 1024, 'application version')
  const releaseId = requireText(config.releaseId, 1024, 'release ID')
  const buildFingerprint = requireText(config.buildFingerprint, 1024, 'build fingerprint')
  const currentRootKey = requireBytes(config.currentRootKey, MAX_ROOT_KEY_BYTES, 'Root key')
  const nextRootKey = config.nextRootKey
    ? requireBytes(config.nextRootKey, MAX_ROOT_KEY_BYTES, 'next Root key')
    : undefined
  const fingerprintSalt = requireBytes(
    config.fingerprintSalt,
    MAX_FINGERPRINT_SALT_BYTES,
    'fingerprint salt',
  )
  const variantConst = fixedBytes(config.variantConst, 32, 'variant constant')
  const expectedModuleDigest = fixedBytes(
    config.expectedModuleDigest,
    32,
    'expected module digest',
  )
  if (!Number.isSafeInteger(config.variantId) || config.variantId < 0 || config.variantId > 0xffff_ffff) {
    throw new TypeError('Invalid variant ID')
  }
  const modulePath = requireAbsolutePath(
    config.modulePath ?? nativeModule.nativeBindingPath,
    'native module path',
  )
  const appPath = electron.app.getAppPath()
  const inferredAsar = appPath.endsWith('.asar') ? appPath : undefined
  const asarPath = config.asarPath ?? inferredAsar

  return {
    serverUrl,
    appId,
    productId,
    appVersion,
    releaseId,
    buildFingerprint,
    currentRootKey: Buffer.from(currentRootKey),
    nextRootKey: nextRootKey ? Buffer.from(nextRootKey) : undefined,
    fingerprintSalt: Buffer.from(fingerprintSalt),
    variantId: config.variantId,
    variantConst: Buffer.from(variantConst),
    evidence: {
      modulePath,
      asarPath: asarPath ? requireAbsolutePath(asarPath, 'ASAR path') : undefined,
      expectedModuleDigest: Buffer.from(expectedModuleDigest),
    },
    allowUnboundOlk: config.allowUnboundOlk,
    allowInsecureLocalhost: config.allowInsecureLocalhost,
  }
}

function fixedBytes(value: unknown, length: number, field: string): Uint8Array {
  const bytes = requireBytes(value, length, field)
  if (bytes.byteLength !== length) throw new TypeError(`Invalid ${field}`)
  return bytes
}

function requireAbsolutePath(value: unknown, field: string): string {
  const path = requireText(value, MAX_PATH_BYTES, field)
  if (!isAbsolute(path)) throw new TypeError(`Invalid ${field}`)
  return path
}

function loadNativeModule(): NativeModuleLike {
  return require('@copylocker/node') as NativeModuleLike
}

function loadElectron(): ElectronMainLike {
  return require('electron') as ElectronMainLike
}
