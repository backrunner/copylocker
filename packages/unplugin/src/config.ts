/**
 * Plugin configuration surface (`50-unplugin-integrity.md §2.1`) and its
 * normalization/validation. All user-facing options live here; the rest of
 * the plugin consumes {@link ResolvedConfig} only.
 */

import { isGlob } from '@copylocker/seal'

/** Hash algorithm selection (FR-BLD-003). */
export type Hasher = 'sha256' | 'blake3' | ((bytes: Uint8Array) => Promise<Uint8Array>)

/** Signer configuration (§2.5). See `signer.ts`. */
export type SignerConfig =
  | { kind: 'local'; keyFile: string; allowLocalInProduction?: boolean }
  | { kind: 'remote'; endpoint: string; token: string; timeoutMs?: number }
  | ((tbs: Uint8Array) => Promise<Uint8Array>)

/** One `seal.assets` entry: bare globs (use the top-level feature) or scoped. */
export type SealAssetSpec = string | { globs: string[] | string; feature: string }

/** One `seal.chunks` entry: chunks whose file name matches are sealed (L3). */
export interface SealChunkSpec {
  match: RegExp | string
  feature: string
}

export interface SealConfig {
  /** Asset globs to seal into `<asset>.sealed` files in the output dir. */
  assets?: SealAssetSpec[]
  /** Default feature id for bare-string `assets` entries. */
  feature?: string
  /** L3 code-chunk sealing (opt-in, CSP `script-src blob:` trade-off). */
  chunks?: SealChunkSpec[]
  /** KEK registry path (default `.copylocker/seal-registry.json`). */
  registryFile?: string
  /** Wrapping-key file path (default `.copylocker/wrapping-key`). */
  wrappingKeyFile?: string
  /** Working directory the asset globs resolve against (default: cwd). */
  cwd?: string
}

export interface GuardConfig {
  /**
   * Reserved for `@guarded` decorator-syntax collection (M4-B). In M4-A the
   * build-time collection path is the `guardedFn('id', fn)` call form, which
   * is always collected when this config block is present.
   */
  decorator?: boolean
  /** Runtime sampling rate for guarded-function body checks (default 0.15). */
  sampleRate?: number
  /** Boot verification strategy passed to `bootGuard` (default 'idle'). */
  strategy?: 'sync' | 'idle' | 'lazy' | 'report-only'
}

export interface CopyLockerOptions {
  /** Product id bound into the manifest (required). */
  productId: string
  /** Output files to cover, matched against output-relative paths. */
  include?: string[]
  /** Output files to exclude (wins over `include`). */
  exclude?: string[]
  /** Digest algorithm; only 'sha256' is implemented in M4-A (see README). */
  hasher?: Hasher
  /** Manifest signer; omit for an unsigned development build (warned). */
  signer?: SignerConfig
  /** Hex Ed25519 public keys injected as `__CL_ROOT_PINS__`. */
  rootPins?: string[]
  /** 4-byte suite id (hex); defaults to CL-STD-1 (`01000001`). */
  suiteId?: string
  /** Reserved: custom verifier runtime (M4-B). */
  verifierRuntime?: 'default'
  /** Asset/chunk sealing via `@copylocker/seal`. */
  seal?: SealConfig
  /** Guarded-function collection + boot tuning. */
  guard?: GuardConfig
  /**
   * WASM export-name randomization (`40-web-sdk-wasm-ts.md §5`): covered
   * `.wasm` assets get seed-derived export names and every covered chunk that
   * references them (the wasm-bindgen glue) is rewritten to match.
   * Obfuscation/diversification, not cryptographic protection.
   */
  randomizeWasmExports?: boolean
  /** Split K_BUILD into N hex shards injected as `__CL_K_BUILD_<i>__`. */
  splitConstants?: number
  /**
   * Prefix for the runtime chunk URLs baked into `__CL_CHUNKS__` (the guard
   * bootstrap fetches these verbatim). The Vite adapter derives this from the
   * vite `base` config; the other adapters default to output-relative URLs.
   * Set it when the out dir is served under a sub-path — e.g. Next.js serves
   * the webpack client output (`.next/`) at `/_next/`, so pass `/_next/`.
   */
  urlBase?: string
}

export interface ResolvedSealAsset {
  globs: string[]
  feature: string
}

export interface ResolvedConfig {
  productId: string
  include: string[]
  exclude: string[]
  hasher: Exclude<Hasher, 'blake3'>
  hashAlg: string
  signer?: SignerConfig
  rootPins: string[]
  suiteId: Uint8Array
  seal?: {
    assets: ResolvedSealAsset[]
    chunks: { match: RegExp; feature: string }[]
    registryFile: string
    wrappingKeyFile: string
    cwd: string
  }
  guard: Required<Pick<GuardConfig, 'sampleRate' | 'strategy'>> & { enabled: boolean }
  randomizeWasmExports: boolean
  splitConstants: number
  /** Normalized runtime chunk-URL prefix ('' or ends with '/'). */
  urlBase: string
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ConfigError'
  }
}

function fail(message: string): never {
  throw new ConfigError(`CopyLocker unplugin: ${message}`)
}

const HEX32 = /^[0-9a-fA-F]{64}$/

export function resolveConfig(options: CopyLockerOptions): ResolvedConfig {
  if (!options || typeof options !== 'object') fail('options are required')
  if (!options.productId) fail('productId is required')

  if (options.hasher === 'blake3') {
    // The guard runtime computes SHA-256 regardless of hash_alg (documented in
    // @copylocker/guard); a blake3 manifest would verify as sha256 and break.
    fail("hasher 'blake3' is not available in M4-A — use 'sha256' or a custom function")
  }
  if (options.verifierRuntime !== undefined && options.verifierRuntime !== 'default') {
    fail("verifierRuntime other than 'default' is reserved for M4-B")
  }

  const rootPins = options.rootPins ?? []
  for (const pin of rootPins) {
    if (!HEX32.test(pin)) fail(`rootPins entries must be 64 hex characters, got '${pin}'`)
  }

  let suiteId: Uint8Array
  const suiteIdHex = options.suiteId ?? '01000001' // CL-STD-1
  if (!/^[0-9a-fA-F]{8}$/.test(suiteIdHex)) fail('suiteId must be 8 hex characters (4 bytes)')
  suiteId = new Uint8Array(4)
  for (let i = 0; i < 4; i += 1) {
    suiteId[i] = Number.parseInt(suiteIdHex.slice(i * 2, i * 2 + 2), 16)
  }

  const splitConstants = options.splitConstants ?? 1
  if (!Number.isInteger(splitConstants) || splitConstants < 1 || splitConstants > 32) {
    fail('splitConstants must be an integer between 1 and 32')
  }

  let seal: ResolvedConfig['seal']
  if (options.seal) {
    const assets: ResolvedSealAsset[] = []
    for (const spec of options.seal.assets ?? []) {
      if (typeof spec === 'string') {
        if (!options.seal.feature) {
          fail(`seal.assets entry '${spec}' needs a feature — set seal.feature or use { globs, feature }`)
        }
        assets.push({ globs: [spec], feature: options.seal.feature })
      } else {
        const globs = Array.isArray(spec.globs) ? spec.globs : [spec.globs]
        if (!spec.feature) fail('seal.assets entries need a feature id')
        assets.push({ globs, feature: spec.feature })
      }
    }
    for (const asset of assets) {
      for (const glob of asset.globs) {
        if (!isGlob(glob)) fail(`seal.assets entry '${glob}' is not a valid glob`)
      }
    }
    const chunks = (options.seal.chunks ?? []).map((spec) => {
      if (typeof spec.match !== 'string') return { match: spec.match, feature: spec.feature }
      try {
        return { match: new RegExp(spec.match), feature: spec.feature }
      } catch (error) {
        fail(
          `seal.chunks match '${spec.match}' is not a valid regular expression (${error instanceof Error ? error.message : String(error)})`,
        )
      }
    })
    seal = {
      assets,
      chunks,
      registryFile: options.seal.registryFile ?? '.copylocker/seal-registry.json',
      wrappingKeyFile: options.seal.wrappingKeyFile ?? '.copylocker/wrapping-key',
      cwd: options.seal.cwd ?? process.cwd(),
    }
  }

  if (typeof options.hasher === 'function') {
    // The guard runtime computes SHA-256 regardless of hash_alg (same
    // rationale as the blake3 rejection above): a custom hasher produces a
    // manifest this runtime cannot verify — every chunk fails closed.
    console.warn(
      "CopyLocker unplugin: a custom hasher yields a manifest the guard runtime cannot verify (it computes SHA-256) — use only with a matching custom verifier (M4-B)",
    )
  }

  return {
    productId: options.productId,
    include: options.include ?? ['**/*.js', '**/*.css', '**/*.wasm'],
    exclude: options.exclude ?? ['**/*.map'],
    hasher: options.hasher ?? 'sha256',
    hashAlg: typeof options.hasher === 'function' ? 'custom' : (options.hasher ?? 'sha256'),
    signer: options.signer,
    rootPins,
    suiteId,
    seal,
    guard: {
      enabled: true, // the bootstrap is always injected
      sampleRate: options.guard?.sampleRate ?? 0.15,
      strategy: options.guard?.strategy ?? 'idle',
    },
    randomizeWasmExports: options.randomizeWasmExports ?? false,
    splitConstants,
    urlBase:
      options.urlBase && !options.urlBase.endsWith('/')
        ? `${options.urlBase}/`
        : (options.urlBase ?? ''),
  }
}
