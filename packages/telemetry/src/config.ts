/**
 * Telemetry configuration and its fail-fast validation (FR-TLM-019).
 *
 * Illegal tier/consent/whitelist combinations throw at **initialization** —
 * they are integration bugs, and the fail-safe direction (silently not
 * reporting, or silently reporting) is exactly what a privacy feature must
 * not do by accident.
 */

import { MAX_BLOCK_BYTES, MAX_FEATURE_ID_LENGTH } from './clip.js'
import type { ConsentProvider } from './consent.js'

export class TelemetryConfigError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TelemetryConfigError'
  }
}

/**
 * Telemetry tier (`ADR-0007`):
 * - `'off'` — nothing is collected or reported; `track()`/`recordSession()` are no-ops.
 * - `'T0'`  — protocol-derived analytics only (server-side; this package stays silent).
 * - `'T1'`  — aggregate telemetry; requires `consent` and is the only tier this package emits for.
 */
export type TelemetryTier = 'off' | 'T0' | 'T1'

/** Default aggregation window: 7 days (`refresh_after`-scale). */
export const DEFAULT_WINDOW_SECS = 7 * 24 * 3600

/** Default session-duration buckets (seconds): <5m / 5–30m / 30m–2h / >2h. */
export const DEFAULT_SESSION_BUCKETS = [300, 1800, 7200] as const

/** Maximum number of whitelisted features (bounds the block size). */
export const MAX_FEATURES = 64

export interface TelemetryConfig {
  tier: TelemetryTier
  /**
   * Consent provider, called before every report; returns the consented
   * privacy-notice version (0 = no consent). **Required for `'T1'`** —
   * omitting it throws at initialization, not at runtime.
   */
  consent?: ConsentProvider
  /** Feature ids `track()` may count; anything else is dropped (or throws in `devMode`). */
  featureWhitelist?: readonly string[]
  /** Bucket upper bounds in seconds for buckets 0–2 (bucket 3 is the overflow). */
  sessionBuckets?: readonly [number, number, number]
  /** Aggregation window in seconds (default 7 days). */
  windowSecs?: number
  /** Encoded block size budget in bytes (default and maximum 512). */
  maxBlockBytes?: number
  /** Development mode: `track()` of a non-whitelisted feature throws instead of dropping it. */
  devMode?: boolean
  /** Clock override (seconds), for tests. Defaults to wall clock. */
  now?: () => number
}

export interface ResolvedTelemetryConfig {
  tier: TelemetryTier
  consent: ConsentProvider | undefined
  featureWhitelist: ReadonlySet<string>
  sessionBuckets: readonly [number, number, number]
  windowSecs: number
  maxBlockBytes: number
  devMode: boolean
  now: () => number
}

const TIERS: readonly TelemetryTier[] = ['off', 'T0', 'T1']

function fail(message: string): never {
  throw new TelemetryConfigError(`CopyLocker telemetry: ${message}`)
}

/** Validate a config, throwing {@link TelemetryConfigError} on any illegal combination. */
export function resolveConfig(config: TelemetryConfig): ResolvedTelemetryConfig {
  if (!config || !TIERS.includes(config.tier)) {
    fail(`tier must be one of ${TIERS.map((t) => `'${t}'`).join(', ')}`)
  }
  const tier = config.tier

  if (tier === 'T1') {
    if (typeof config.consent !== 'function') {
      fail("tier 'T1' requires a consent provider — reporting without consent is not possible")
    }
  } else {
    // Dead configuration is a misconfiguration: these knobs only do anything
    // under T1, so setting them under 'off'/'T0' means the integration is
    // not doing what its author thinks it does.
    if (config.consent !== undefined) {
      fail(`consent provider is meaningless with tier '${tier}' (it only applies to 'T1')`)
    }
    if (config.featureWhitelist !== undefined && config.featureWhitelist.length > 0) {
      fail(`featureWhitelist is meaningless with tier '${tier}' (it only applies to 'T1')`)
    }
  }

  const whitelist = new Set<string>()
  for (const feature of config.featureWhitelist ?? []) {
    if (typeof feature !== 'string' || feature.length === 0) {
      fail('featureWhitelist entries must be non-empty strings')
    }
    if (feature.length > MAX_FEATURE_ID_LENGTH) {
      fail(`featureWhitelist entry exceeds ${MAX_FEATURE_ID_LENGTH} characters: '${feature.slice(0, 32)}…'`)
    }
    if (whitelist.has(feature)) {
      fail(`duplicate featureWhitelist entry '${feature}'`)
    }
    whitelist.add(feature)
  }
  if (whitelist.size > MAX_FEATURES) {
    fail(`featureWhitelist is limited to ${MAX_FEATURES} entries`)
  }

  const buckets = config.sessionBuckets ?? DEFAULT_SESSION_BUCKETS
  if (
    buckets.length !== 3 ||
    !buckets.every((b) => Number.isSafeInteger(b) && b > 0) ||
    !(buckets[0] < buckets[1] && buckets[1] < buckets[2])
  ) {
    fail('sessionBuckets must be three strictly ascending positive integers (seconds)')
  }

  const windowSecs = config.windowSecs ?? DEFAULT_WINDOW_SECS
  if (!Number.isSafeInteger(windowSecs) || windowSecs <= 0) {
    fail('windowSecs must be a positive integer (seconds)')
  }

  const maxBlockBytes = config.maxBlockBytes ?? MAX_BLOCK_BYTES
  if (!Number.isSafeInteger(maxBlockBytes) || maxBlockBytes <= 0 || maxBlockBytes > MAX_BLOCK_BYTES) {
    fail(`maxBlockBytes must be a positive integer no larger than ${MAX_BLOCK_BYTES}`)
  }

  const now = config.now ?? (() => Math.floor(Date.now() / 1000))
  if (config.now !== undefined) {
    // Sample the custom clock once at initialization: a garbage clock turns
    // into a `CborError` deep in the reporting path otherwise — exactly the
    // kind of integration bug this package fails fast on.
    const sample = now()
    if (!Number.isSafeInteger(sample) || sample < 0) {
      fail('now() must return a non-negative safe integer (seconds)')
    }
  }

  return {
    tier,
    consent: config.consent,
    featureWhitelist: whitelist,
    sessionBuckets: [buckets[0], buckets[1], buckets[2]],
    windowSecs,
    maxBlockBytes,
    devMode: config.devMode ?? false,
    now,
  }
}
