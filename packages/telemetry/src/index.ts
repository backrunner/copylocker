/**
 * `@copylocker/telemetry` — the SDK side of CopyLocker T1 aggregate
 * telemetry (M6; `90-analytics-telemetry.md`, `ADR-0007`).
 *
 * T1 reports **pre-aggregated counters only** — session counts, a 4-bucket
 * duration histogram, whitelisted feature hits, active days — piggybacked on
 * the existing `/v1/validate` request (proto key 11). No event stream, no
 * timestamps, no device identifiers beyond what validation already carries.
 * Reporting requires end-user consent: the consent provider is consulted
 * before every report, and `consent_version = 0` means nothing is sent.
 *
 * ```ts
 * const telemetry = createTelemetryHook({
 *   tier: 'T1',
 *   consent: () => consentStore.get('analytics'), // privacy-notice version, 0 = no consent
 *   featureWhitelist: ['export', 'render'],
 * })
 * telemetry.track('export')
 * telemetry.recordSession(420)
 * // Pass the hook to `@copylocker/web` as `CopyLockerOptions.telemetry`;
 * // it calls buildBlock() before each /v1/validate and attaches the block.
 * ```
 */

import { encodeTelemetryBlock, type TelemetryBlock } from './block.js'
import { clipBlock } from './clip.js'
import { WindowCollector } from './collector.js'
import { resolveConfig, type TelemetryConfig } from './config.js'
import { resolveConsentVersion } from './consent.js'

export { CborError } from './cbor.js'
export { encodeTelemetryBlock, type TelemetryBlock } from './block.js'
export {
  clipBlock,
  MAX_BLOCK_BYTES,
  MAX_BUCKET_COUNT,
  MAX_DAYS_ACTIVE,
  MAX_FEATURE_HITS,
  MAX_FEATURE_ID_LENGTH,
  MAX_SESSION_COUNT,
  type ClipOptions,
  type ClipResult,
} from './clip.js'
export { WindowCollector, type WindowSnapshot } from './collector.js'
export {
  DEFAULT_SESSION_BUCKETS,
  DEFAULT_WINDOW_SECS,
  MAX_FEATURES,
  resolveConfig,
  TelemetryConfigError,
  type ResolvedTelemetryConfig,
  type TelemetryConfig,
  type TelemetryTier,
} from './config.js'
export { resolveConsentVersion, staticConsent, type ConsentProvider } from './consent.js'

/** Cumulative diagnostics counters kept by a hook (not part of the wire format). */
export interface TelemetryStats {
  /** Blocks successfully built for reporting. */
  blocksBuilt: number
  /** `buildBlock()` calls suppressed because consent was absent (`consent_version = 0`). */
  consentSkips: number
  /** Scalar fields clipped to their allowed maximum, cumulative. */
  clippedFields: number
  /** `feature_hits` entries dropped by clipping (non-whitelisted or over the size budget). */
  droppedFeatures: number
  /** `track()` calls dropped because the feature was not whitelisted (production mode). */
  droppedFeatureHits: number
}

/**
 * The object a CopyLocker host mounts as its telemetry hook
 * (`CopyLockerOptions.telemetry` in `@copylocker/web`).
 */
export interface TelemetryHook {
  /** Count a feature use (whitelisted ids only). No-op unless the tier is `'T1'`. */
  track(featureId: string): void
  /** Record a finished session with its duration in seconds. No-op unless the tier is `'T1'`. */
  recordSession(durationSecs: number): void
  /**
   * Build the CBOR `telemetry_block` for the next `/v1/validate` and reset
   * the aggregation window. Returns `undefined` when there is no consent,
   * when the tier is not `'T1'`, or when the window holds no activity.
   *
   * The reset happens at build time: if the validate request then fails on
   * the network, that window's counters are lost. T1 data is untrusted,
   * low-value aggregate — the protocol trades exactly-once delivery for not
   * adding a retry queue (or a second request) to the client.
   */
  buildBlock(now?: number): Uint8Array | undefined
  /** Cumulative diagnostics (clipped/dropped counts). */
  stats(): TelemetryStats
}

/**
 * Create the telemetry hook for a CopyLocker integration. Illegal
 * tier/consent/whitelist combinations throw {@link TelemetryConfigError}
 * immediately (FR-TLM-019).
 */
export function createTelemetryHook(config: TelemetryConfig): TelemetryHook {
  const resolved = resolveConfig(config)
  const stats: TelemetryStats = {
    blocksBuilt: 0,
    consentSkips: 0,
    clippedFields: 0,
    droppedFeatures: 0,
    droppedFeatureHits: 0,
  }

  if (resolved.tier !== 'T1') {
    // 'off' / 'T0': collection is fully disabled; every entry point is a no-op.
    return {
      track: () => {},
      recordSession: () => {},
      buildBlock: () => undefined,
      stats: () => ({ ...stats }),
    }
  }

  const collector = new WindowCollector(resolved)
  // resolveConfig guarantees the provider exists under 'T1'.
  const consent = resolved.consent as () => number

  return {
    track: (featureId: string) => collector.track(featureId),
    recordSession: (durationSecs: number) => collector.recordSession(durationSecs),
    buildBlock: (now?: number): Uint8Array | undefined => {
      // Consent is consulted before every report (privacy-and-legal-pack §5):
      // a withdrawal stops the very next upload. Counters stay local while
      // consent is absent and are reported once consent is granted.
      const consentVersion = resolveConsentVersion(consent)
      if (consentVersion === 0) {
        stats.consentSkips += 1
        return undefined
      }
      if (collector.isEmpty) return undefined
      const window = collector.takeWindow(now)
      stats.droppedFeatureHits += window.droppedFeatureHits
      const raw: TelemetryBlock = {
        consentVersion,
        windowStart: window.windowStart,
        sessionCount: window.sessionCount,
        sessionDurationHistogram: window.sessionDurationHistogram,
        featureHits: window.featureHits,
        daysActive: window.daysActive,
      }
      const clipped = clipBlock(raw, {
        featureWhitelist: resolved.featureWhitelist,
        maxBlockBytes: resolved.maxBlockBytes,
      })
      stats.clippedFields += clipped.clipped
      stats.droppedFeatures += clipped.droppedFeatures
      stats.blocksBuilt += 1
      return encodeTelemetryBlock(clipped.block)
    },
    stats: () => ({ ...stats }),
  }
}
