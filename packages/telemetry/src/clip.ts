/**
 * Anomaly clipping for T1 telemetry (`90-analytics-telemetry.md` §6).
 *
 * Every value in a telemetry block is **untrusted** — the server clips again
 * before projection and counts what it clipped. The SDK clips at build time
 * for the same reason it whitelists features: a poisoned or buggy integration
 * (e.g. `session_count = 10^9`) must not emit a block that distorts the
 * vendor-facing aggregates or blows the 512-byte report budget.
 *
 * The clipped/dropped counts are returned to the caller (and surfaced via the
 * hook's {@link TelemetryStats}); the proto wire format has no field for
 * them — the server keeps its own clipped counters.
 */

import { encodeTelemetryBlock, type TelemetryBlock } from './block.js'

/** Maximum plausible sessions per aggregation window (doc: `> 10000` is anomalous). */
export const MAX_SESSION_COUNT = 10_000
/** Maximum count per duration bucket. */
export const MAX_BUCKET_COUNT = 10_000
/** Maximum hits per feature per window. */
export const MAX_FEATURE_HITS = 10_000
/** `days_active` is semantically constrained to 0..=28 by the proto. */
export const MAX_DAYS_ACTIVE = 28
/** Maximum feature id length accepted into a block. */
export const MAX_FEATURE_ID_LENGTH = 64
/** Hard report-size budget (`90-analytics-telemetry.md` §2.6). */
export const MAX_BLOCK_BYTES = 512

export interface ClipOptions {
  /** Feature ids the vendor declared in the SDK config; anything else is dropped. */
  featureWhitelist: ReadonlySet<string>
  /** Encoded-size budget in bytes (default {@link MAX_BLOCK_BYTES}). */
  maxBlockBytes?: number
}

export interface ClipResult {
  block: TelemetryBlock
  /** Scalar fields clipped to their allowed maximum. */
  clipped: number
  /** `feature_hits` entries dropped (not whitelisted, or over the size budget). */
  droppedFeatures: number
}

function clipScalar(value: number, max: number): { value: number; clipped: boolean } {
  if (!Number.isSafeInteger(value) || value < 0) return { value: 0, clipped: true }
  return value > max ? { value: max, clipped: true } : { value, clipped: false }
}

/**
 * Clip a raw block into wire-safe form: scalar ceilings, feature whitelist,
 * then the encoded-size budget (lowest-priority `feature_hits` entries are
 * dropped first — lowest hit count, then lexicographically smaller id).
 */
export function clipBlock(raw: TelemetryBlock, options: ClipOptions): ClipResult {
  let clipped = 0
  let droppedFeatures = 0

  const session = clipScalar(raw.sessionCount, MAX_SESSION_COUNT)
  if (session.clipped) clipped += 1
  const days = clipScalar(raw.daysActive, MAX_DAYS_ACTIVE)
  if (days.clipped) clipped += 1

  const histogram = [0, 0, 0, 0] as [number, number, number, number]
  for (let i = 0; i < 4; i += 1) {
    const bucket = clipScalar(raw.sessionDurationHistogram[i] as number, MAX_BUCKET_COUNT)
    if (bucket.clipped) clipped += 1
    histogram[i] = bucket.value
  }

  // Null-prototype map: a whitelisted id like '__proto__' must survive the
  // round trip (bracket-assigning it on a plain object is silently ignored).
  const featureHits: Record<string, number> = Object.create(null)
  for (const [feature, count] of Object.entries(raw.featureHits)) {
    if (!options.featureWhitelist.has(feature) || feature.length > MAX_FEATURE_ID_LENGTH) {
      droppedFeatures += 1
      continue
    }
    const hits = clipScalar(count, MAX_FEATURE_HITS)
    if (hits.clipped) clipped += 1
    featureHits[feature] = hits.value
  }

  const block: TelemetryBlock = {
    consentVersion: raw.consentVersion,
    windowStart: raw.windowStart,
    sessionCount: session.value,
    sessionDurationHistogram: histogram,
    featureHits,
    daysActive: days.value,
  }

  // Size budget: drop the lowest-priority feature entries until the encoded
  // block fits. Scalars and the histogram are never dropped — the block
  // without features is ~40 bytes, far below the budget.
  const maxBytes = options.maxBlockBytes ?? MAX_BLOCK_BYTES
  const mutableHits = block.featureHits as Record<string, number>
  while (encodeTelemetryBlock(block).byteLength > maxBytes) {
    const entries = Object.entries(mutableHits)
    if (entries.length === 0) break
    entries.sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : 1))
    const victim = entries[0] as [string, number]
    delete mutableHits[victim[0]]
    droppedFeatures += 1
  }

  return { block, clipped, droppedFeatures }
}
