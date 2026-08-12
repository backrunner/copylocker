/**
 * The T1 `telemetry_block` carried at key 11 of the `/v1/validate` request
 * (`90-analytics-telemetry.md` §6). The wire layout is defined by
 * `copylocker-proto`'s `TelemetryBlock` (`crates/copylocker-proto/src/requests.rs`):
 *
 * ```cddl
 * telemetry_block = {
 *   0: uint,                     ; consent_version — 0 means no valid consent
 *   1: uint,                     ; window_start (server time of the last VT)
 *   2: uint,                     ; session_count
 *   3: [uint, uint, uint, uint], ; session_duration_histogram (4 buckets)
 *   4: { * tstr => uint },       ; feature_hits (SDK-configured whitelist only)
 *   5: uint,                     ; days_active (0..28)
 * }
 * ```
 *
 * All six keys are always present (the proto emits them unconditionally), the
 * encoding is canonical CBOR, and the block never exceeds 512 bytes on the
 * wire (`clip.ts` enforces the budget before encoding).
 */

import { encode, type CborValue } from './cbor.js'

/** Decoded form of a telemetry block. All counts are non-negative integers. */
export interface TelemetryBlock {
  /** Privacy notice version the user consented to; 0 means no valid consent. */
  consentVersion: number
  /** Start of the aggregation window (unix seconds). */
  windowStart: number
  /** Sessions observed during the window. */
  sessionCount: number
  /** Four duration-bucket counters (default: <5m / 5–30m / 30m–2h / >2h). */
  sessionDurationHistogram: readonly [number, number, number, number]
  /** Per-feature counts; keys are restricted to the configured whitelist. */
  featureHits: Readonly<Record<string, number>>
  /** Distinct active days in the window, 0..28. */
  daysActive: number
}

/** Encode a block as the canonical CBOR `telemetry_block` (proto key 11). */
export function encodeTelemetryBlock(block: TelemetryBlock): Uint8Array {
  const featureHits = new Map<string, CborValue>()
  for (const [feature, count] of Object.entries(block.featureHits)) {
    featureHits.set(feature, count)
  }
  return encode(
    new Map<number, CborValue>([
      [0, block.consentVersion],
      [1, block.windowStart],
      [2, block.sessionCount],
      [3, [...block.sessionDurationHistogram]],
      [4, featureHits],
      [5, block.daysActive],
    ]),
  )
}
