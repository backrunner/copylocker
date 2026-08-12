/**
 * Windowed aggregator for T1 telemetry (`90-analytics-telemetry.md` §2.6).
 *
 * Everything stays on the device as **pre-aggregated counters**: a session
 * count, a 4-bucket duration histogram, per-feature hit counts (whitelist
 * only), and a count of distinct active days (UTC). No timestamps, no event
 * order, no event stream — the aggregation window is the only time
 * resolution, and it is meant to equal `refresh_after`.
 *
 * After a window is taken for reporting, all counters reset and the next
 * window starts aligned to the `windowSecs` boundary (`window_start` is the
 * aligned start of the reported window).
 */

import { MAX_DAYS_ACTIVE } from './clip.js'
import { TelemetryConfigError, type ResolvedTelemetryConfig } from './config.js'

/** The raw counters of one aggregation window, before clipping. */
export interface WindowSnapshot {
  windowStart: number
  sessionCount: number
  sessionDurationHistogram: [number, number, number, number]
  featureHits: Record<string, number>
  daysActive: number
  /** `track()` calls dropped because the feature was not whitelisted. */
  droppedFeatureHits: number
}

const SECS_PER_DAY = 86_400

export class WindowCollector {
  private readonly config: ResolvedTelemetryConfig
  private windowStart: number
  private sessionCount = 0
  private readonly histogram: [number, number, number, number] = [0, 0, 0, 0]
  private readonly featureHits = new Map<string, number>()
  private readonly activeDays = new Set<number>()
  private droppedFeatureHits = 0

  constructor(config: ResolvedTelemetryConfig) {
    this.config = config
    this.windowStart = this.align(config.now())
  }

  /** Align a timestamp to its window boundary. */
  private align(now: number): number {
    return Math.floor(now / this.config.windowSecs) * this.config.windowSecs
  }

  /** Whether the current window holds any activity worth reporting. */
  get isEmpty(): boolean {
    return this.sessionCount === 0 && this.featureHits.size === 0 && this.activeDays.size === 0
  }

  private markActive(now: number): void {
    if (this.activeDays.size < MAX_DAYS_ACTIVE) {
      this.activeDays.add(Math.floor(now / SECS_PER_DAY))
    }
  }

  /**
   * Count a feature use. Only whitelisted feature ids are counted; anything
   * else throws in `devMode` and is silently dropped (but counted) in
   * production (`90-analytics-telemetry.md` §10).
   */
  track(featureId: string, now = this.config.now()): void {
    if (!this.config.featureWhitelist.has(featureId)) {
      this.droppedFeatureHits += 1
      if (this.config.devMode) {
        throw new TelemetryConfigError(
          `CopyLocker telemetry: track('${featureId}') — feature is not in the configured featureWhitelist`,
        )
      }
      return
    }
    this.featureHits.set(featureId, (this.featureHits.get(featureId) ?? 0) + 1)
    this.markActive(now)
  }

  /** Record a finished session with its duration in seconds. */
  recordSession(durationSecs: number, now = this.config.now()): void {
    if (!Number.isFinite(durationSecs) || durationSecs < 0) {
      throw new TelemetryConfigError('CopyLocker telemetry: recordSession() duration must be a non-negative number')
    }
    this.sessionCount += 1
    const [b0, b1, b2] = this.config.sessionBuckets
    const bucket = durationSecs < b0 ? 0 : durationSecs < b1 ? 1 : durationSecs < b2 ? 2 : 3
    this.histogram[bucket] += 1
    this.markActive(now)
  }

  /**
   * Take the current window for reporting and start a fresh one. The returned
   * `windowStart` is the aligned start of the window just closed; the new
   * window is aligned to `now`.
   */
  takeWindow(now = this.config.now()): WindowSnapshot {
    const snapshot: WindowSnapshot = {
      windowStart: this.windowStart,
      sessionCount: this.sessionCount,
      sessionDurationHistogram: [...this.histogram],
      featureHits: Object.fromEntries(this.featureHits),
      daysActive: this.activeDays.size,
      droppedFeatureHits: this.droppedFeatureHits,
    }
    // Never move the window start backwards: a regressed clock (NTP
    // correction, stale `now`) must not produce overlapping windows.
    this.windowStart = Math.max(this.align(now), this.windowStart)
    this.sessionCount = 0
    this.histogram[0] = 0
    this.histogram[1] = 0
    this.histogram[2] = 0
    this.histogram[3] = 0
    this.featureHits.clear()
    this.activeDays.clear()
    this.droppedFeatureHits = 0
    return snapshot
  }
}
