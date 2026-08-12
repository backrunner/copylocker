import { describe, expect, it } from 'vitest'
import { WindowCollector } from '../src/collector.js'
import { resolveConfig, TelemetryConfigError, type TelemetryConfig } from '../src/config.js'

function makeCollector(overrides: Partial<TelemetryConfig> = {}, now = 0) {
  const config = resolveConfig({
    tier: 'T1',
    consent: () => 1,
    featureWhitelist: ['export', 'render'],
    windowSecs: 3600,
    now: () => now,
    ...overrides,
  })
  return new WindowCollector(config)
}

describe('WindowCollector', () => {
  it('aggregates session counts and duration buckets on the boundaries', () => {
    const c = makeCollector()
    // default buckets: <300 / 300–1799 / 1800–7199 / >=7200
    for (const d of [0, 299]) c.recordSession(d)
    for (const d of [300, 1799]) c.recordSession(d)
    for (const d of [1800, 7199]) c.recordSession(d)
    for (const d of [7200, 36_000]) c.recordSession(d)
    const w = c.takeWindow(0)
    expect(w.sessionCount).toBe(8)
    expect(w.sessionDurationHistogram).toEqual([2, 2, 2, 2])
  })

  it('counts whitelisted features and drops others (production mode)', () => {
    const c = makeCollector()
    c.track('export')
    c.track('export')
    c.track('render')
    c.track('debug-console') // not whitelisted: silently dropped, counted
    const w = c.takeWindow(0)
    expect(w.featureHits).toEqual({ export: 2, render: 1 })
    expect(w.droppedFeatureHits).toBe(1)
  })

  it('throws on non-whitelisted track() in devMode', () => {
    const c = makeCollector({ devMode: true })
    expect(() => c.track('debug-console')).toThrow(TelemetryConfigError)
    expect(() => c.track('export')).not.toThrow()
  })

  it('counts distinct UTC active days, not events', () => {
    let now = 86_400 * 10 + 100 // day 10
    const c = makeCollector({ now: () => now }, now)
    c.track('export', now)
    c.recordSession(10, now)
    now += 86_400 // day 11
    c.track('export', now)
    now += 86_400 * 2 // day 13
    c.track('render', now)
    const w = c.takeWindow(now)
    expect(w.daysActive).toBe(3)
  })

  it('caps days_active at 28', () => {
    let now = 0
    const c = makeCollector({ now: () => now }, now)
    for (let day = 0; day < 35; day += 1) {
      c.track('export', day * 86_400)
    }
    expect(c.takeWindow(35 * 86_400).daysActive).toBe(28)
  })

  it('aligns window_start to the windowSecs boundary and rolls after take', () => {
    // windowSecs 3600; t = 3600*10 + 900 → window start 36000
    const start = 36_900
    const c = makeCollector({ now: () => start }, start)
    c.recordSession(5, start)
    const w = c.takeWindow(36_900)
    expect(w.windowStart).toBe(36_000)
    // Next window starts aligned to the take time; counters are reset.
    const w2 = c.takeWindow(36_900)
    expect(w2.sessionCount).toBe(0)
    expect(w2.windowStart).toBe(36_000)
    expect(c.isEmpty).toBe(true)
  })

  it('never moves window_start backwards when the clock regresses', () => {
    let now = 36_900
    const c = makeCollector({ now: () => now }, now)
    c.recordSession(5, now)
    const w1 = c.takeWindow(now)
    expect(w1.windowStart).toBe(36_000)
    now = 3_600 // clock regresses (NTP correction, stale `now`)
    c.track('export', now)
    const w2 = c.takeWindow(now)
    expect(w2.windowStart).toBe(36_000)
    expect(w2.featureHits).toEqual({ export: 1 })
  })

  it('rejects negative or non-finite session durations', () => {
    const c = makeCollector()
    expect(() => c.recordSession(-1)).toThrow(TelemetryConfigError)
    expect(() => c.recordSession(Number.NaN)).toThrow(TelemetryConfigError)
  })
})
