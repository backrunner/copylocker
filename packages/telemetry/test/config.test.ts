import { describe, expect, it } from 'vitest'
import { resolveConfig, TelemetryConfigError, type TelemetryConfig } from '../src/config.js'

function t1(overrides: Partial<TelemetryConfig> = {}): TelemetryConfig {
  return { tier: 'T1', consent: () => 1, featureWhitelist: ['export'], ...overrides }
}

describe('resolveConfig fail-fast validation (FR-TLM-019)', () => {
  it("rejects tier 'T1' without a consent provider — the headline footgun", () => {
    expect(() => resolveConfig({ tier: 'T1' })).toThrow(TelemetryConfigError)
    expect(() => resolveConfig(t1({ consent: undefined }))).toThrow(/consent/)
  })

  it('rejects an unknown tier', () => {
    expect(() => resolveConfig({ tier: 'T2' } as unknown as TelemetryConfig)).toThrow(TelemetryConfigError)
    expect(() => resolveConfig({} as unknown as TelemetryConfig)).toThrow(TelemetryConfigError)
  })

  it("rejects dead config: consent or a whitelist under 'off'/'T0'", () => {
    expect(() => resolveConfig({ tier: 'off', consent: () => 1 })).toThrow(TelemetryConfigError)
    expect(() => resolveConfig({ tier: 'T0', consent: () => 1 })).toThrow(TelemetryConfigError)
    expect(() => resolveConfig({ tier: 'off', featureWhitelist: ['export'] })).toThrow(TelemetryConfigError)
    expect(() => resolveConfig({ tier: 'T0', featureWhitelist: ['export'] })).toThrow(TelemetryConfigError)
    // But the plain tiers themselves are fine.
    expect(resolveConfig({ tier: 'off' }).tier).toBe('off')
    expect(resolveConfig({ tier: 'T0' }).tier).toBe('T0')
  })

  it('rejects malformed whitelists', () => {
    expect(() => resolveConfig(t1({ featureWhitelist: [''] }))).toThrow(TelemetryConfigError)
    expect(() => resolveConfig(t1({ featureWhitelist: ['export', 'export'] }))).toThrow(/duplicate/)
    expect(() => resolveConfig(t1({ featureWhitelist: ['x'.repeat(65)] }))).toThrow(TelemetryConfigError)
    expect(() => resolveConfig(t1({ featureWhitelist: ['export', 1 as unknown as string] }))).toThrow(
      TelemetryConfigError,
    )
  })

  it('rejects malformed session buckets', () => {
    expect(() => resolveConfig(t1({ sessionBuckets: [300, 100, 7200] }))).toThrow(TelemetryConfigError)
    expect(() => resolveConfig(t1({ sessionBuckets: [0, 100, 7200] }))).toThrow(TelemetryConfigError)
    expect(() => resolveConfig(t1({ sessionBuckets: [300, 1800] as unknown as [number, number, number] }))).toThrow(
      TelemetryConfigError,
    )
  })

  it('rejects non-positive windows and oversized block budgets', () => {
    expect(() => resolveConfig(t1({ windowSecs: 0 }))).toThrow(TelemetryConfigError)
    expect(() => resolveConfig(t1({ windowSecs: -5 }))).toThrow(TelemetryConfigError)
    expect(() => resolveConfig(t1({ maxBlockBytes: 0 }))).toThrow(TelemetryConfigError)
    expect(() => resolveConfig(t1({ maxBlockBytes: 1024 }))).toThrow(TelemetryConfigError)
  })

  it('rejects a garbage custom clock at initialization', () => {
    expect(() => resolveConfig(t1({ now: () => Number.NaN }))).toThrow(TelemetryConfigError)
    expect(() => resolveConfig(t1({ now: () => -1 }))).toThrow(TelemetryConfigError)
    expect(() => resolveConfig(t1({ now: () => 1.5 }))).toThrow(TelemetryConfigError)
    expect(resolveConfig(t1({ now: () => 1_700_000_000 })).now()).toBe(1_700_000_000)
  })

  it('accepts a well-formed T1 config and applies defaults', () => {
    const resolved = resolveConfig(t1())
    expect(resolved.tier).toBe('T1')
    expect(resolved.windowSecs).toBe(7 * 24 * 3600)
    expect(resolved.sessionBuckets).toEqual([300, 1800, 7200])
    expect(resolved.maxBlockBytes).toBe(512)
    expect(resolved.devMode).toBe(false)
    expect([...resolved.featureWhitelist]).toEqual(['export'])
  })
})
