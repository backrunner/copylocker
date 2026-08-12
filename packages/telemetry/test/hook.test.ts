import { describe, expect, it } from 'vitest'
import { createTelemetryHook, TelemetryConfigError } from '../src/index.js'

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' ')
}

describe('createTelemetryHook', () => {
  it('aggregates a window and encodes it as the proto telemetry_block', () => {
    let now = 360_000
    const hook = createTelemetryHook({
      tier: 'T1',
      consent: () => 3,
      featureWhitelist: ['export', 'render'],
      windowSecs: 3600,
      now: () => now,
    })
    hook.track('export')
    hook.track('export')
    hook.track('render')
    hook.track('not-whitelisted') // silently dropped, counted in stats
    hook.recordSession(100) // bucket 0
    hook.recordSession(600) // bucket 1
    hook.recordSession(2000) // bucket 2
    hook.recordSession(10_000) // bucket 3

    const block = hook.buildBlock(now)
    expect(block).toBeDefined()
    // Hand-computed canonical block:
    // {0: 3, 1: 360000, 2: 4, 3: [1,1,1,1], 4: {"export": 2, "render": 1}, 5: 1}
    expect(hex(block as Uint8Array)).toBe(
      'a6 00 03 01 1a 00 05 7e 40 02 04 03 84 01 01 01 01 04 a2 ' +
        '66 65 78 70 6f 72 74 02 66 72 65 6e 64 65 72 01 05 01',
    )

    const stats = hook.stats()
    expect(stats.blocksBuilt).toBe(1)
    expect(stats.droppedFeatureHits).toBe(1)

    // The window was reset by the report: nothing left to send.
    now += 3600
    expect(hook.buildBlock(now)).toBeUndefined()
    expect(hook.stats().blocksBuilt).toBe(1)
  })

  it('produces nothing while consent is absent (consent_version = 0), and keeps counting locally', () => {
    let consentVersion = 0
    const now = 360_000
    const hook = createTelemetryHook({
      tier: 'T1',
      consent: () => consentVersion,
      featureWhitelist: ['export'],
      windowSecs: 3600,
      now: () => now,
    })
    hook.track('export')
    hook.recordSession(10)
    expect(hook.buildBlock(now)).toBeUndefined()
    expect(hook.buildBlock(now)).toBeUndefined()
    expect(hook.stats().consentSkips).toBe(2)
    expect(hook.stats().blocksBuilt).toBe(0)

    // Consent granted → the accumulated window is reported with the version.
    consentVersion = 5
    const block = hook.buildBlock(now)
    expect(block).toBeDefined()
    // {0: 5, 1: 360000, 2: 1, 3: [1,0,0,0], 4: {"export": 1}, 5: 1}
    expect(hex(block as Uint8Array)).toBe(
      'a6 00 05 01 1a 00 05 7e 40 02 01 03 84 01 00 00 00 04 a1 66 65 78 70 6f 72 74 01 05 01',
    )
  })

  it('treats a throwing or garbage consent provider as no consent', () => {
    const now = 360_000
    const hook = createTelemetryHook({
      tier: 'T1',
      consent: () => {
        throw new Error('consent store unavailable')
      },
      featureWhitelist: ['export'],
      windowSecs: 3600,
      now: () => now,
    })
    hook.track('export')
    expect(hook.buildBlock(now)).toBeUndefined()
    expect(hook.stats().consentSkips).toBe(1)

    const nan = createTelemetryHook({
      tier: 'T1',
      consent: () => Number.NaN,
      featureWhitelist: ['export'],
      windowSecs: 3600,
      now: () => now,
    })
    nan.track('export')
    expect(nan.buildBlock(now)).toBeUndefined()
  })

  it("is a complete no-op under tier 'off' and 'T0'", () => {
    for (const tier of ['off', 'T0'] as const) {
      const hook = createTelemetryHook({ tier })
      hook.track('export')
      hook.recordSession(42)
      expect(hook.buildBlock()).toBeUndefined()
      expect(hook.stats()).toEqual({
        blocksBuilt: 0,
        consentSkips: 0,
        clippedFields: 0,
        droppedFeatures: 0,
        droppedFeatureHits: 0,
      })
    }
  })

  it('throws on non-whitelisted track() in devMode', () => {
    const hook = createTelemetryHook({
      tier: 'T1',
      consent: () => 1,
      featureWhitelist: ['export'],
      devMode: true,
    })
    expect(() => hook.track('nope')).toThrow(TelemetryConfigError)
  })

  it('reports an empty window as undefined (no block for zero activity)', () => {
    const hook = createTelemetryHook({
      tier: 'T1',
      consent: () => 1,
      featureWhitelist: ['export'],
      now: () => 360_000,
    })
    expect(hook.buildBlock(360_000)).toBeUndefined()
    expect(hook.stats().blocksBuilt).toBe(0)
  })
})
