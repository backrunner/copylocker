import { describe, expect, it } from 'vitest'
import { encodeTelemetryBlock, type TelemetryBlock } from '../src/block.js'
import {
  clipBlock,
  MAX_BLOCK_BYTES,
  MAX_DAYS_ACTIVE,
  MAX_FEATURE_HITS,
  MAX_SESSION_COUNT,
} from '../src/clip.js'

function rawBlock(overrides: Partial<TelemetryBlock> = {}): TelemetryBlock {
  return {
    consentVersion: 3,
    windowStart: 3600,
    sessionCount: 4,
    sessionDurationHistogram: [1, 1, 1, 1],
    featureHits: { export: 2 },
    daysActive: 2,
    ...overrides,
  }
}

describe('clipBlock', () => {
  it('passes a clean block through untouched', () => {
    const { block, clipped, droppedFeatures } = clipBlock(rawBlock(), {
      featureWhitelist: new Set(['export']),
    })
    expect(block).toEqual(rawBlock())
    expect(clipped).toBe(0)
    expect(droppedFeatures).toBe(0)
  })

  it('clips a poisoned session_count (10^9) and counts it', () => {
    const { block, clipped } = clipBlock(rawBlock({ sessionCount: 1e9 }), {
      featureWhitelist: new Set(['export']),
    })
    expect(block.sessionCount).toBe(MAX_SESSION_COUNT)
    expect(clipped).toBe(1)
  })

  it('clips poisoned histogram buckets independently', () => {
    const { block, clipped } = clipBlock(rawBlock({ sessionDurationHistogram: [2e9, 0, 5, 1e12] }), {
      featureWhitelist: new Set(['export']),
    })
    expect(block.sessionDurationHistogram).toEqual([10_000, 0, 5, 10_000])
    expect(clipped).toBe(2)
  })

  it('clips days_active above 28', () => {
    const { block, clipped } = clipBlock(rawBlock({ daysActive: 100 }), {
      featureWhitelist: new Set(['export']),
    })
    expect(block.daysActive).toBe(MAX_DAYS_ACTIVE)
    expect(clipped).toBe(1)
  })

  it('drops non-whitelisted features and counts them', () => {
    const { block, clipped, droppedFeatures } = clipBlock(
      rawBlock({ featureHits: { export: 2, 'not-allowed': 7 } }),
      { featureWhitelist: new Set(['export']) },
    )
    expect(block.featureHits).toEqual({ export: 2 })
    expect(droppedFeatures).toBe(1)
    expect(clipped).toBe(0)
  })

  it('clips poisoned feature hit counts', () => {
    const { block, clipped } = clipBlock(rawBlock({ featureHits: { export: 5e6 } }), {
      featureWhitelist: new Set(['export']),
    })
    expect(block.featureHits['export']).toBe(MAX_FEATURE_HITS)
    expect(clipped).toBe(1)
  })

  it('zeroes non-integer or negative scalar garbage and counts it as clipped', () => {
    const { block, clipped } = clipBlock(
      rawBlock({ sessionCount: Number.NaN, daysActive: -4 }),
      { featureWhitelist: new Set(['export']) },
    )
    expect(block.sessionCount).toBe(0)
    expect(block.daysActive).toBe(0)
    expect(clipped).toBe(2)
  })

  it('enforces the encoded-size budget by dropping lowest-priority features', () => {
    // 18 bytes without features; each xxxx:N entry adds 6 bytes.
    const { block, droppedFeatures } = clipBlock(
      rawBlock({ featureHits: { aaaa: 1, bbbb: 2 } }),
      { featureWhitelist: new Set(['aaaa', 'bbbb']), maxBlockBytes: 29 },
    )
    expect(block.featureHits).toEqual({ bbbb: 2 })
    expect(droppedFeatures).toBe(1)
    expect(encodeTelemetryBlock(block).byteLength).toBeLessThanOrEqual(29)
  })

  it('keeps the full block within 512 bytes even with the maximum feature set', () => {
    const features: Record<string, number> = {}
    const whitelist = new Set<string>()
    for (let i = 0; i < 64; i += 1) {
      const id = `feature-${String(i).padStart(2, '0')}-abcdefgh`
      features[id] = i + 1
      whitelist.add(id)
    }
    const { block, droppedFeatures } = clipBlock(rawBlock({ featureHits: features }), {
      featureWhitelist: whitelist,
    })
    expect(encodeTelemetryBlock(block).byteLength).toBeLessThanOrEqual(MAX_BLOCK_BYTES)
    expect(droppedFeatures).toBeGreaterThan(0)
    for (const key of Object.keys(block.featureHits)) expect(whitelist.has(key)).toBe(true)
  })

  it('keeps a whitelisted __proto__ feature id instead of silently losing it', () => {
    const raw = rawBlock()
    raw.featureHits = Object.fromEntries([
      ['__proto__', 3],
      ['export', 2],
    ])
    const { block, droppedFeatures } = clipBlock(raw, {
      featureWhitelist: new Set(['export', '__proto__']),
    })
    expect(Object.keys(block.featureHits).sort()).toEqual(['__proto__', 'export'])
    expect(block.featureHits['__proto__']).toBe(3)
    expect(droppedFeatures).toBe(0)
  })

  it('never touches consent_version or window_start', () => {
    const { block } = clipBlock(rawBlock({ consentVersion: 42, windowStart: 1_700_000_000 }), {
      featureWhitelist: new Set(['export']),
    })
    expect(block.consentVersion).toBe(42)
    expect(block.windowStart).toBe(1_700_000_000)
  })
})
