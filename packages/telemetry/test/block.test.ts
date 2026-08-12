import { describe, expect, it } from 'vitest'
import { encodeTelemetryBlock, type TelemetryBlock } from '../src/block.js'
import { CborError } from '../src/cbor.js'

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' ')
}

/**
 * Hand-computed vectors for the `telemetry_block` wire format, mirroring
 * `TelemetryBlock::to_value` in `crates/copylocker-proto/src/requests.rs`
 * (keys 0..5 always present, canonical CBOR, feature map keys ordered by
 * encoded bytes).
 */
describe('encodeTelemetryBlock', () => {
  it('matches the hand-computed proto vector (single feature)', () => {
    const block: TelemetryBlock = {
      consentVersion: 1,
      windowStart: 1000,
      sessionCount: 3,
      sessionDurationHistogram: [1, 2, 0, 0],
      featureHits: { export: 5 },
      daysActive: 2,
    }
    expect(hex(encodeTelemetryBlock(block))).toBe(
      'a6 00 01 01 19 03 e8 02 03 03 84 01 02 00 00 04 a1 66 65 78 70 6f 72 74 05 05 02',
    )
  })

  it('matches the hand-computed proto vector (multi-byte ints, canonical feature order)', () => {
    const block: TelemetryBlock = {
      consentVersion: 2,
      windowStart: 1_700_000_000,
      sessionCount: 10_000,
      sessionDurationHistogram: [0, 0, 24, 300],
      featureHits: { export: 1, ai: 24 },
      daysActive: 28,
    }
    // 'ai' (0x62…) sorts before 'export' (0x66…): shorter encoded key first.
    expect(hex(encodeTelemetryBlock(block))).toBe(
      'a6 00 02 01 1a 65 53 f1 00 02 19 27 10 03 84 00 00 18 18 19 01 2c ' +
        '04 a2 62 61 69 18 18 66 65 78 70 6f 72 74 01 05 18 1c',
    )
  })

  it('always emits all six keys, even for an all-zero block', () => {
    const block: TelemetryBlock = {
      consentVersion: 7,
      windowStart: 0,
      sessionCount: 0,
      sessionDurationHistogram: [0, 0, 0, 0],
      featureHits: {},
      daysActive: 0,
    }
    expect(hex(encodeTelemetryBlock(block))).toBe('a6 00 07 01 00 02 00 03 84 00 00 00 00 04 a0 05 00')
  })

  it('rejects negative or non-integer counts', () => {
    const base: TelemetryBlock = {
      consentVersion: 1,
      windowStart: 0,
      sessionCount: -1,
      sessionDurationHistogram: [0, 0, 0, 0],
      featureHits: {},
      daysActive: 0,
    }
    expect(() => encodeTelemetryBlock(base)).toThrow(CborError)
    expect(() => encodeTelemetryBlock({ ...base, sessionCount: 1.5 })).toThrow(CborError)
    expect(() => encodeTelemetryBlock({ ...base, sessionCount: 2 ** 53 })).toThrow(CborError)
  })
})
