import { describe, expect, it } from 'vitest'
import { CborError, decode, encode, type CborValue } from '../src/cbor.js'

function roundtrip(value: CborValue): CborValue {
  return decode(encode(value))
}

describe('cbor', () => {
  it('round-trips the full supported value model, including nested maps/bytes', () => {
    const value: CborValue = new Map<CborValue, CborValue>([
      [0, 1],
      [1, 'product'],
      [2, new Uint8Array([1, 2, 3])],
      [3, -42],
      [4, true],
      [5, null],
      [
        6,
        new Map<CborValue, CborValue>([
          [0, new Uint8Array(32).fill(9)],
          [1, [1, 2, new Map<CborValue, CborValue>([[0, false]])]],
        ]),
      ],
      [90, [1, 2, 5]],
    ])
    const decoded = roundtrip(value)
    expect(decoded).toEqual(value)
  })

  it('round-trips integer boundary values', () => {
    for (const n of [0, 1, 23, 24, 255, 256, 65535, 65536, 2 ** 32, 2 ** 53 - 1, -1, -24, -25, -256, -257, -(2 ** 32)]) {
      expect(roundtrip(n)).toBe(n)
    }
  })

  it('encodes known canonical forms', () => {
    expect([...encode(0)]).toEqual([0x00])
    expect([...encode(23)]).toEqual([0x17])
    expect([...encode(24)]).toEqual([0x18, 0x18])
    expect([...encode(256)]).toEqual([0x19, 0x01, 0x00])
    expect([...encode(-1)]).toEqual([0x20])
    expect([...encode('a')]).toEqual([0x61, 0x61])
    expect([...encode(new Uint8Array([0, 1]))]).toEqual([0x42, 0x00, 0x01])
    expect([...encode(true)]).toEqual([0xf5])
    expect([...encode(null)]).toEqual([0xf6])
    // {1: 2} with canonical single-byte key
    expect([...encode(new Map([[1, 2]]))]).toEqual([0xa1, 0x01, 0x02])
  })

  it('orders map keys canonically (shorter encoded key first)', () => {
    // key 24 encodes as 0x1818 (2 bytes), key 1 as 0x01 (1 byte): 1 sorts first.
    const map = new Map<CborValue, CborValue>([
      [24, 'b'],
      [1, 'a'],
    ])
    expect([...encode(map)]).toEqual([0xa2, 0x01, 0x61, 0x61, 0x18, 0x18, 0x61, 0x62])
  })

  it('rejects non-shortest-form integers', () => {
    expect(() => decode(new Uint8Array([0x18, 0x00]))).toThrow(CborError)
    expect(() => decode(new Uint8Array([0x1a, 0, 0, 0, 5]))).toThrow(CborError)
  })

  it('rejects indefinite-length items', () => {
    expect(() => decode(new Uint8Array([0x9f, 0x01, 0xff]))).toThrow(CborError)
    expect(() => decode(new Uint8Array([0x5f, 0x40, 0xff]))).toThrow(CborError)
  })

  it('rejects floats, tags and trailing bytes', () => {
    expect(() => decode(new Uint8Array([0xfa, 0, 0, 0, 0]))).toThrow(CborError)
    expect(() => decode(new Uint8Array([0xc0, 0x00]))).toThrow(CborError)
    expect(() => decode(new Uint8Array([0x01, 0x02]))).toThrow(CborError)
  })

  it('rejects non-canonically-ordered and duplicate map keys', () => {
    // {24: 'b', 1: 'a'} — out of canonical order
    expect(() =>
      decode(new Uint8Array([0xa2, 0x18, 0x18, 0x61, 0x62, 0x01, 0x61, 0x61])),
    ).toThrow(CborError)
    // {1: 'a', 1: 'b'} — duplicate key
    expect(() =>
      decode(new Uint8Array([0xa2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62])),
    ).toThrow(CborError)
  })

  it('enforces depth and item limits', () => {
    let nested: CborValue = 0
    for (let i = 0; i < 40; i += 1) nested = [nested]
    expect(() => decode(encode(nested))).toThrow(CborError)
  })
})
