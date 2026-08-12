/**
 * Minimal canonical (deterministic) CBOR encoder for the integrity manifest.
 *
 * Byte-compatible with the strict decoder in `@copylocker/guard`
 * (`packages/guard/src/cbor.ts`): shortest-form integers, map keys sorted by
 * their encoded bytes (shorter first, then bytewise — RFC 7049 §3.9). Only
 * the value shapes the manifest needs are supported: unsigned/negative
 * integers, byte strings, text strings, arrays, and maps. Parity with the
 * guard decoder is proven by the test-suite (every manifest this plugin emits
 * is decoded and verified by `@copylocker/guard` in tests).
 */

export type CborValue =
  | number
  | Uint8Array
  | string
  | boolean
  | null
  | CborValue[]
  | Map<CborValue, CborValue>

export class CborEncodeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CborEncodeError'
  }
}

function encodeHead(out: number[], major: number, value: bigint): void {
  const tag = major << 5
  if (value < 24n) {
    out.push(tag | Number(value))
  } else if (value <= 0xffn) {
    out.push(tag | 24, Number(value))
  } else if (value <= 0xffffn) {
    out.push(tag | 25, Number(value >> 8n), Number(value & 0xffn))
  } else if (value <= 0xffff_ffffn) {
    out.push(
      tag | 26,
      Number(value >> 24n),
      Number((value >> 16n) & 0xffn),
      Number((value >> 8n) & 0xffn),
      Number(value & 0xffn),
    )
  } else if (value <= 0xffff_ffff_ffff_ffffn) {
    out.push(tag | 27)
    for (let shift = 56n; shift >= 0n; shift -= 8n) {
      out.push(Number((value >> shift) & 0xffn))
    }
  } else {
    throw new CborEncodeError('integer out of range')
  }
}

const textEncoder = new TextEncoder()

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  if (a.byteLength !== b.byteLength) return a.byteLength - b.byteLength
  for (let i = 0; i < a.byteLength; i += 1) {
    const diff = (a[i] as number) - (b[i] as number)
    if (diff !== 0) return diff
  }
  return 0
}

function encodeInto(out: number[], value: CborValue): void {
  if (value === null) {
    out.push(0xf6)
    return
  }
  if (typeof value === 'boolean') {
    out.push(value ? 0xf5 : 0xf4)
    return
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new CborEncodeError('integer is not a safe integer')
    if (value >= 0) {
      encodeHead(out, 0, BigInt(value))
    } else {
      encodeHead(out, 1, BigInt(-1 - value))
    }
    return
  }
  if (value instanceof Uint8Array) {
    encodeHead(out, 2, BigInt(value.byteLength))
    for (const byte of value) out.push(byte)
    return
  }
  if (typeof value === 'string') {
    const bytes = textEncoder.encode(value)
    encodeHead(out, 3, BigInt(bytes.byteLength))
    for (const byte of bytes) out.push(byte)
    return
  }
  if (Array.isArray(value)) {
    encodeHead(out, 4, BigInt(value.length))
    for (const item of value) encodeInto(out, item)
    return
  }
  if (value instanceof Map) {
    const entries: { key: Uint8Array; value: CborValue }[] = []
    for (const [key, item] of value) {
      entries.push({ key: encode(key), value: item })
    }
    entries.sort((a, b) => compareBytes(a.key, b.key))
    encodeHead(out, 5, BigInt(entries.length))
    for (const entry of entries) {
      for (const byte of entry.key) out.push(byte)
      encodeInto(out, entry.value)
    }
    return
  }
  throw new CborEncodeError('unsupported value type')
}

/** Encode a value as canonical CBOR (RFC 7049 §3.9). */
export function encode(value: CborValue): Uint8Array {
  const out: number[] = []
  encodeInto(out, value)
  return Uint8Array.from(out)
}

/**
 * Canonical order for text keys: by their encoded bytes (shorter encoded form
 * first, then bytewise). This is exactly the order `@copylocker/guard`'s
 * strict decoder enforces, so it defines the Merkle leaf order.
 */
export function canonicalTextKeyOrder(a: string, b: string): number {
  return compareBytes(encode(a), encode(b))
}
