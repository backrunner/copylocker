/**
 * Minimal canonical (deterministic) CBOR codec, dependency-free (CSP-friendly).
 *
 * Covers exactly the value model the `copylocker-wasm` op protocol uses:
 * unsigned/negative integers, byte strings, text strings, arrays, maps,
 * booleans and null. Tags, floats, and indefinite-length items are rejected.
 *
 * Encoding follows RFC 7049 §3.9 canonical ordering: shortest-form integers
 * and map keys sorted by their encoded bytes (shorter first, then bytewise
 * lexicographic). Decoding is strict: non-canonical input is rejected, the
 * same discipline as `copylocker_suite::cbor::decode_canonical`.
 */

/** JavaScript representation of a decoded CBOR data item. */
export type CborValue =
  | number
  | Uint8Array
  | string
  | boolean
  | null
  | CborValue[]
  | Map<CborValue, CborValue>

/** Bounds applied while decoding. Defaults mirror the wasm op limits. */
export interface CborLimits {
  maxDepth: number
  maxItems: number
  maxString: number
}

export const DEFAULT_CBOR_LIMITS: CborLimits = {
  maxDepth: 32,
  maxItems: 4096,
  maxString: 1024 * 1024,
}

export class CborError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CborError'
  }
}

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER)

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
    throw new CborError('integer out of range')
  }
}

function intArgument(value: number): { major: number; argument: bigint } {
  if (!Number.isSafeInteger(value)) {
    throw new CborError('integer is not a safe integer')
  }
  if (value >= 0) {
    return { major: 0, argument: BigInt(value) }
  }
  // CBOR negative integers encode -1 - n.
  return { major: 1, argument: BigInt(-1 - value) }
}

const textEncoder = new TextEncoder()

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
    const { major, argument } = intArgument(value)
    encodeHead(out, major, argument)
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
    // Canonical order: sort entries by the encoded key bytes (shorter first,
    // then bytewise). Keys are encoded separately to compare them.
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
  throw new CborError('unsupported value type')
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  if (a.byteLength !== b.byteLength) return a.byteLength - b.byteLength
  for (let i = 0; i < a.byteLength; i += 1) {
    const diff = (a[i] as number) - (b[i] as number)
    if (diff !== 0) return diff
  }
  return 0
}

/** Encode a value as canonical CBOR. */
export function encode(value: CborValue): Uint8Array {
  const out: number[] = []
  encodeInto(out, value)
  return Uint8Array.from(out)
}

const textDecoder = new TextDecoder('utf-8', { fatal: true })

class Decoder {
  private offset = 0

  constructor(
    private readonly bytes: Uint8Array,
    private readonly limits: CborLimits,
  ) {}

  decode(): CborValue {
    const value = this.item(0)
    if (this.offset !== this.bytes.byteLength) {
      throw new CborError('trailing bytes')
    }
    return value
  }

  private read(length: number): Uint8Array {
    if (this.bytes.byteLength - this.offset < length) {
      throw new CborError('truncated input')
    }
    const slice = this.bytes.subarray(this.offset, this.offset + length)
    this.offset += length
    return slice
  }

  private head(additional: number): bigint {
    if (additional < 24) return BigInt(additional)
    if (additional === 24) return BigInt(this.read(1)[0] as number)
    if (additional === 25) {
      const b = this.read(2)
      return BigInt(((b[0] as number) << 8) | (b[1] as number))
    }
    if (additional === 26) {
      const b = this.read(4)
      // `>>> 0` keeps the 32-bit assembly unsigned.
      return BigInt(
        (((b[0] as number) << 24) |
          ((b[1] as number) << 16) |
          ((b[2] as number) << 8) |
          (b[3] as number)) >>>
          0,
      )
    }
    if (additional === 27) {
      const b = this.read(8)
      let value = 0n
      for (const byte of b) value = (value << 8n) | BigInt(byte)
      return value
    }
    throw new CborError('indefinite or reserved additional information')
  }

  /** Read a head and enforce the canonical shortest form. */
  private canonicalHead(additional: number): { argument: bigint; minimal: number } {
    const argument = this.head(additional)
    if (additional < 24) return { argument, minimal: additional }
    if (argument < 24n) throw new CborError('non-canonical integer encoding')
    const minimal = argument <= 0xffn ? 24 : argument <= 0xffffn ? 25 : argument <= 0xffff_ffffn ? 26 : 27
    if (additional !== minimal) {
      throw new CborError('non-canonical integer encoding')
    }
    return { argument, minimal }
  }

  private safeNumber(argument: bigint): number {
    if (argument > MAX_SAFE) throw new CborError('integer exceeds safe range')
    return Number(argument)
  }

  private boundedLength(argument: bigint): number {
    if (argument > BigInt(this.limits.maxString)) {
      throw new CborError('item exceeds length limit')
    }
    return Number(argument)
  }

  private item(depth: number): CborValue {
    if (depth > this.limits.maxDepth) throw new CborError('nesting too deep')
    const initial = this.read(1)[0] as number
    const major = initial >> 5
    const additional = initial & 0x1f
    switch (major) {
      case 0: {
        const { argument } = this.canonicalHead(additional)
        return this.safeNumber(argument)
      }
      case 1: {
        const { argument } = this.canonicalHead(additional)
        return -1 - this.safeNumber(argument)
      }
      case 2: {
        const { argument } = this.canonicalHead(additional)
        const length = this.boundedLength(argument)
        return new Uint8Array(this.read(length))
      }
      case 3: {
        const { argument } = this.canonicalHead(additional)
        const length = this.boundedLength(argument)
        try {
          return textDecoder.decode(this.read(length))
        } catch {
          throw new CborError('invalid UTF-8 text string')
        }
      }
      case 4: {
        const { argument } = this.canonicalHead(additional)
        if (argument > BigInt(this.limits.maxItems)) {
          throw new CborError('array exceeds item limit')
        }
        const items: CborValue[] = []
        for (let i = 0; i < Number(argument); i += 1) {
          items.push(this.item(depth + 1))
        }
        return items
      }
      case 5: {
        const { argument } = this.canonicalHead(additional)
        if (argument > BigInt(this.limits.maxItems)) {
          throw new CborError('map exceeds item limit')
        }
        const map = new Map<CborValue, CborValue>()
        let previousKey: Uint8Array | null = null
        for (let i = 0; i < Number(argument); i += 1) {
          const keyStart = this.offset
          const key = this.item(depth + 1)
          const keyBytes = this.bytes.subarray(keyStart, this.offset)
          if (previousKey !== null && compareBytes(previousKey, keyBytes) >= 0) {
            throw new CborError('map keys are not in canonical order')
          }
          previousKey = new Uint8Array(keyBytes)
          map.set(key, this.item(depth + 1))
        }
        return map
      }
      case 7: {
        if (additional === 20) return false
        if (additional === 21) return true
        if (additional === 22) return null
        throw new CborError('unsupported simple/float value')
      }
      default:
        throw new CborError('unsupported major type')
    }
  }
}

/** Decode strict canonical CBOR. Throws {@link CborError} on any deviation. */
export function decode(bytes: Uint8Array, limits: CborLimits = DEFAULT_CBOR_LIMITS): CborValue {
  return new Decoder(bytes, limits).decode()
}

/** Read a required integer-keyed field from a decoded map. */
export function mapGet(value: CborValue, key: number): CborValue | undefined {
  if (!(value instanceof Map)) throw new CborError('expected a map')
  return value.get(key)
}
