/**
 * Minimal canonical CBOR *encoder*, dependency-free (CSP-friendly).
 *
 * Mirrors the encoder half of `packages/web/src/cbor.ts`, narrowed to the
 * value model the T1 `telemetry_block` needs: unsigned integers, text
 * strings, arrays, and maps. Encoding follows the same canonical form as
 * `copylocker_suite::cbor` (RFC 8949 §4.2.1): shortest-form integers and map
 * keys ordered by their encoded bytes (for text keys this is byte-length
 * first, then bytewise — identical to the Rust writer's lexicographic order
 * on the encoded head+content).
 */

/** JavaScript representation of an encodable CBOR data item. */
export type CborValue = number | string | CborValue[] | Map<number | string, CborValue>

export class CborError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CborError'
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
    throw new CborError('integer out of range')
  }
}

function encodeUint(out: number[], value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new CborError('integer is not a non-negative safe integer')
  }
  encodeHead(out, 0, BigInt(value))
}

const textEncoder = new TextEncoder()

function encodeInto(out: number[], value: CborValue): void {
  if (typeof value === 'number') {
    encodeUint(out, value)
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
    // then bytewise — equivalent to bytewise lexicographic for the integer
    // and text keys this encoder supports).
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
