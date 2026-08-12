/** Internal byte/hash helpers shared by the guard modules. */

const textEncoder = new TextEncoder()

export function utf8(text: string): Uint8Array {
  return textEncoder.encode(text)
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (const part of parts) total += part.byteLength
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.byteLength
  }
  return out
}

/** SHA-256 over the concatenation of `parts`, via WebCrypto. */
export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('CopyLocker guard: WebCrypto SubtleCrypto is required (secure context)')
  }
  return new Uint8Array(await subtle.digest('SHA-256', concat(...parts) as unknown as ArrayBuffer))
}

/**
 * Synchronous non-cryptographic fallback used only where async hashing cannot
 * be awaited (function-body sampling without WebCrypto). Eight FNV-1a 32-bit
 * lanes with distinct seeds fill 32 bytes. Degraded: still deterministic, so
 * tampering still changes the mixed state, but it is not collision-resistant.
 */
export function fallbackDigest(...parts: Uint8Array[]): Uint8Array {
  const seeds = [0x811c9dc5, 0x01000193, 0x9e3779b9, 0x85ebca6b, 0x27d4eb2f, 0x165667b1, 0xd3a2646c, 0xfd7046c5]
  const lanes = new Uint32Array(seeds)
  for (const part of parts) {
    for (let i = 0; i < part.byteLength; i += 1) {
      const lane = i % lanes.length
      lanes[lane] = ((lanes[lane] as number) ^ (part[i] as number)) >>> 0
      lanes[lane] = Math.imul(lanes[lane] as number, 0x01000193) >>> 0
    }
  }
  const out = new Uint8Array(32)
  const view = new DataView(out.buffer)
  for (let i = 0; i < lanes.length; i += 1) {
    view.setUint32(i * 4, lanes[i] as number, false)
  }
  return out
}

export function toHex(bytes: Uint8Array): string {
  let hex = ''
  for (const byte of bytes) hex += (byte as number).toString(16).padStart(2, '0')
  return hex
}

export function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new TypeError('CopyLocker guard: invalid hex string')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.byteLength; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false
  let diff = 0
  for (let i = 0; i < a.byteLength; i += 1) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}
