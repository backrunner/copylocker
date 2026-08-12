/**
 * IntegrityManifest decoding and signature verification.
 *
 * Wire format (`protocol-spec.md §9` plus the web v1 extension recorded in
 * `50-unplugin-integrity.md §2.4`). The signed container is:
 *
 * ```cddl
 * signed_integrity_manifest = {
 *   0: bytes,   ; canonical CBOR of integrity_manifest_tbs
 *   1: bytes,   ; Ed25519 signature (empty = unsigned development build)
 * }
 *
 * integrity_manifest_tbs = {
 *   0: uint,              ; proto_ver (= 1)
 *   1: bytes .size 4,     ; suite_id
 *   2: tstr,              ; product_id
 *   3: tstr,              ; build_fingerprint
 *   4: int,               ; built_at (unix seconds)
 *   5: tstr,              ; hash_alg ("sha256" for this runtime)
 *   6: { * tstr => {      ; pattern => entry (v1 extension of the spec's
 *         1: bytes,       ;   bare `bytes` digest: a map carrying the digest
 *         2: ? [* [uint, uint]], ;   plus excludedRanges [start, end) pairs
 *       } },
 *   7: ? { * tstr => bytes }, ; guarded function id => normalized body digest
 *   8: ? [* tstr],        ; sealed asset ids
 *   9: bytes,             ; root — Merkle root over the entries
 * }
 * ```
 *
 * The signature covers `"copylocker/im-sig/v1" ‖ tbs-bytes` (domain-separated)
 * where `tbs-bytes` is the exact canonical-CBOR payload of field 0. Keeping
 * the tbs as an embedded bstr (instead of re-encoding a decoded map) makes
 * verification independent of re-encoding correctness.
 *
 * Signature verification provides **provenance** only. The integrity
 * enforcement comes from `R` (the actually-computed root) participating in
 * key derivation — see the README. When WebCrypto Ed25519 is unavailable
 * (e.g. older Firefox) verification degrades to `'unsupported'`: a warning
 * is recorded and boot continues.
 */

import { CborError, decode, mapGet, type CborValue } from './cbor.js'
import { concat, utf8 } from './bytes.js'

/** Domain separator prefixed to the signed manifest payload. */
export const MANIFEST_SIGNATURE_DOMAIN = 'copylocker/im-sig/v1'

/** One chunk entry of the manifest. */
export interface ManifestEntry {
  /** Expected digest of the chunk with `excludedRanges` zeroed. */
  digest: Uint8Array
  /** Byte ranges [start, end) zeroed before digesting (placeholder regions). */
  excludedRanges: [number, number][]
}

/** Decoded integrity manifest (fields of the tbs payload). */
export interface IntegrityManifest {
  protoVer: number
  suiteId: Uint8Array
  productId: string
  buildFingerprint: string
  builtAt: number
  hashAlg: string
  /** Entries in canonical CBOR key order — this order defines the Merkle leaf order. */
  entries: Map<string, ManifestEntry>
  guarded: Map<string, Uint8Array>
  sealed: string[]
  root: Uint8Array
}

/** Decoded signed container: the manifest plus its raw signature material. */
export interface SignedManifest {
  manifest: IntegrityManifest
  /** Exact signed bytes (canonical CBOR of the tbs map). */
  tbsBytes: Uint8Array
  /** Raw Ed25519 signature; empty when the build is unsigned. */
  signature: Uint8Array
}

export class ManifestError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ManifestError'
  }
}

function fail(message: string): never {
  throw new ManifestError(`CopyLocker guard: invalid manifest: ${message}`)
}

function expectBytes(value: CborValue | undefined, field: string): Uint8Array {
  if (!(value instanceof Uint8Array)) fail(`${field} must be a byte string`)
  return value
}

function expectText(value: CborValue | undefined, field: string): string {
  if (typeof value !== 'string') fail(`${field} must be a text string`)
  return value
}

function expectInt(value: CborValue | undefined, field: string): number {
  if (typeof value !== 'number') fail(`${field} must be an integer`)
  return value
}

function decodeEntries(value: CborValue | undefined): Map<string, ManifestEntry> {
  if (!(value instanceof Map)) fail('entries (key 6) must be a map')
  const entries = new Map<string, ManifestEntry>()
  for (const [pattern, entryValue] of value) {
    if (typeof pattern !== 'string') fail('entry key must be a text pattern')
    let digest: Uint8Array
    let excludedRanges: [number, number][] = []
    if (entryValue instanceof Uint8Array) {
      // Bare-digest form tolerated for forward compatibility with the spec's
      // `{ * tstr => bytes }` shape; no excludedRanges possible there.
      digest = entryValue
    } else if (entryValue instanceof Map) {
      digest = expectBytes(mapGet(entryValue, 1), 'entry digest (key 1)')
      const rangesValue = mapGet(entryValue, 2)
      if (rangesValue !== undefined) {
        if (!Array.isArray(rangesValue)) fail('excludedRanges (key 2) must be an array')
        excludedRanges = rangesValue.map((range) => {
          if (!Array.isArray(range) || range.length !== 2) {
            fail('excludedRange must be a [start, end] pair')
          }
          const [start, end] = range
          if (typeof start !== 'number' || typeof end !== 'number' || start < 0 || end < 0) {
            fail('excludedRange bounds must be non-negative integers')
          }
          return [start, end]
        })
      }
    } else {
      fail('entry value must be a byte string or an entry map')
    }
    entries.set(pattern, { digest, excludedRanges })
  }
  return entries
}

function decodeGuarded(value: CborValue | undefined): Map<string, Uint8Array> {
  const guarded = new Map<string, Uint8Array>()
  if (value === undefined) return guarded
  if (!(value instanceof Map)) fail('guarded (key 7) must be a map')
  for (const [id, digest] of value) {
    if (typeof id !== 'string') fail('guarded key must be a text id')
    guarded.set(id, expectBytes(digest, 'guarded digest'))
  }
  return guarded
}

function decodeSealed(value: CborValue | undefined): string[] {
  if (value === undefined) return []
  if (!Array.isArray(value)) fail('sealed (key 8) must be an array')
  return value.map((item) => expectText(item, 'sealed asset id'))
}

/**
 * Decode a signed manifest container. Strict: any shape deviation throws
 * {@link ManifestError} (or {@link CborError} for malformed CBOR).
 */
export function decodeManifest(bytes: Uint8Array): SignedManifest {
  let container: CborValue
  try {
    container = decode(bytes)
  } catch (error) {
    if (error instanceof CborError) fail(error.message)
    throw error
  }
  const tbsBytes = expectBytes(mapGet(container, 0), 'tbs (key 0)')
  const signature = expectBytes(mapGet(container, 1), 'signature (key 1)')

  let tbs: CborValue
  try {
    tbs = decode(tbsBytes)
  } catch (error) {
    if (error instanceof CborError) fail(`tbs: ${error.message}`)
    throw error
  }
  const manifest: IntegrityManifest = {
    protoVer: expectInt(mapGet(tbs, 0), 'proto_ver (key 0)'),
    suiteId: expectBytes(mapGet(tbs, 1), 'suite_id (key 1)'),
    productId: expectText(mapGet(tbs, 2), 'product_id (key 2)'),
    buildFingerprint: expectText(mapGet(tbs, 3), 'build_fingerprint (key 3)'),
    builtAt: expectInt(mapGet(tbs, 4), 'built_at (key 4)'),
    hashAlg: expectText(mapGet(tbs, 5), 'hash_alg (key 5)'),
    entries: decodeEntries(mapGet(tbs, 6)),
    guarded: decodeGuarded(mapGet(tbs, 7)),
    sealed: decodeSealed(mapGet(tbs, 8)),
    root: expectBytes(mapGet(tbs, 9), 'root (key 9)'),
  }
  if (manifest.protoVer !== 1) fail(`unsupported proto_ver ${manifest.protoVer}`)
  if (manifest.suiteId.byteLength !== 4) fail('suite_id must be 4 bytes')
  return { manifest, tbsBytes, signature }
}

/** Outcome of a manifest signature check. */
export type SignatureStatus =
  | 'verified' // signature valid under one of the pins
  | 'failed' // signature present and pins given, but no pin verifies
  | 'unsigned' // empty signature (development build)
  | 'no-pins' // signature present but no pins configured to check against
  | 'unsupported' // WebCrypto Ed25519 not available in this environment

/**
 * Verify the manifest signature against pinned Ed25519 public keys (raw
 * 32-byte keys). Never throws: degradation is reported via the status.
 */
export async function verifyManifestSignature(
  signed: SignedManifest,
  publicKeys: Uint8Array[],
): Promise<SignatureStatus> {
  if (signed.signature.byteLength === 0) return 'unsigned'
  if (publicKeys.length === 0) return 'no-pins'
  const subtle = globalThis.crypto?.subtle
  if (!subtle) return 'unsupported'
  const message = concat(utf8(MANIFEST_SIGNATURE_DOMAIN), signed.tbsBytes)
  let attempted = false
  for (const keyBytes of publicKeys) {
    try {
      const key = await subtle.importKey('raw', keyBytes as unknown as ArrayBuffer, 'Ed25519', false, [
        'verify',
      ])
      const ok = await subtle.verify(
        'Ed25519',
        key,
        signed.signature as unknown as ArrayBuffer,
        message as unknown as ArrayBuffer,
      )
      attempted = true
      if (ok) return 'verified'
    } catch {
      // A malformed pin must not mask the remaining ones — keep trying.
      continue
    }
  }
  // No pin verified: 'failed' when at least one pin could be checked,
  // 'unsupported' when none could even be imported (e.g. no Ed25519).
  return attempted ? 'failed' : 'unsupported'
}

/** Sign a tbs payload — test/build-side helper mirroring the verifier. */
export async function signManifestTbs(
  tbsBytes: Uint8Array,
  privateKey: CryptoKey,
): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) throw new Error('CopyLocker guard: WebCrypto is required')
  const message = concat(utf8(MANIFEST_SIGNATURE_DOMAIN), tbsBytes)
  return new Uint8Array(
    await subtle.sign('Ed25519', privateKey, message as unknown as ArrayBuffer),
  )
}
