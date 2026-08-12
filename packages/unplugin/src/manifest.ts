/**
 * IntegrityManifest encoding — the build-time half of the wire format
 * owned by `@copylocker/guard` (`packages/guard/src/manifest.ts`):
 *
 * ```cddl
 * signed_integrity_manifest = { 0: bytes (tbs), 1: bytes (signature) }
 * integrity_manifest_tbs = {
 *   0: 1, 1: suite_id(4), 2: product_id, 3: build_fingerprint,
 *   4: built_at, 5: hash_alg,
 *   6: { * pattern => { 1: digest, 2: ? [* [start, end)) ] } },
 *   7: ? { * fnId => digest }, 8: ? [* assetId ], 9: root,
 * }
 * ```
 *
 * Encoded with the local canonical CBOR encoder (`cbor.ts`); the guard
 * package's strict decoder accepts every manifest produced here (proven by
 * the tests, which round-trip through `decodeManifest`).
 */

import { canonicalTextKeyOrder, encode, type CborValue } from './cbor.js'

export interface ManifestEntryInput {
  digest: Uint8Array
  excludedRanges: [number, number][]
}

export interface ManifestInput {
  suiteId: Uint8Array
  productId: string
  buildFingerprint: string
  builtAt: number
  hashAlg: string
  entries: Map<string, ManifestEntryInput>
  guarded: Map<string, Uint8Array>
  sealed: string[]
  root: Uint8Array
}

function encodeEntries(entries: Map<string, ManifestEntryInput>): Map<string, CborValue> {
  const sorted = [...entries.keys()].sort(canonicalTextKeyOrder)
  const out = new Map<string, CborValue>()
  for (const pattern of sorted) {
    const entry = entries.get(pattern) as ManifestEntryInput
    const value = new Map<number, CborValue>()
    value.set(1, entry.digest)
    if (entry.excludedRanges.length > 0) {
      value.set(2, entry.excludedRanges.map(([start, end]) => [start, end]))
    }
    out.set(pattern, value)
  }
  return out
}

function encodeGuarded(guarded: Map<string, Uint8Array>): Map<string, CborValue> {
  const sorted = [...guarded.keys()].sort(canonicalTextKeyOrder)
  const out = new Map<string, CborValue>()
  for (const id of sorted) out.set(id, guarded.get(id) as Uint8Array)
  return out
}

/** Encode the tbs map as canonical CBOR. */
export function encodeTbs(input: ManifestInput): Uint8Array {
  const tbs = new Map<number, CborValue>()
  tbs.set(0, 1)
  tbs.set(1, input.suiteId)
  tbs.set(2, input.productId)
  tbs.set(3, input.buildFingerprint)
  tbs.set(4, input.builtAt)
  tbs.set(5, input.hashAlg)
  tbs.set(6, encodeEntries(input.entries))
  if (input.guarded.size > 0) tbs.set(7, encodeGuarded(input.guarded))
  if (input.sealed.length > 0) tbs.set(8, [...input.sealed].sort(canonicalTextKeyOrder))
  tbs.set(9, input.root)
  return encode(tbs)
}

/** Encode the signed container `{0: tbs, 1: signature}`. */
export function encodeContainer(tbsBytes: Uint8Array, signature: Uint8Array): Uint8Array {
  const container = new Map<number, CborValue>()
  container.set(0, tbsBytes)
  container.set(1, signature)
  return encode(container)
}
