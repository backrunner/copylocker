/**
 * Merkle root computation over manifest entries.
 *
 * Exact rules (both the build-time `@copylocker/unplugin` and this runtime
 * MUST implement them identically):
 *
 * - Leaf order: the manifest `entries` map order, which is canonical CBOR
 *   key order (encoded keys: shorter first, then bytewise lexicographic).
 *   The strict CBOR decoder rejects any other order, so the decoded map's
 *   iteration order IS the canonical order.
 * - Leaf: `leaf = SHA-256( utf8(pattern) ‖ digest )` where `digest` is the
 *   32-byte chunk digest used for this run (the actually-computed digest at
 *   runtime; the expected digest at build time).
 * - Internal node: `node = SHA-256( left ‖ right )`.
 * - Odd count at a level: the last node is duplicated (`H(last ‖ last)`).
 * - Single leaf: the root IS that leaf (no extra hashing round).
 * - Empty tree: the root is `SHA-256("")` (digest of the empty input).
 */

import { sha256, utf8 } from './bytes.js'

/** Hash one leaf: `SHA-256( utf8(pattern) ‖ digest )`. */
export async function leafHash(pattern: string, digest: Uint8Array): Promise<Uint8Array> {
  return sha256(utf8(pattern), digest)
}

/**
 * Reduce leaf hashes to the Merkle root following the rules above.
 * `leaves` must already be in canonical order.
 */
export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return sha256()
  let level = leaves
  while (level.length > 1) {
    const next: Uint8Array[] = []
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i] as Uint8Array
      const right = (i + 1 < level.length ? level[i + 1] : level[i]) as Uint8Array
      next.push(await sha256(left, right))
    }
    level = next
  }
  return level[0] as Uint8Array
}

/** Merkle root over `(pattern, digest)` pairs in canonical order. */
export async function merkleRootFromEntries(
  entries: Iterable<[string, Uint8Array]>,
): Promise<Uint8Array> {
  const leaves: Uint8Array[] = []
  for (const [pattern, digest] of entries) {
    leaves.push(await leafHash(pattern, digest))
  }
  return merkleRoot(leaves)
}
