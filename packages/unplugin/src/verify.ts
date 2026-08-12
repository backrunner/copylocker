/**
 * Post-build verification (FR-BLD-010): recompute every artifact digest from
 * the files on disk (with `excludedRanges` zeroed — the two-round scheme's
 * runtime half), rebuild the Merkle root, and compare against the manifest.
 * Optionally verifies the Ed25519 signature against given public keys.
 *
 * Used by the `copylocker-unplugin verify` CLI and by CI pipelines to catch
 * publishing accidents (tampered/stale artifacts). Exit-code logic lives in
 * `cli.ts`.
 */

import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import {
  decodeManifest,
  merkleRootFromEntries,
  verifyManifestSignature,
  zeroExcludedRanges,
  type SignatureStatus,
} from '@copylocker/guard'
import { sha256, toHex } from './hash.js'

export interface VerifyEntryResult {
  pattern: string
  status: 'ok' | 'mismatch' | 'missing'
  expected: string
  actual: string
}

export interface VerifyResult {
  ok: boolean
  /** Signature status, or 'skipped' when no public keys were given. */
  signature: SignatureStatus | 'skipped'
  expectedRoot: string
  actualRoot: string
  rootMatches: boolean
  entries: VerifyEntryResult[]
  productId: string
  buildFingerprint: string
}

export interface VerifyOptions {
  distDir: string
  /** Raw Ed25519 public keys for signature verification. */
  publicKeys?: Uint8Array[]
  /** Override the manifest path (default `<distDir>/.copylocker/manifest.cbor`). */
  manifestPath?: string
}

const ZERO_DIGEST = new Uint8Array(32)

export async function verifyDist(options: VerifyOptions): Promise<VerifyResult> {
  const manifestPath = options.manifestPath ?? join(options.distDir, '.copylocker', 'manifest.cbor')
  const manifestBytes = new Uint8Array(await readFile(manifestPath))
  const signed = decodeManifest(manifestBytes)
  const { manifest } = signed

  const entries: VerifyEntryResult[] = []
  const actualDigests = new Map<string, Uint8Array>()
  for (const [pattern, entry] of manifest.entries) {
    const expected = toHex(entry.digest)
    let bytes: Uint8Array
    try {
      bytes = new Uint8Array(await readFile(join(options.distDir, ...pattern.split('/'))))
    } catch {
      entries.push({ pattern, status: 'missing', expected, actual: toHex(ZERO_DIGEST) })
      actualDigests.set(pattern, ZERO_DIGEST)
      continue
    }
    const digest = await sha256(zeroExcludedRanges(bytes, entry.excludedRanges))
    const actual = toHex(digest)
    entries.push({
      pattern,
      status: actual === expected ? 'ok' : 'mismatch',
      expected,
      actual,
    })
    actualDigests.set(pattern, digest)
  }

  const actualRoot = await merkleRootFromEntries(actualDigests)
  const rootMatches = toHex(actualRoot) === toHex(manifest.root)

  let signature: VerifyResult['signature'] = 'skipped'
  if (options.publicKeys && options.publicKeys.length > 0) {
    signature = await verifyManifestSignature(signed, options.publicKeys)
  }

  const entriesOk = entries.every((entry) => entry.status === 'ok')
  // With explicit public keys, provenance is being checked: only a VERIFIED
  // signature passes. An unsigned dist (accidentally built without a signer)
  // is exactly the publishing accident `--pubkey` exists to catch.
  const signatureOk =
    options.publicKeys && options.publicKeys.length > 0
      ? signature === 'verified'
      : signature === 'skipped'
  return {
    ok: entriesOk && rootMatches && signatureOk,
    signature,
    expectedRoot: toHex(manifest.root),
    actualRoot: toHex(actualRoot),
    rootMatches,
    entries,
    productId: manifest.productId,
    buildFingerprint: manifest.buildFingerprint,
  }
}

/** Render a verification result as plain text (per-entry comparison). */
export function formatVerifyResult(result: VerifyResult): string {
  const lines: string[] = [
    'CopyLocker build verification',
    `  product:       ${result.productId}`,
    `  build:         ${result.buildFingerprint}`,
    `  signature:     ${result.signature}`,
    `  expected root: ${result.expectedRoot}`,
    `  actual root:   ${result.actualRoot}`,
    `  root matches:  ${result.rootMatches ? 'yes' : 'NO'}`,
    `  entries (${result.entries.length}):`,
  ]
  for (const entry of result.entries) {
    lines.push(
      `    [${entry.status}] ${entry.pattern}`,
      `      expected: ${entry.expected}`,
      `      actual:   ${entry.actual}`,
    )
  }
  lines.push(result.ok ? '  RESULT: OK' : '  RESULT: FAILED')
  return lines.join('\n')
}
