/**
 * `@copylocker/guard/diagnose` — human-facing integrity diagnostics
 * (`50-unplugin-integrity.md §3.3`).
 *
 * Runs the same verification as `bootGuard` (always synchronously) and
 * returns a per-entry expected/actual digest comparison. This exists so a
 * false positive can be debugged in minutes instead of shipped as a
 * "feature silently missing" incident. It is ONLY for explicit invocation
 * (console, support tooling) — never wire it into the boot path.
 */

import { toHex } from './bytes.js'
import { bootGuard, type BootGuardOptions, type GuardReport } from './guard.js'
import { decodeManifest, type SignedManifest } from './manifest.js'

export interface Diagnosis {
  signature: GuardReport['signature']
  /** Manifest-declared Merkle root (hex). */
  expectedRoot: string
  /** Actually-computed Merkle root (hex). */
  actualRoot: string
  /** True when expected == actual (all entries verified). */
  rootMatches: boolean
  entries: GuardReport['entries']
  durationMs: number
}

/** Full synchronous verification with a comparison-friendly result. */
export async function diagnose(
  options: Omit<BootGuardOptions, 'strategy'>,
): Promise<Diagnosis> {
  const signed: SignedManifest =
    options.manifest instanceof Uint8Array ? decodeManifest(options.manifest) : options.manifest
  const { R, report } = await bootGuard({ ...options, strategy: 'sync' })
  const expectedRoot = toHex(signed.manifest.root)
  const actualRoot = toHex(R)
  return {
    signature: report.signature,
    expectedRoot,
    actualRoot,
    rootMatches: expectedRoot === actualRoot,
    entries: report.entries,
    durationMs: report.durationMs,
  }
}

/** Render a diagnosis as plain text for console/support output. */
export function formatDiagnosis(diagnosis: Diagnosis): string {
  const lines: string[] = [
    `CopyLocker integrity diagnosis`,
    `  signature:     ${diagnosis.signature}`,
    `  expected root: ${diagnosis.expectedRoot}`,
    `  actual root:   ${diagnosis.actualRoot}`,
    `  root matches:  ${diagnosis.rootMatches ? 'yes' : 'NO'}`,
    `  entries (${diagnosis.entries.length}):`,
  ]
  for (const entry of diagnosis.entries) {
    lines.push(
      `    [${entry.status}] ${entry.pattern}`,
      `      expected: ${entry.expected}`,
      `      actual:   ${entry.actual}`,
    )
    if (entry.url) lines.push(`      url:      ${entry.url}`)
  }
  lines.push(`  verified in ${diagnosis.durationMs.toFixed(1)}ms`)
  return lines.join('\n')
}
