/**
 * Build identity (`50-unplugin-integrity.md §2.2`): a content-independent
 * `build_fingerprint` (random + git sha + time) and a random `build_seed`
 * (drives the M5 WASM export-name randomization; K_BUILD is drawn independently).
 */

import { randomBytes } from 'node:crypto'
import { execFile } from 'node:child_process'
import { toHex } from './hash.js'

/** Short git HEAD for `cwd`, or null when git is unavailable / not a repo. */
export function gitHead(cwd: string): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(
      'git',
      ['rev-parse', 'HEAD'],
      { cwd, timeout: 2000 },
      (error, stdout) => {
        if (error) {
          resolve(null)
          return
        }
        const sha = stdout.trim()
        resolve(/^[0-9a-f]{40}$/.test(sha) ? sha : null)
      },
    )
  })
}

/**
 * Format: `clb-<base36 time>-<git sha 12 | 'nogit'>-<16 random hex>`.
 * Content-independent by design (§2.2): two builds of the same tree differ.
 */
export async function makeBuildFingerprint(cwd: string): Promise<string> {
  const sha = await gitHead(cwd)
  const time = Date.now().toString(36)
  const rand = toHex(randomBytes(8))
  return `clb-${time}-${sha?.slice(0, 12) ?? 'nogit'}-${rand}`
}

/** Random 32-byte build seed (hex) — derives the M5 hardening passes (WASM export-name randomization). */
export function makeBuildSeed(): string {
  return toHex(randomBytes(32))
}

/** The K_BUILD constant injected into the bundle (random per build). */
export function makeKBuild(): Uint8Array {
  return randomBytes(32)
}

/**
 * Split a 32-byte constant into `shards` hex shards. The shard boundaries are
 * byte-aligned when possible; the runtime (`@copylocker/web`) concatenates
 * `__CL_K_BUILD_0__..__CL_K_BUILD_<n-1>__` back together.
 */
export function splitHex(hex: string, shards: number): string[] {
  if (shards < 1 || hex.length % 2 !== 0) {
    throw new Error('CopyLocker unplugin: splitHex needs an even-length hex string')
  }
  const total = hex.length / 2
  const base = Math.floor(total / shards)
  const extra = total % shards
  const out: string[] = []
  let offset = 0
  for (let i = 0; i < shards; i += 1) {
    const size = (base + (i < extra ? 1 : 0)) * 2
    out.push(hex.slice(offset, offset + size))
    offset += size
  }
  return out
}
