/**
 * Shared assertions for the bundler integration tests: given a dist dir with
 * a built fixture app, the manifest must decode, the guard runtime must
 * recompute R == manifest.root over the real bytes, and a one-byte tamper
 * must change R. Also exercises `verifyDist` in both directions.
 */

import { readdir, readFile, stat, writeFile, mkdtemp, mkdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { expect } from 'vitest'
import { bootGuard, decodeManifest, type SignedManifest } from '@copylocker/guard'
import { toHex } from '../src/hash.js'
import { verifyDist } from '../src/verify.js'
import { distFetch } from './helpers.js'

export interface DistInspection {
  manifestBytes: Uint8Array
  signed: SignedManifest
  files: Map<string, Uint8Array>
  entryFile: string
}

export async function readDist(distDir: string): Promise<DistInspection> {
  const manifestBytes = new Uint8Array(
    await readFile(join(distDir, '.copylocker', 'manifest.cbor')),
  )
  const signed = decodeManifest(manifestBytes)

  const files = new Map<string, Uint8Array>()
  async function walk(dir: string, prefix: string): Promise<void> {
    for (const name of await readdir(dir)) {
      const full = join(dir, name)
      if ((await stat(full)).isDirectory()) {
        await walk(full, `${prefix}${name}/`)
      } else {
        files.set(`${prefix}${name}`, new Uint8Array(await readFile(full)))
      }
    }
  }
  await walk(distDir, '')

  // The entry chunk is the one carrying excludedRanges (the prelude spans).
  const entryPattern = [...signed.manifest.entries.entries()].find(
    ([, entry]) => entry.excludedRanges.length > 0,
  )?.[0]
  expect(entryPattern).toBeDefined()
  return { manifestBytes, signed, files, entryFile: entryPattern as string }
}

export async function expectRuntimeMatch(inspection: DistInspection, publicKey: string) {
  const { signed, files } = inspection
  const chunks = [...signed.manifest.entries.keys()].map((pattern) => ({ url: pattern, pattern }))
  const { R, report } = await bootGuard({
    manifest: inspection.manifestBytes,
    rootPins: [publicKey],
    chunks,
    strategy: 'sync',
    fetchImpl: distFetch(files),
  })
  expect(report.signature).toBe('verified')
  expect(report.entries.map((e) => `${e.pattern}:${e.status}`)).toEqual(
    [...signed.manifest.entries.keys()].map((p) => `${p}:ok`),
  )
  expect(toHex(R)).toBe(toHex(signed.manifest.root))
}

export async function expectTamperDetected(inspection: DistInspection) {
  const { signed, files } = inspection
  // Flip one byte in a non-entry chunk (or any non-entry covered file).
  const victim = [...signed.manifest.entries.keys()].find((p) => p !== inspection.entryFile)
  expect(victim).toBeDefined()
  const tampered = new Map(files)
  const bytes = new Uint8Array(files.get(victim as string) as Uint8Array)
  bytes[Math.floor(bytes.byteLength / 2)] ^= 0xff
  tampered.set(victim as string, bytes)

  const chunks = [...signed.manifest.entries.keys()].map((pattern) => ({ url: pattern, pattern }))
  const { R, report } = await bootGuard({
    manifest: inspection.manifestBytes,
    chunks,
    strategy: 'sync',
    fetchImpl: distFetch(tampered),
  })
  expect(toHex(R)).not.toBe(toHex(signed.manifest.root))
  expect(report.entries.find((e) => e.pattern === victim)?.status).toBe('mismatch')

  // The verify CLI core agrees (and catches the same byte).
  const bad = await verifyDist({ distDir: await writeTamperedCopy(files, tampered) })
  expect(bad.ok).toBe(false)
  expect(bad.entries.find((e) => e.pattern === victim)?.status).toBe('mismatch')
}


async function writeTamperedCopy(
  _files: Map<string, Uint8Array>,
  tampered: Map<string, Uint8Array>,
): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'cl-verify-'))
  for (const [name, bytes] of tampered) {
    const target = join(dir, ...name.split('/'))
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, bytes)
  }
  return dir
}

export async function expectVerifyOk(distDir: string, publicKey: string) {
  const result = await verifyDist({
    distDir,
    publicKeys: [
      (() => {
        const out = new Uint8Array(32)
        for (let i = 0; i < 32; i += 1) out[i] = Number.parseInt(publicKey.slice(i * 2, i * 2 + 2), 16)
        return out
      })(),
    ],
  })
  expect(result.ok).toBe(true)
  expect(result.signature).toBe('verified')
  expect(result.rootMatches).toBe(true)
  expect(result.entries.every((e) => e.status === 'ok')).toBe(true)
}

export { rm as rmDir }
