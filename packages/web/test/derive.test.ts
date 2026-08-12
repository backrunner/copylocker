import { describe, expect, it } from 'vitest'
import {
  deriveFinalKey,
  resolveBuildConstants,
  resolveExpectedWasmDigest,
  resolveManifestRoot,
  resolveRequireIntegrityProof,
} from '../src/derive.js'

const m = new Uint8Array(32).fill(1)
const kBuild = new Uint8Array(32).fill(2)
const manifestRoot = new Uint8Array(32).fill(3)
const wasmDigest = new Uint8Array(32).fill(4)

function flip(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes)
  copy[0] = (copy[0] as number) ^ 0xff
  return copy
}

describe('derive (two-stage transform)', () => {
  it('is deterministic for identical inputs', async () => {
    const a = await deriveFinalKey(m, { kBuild, manifestRoot }, wasmDigest)
    const b = await deriveFinalKey(m, { kBuild, manifestRoot }, wasmDigest)
    expect(a).toEqual(b)
    expect(a.byteLength).toBe(32)
  })

  it('changes when M changes', async () => {
    const a = await deriveFinalKey(m, { kBuild, manifestRoot }, wasmDigest)
    const b = await deriveFinalKey(flip(m), { kBuild, manifestRoot }, wasmDigest)
    expect(a).not.toEqual(b)
  })

  it('changes when K_BUILD changes (FR-WEB-003)', async () => {
    const a = await deriveFinalKey(m, { kBuild, manifestRoot }, wasmDigest)
    const b = await deriveFinalKey(m, { kBuild: flip(kBuild), manifestRoot }, wasmDigest)
    expect(a).not.toEqual(b)
  })

  it('changes when MANIFEST_ROOT changes (FR-WEB-005)', async () => {
    const a = await deriveFinalKey(m, { kBuild, manifestRoot }, wasmDigest)
    const b = await deriveFinalKey(m, { kBuild, manifestRoot: flip(manifestRoot) }, wasmDigest)
    expect(a).not.toEqual(b)
  })

  it('changes when the wasm digest changes (wasm replacement fails)', async () => {
    const a = await deriveFinalKey(m, { kBuild, manifestRoot }, wasmDigest)
    const b = await deriveFinalKey(m, { kBuild, manifestRoot }, flip(wasmDigest))
    expect(a).not.toEqual(b)
  })

  it('matches an independent SHA-256 of the concatenation', async () => {
    const expected = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new Uint8Array([...m, ...kBuild, ...manifestRoot, ...wasmDigest]) as unknown as ArrayBuffer),
    )
    const actual = await deriveFinalKey(m, { kBuild, manifestRoot }, wasmDigest)
    expect(actual).toEqual(expected)
  })

  it('rejects malformed material lengths', async () => {
    await expect(
      deriveFinalKey(new Uint8Array(31), { kBuild, manifestRoot }, wasmDigest),
    ).rejects.toThrow(TypeError)
  })

  it('resolveBuildConstants: explicit override wins, default is all zeros', () => {
    const zeros = resolveBuildConstants()
    expect(zeros.kBuild).toEqual(new Uint8Array(32))
    expect(zeros.manifestRoot).toEqual(new Uint8Array(32))
    const override = resolveBuildConstants({ kBuild })
    expect(override.kBuild).toEqual(kBuild)
    expect(override.manifestRoot).toEqual(new Uint8Array(32))
  })

  it('resolveBuildConstants: assembles sharded K_BUILD (unplugin splitConstants)', () => {
    const globals = globalThis as Record<string, unknown>
    const hex = Array.from({ length: 64 }, (_, i) => (i % 16).toString(16)).join('')
    globals.__CL_K_BUILD_0__ = hex.slice(0, 32)
    globals.__CL_K_BUILD_1__ = hex.slice(32, 48)
    globals.__CL_K_BUILD_2__ = hex.slice(48)
    try {
      const resolved = resolveBuildConstants()
      expect(resolved.kBuild.byteLength).toBe(32)
      expect(resolved.kBuild[0]).toBe(0x01)
      expect(resolved.kBuild[31]).toBe(0xef)
    } finally {
      delete globals.__CL_K_BUILD_0__
      delete globals.__CL_K_BUILD_1__
      delete globals.__CL_K_BUILD_2__
    }
  })

  it('resolveBuildConstants: single constant wins over shards; malformed shards throw', () => {
    const globals = globalThis as Record<string, unknown>
    const single = 'ab'.repeat(32)
    globals.__COPYLOCKER_K_BUILD__ = single
    globals.__CL_K_BUILD_0__ = 'cd'.repeat(16)
    globals.__CL_K_BUILD_1__ = 'cd'.repeat(16)
    try {
      const resolved = resolveBuildConstants()
      expect(resolved.kBuild[0]).toBe(0xab)
      // malformed: shards that do not total 32 bytes
      globals.__COPYLOCKER_K_BUILD__ = undefined
      globals.__CL_K_BUILD_0__ = 'cd'
      expect(() => resolveBuildConstants()).toThrow(TypeError)
    } finally {
      delete globals.__COPYLOCKER_K_BUILD__
      delete globals.__CL_K_BUILD_0__
      delete globals.__CL_K_BUILD_1__
    }
  })

  it('resolveManifestRoot: integrity provider wins over the injected constant', async () => {
    const computed = new Uint8Array(32).fill(9)
    await expect(
      resolveManifestRoot({ manifestRoot: () => computed }, manifestRoot),
    ).resolves.toEqual(computed)
    // async providers work too
    await expect(
      resolveManifestRoot({ manifestRoot: async () => computed }, manifestRoot),
    ).resolves.toEqual(computed)
  })

  it('resolveManifestRoot: no provider keeps the injected constant', async () => {
    await expect(resolveManifestRoot(undefined, manifestRoot)).resolves.toEqual(manifestRoot)
    await expect(resolveManifestRoot({}, manifestRoot)).resolves.toEqual(manifestRoot)
  })

  it('resolveManifestRoot: malformed provider results are rejected', async () => {
    await expect(
      resolveManifestRoot({ manifestRoot: () => new Uint8Array(16) }, manifestRoot),
    ).rejects.toThrow(TypeError)
  })

  it('resolveManifestRoot: undefined provider result falls back only without requireProof', async () => {
    // The M4 wiring `() => globalThis.__CL_GUARD_R__` yields undefined when the
    // guard bootstrap is gone — the default keeps the injected constant…
    await expect(
      resolveManifestRoot({ manifestRoot: () => undefined }, manifestRoot),
    ).resolves.toEqual(manifestRoot)
    // …while requireProof fails closed with the indistinguishable derivation
    // error (NotEntitledError, code 17 — same as a wasm-side refusal).
    const missingProvider = resolveManifestRoot(undefined, manifestRoot, true)
    await expect(missingProvider).rejects.toMatchObject({ name: 'NotEntitledError', code: 17 })
    const undefinedResult = resolveManifestRoot({ manifestRoot: () => undefined }, manifestRoot, true)
    await expect(undefinedResult).rejects.toMatchObject({ name: 'NotEntitledError', code: 17 })
    // A real R still wins and resolves normally.
    const computed = new Uint8Array(32).fill(9)
    await expect(
      resolveManifestRoot({ manifestRoot: () => computed }, manifestRoot, true),
    ).resolves.toEqual(computed)
  })

  it('resolveRequireIntegrityProof: explicit option wins, then the injected constant', () => {
    const globals = globalThis as Record<string, unknown>
    expect(resolveRequireIntegrityProof(true)).toBe(true)
    expect(resolveRequireIntegrityProof(false)).toBe(false)
    expect(resolveRequireIntegrityProof()).toBe(false)
    globals.__CL_REQUIRE_INTEGRITY_PROOF__ = true
    try {
      expect(resolveRequireIntegrityProof()).toBe(true)
      // An explicit false still overrides the injection point.
      expect(resolveRequireIntegrityProof(false)).toBe(false)
    } finally {
      delete globals.__CL_REQUIRE_INTEGRITY_PROOF__
    }
  })

  it('resolveExpectedWasmDigest: reads the unplugin __CL_WASM_DIGEST__ constant', () => {
    const globals = globalThis as Record<string, unknown>
    // No injection (dev build) → no comparison is possible.
    expect(resolveExpectedWasmDigest()).toBeUndefined()
    globals.__CL_WASM_DIGEST__ = 'ab'.repeat(32)
    try {
      const resolved = resolveExpectedWasmDigest()
      expect(resolved).toBeInstanceOf(Uint8Array)
      expect(resolved?.[0]).toBe(0xab)
      expect(resolved?.byteLength).toBe(32)
      // A raw 32-byte Uint8Array is accepted too (same as the other injection points).
      globals.__CL_WASM_DIGEST__ = new Uint8Array(32).fill(0xcd)
      expect(resolveExpectedWasmDigest()?.[0]).toBe(0xcd)
      // Malformed values are not a digest — treated as "not injected".
      globals.__CL_WASM_DIGEST__ = 'ab'
      expect(resolveExpectedWasmDigest()).toBeUndefined()
    } finally {
      delete globals.__CL_WASM_DIGEST__
    }
  })
})
