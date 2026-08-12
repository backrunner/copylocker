import { describe, expect, it } from 'vitest'
import { makeBuildFingerprint, makeKBuild, splitHex } from '../src/fingerprint.js'
import { toHex } from '../src/hash.js'
import { withTempDir } from './helpers.js'

describe('build identity', () => {
  it('build_fingerprint matches the documented format (git repo)', async () => {
    // packages/unplugin lives inside the copylocker git checkout
    const fp = await makeBuildFingerprint(process.cwd())
    expect(fp).toMatch(/^clb-[0-9a-z]+-[0-9a-f]{12}-[0-9a-f]{16}$/)
  })

  it('degrades to nogit outside a git repository', async () => {
    await withTempDir(async (dir) => {
      const fp = await makeBuildFingerprint(dir)
      expect(fp).toMatch(/^clb-[0-9a-z]+-nogit-[0-9a-f]{16}$/)
    })
  })

  it('is content-independent (two calls differ)', async () => {
    const a = await makeBuildFingerprint(process.cwd())
    const b = await makeBuildFingerprint(process.cwd())
    expect(a).not.toBe(b)
  })

  it('K_BUILD is 32 random bytes; splits reassemble exactly', () => {
    const hex = toHex(makeKBuild())
    expect(hex).toMatch(/^[0-9a-f]{64}$/)
    for (const shards of [1, 2, 3, 4, 5, 7, 32]) {
      const parts = splitHex(hex, shards)
      expect(parts).toHaveLength(shards)
      expect(parts.join('')).toBe(hex)
      for (const part of parts) expect(part.length % 2).toBe(0)
    }
    expect(splitHex(hex, 4)).toHaveLength(4)
  })
})
