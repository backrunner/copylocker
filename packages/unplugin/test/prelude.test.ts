import { describe, expect, it } from 'vitest'
import { zeroExcludedRanges } from '@copylocker/guard'
import {
  backfillPrelude,
  buildPrelude,
  preludeExcludedRanges,
  type PreludeConfig,
} from '../src/prelude.js'
import { sha256, toHex } from '../src/hash.js'

const CONFIG: PreludeConfig = {
  pins: ['ab'.repeat(32)],
  chunks: [
    { url: '/assets/index-aaa.js', pattern: 'assets/index-aaa.js' },
    { url: '/assets/chunk-bbb.js', pattern: 'assets/chunk-bbb.js' },
  ],
  kbuild: ['cd'.repeat(8), 'ef'.repeat(8)],
  strategy: 'idle',
  sampleRate: 0.15,
}

const BOOTSTRAP = ';(function(){/* guard runtime */})();'

describe('prelude (two-round self-reference placeholders)', () => {
  it('places fixed-length zero placeholders and reports exact spans', () => {
    const prelude = buildPrelude(CONFIG, 200, BOOTSTRAP)
    const [ms, me] = prelude.spans.manifest
    const [rs, re] = prelude.spans.root
    expect(me - ms).toBe(200)
    expect(re - rs).toBe(64)
    expect(prelude.text.slice(ms, me)).toBe('0'.repeat(200))
    expect(prelude.text.slice(rs, re)).toBe('0'.repeat(64))
    expect(prelude.text.slice(0, ms)).toContain('"manifest":"')
    expect(prelude.text.slice(me, rs)).toContain('"root":"')
    // ASCII-only prelude → char offsets are byte offsets in the utf8 output.
    expect(/^[\x20-\x7e\n]*$/.test(prelude.text)).toBe(true)
  })

  it('backfill preserves length and only touches the spans', () => {
    const prelude = buildPrelude(CONFIG, 256, BOOTSTRAP)
    const chunk = `${prelude.text}console.log("app");`
    const manifestHex = 'ab'.repeat(128)
    const rootHex = 'cd'.repeat(32)
    const backfilled = backfillPrelude(chunk, prelude.spans, manifestHex, rootHex)
    expect(backfilled.length).toBe(chunk.length)
    expect(backfilled.slice(prelude.spans.manifest[0], prelude.spans.manifest[1])).toBe(manifestHex)
    expect(backfilled.slice(prelude.spans.root[0], prelude.spans.root[1])).toBe(rootHex)
    // everything outside the spans is untouched
    const mask = (text: string): string => {
      const ranges = preludeExcludedRanges(prelude.spans)
      const chars = text.split('')
      for (const [s, e] of ranges) for (let i = s; i < e; i += 1) chars[i] = '#'
      return chars.join('')
    }
    expect(mask(backfilled)).toBe(mask(chunk))
  })

  it('round-1 and round-2 digests agree after zeroing excludedRanges', async () => {
    const prelude = buildPrelude(CONFIG, 512, BOOTSTRAP)
    const code = 'function main(){return 1}\nmain();'
    const round1 = `${prelude.text}${code}`
    const ranges = preludeExcludedRanges(prelude.spans)
    const encode = (s: string): Uint8Array => new TextEncoder().encode(s)
    const digestRound1 = await sha256(zeroExcludedRanges(encode(round1), ranges))

    const backfilled = backfillPrelude(round1, prelude.spans, 'f'.repeat(512), 'e'.repeat(64))
    const digestRound2 = await sha256(zeroExcludedRanges(encode(backfilled), ranges))

    expect(toHex(digestRound2)).toBe(toHex(digestRound1))
    // …and the un-zeroed digests differ (the backfill is really in the bytes)
    expect(toHex(await sha256(encode(backfilled)))).not.toBe(toHex(await sha256(encode(round1))))
  })

  it('rejects a length-mismatched backfill', () => {
    const prelude = buildPrelude(CONFIG, 100, BOOTSTRAP)
    expect(() => backfillPrelude(prelude.text, prelude.spans, 'aa', 'b'.repeat(64))).toThrow(
      /length drifted/,
    )
  })

  it('rejects non-ASCII chunk file names (byte offsets would drift)', () => {
    expect(() =>
      buildPrelude(
        { ...CONFIG, chunks: [{ url: '/资产.js', pattern: '资产.js' }] },
        64,
        BOOTSTRAP,
      ),
    ).toThrow(/ASCII/)
  })

  it('injects __CL_REQUIRE_INTEGRITY_PROOF__ between the config and the bootstrap', () => {
    const prelude = buildPrelude(CONFIG, 200, BOOTSTRAP)
    const flag = ';globalThis.__CL_REQUIRE_INTEGRITY_PROOF__=true;'
    const flagAt = prelude.text.indexOf(flag)
    expect(flagAt).toBeGreaterThan(-1)
    // After the config assignment (so the constants exist), before the
    // bootstrap (so deleting the bootstrap cannot remove the flag).
    expect(flagAt).toBeGreaterThan(prelude.text.indexOf('__CL_GUARD_CONFIG__'))
    expect(flagAt).toBeLessThan(prelude.text.indexOf(BOOTSTRAP))
    // Pure ASCII invariant still holds with the flag present.
    expect(/^[\x20-\x7e\n]*$/.test(prelude.text)).toBe(true)
  })
})
