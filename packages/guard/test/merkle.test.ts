import { describe, expect, it } from 'vitest'
import { leafHash, merkleRoot, merkleRootFromEntries } from '../src/merkle.js'
import { sha256, utf8 } from '../src/bytes.js'

const d = (fill: number) => new Uint8Array(32).fill(fill)

describe('merkle', () => {
  it('empty tree root is SHA-256 of the empty input', async () => {
    const root = await merkleRoot([])
    expect(root).toEqual(await sha256())
  })

  it('single leaf: root IS the leaf (no extra round)', async () => {
    const leaf = await leafHash('a.js', d(1))
    expect(await merkleRoot([leaf])).toEqual(leaf)
    // …and not H(leaf ‖ leaf)
    expect(await merkleRoot([leaf])).not.toEqual(await sha256(leaf, leaf))
  })

  it('two leaves: root = H(left ‖ right)', async () => {
    const a = await leafHash('a.js', d(1))
    const b = await leafHash('b.js', d(2))
    expect(await merkleRoot([a, b])).toEqual(await sha256(a, b))
  })

  it('odd leaf count duplicates the last node', async () => {
    const a = await leafHash('a.js', d(1))
    const b = await leafHash('b.js', d(2))
    const c = await leafHash('c.js', d(3))
    const expected = await sha256(await sha256(a, b), await sha256(c, c))
    expect(await merkleRoot([a, b, c])).toEqual(expected)
  })

  it('is order-sensitive', async () => {
    const a = await leafHash('a.js', d(1))
    const b = await leafHash('b.js', d(2))
    const c = await leafHash('c.js', d(3))
    expect(await merkleRoot([a, b, c])).not.toEqual(await merkleRoot([c, b, a]))
    expect(await merkleRoot([a, b, c])).not.toEqual(await merkleRoot([b, a, c]))
  })

  it('leaf hash binds the pattern: H(utf8(pattern) ‖ digest)', async () => {
    expect(await leafHash('x.js', d(7))).toEqual(await sha256(utf8('x.js'), d(7)))
    expect(await leafHash('x.js', d(7))).not.toEqual(await leafHash('y.js', d(7)))
  })

  it('merkleRootFromEntries follows iteration order', async () => {
    const entries: [string, Uint8Array][] = [
      ['a.js', d(1)],
      ['b.js', d(2)],
    ]
    const manual = await sha256(await leafHash('a.js', d(1)), await leafHash('b.js', d(2)))
    expect(await merkleRootFromEntries(entries)).toEqual(manual)
  })
})
