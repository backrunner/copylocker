import { describe, expect, it } from 'vitest'
import { normalizeSource } from '../src/normalize.js'

describe('normalizeSource', () => {
  it('unifies comment and whitespace variants', () => {
    const variants = [
      'function f() { return 1 + 2; }',
      'function f(){return 1+2;}',
      'function f() {\n  // add them\n  return 1 + 2;\n}',
      'function f() {\r\n  /* add\r\n     them */\r\n  return  1\r\n  +\r\n  2;\r\n}',
      'function f() {\treturn\t\t1 + 2; }',
    ]
    const normalized = variants.map(normalizeSource)
    for (const variant of normalized.slice(1)) {
      expect(variant).toBe(normalized[0])
    }
  })

  it('keeps the space between identifier tokens (return x)', () => {
    expect(normalizeSource('return x')).toBe('return x')
    expect(normalizeSource('return   x')).toBe('return x')
    expect(normalizeSource('return\n\tx')).toBe('return x')
  })

  it('does not strip comment-looking text inside strings', () => {
    const src = 'const u = "http://a/*b*/c" // trailing'
    expect(normalizeSource(src)).toBe('const u="http://a/*b*/c"')
  })

  it('handles escapes inside strings', () => {
    const src = 'const q = "a\\"//not a comment"'
    expect(normalizeSource(src)).toBe('const q="a\\"//not a comment"')
  })

  it('preserves template literal contents verbatim, including newlines', () => {
    const src = 'const t = `a  b\n//not a comment`'
    expect(normalizeSource(src)).toBe('const t=`a  b\n//not a comment`')
  })

  it('normalizes code inside template substitutions but not the literal parts', () => {
    const a = 'const t = `sum: ${a + /* add */ b}`'
    const b = 'const t = `sum: ${a+b}`'
    expect(normalizeSource(a)).toBe(normalizeSource(b))
    expect(normalizeSource(a)).toBe('const t=`sum: ${a+b}`')
  })

  it('treats // inside a regex literal as regex content, not a comment', () => {
    const src = 'const re = /https:\\/\\/example/' // regex containing //
    expect(normalizeSource(src)).toBe('const re=/https:\\/\\/example/')
    const afterReturn = 'return /a\\/\\/b/.test(x)'
    expect(normalizeSource(afterReturn)).toBe('return/a\\/\\/b/.test(x)')
  })

  it('keeps division operators intact', () => {
    expect(normalizeSource('const q = a / b / c')).toBe('const q=a/b/c')
    expect(normalizeSource('x = (a + b) / 2')).toBe('x=(a+b)/2')
  })

  it('comments acting as token separators keep tokens apart', () => {
    expect(normalizeSource('a/*x*/b')).toBe('a b')
    expect(normalizeSource('a/**/+b')).toBe('a+b')
  })

  it('is idempotent', () => {
    const src = 'function f() { // c\n  return `x${a + b}y` / 2 }'
    const once = normalizeSource(src)
    expect(normalizeSource(once)).toBe(once)
  })

  it('produces different output for different bodies', () => {
    expect(normalizeSource('function f() { return 1 }')).not.toBe(
      normalizeSource('function f() { return 2 }'),
    )
  })
})
