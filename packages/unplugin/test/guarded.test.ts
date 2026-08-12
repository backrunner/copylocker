import { describe, expect, it } from 'vitest'
import { normalizeSource } from '@copylocker/guard'
import {
  extractFunctionSource,
  extractGuarded,
  findGuardedFnBindings,
  guardedDigest,
  rewriteGuardedMarkers,
} from '../src/guarded.js'
import { sha256 } from '../src/hash.js'

describe('guarded marker rewrite (transform)', () => {
  it('finds plain and aliased guardedFn imports from @copylocker/guard', () => {
    expect(findGuardedFnBindings(`import { guardedFn } from '@copylocker/guard'`)).toEqual([
      'guardedFn',
    ])
    expect(
      findGuardedFnBindings(`import { guardedFn as g, bootGuard } from "@copylocker/guard"`),
    ).toEqual(['g'])
    expect(findGuardedFnBindings(`import { guardedFn } from 'other-package'`)).toEqual([])
  })

  it('rewrites call sites to the minify-proof global marker', () => {
    const code = [
      `import { guardedFn } from '@copylocker/guard'`,
      `export const compute = guardedFn('compute', (x) => x * 2)`,
      `const notIt = obj.guardedFn('no', () => 1)`,
    ].join('\n')
    const out = rewriteGuardedMarkers(code)
    expect(out).toContain(`__CL_GUARD_FN__('compute', (x) => x * 2)`)
    expect(out).toContain(`obj.guardedFn('no'`)
    expect(out).not.toContain(`= guardedFn(`)
  })

  it('does not rewrite occurrences inside string literals or comments', () => {
    const code = [
      `import { guardedFn } from '@copylocker/guard'`,
      `const s = "call guardedFn('x', fn) here"`,
      `// guardedFn('y', fn) in a comment`,
      `const re = /guardedFn\\(/`,
      `export const compute = guardedFn('compute', (x) => x * 2)`,
    ].join('\n')
    const out = rewriteGuardedMarkers(code) as string
    expect(out).toContain(`"call guardedFn('x', fn) here"`)
    expect(out).toContain(`// guardedFn('y', fn) in a comment`)
    expect(out).toContain(`/guardedFn\\(/`)
    expect(out).toContain(`__CL_GUARD_FN__('compute', (x) => x * 2)`)
  })

  it('returns null when the module imports no guardedFn', () => {
    expect(rewriteGuardedMarkers(`const x = 1`)).toBeNull()
    expect(rewriteGuardedMarkers(`import { bootGuard } from '@copylocker/guard'`)).toBeNull()
  })
})

describe('guarded extraction (final bundle text)', () => {
  it('extracts arrow and classic function bodies from minified text', () => {
    const code = `const a=__CL_GUARD_FN__("compute",(x)=>{return x*2}),b=__CL_GUARD_FN__('render',function render(scene){draw(scene);return {ok:true}});`
    const found = extractGuarded(code)
    expect(found).toHaveLength(2)
    expect(found[0]).toEqual({ id: 'compute', source: '(x)=>{return x*2}' })
    expect(found[1]).toEqual({
      id: 'render',
      source: 'function render(scene){draw(scene);return {ok:true}}',
    })
  })

  it('handles expression bodies, async, strings and nested braces', () => {
    const code = [
      `__CL_GUARD_FN__("expr",(x)=>x+1)`,
      `__CL_GUARD_FN__("async-fn",async function(){await f("}{")})`,
      `__CL_GUARD_FN__("tmpl",()=>\`a\${b({c:1})}d\`)`,
    ].join(';')
    const found = extractGuarded(code)
    expect(found.map((f) => f.id)).toEqual(['expr', 'async-fn', 'tmpl'])
    expect(found[0]?.source).toBe('(x)=>x+1')
    expect(found[1]?.source).toBe('async function(){await f("}{")}')
    expect(found[2]?.source).toBe('()=>`a${b({c:1})}d`')
  })

  it('skips non-literal call sites', () => {
    expect(extractGuarded(`__CL_GUARD_FN__(id, () => 1)`)).toEqual([])
    expect(extractGuarded(`__CL_GUARD_FN__("x", notAFunction)`)).toEqual([])
  })

  it('digest matches SHA-256(utf8(normalizeSource(source))) — the runtime construction', async () => {
    const source = '(x)=>{return x*2}'
    const expected = await sha256(new TextEncoder().encode(normalizeSource(source)))
    expect(await guardedDigest(source)).toEqual(expected)
  })

  it('extractFunctionSource stops at the call boundary for expression bodies', () => {
    const code = `f((a,b)=>a+b,{sampleRate:0.5})`
    const found = extractFunctionSource(code, 2)
    expect(found?.source).toBe('(a,b)=>a+b')
  })

  it('extracts arrows with nested parens in the parameter list', () => {
    const code = `__CL_GUARD_FN__("nested",(a = (1))=>a+1)`
    const found = extractGuarded(code)
    expect(found).toHaveLength(1)
    expect(found[0]?.source).toBe('(a = (1))=>a+1')
  })

  it('does not truncate bodies containing regex literals', () => {
    const code = `__CL_GUARD_FN__("re",function f(s){return /\\}/.test(s)})`
    const found = extractGuarded(code)
    expect(found).toHaveLength(1)
    expect(found[0]?.source).toBe('function f(s){return /\\}/.test(s)}')
  })

  it('finds the body brace past parameter defaults containing braces', () => {
    const code = `__CL_GUARD_FN__("def",function f(a = {}) { return a })`
    const found = extractGuarded(code)
    expect(found).toHaveLength(1)
    expect(found[0]?.source).toBe('function f(a = {}) { return a }')
  })
})
