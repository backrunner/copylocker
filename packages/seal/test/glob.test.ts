import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { expandGlobs, globToRegExp, isGlob } from '../src/glob.js'

describe('glob: pattern compilation', () => {
  it('matches literals, *, and **', () => {
    expect(globToRegExp('assets/a.json').test('assets/a.json')).toBe(true)
    expect(globToRegExp('assets/a.json').test('assets/b.json')).toBe(false)
    expect(globToRegExp('assets/*.json').test('assets/a.json')).toBe(true)
    expect(globToRegExp('assets/*.json').test('assets/deep/a.json')).toBe(false)
    expect(globToRegExp('assets/**').test('assets/deep/deeper/a.bin')).toBe(true)
    expect(globToRegExp('assets/**').test('assets/a.bin')).toBe(true)
    expect(globToRegExp('**/*.json').test('a.json')).toBe(true)
    expect(globToRegExp('**/*.json').test('x/y/a.json')).toBe(true)
    expect(globToRegExp('**/*.json').test('x/y/a.bin')).toBe(false)
    expect(globToRegExp('pro-*').test('pro-alpha')).toBe(true)
    expect(globToRegExp('pro-*').test('xpro-alpha')).toBe(false)
    // Regression: a literal segment followed by `/**/` must keep its separator.
    expect(globToRegExp('static/**/*.js').test('static/a.js')).toBe(true)
    expect(globToRegExp('static/**/*.js').test('static/a/b.js')).toBe(true)
    expect(globToRegExp('static/**/*.js').test('static/a/b.css')).toBe(false)
    expect(globToRegExp('static/**/*.js').test('staticx/a.js')).toBe(false)
    expect(globToRegExp('static/**/*.js').test('other/a.js')).toBe(false)
  })

  it('escapes regex metacharacters in literals', () => {
    expect(globToRegExp('a.b+c').test('a.b+c')).toBe(true)
    expect(globToRegExp('a.b+c').test('aXb+c')).toBe(false)
  })

  it('detects magic', () => {
    expect(isGlob('assets/*.json')).toBe(true)
    expect(isGlob('assets/a.json')).toBe(false)
  })
})

describe('glob: filesystem expansion', () => {
  let dir: string

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'copylocker-seal-glob-'))
    await mkdir(join(dir, 'assets/pro'), { recursive: true })
    await mkdir(join(dir, 'node_modules/pkg'), { recursive: true })
    await writeFile(join(dir, 'assets/pro/a.json'), '{}')
    await writeFile(join(dir, 'assets/pro/b.bin'), 'xx')
    await writeFile(join(dir, 'assets/top.json'), '{}')
    await writeFile(join(dir, 'node_modules/pkg/skip.json'), '{}')
  })

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  it('expands mixed literal and glob patterns, sorted and deduped', async () => {
    const files = await expandGlobs(dir, ['assets/*.json', 'assets/pro/*', 'assets/top.json'])
    expect(files).toEqual(['assets/pro/a.json', 'assets/pro/b.bin', 'assets/top.json'])
  })

  it('supports ** across depths', async () => {
    const files = await expandGlobs(dir, ['**/*.json'])
    expect(files).toEqual(['assets/pro/a.json', 'assets/top.json'])
  })

  it('never descends into node_modules', async () => {
    const files = await expandGlobs(dir, ['**'])
    expect(files.some((f) => f.includes('node_modules'))).toBe(false)
  })

  it('missing literals are silently skipped', async () => {
    await expect(expandGlobs(dir, ['nope.json'])).resolves.toEqual([])
  })

  it('rejects literal patterns that escape the working directory', async () => {
    await expect(expandGlobs(dir, ['../outside.json'])).rejects.toMatchObject({ code: 'CONFIG' })
    await expect(expandGlobs(dir, ['assets/../../outside.json'])).rejects.toMatchObject({
      code: 'CONFIG',
    })
    // …while '..' that resolves back INSIDE cwd is fine.
    await expect(expandGlobs(dir, ['assets/../assets/top.json'])).resolves.toEqual([
      'assets/../assets/top.json',
    ])
  })

  it('never descends into the .copylocker key-material directory', async () => {
    await mkdir(join(dir, '.copylocker'), { recursive: true })
    await writeFile(join(dir, '.copylocker/wrapping-key'), 'secret')
    const files = await expandGlobs(dir, ['**'])
    expect(files.some((f) => f.includes('.copylocker'))).toBe(false)
  })
})
