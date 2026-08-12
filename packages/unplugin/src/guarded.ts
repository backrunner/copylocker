/**
 * `@guarded` build-time collection (`50-unplugin-integrity.md §2.2 transform`,
 * guard README "Interface for @copylocker/unplugin").
 *
 * Two halves:
 *
 * 1. {@link rewriteGuardedMarkers} (transform hook, per source module):
 *    rewrites `guardedFn('id', fn)` call sites that use the
 *    `@copylocker/guard` import into `__CL_GUARD_FN__('id', fn)`. The marker
 *    is an UNDECLARED global reference, so minifiers never rename it —
 *    `enforce: 'post'` collection in the final bundle can still find it. The
 *    global is provided by the injected bootstrap (it wraps the guard
 *    package's `guardedFn` with the configured sample rate).
 *
 * 2. {@link extractGuarded} (post-bundle): scans FINAL chunk text for the
 *    marker, extracts the function source with a bracket/string/template
 *    scanner, and digests `SHA-256(utf8(normalizeSource(source)))` using the
 *    guard package's own `normalizeSource` — the same normalizer the runtime
 *    wrapper applies to `Function.prototype.toString` output, so build-time
 *    and runtime agree.
 */

import { normalizeSource } from '@copylocker/guard'
import { sha256 } from './hash.js'

/** Global marker the transform rewrites `guardedFn` calls to. */
export const GUARD_FN_GLOBAL = '__CL_GUARD_FN__'

const GUARD_PACKAGE = '@copylocker/guard'

/**
 * Find local bindings of `guardedFn` imported from `@copylocker/guard`:
 * handles `import { guardedFn }` and `import { guardedFn as g }`.
 */
export function findGuardedFnBindings(code: string): string[] {
  const bindings: string[] = []
  const importRe = /import\s*\{([^}]*)\}\s*from\s*['"]@copylocker\/guard['"]/g
  let match: RegExpExecArray | null
  while ((match = importRe.exec(code)) !== null) {
    const specifiers = (match[1] as string).split(',')
    for (const specifier of specifiers) {
      const alias = /^\s*guardedFn\s+as\s+([$\w]+)\s*$/.exec(specifier)
      if (alias) {
        bindings.push(alias[1] as string)
      } else if (/^\s*guardedFn\s*$/.test(specifier)) {
        bindings.push('guardedFn')
      }
    }
  }
  return bindings
}

/**
 * Rewrite `guardedFn(` call sites to the minify-proof global marker. Returns
 * `null` when nothing changed (the common case — most modules import no
 * guarded functions).
 *
 * The scan is literal-aware: occurrences inside string/template/comment/regex
 * literals are left untouched (a regex replace would corrupt string CONTENT).
 * It is still scope-blind: a shadowed local binding named like the import is
 * rewritten too — a documented limitation, same as any parser-free codemod.
 */
export function rewriteGuardedMarkers(code: string): string | null {
  const bindings = new Set(findGuardedFnBindings(code))
  if (bindings.size === 0) return null
  const n = code.length
  const state: ScanState = { prevSig: '', prevWord: '' }
  let out = ''
  let i = 0
  let changed = false
  while (i < n) {
    const ch = code[i] as string
    if (isIdentChar(ch)) {
      // Identifier-ish word — checked BEFORE step() so call sites of the
      // imported binding can be intercepted.
      let j = i + 1
      while (j < n && isIdentChar(code[j] as string)) j += 1
      const word = code.slice(i, j)
      let k = j
      while (k < n && /\s/.test(code[k] as string)) k += 1
      // Not preceded by '.' (member access / property) — an identifier char
      // before a word start is impossible (words are consumed whole).
      if (bindings.has(word) && code[k] === '(' && !out.endsWith('.')) {
        out += `${GUARD_FN_GLOBAL}(`
        changed = true
        i = k + 1
      } else {
        out += word
        i = j
      }
      state.prevWord = word
      state.prevSig = word[word.length - 1] as string
      continue
    }
    const stepped = step(code, i, state)
    if (stepped !== -1) {
      out += code.slice(i, stepped)
      i = stepped
      continue
    }
    noteChar(ch, state)
    out += ch
    i += 1
  }
  return changed ? out : null
}

export interface ExtractedGuarded {
  id: string
  /** Exact function source text as it appears in the final chunk. */
  source: string
}

/** Skip a string/template/comment starting at `i`; returns the index past it. */
function skipLiteral(code: string, i: number): number {
  const n = code.length
  const ch = code[i] as string
  if (ch === '/' && code[i + 1] === '/') {
    let j = i + 2
    while (j < n && code[j] !== '\n') j += 1
    return j
  }
  if (ch === '/' && code[i + 1] === '*') {
    let j = i + 2
    while (j < n && !(code[j] === '*' && code[j + 1] === '/')) j += 1
    return Math.min(j + 2, n)
  }
  if (ch === '`') {
    let j = i + 1
    while (j < n) {
      const c = code[j] as string
      if (c === '\\') {
        j += 2
        continue
      }
      if (c === '`') return j + 1
      // Template substitutions are scanned as code (they can contain brackets).
      if (c === '$' && code[j + 1] === '{') {
        j = skipBalanced(code, j + 1) // past the matching '}'
        continue
      }
      j += 1
    }
    return n
  }
  // Quoted string.
  let j = i + 1
  while (j < n) {
    const c = code[j] as string
    if (c === '\\') {
      j += 2
      continue
    }
    if (c === ch) return j + 1
    j += 1
  }
  return n
}

function isIdentChar(ch: string): boolean {
  return /[$\w]/.test(ch)
}

/** Keywords after which a `/` begins a regex literal (mirrors guard's normalizeSource). */
const REGEX_PREFIX_KEYWORDS = new Set([
  'return',
  'typeof',
  'instanceof',
  'in',
  'of',
  'new',
  'delete',
  'void',
  'throw',
  'case',
  'do',
  'else',
  'yield',
  'await',
])

/** Scanner state for the regex-vs-division heuristic. */
interface ScanState {
  /** Last significant (non-space) character. */
  prevSig: string
  /** Last identifier-ish word ('' when the last token was not one). */
  prevWord: string
}

/**
 * Regex-vs-division heuristic — the SAME rule the guard package's
 * `normalizeSource` applies, so the extractor and the runtime normalizer
 * scan ambiguous source identically. Known limitation (inherited):
 * `if (x) /re/.test(y)` is misclassified.
 */
function regexAllowed(state: ScanState): boolean {
  if (state.prevWord !== '') return REGEX_PREFIX_KEYWORDS.has(state.prevWord)
  if (state.prevSig === '') return true
  return !(isIdentChar(state.prevSig) || state.prevSig === ')' || state.prevSig === ']')
}

/**
 * Skip a regex literal starting at `i` (the leading `/`), flags included.
 * Returns -1 when the literal is unterminated (treat the `/` as division).
 */
function skipRegexLiteral(code: string, i: number): number {
  const n = code.length
  let j = i + 1
  let inClass = false
  while (j < n) {
    const c = code[j] as string
    if (c === '\\') {
      j += 2
      continue
    }
    if (c === '\n') return -1
    if (c === '[') inClass = true
    else if (c === ']') inClass = false
    else if (c === '/' && !inClass) {
      j += 1
      while (j < n && isIdentChar(code[j] as string)) j += 1
      return j
    }
    j += 1
  }
  return -1
}

/**
 * Advance past a string/template/comment/regex literal or an identifier-ish
 * word at `i`, updating the scan state. Returns the new index, or -1 when
 * the character at `i` is ordinary punctuation/whitespace the caller must
 * handle itself.
 */
function step(code: string, i: number, state: ScanState): number {
  const n = code.length
  const ch = code[i] as string
  if (ch === '"' || ch === "'" || ch === '`') {
    state.prevSig = ch // a string/template operand — division follows
    state.prevWord = ''
    return skipLiteral(code, i)
  }
  if (ch === '/' && (code[i + 1] === '/' || code[i + 1] === '*')) {
    return skipLiteral(code, i) // comments are whitespace: state unchanged
  }
  if (ch === '/') {
    if (regexAllowed(state)) {
      const end = skipRegexLiteral(code, i)
      if (end !== -1) {
        state.prevSig = '/'
        state.prevWord = ''
        return end
      }
    }
    state.prevSig = '/'
    state.prevWord = ''
    return i + 1
  }
  if (isIdentChar(ch)) {
    let j = i + 1
    while (j < n && isIdentChar(code[j] as string)) j += 1
    state.prevWord = code.slice(i, j)
    state.prevSig = code[j - 1] as string
    return j
  }
  return -1
}

/** Note an ordinary punctuation/whitespace character in the scan state. */
function noteChar(ch: string, state: ScanState): void {
  if (/\s/.test(ch)) return
  state.prevSig = ch
  state.prevWord = ''
}

/** Starting at a `{`, returns the index just past the matching `}`. */
function skipBalanced(code: string, openIndex: number): number {
  const n = code.length
  let depth = 0
  let i = openIndex
  const state: ScanState = { prevSig: '', prevWord: '' }
  while (i < n) {
    const stepped = step(code, i, state)
    if (stepped !== -1) {
      i = stepped
      continue
    }
    const ch = code[i] as string
    if (ch === '{') depth += 1
    if (ch === '}') {
      depth -= 1
      if (depth === 0) return i + 1
    }
    noteChar(ch, state)
    i += 1
  }
  return n
}

/** Starting at a `(`, returns the index just past the matching `)`. */
function skipBalancedParens(code: string, openIndex: number): number {
  const n = code.length
  let depth = 0
  let i = openIndex
  const state: ScanState = { prevSig: '', prevWord: '' }
  while (i < n) {
    const stepped = step(code, i, state)
    if (stepped !== -1) {
      i = stepped
      continue
    }
    const ch = code[i] as string
    if (ch === '(') depth += 1
    if (ch === ')') {
      depth -= 1
      if (depth === 0) return i + 1
    }
    noteChar(ch, state)
    i += 1
  }
  return n
}

/**
 * Extract the function expression starting at `start` (first non-space char
 * after the marker's first-argument comma). Returns the source and the index
 * just past it, or null when the shape is not a statically extractable
 * function expression.
 */
export function extractFunctionSource(
  code: string,
  start: number,
): { source: string; end: number } | null {
  const n = code.length
  let i = start
  while (i < n && /\s/.test(code[i] as string)) i += 1
  const rest = code.slice(i)

  // `function name?(...) { ... }` / `async function ...`
  const fnMatch = /^(?:async\s+)?function(?:[\s*]|\()/.exec(rest)
  if (fnMatch) {
    // The body brace is the first `{` AFTER the parameter list — a default
    // like `function f(a = {})` must not fool a naive indexOf('{').
    const paren = code.indexOf('(', i)
    if (paren === -1) return null
    const paramsEnd = skipBalancedParens(code, paren)
    let brace = paramsEnd
    while (brace < n && /\s/.test(code[brace] as string)) brace += 1
    if (code[brace] !== '{') return null
    const end = skipBalanced(code, brace)
    return { source: code.slice(i, end), end }
  }

  // Arrow functions: `(...) => body`, `async (...) => body`, `x => body`.
  // The parameter list is scanned with balanced parens — nested parens in
  // defaults (`(a = (1)) => …`) must not truncate the match.
  let headerStart = i
  const asyncMatch = /^async\s+/.exec(rest)
  if (asyncMatch) headerStart = i + asyncMatch[0].length
  let paramsEnd = -1
  if (code[headerStart] === '(') {
    paramsEnd = skipBalancedParens(code, headerStart)
  } else {
    const ident = /^[$\w]+/.exec(code.slice(headerStart))
    if (ident) paramsEnd = headerStart + ident[0].length
  }
  let arrow = paramsEnd
  while (arrow < n && /\s/.test(code[arrow] as string)) arrow += 1
  if (paramsEnd !== -1 && code[arrow] === '=' && code[arrow + 1] === '>') {
    let bodyStart = arrow + 2
    while (bodyStart < n && /\s/.test(code[bodyStart] as string)) bodyStart += 1
    if (code[bodyStart] === '{') {
      const end = skipBalanced(code, bodyStart)
      return { source: code.slice(i, end), end }
    }
    // Expression body: ends at the marker call's `,` or `)` at depth 0.
    let depth = 0
    let j = bodyStart
    const state: ScanState = { prevSig: '', prevWord: '' }
    while (j < n) {
      const stepped = step(code, j, state)
      if (stepped !== -1) {
        j = stepped
        continue
      }
      const ch = code[j] as string
      if (ch === '(' || ch === '[' || ch === '{') depth += 1
      else if (ch === ')' || ch === ']' || ch === '}') {
        if (depth === 0) return { source: code.slice(i, j), end: j }
        depth -= 1
      } else if (ch === ',' && depth === 0) {
        return { source: code.slice(i, j), end: j }
      }
      noteChar(ch, state)
      j += 1
    }
    return null
  }

  return null
}

/** Parse a string literal at `i`; returns its value and the index past it. */
function parseStringLiteral(code: string, i: number): { value: string; end: number } | null {
  const quote = code[i]
  if (quote !== '"' && quote !== "'" && quote !== '`') return null
  const end = skipLiteral(code, i)
  if (end > code.length) return null
  const raw = code.slice(i + 1, end - 1)
  if (quote === '`') {
    // Minifiers rewrite plain strings as template literals; only accept
    // substitution-free ones as static ids.
    if (raw.includes('${')) return null
    return { value: raw.replace(/\\([`$\\])/g, '$1'), end }
  }
  try {
    // JSON.parse handles double quotes; for single quotes use Function-free
    // manual unescape of the common escapes.
    const value = raw.replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (m, esc: string) => {
      if (esc.startsWith('u{')) return String.fromCodePoint(Number.parseInt(esc.slice(2, -1), 16))
      if (esc.startsWith('u')) return String.fromCharCode(Number.parseInt(esc.slice(1), 16))
      if (esc.startsWith('x')) return String.fromCharCode(Number.parseInt(esc.slice(1), 16))
      const simple: Record<string, string> = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', v: '\v', '0': '\0' }
      return simple[esc] ?? esc
    })
    return { value, end }
  } catch {
    return null
  }
}

/** Scan final chunk text for `__CL_GUARD_FN__('id', <fn>)` call sites. */
export function extractGuarded(code: string): ExtractedGuarded[] {
  const out: ExtractedGuarded[] = []
  const markerRe = /__CL_GUARD_FN__\s*\(\s*/g
  let match: RegExpExecArray | null
  while ((match = markerRe.exec(code)) !== null) {
    const argsStart = match.index + match[0].length
    const idLiteral = parseStringLiteral(code, argsStart)
    if (!idLiteral) continue
    let i = idLiteral.end
    while (i < code.length && /\s/.test(code[i] as string)) i += 1
    if (code[i] !== ',') continue
    const fn = extractFunctionSource(code, i + 1)
    if (!fn) continue
    out.push({ id: idLiteral.value, source: fn.source })
  }
  return out
}

/**
 * Build-time guarded digest: `SHA-256(utf8(normalizeSource(source)))` — the
 * exact construction the runtime wrapper performs (guard `guarded.ts`).
 */
export async function guardedDigest(source: string): Promise<Uint8Array> {
  return sha256(new TextEncoder().encode(normalizeSource(source)))
}
