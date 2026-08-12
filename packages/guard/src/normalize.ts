/**
 * Function-body source normalization for `@guarded` digests.
 *
 * Goal: make the digest insensitive to the formatting jitter between build
 * output and `Function.prototype.toString()` across engines — comments,
 * whitespace runs, and line-ending style. The output is NOT required to be
 * valid JavaScript; it must be **deterministic** (same input text → same
 * output, on every engine) so that build-time and runtime agree.
 *
 * Transformations:
 * - `\r\n` / `\r` → `\n` (also inside strings and templates);
 * - line and block comments are removed (treated as whitespace);
 * - whitespace is dropped entirely, except a single space between two
 *   identifier-ish tokens (`return x` stays separated). String and
 *   template-literal contents are preserved verbatim.
 *
 * Regex-vs-division ambiguity: distinguishing a regex literal from the
 * division operator requires full parsing; this scanner uses the standard
 * heuristic — after an identifier, number, `)` or `]` a `/` is division,
 * after punctuation or a keyword (`return`, `typeof`, ...) it starts a
 * regex. Known limitation: `if (x) /re/.test(y)` (regex right after `)`)
 * is misclassified, which can desynchronize the scanner. Guarded functions
 * should avoid regex literals in that position. Because the SAME normalizer
 * runs at build time and runtime, a misclassification only matters when it
 * makes the output depend on engine-specific `toString` formatting inside
 * the mis-scanned region — a rare, diagnosable false positive (see
 * `@copylocker/guard/diagnose`).
 */

/** Keywords after which a `/` begins a regex literal. */
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

function isIdentChar(ch: string): boolean {
  return /[$\w]/.test(ch)
}

function isSpace(ch: string): boolean {
  return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\v' || ch === '\f'
}

/** Normalize function source text; see module docs for the exact rules. */
export function normalizeSource(source: string): string {
  const src = source.replace(/\r\n?/g, '\n')
  const n = src.length
  const out: string[] = []
  let spacePending = false
  let prevSig = '' // last significant (non-space) emitted character
  let prevWord = '' // last emitted identifier-ish word

  const emit = (text: string): void => {
    if (text === '') return
    // Whitespace is dropped entirely, EXCEPT a single space between two
    // identifier-ish tokens where removal would merge them (`return x`).
    if (spacePending && out.length > 0 && isIdentChar(prevSig) && isIdentChar(text[0] as string)) {
      out.push(' ')
    }
    spacePending = false
    out.push(text)
  }
  const markSpace = (): void => {
    if (out.length > 0) spacePending = true
  }
  const note = (ch: string, word = ''): void => {
    prevSig = ch
    prevWord = word
  }

  /** Scan a quoted string starting at `i`; returns the index past it. */
  function scanString(i: number): number {
    const quote = src[i] as string
    let j = i + 1
    while (j < n) {
      const c = src[j] as string
      if (c === '\\') {
        j += 2
        continue
      }
      if (c === quote) {
        j += 1
        break
      }
      j += 1
    }
    emit(src.slice(i, j))
    note(quote)
    return j
  }

  /** Scan a template literal starting at `i`; returns the index past it. */
  function scanTemplate(i: number): number {
    let start = i
    let j = i + 1
    while (j < n) {
      const c = src[j] as string
      if (c === '\\') {
        j += 2
        continue
      }
      if (c === '`') {
        emit(src.slice(start, j + 1))
        note('`')
        return j + 1
      }
      if (c === '$' && src[j + 1] === '{') {
        emit(src.slice(start, j + 2))
        note('{')
        j = scanNormal(j + 2, true)
        start = j
        continue
      }
      j += 1
    }
    emit(src.slice(start))
    note('`')
    return n
  }

  /**
   * Scan normal code from `i`. When `inSubst`, returns just past the `}`
   * closing the template substitution; otherwise scans to the end.
   */
  function scanNormal(startIndex: number, inSubst: boolean): number {
    let depth = 0
    let i = startIndex
    while (i < n) {
      const ch = src[i] as string
      const next = i + 1 < n ? (src[i + 1] as string) : ''

      if (isSpace(ch)) {
        markSpace()
        i += 1
        continue
      }

      if (ch === '/' && next === '/') {
        markSpace()
        i += 2
        while (i < n && src[i] !== '\n') i += 1
        continue
      }
      if (ch === '/' && next === '*') {
        markSpace()
        i += 2
        while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i += 1
        i = Math.min(i + 2, n)
        continue
      }

      if (ch === '"' || ch === "'") {
        i = scanString(i)
        continue
      }
      if (ch === '`') {
        i = scanTemplate(i)
        continue
      }

      if (ch === '{') {
        depth += 1
        emit('{')
        note('{')
        i += 1
        continue
      }
      if (ch === '}') {
        emit('}')
        note('}')
        i += 1
        if (inSubst && depth === 0) return i
        depth = Math.max(0, depth - 1)
        continue
      }

      if (ch === '/') {
        // Regex vs division heuristic (module docs).
        let regexAllowed: boolean
        if (prevWord !== '') {
          regexAllowed = REGEX_PREFIX_KEYWORDS.has(prevWord)
        } else if (prevSig === '') {
          regexAllowed = true
        } else {
          regexAllowed = !(isIdentChar(prevSig) || prevSig === ')' || prevSig === ']')
        }
        if (regexAllowed) {
          let j = i + 1
          let inClass = false
          let closed = false
          while (j < n) {
            const c = src[j] as string
            if (c === '\\') {
              j += 2
              continue
            }
            if (c === '\n') break
            if (c === '[') inClass = true
            else if (c === ']') inClass = false
            else if (c === '/' && !inClass) {
              closed = true
              break
            }
            j += 1
          }
          if (closed) {
            emit(src.slice(i, j + 1))
            note('/')
            i = j + 1
            continue
          }
          // Unterminated regex: fall through, treat as division.
        }
        emit('/')
        note('/')
        i += 1
        continue
      }

      if (isIdentChar(ch)) {
        let j = i + 1
        while (j < n && isIdentChar(src[j] as string)) j += 1
        const word = src.slice(i, j)
        emit(word)
        note(word[word.length - 1] as string, word)
        i = j
        continue
      }

      emit(ch)
      note(ch)
      i += 1
    }
    return i
  }

  scanNormal(0, false)
  return out.join('')
}
