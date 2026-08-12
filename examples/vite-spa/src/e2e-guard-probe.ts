/**
 * M4 multi-engine consistency fixture for the packages/web-e2e
 * `vite-spa.r-consistency` spec (`50-unplugin-integrity.md` §3.2).
 *
 * The risk under test: `Function.prototype.toString` output can differ
 * subtly between JS engines, and the guarded-function body digest is
 * computed at runtime from `toString` while the build-time digest in the
 * manifest comes from the final chunk text. `normalizeSource` must absorb
 * any engine difference — otherwise a clean build produces a different
 * guard state on one engine (a false positive).
 *
 * Two functions with byte-identical bodies:
 *
 * - the probe wrapped through `guardedFn('e2e.probe', …)` — the REAL
 *   guarded path: the unplugin transform rewrites the call to the
 *   `__CL_GUARD_FN__` marker, the build collects the body digest into the
 *   signed manifest (`guarded['e2e.probe']`), and the injected bootstrap
 *   wraps the function at runtime.
 * - `e2eProbeTwin` — unwrapped, same body, diagnostics only. The runtime
 *   wrapper closes over the original function and exposes no reference to
 *   it, so the probe reads `toString`/`normalizeSource` from the twin.
 *   Both functions are minified from identical tokens in the same chunk, so
 *   their source slices are identical; the r-consistency spec asserts the
 *   twin's runtime digest equals the manifest entry, which also keeps the
 *   two bodies from drifting apart.
 *
 * The body packs the §3.2 jitter hotspots: comments (present pre-minify),
 * a template literal with substitution, a regex literal, a nested arrow,
 * escapes and a non-ASCII string. (Regexes only in keyword/punctuation
 * position — never right after `)`, the normalizer's documented limit.)
 *
 * The wrap is LAZY and failure-tolerant: the rewritten `__CL_GUARD_FN__`
 * global only exists when the guard bootstrap ran. The web-e2e
 * delete-the-bootstrap attack scenario strips exactly that bootstrap while
 * keeping the constants block — a module-scope marker call would throw a
 * ReferenceError during chunk evaluation and take the whole app down with
 * it, which is NOT what that scenario asserts (derivation must fail closed
 * at unseal time, not at module load).
 */
import { GuardState, guardedFn, normalizeSource } from '@copylocker/guard'

type ProbeFn = (x: number) => number

const e2eProbeTwin: ProbeFn = (x) => {
  // line comment — the normalizer strips these from pre-minify sources
  const label = `probe:${x}` /* block comment */
  const digits = /^\d+$/u.test(String(x)) ? x : 0
  const bump = (n: number) => n + 1
  const snowman = '☃☃'
  return bump(digits) + label.length + snowman.length
}

let e2eGuardedProbe: ProbeFn | undefined

/**
 * Wrap the probe through the (rewritten) guarded path on first use. Falls
 * back to the twin when the marker global is absent — `vite dev` has no
 * injection, and the delete-the-bootstrap attack removes it on purpose.
 */
function wrappedProbe(): ProbeFn {
  if (e2eGuardedProbe) return e2eGuardedProbe
  try {
    e2eGuardedProbe = guardedFn(
      'e2e.probe',
      (x: number): number => {
        // line comment — the normalizer strips these from pre-minify sources
        const label = `probe:${x}` /* block comment */
        const digits = /^\d+$/u.test(String(x)) ? x : 0
        const bump = (n: number) => n + 1
        const snowman = '☃\u2603'
        return bump(digits) + label.length + snowman.length
      },
      // sampleRate 1: every call is digested — deterministic for the probe.
      { sampleRate: 1 },
    )
  } catch {
    // `__CL_GUARD_FN__` undefined (bootstrap deleted / dev): unwrapped twin.
    e2eGuardedProbe = e2eProbeTwin
  }
  return e2eGuardedProbe
}

const toHex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')

export interface GuardProbeResult {
  /** Guarded function id, as collected into the manifest. */
  id: string
  /** Raw `Function.prototype.toString` output on this engine (twin). */
  raw: string
  /** `normalizeSource(raw)` — must be byte-identical across engines. */
  normalized: string
  /** `SHA-256(utf8(normalized))` — the runtime body digest. */
  digestHex: string
  /**
   * `GuardState.getR()` after `reset()` + one `mix(id, digest)`: the exact
   * state evolution the guarded wrapper performs, isolated for comparison.
   * Exercises the real GuardState mix queue (async SHA-256 chaining).
   */
  guardStateHex: string
  /** Result of invoking the wrapped probe (exercises the wrapper). */
  wrappedResult: number
  userAgent: string
}

async function probe(): Promise<GuardProbeResult> {
  const raw = Function.prototype.toString.call(e2eProbeTwin)
  const normalized = normalizeSource(raw)
  const digest = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(normalized)),
  )
  GuardState.reset()
  GuardState.mix('e2e.probe', digest)
  await GuardState.settled()
  return {
    id: 'e2e.probe',
    raw,
    normalized,
    digestHex: toHex(digest),
    guardStateHex: toHex(GuardState.getR()),
    wrappedResult: wrappedProbe()(41),
    userAgent: navigator.userAgent,
  }
}

// E2E hook, same pattern as `window.__copylocker` in main.ts: it exposes
// nothing the page's own JS could not already reach.
;(window as unknown as Record<string, unknown>).__CL_E2E_GUARD_PROBE__ = { probe }
