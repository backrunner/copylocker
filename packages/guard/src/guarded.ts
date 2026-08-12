/**
 * `@guarded` decorator and the global {@link GuardState}.
 *
 * Design (`50-unplugin-integrity.md §3.2`): a guarded function whose body was
 * replaced must NOT throw — the normalized-body digest is **mixed into** the
 * global guard state (`state = H(state ‖ id ‖ digest)`), so tampering changes
 * the state, which changes `R`, which breaks key derivation. Deleting a
 * `throw` gains the attacker nothing.
 *
 * `Function.prototype.toString` hardening: the native reference is captured
 * at module load (the guard runtime is the first chunk to execute). All
 * reads go through the captured reference, and every sampled call re-checks
 * `Function.prototype.toString === captured`; an override is detected and
 * mixed in (never thrown). Honest limitation: an attacker running BEFORE us
 * (browser extension, patched index.html) can still win — this raises the
 * cost of automated tooling.
 */

import { fallbackDigest, sha256, utf8 } from './bytes.js'
import { normalizeSource } from './normalize.js'

/** Native `Function.prototype.toString`, captured at module load. */
const NATIVE_TOSTRING = Function.prototype.toString

/** Marker mixed in when a `toString` override is detected. */
const TOSTRING_OVERRIDE_MARKER = 'copylocker/guard:tostring-override'

const textEncoder = new TextEncoder()

/**
 * Global guard state: a 32-byte value evolved by {@link GuardState.mix}.
 * Starts at 32 zero bytes; every mix replaces it with
 * `SHA-256(state ‖ utf8(id) ‖ digest)` (or the fallback digest when
 * WebCrypto is unavailable). Mixes are chained through a promise queue so
 * their ORDER is deterministic regardless of async completion order.
 */
class GuardStateImpl {
  private current: Uint8Array = new Uint8Array(32)
  private chain: Promise<void> = Promise.resolve()

  /** Mix a digest into the state. Async completion; order is preserved. */
  mix(id: string, digest: Uint8Array | Promise<Uint8Array>): void {
    this.chain = this.chain.then(async () => {
      let resolved: Uint8Array
      try {
        resolved = await digest
      } catch {
        // A failed digest must not kill the mix queue; mix a deterministic
        // fallback derived from the id instead.
        resolved = fallbackDigest(textEncoder.encode(id))
      }
      const parts = [this.current, textEncoder.encode(id), resolved]
      try {
        this.current = globalThis.crypto?.subtle
          ? await sha256(...parts)
          : fallbackDigest(...parts)
      } catch {
        // A failing WebCrypto digest must not kill the mix queue either —
        // fall back deterministically so later mixes still land.
        this.current = fallbackDigest(...parts)
      }
    })
  }

  /**
   * The current mixed value (snapshot). Reflects only COMPLETED mixes —
   * call {@link settled} first when a deterministic value is needed (e.g.
   * right before key derivation).
   */
  getR(): Uint8Array {
    return new Uint8Array(this.current)
  }

  /** Resolves when all mixes queued so far have completed. */
  settled(): Promise<void> {
    return this.chain
  }

  /** Test hook: reset state and the mix queue. */
  reset(): void {
    this.current = new Uint8Array(32)
    this.chain = Promise.resolve()
  }
}

export const GuardState = new GuardStateImpl()

/** Returns true with probability `rate` (0 → never, 1 → always). */
export function shouldSample(rate: number, rng: () => number = Math.random): boolean {
  if (rate <= 0) return false
  if (rate >= 1) return true
  return rng() < rate
}

/** True while `Function.prototype.toString` is still the captured native. */
export function isToStringIntact(): boolean {
  return Function.prototype.toString === NATIVE_TOSTRING
}

/**
 * Periodic `===` watch on `Function.prototype.toString`. On detecting an
 * override, mixes the marker into {@link GuardState} (never throws). The
 * interval is unref'd where the platform supports it. Returns a stop
 * function. This complements the per-call check done by guarded wrappers.
 */
export function startToStringWatch(intervalMs = 5000): () => void {
  const timer = setInterval(() => {
    if (!isToStringIntact()) {
      GuardState.mix(TOSTRING_OVERRIDE_MARKER, utf8(String(Date.now())))
    }
  }, intervalMs)
  const maybeUnref = timer as unknown as { unref?: () => void }
  maybeUnref.unref?.()
  return () => clearInterval(timer)
}

type AnyFn = (...args: any[]) => any

/** Digest of a function's normalized body text, read via the native toString. */
async function bodyDigest(fn: AnyFn): Promise<Uint8Array> {
  const source = normalizeSource(NATIVE_TOSTRING.call(fn))
  const bytes = utf8(source)
  return globalThis.crypto?.subtle ? sha256(bytes) : fallbackDigest(bytes)
}

function wrapGuarded<F extends AnyFn>(id: string, fn: F, sampleRate: number): F {
  const wrapped = function (this: unknown, ...args: unknown[]) {
    if (!isToStringIntact()) {
      GuardState.mix(TOSTRING_OVERRIDE_MARKER, utf8(String(Date.now())))
    }
    if (shouldSample(sampleRate)) {
      // The digest resolves asynchronously; GuardState's queue keeps the
      // mix order deterministic regardless of resolution order.
      GuardState.mix(id, bodyDigest(fn))
    }
    return fn.apply(this, args)
  } as F
  return wrapped
}

export interface GuardedOptions {
  /** Runtime sampling rate (build-time default: 0.15). */
  sampleRate?: number
}

type LegacyDescriptor = {
  value?: AnyFn
  get?: AnyFn
  set?: AnyFn
}

/**
 * `@guarded(id)` decorator. Supports BOTH signatures:
 *
 * - TS 5 standard decorators: `guarded(id)(value, context)` where
 *   `context.kind` is `'method'` (also `'getter'`/`'setter'`).
 * - Legacy experimental decorators: `guarded(id)(target, key, descriptor)`.
 *
 * For plain functions use {@link guardedFn}.
 */
export function guarded(
  id: string,
  options: GuardedOptions = {},
): (target: unknown, keyOrContext?: unknown, descriptor?: LegacyDescriptor) => unknown {
  const sampleRate = options.sampleRate ?? 0.15
  return (target: unknown, keyOrContext?: unknown, descriptor?: LegacyDescriptor) => {
    // Legacy: (target, propertyKey, descriptor)
    if (descriptor !== undefined && typeof descriptor === 'object') {
      if (typeof descriptor.value === 'function') {
        descriptor.value = wrapGuarded(id, descriptor.value, sampleRate)
      }
      if (typeof descriptor.get === 'function') {
        descriptor.get = wrapGuarded(id, descriptor.get, sampleRate)
      }
      if (typeof descriptor.set === 'function') {
        descriptor.set = wrapGuarded(id, descriptor.set, sampleRate)
      }
      return descriptor
    }
    // Standard: (value, context)
    const kind = (keyOrContext as { kind?: string } | undefined)?.kind
    if (typeof target === 'function' && (kind === undefined || kind === 'method' || kind === 'getter' || kind === 'setter')) {
      return wrapGuarded(id, target as AnyFn, sampleRate)
    }
    throw new TypeError(`CopyLocker guard: @guarded('${id}') applied to an unsupported target`)
  }
}

/** Functional form: `const compute = guardedFn('compute', (x) => ...)`. */
export function guardedFn<F extends AnyFn>(id: string, fn: F, options: GuardedOptions = {}): F {
  return wrapGuarded(id, fn, options.sampleRate ?? 0.15)
}
