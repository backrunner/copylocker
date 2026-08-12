/**
 * Validation trigger scheduling (design §4.3).
 *
 * Triggers: `online` events, `visibilitychange` (visible → resume), a
 * **recursive `setTimeout`** tick (never an interval timer, which accumulates
 * throttled callbacks in background tabs), an explicit `hintOnline()`, and
 * wake-ups requested by the core (`EFFECT_SCHEDULE_WAKE`). The global `fetch`
 * is never monkey-patched; {@link wrapFetch} is an opt-in helper.
 */

export type TriggerReason = 'tick' | 'network' | 'resume' | 'hint' | 'wake'

export interface SchedulerHooks {
  onTrigger(reason: TriggerReason): void
}

interface EventTargetLike {
  addEventListener(type: string, listener: () => void): void
  removeEventListener(type: string, listener: () => void): void
}

export interface SchedulerOptions {
  /** Periodic tick interval in milliseconds (default 60s). */
  intervalMs?: number
  /** Injectable targets for tests; default to the globals when present. */
  window?: EventTargetLike | null
  document?: (EventTargetLike & { hidden?: boolean }) | null
  setTimeoutFn?: typeof setTimeout
  clearTimeoutFn?: typeof clearTimeout
}

export class Scheduler {
  private readonly intervalMs: number
  private readonly win: EventTargetLike | null
  private readonly doc: (EventTargetLike & { hidden?: boolean }) | null
  private readonly setTimeoutFn: typeof setTimeout
  private readonly clearTimeoutFn: typeof clearTimeout
  private timer: ReturnType<typeof setTimeout> | null = null
  private wakeTimer: ReturnType<typeof setTimeout> | null = null
  private running = false
  private lastResumeAt = 0

  private readonly onOnline = (): void => this.trigger('network')
  private readonly onVisibility = (): void => {
    if (this.doc && !this.doc.hidden) this.trigger('resume')
  }

  constructor(
    private readonly hooks: SchedulerHooks,
    options: SchedulerOptions = {},
  ) {
    this.intervalMs = options.intervalMs ?? 60_000
    this.win = options.window === undefined ? safeGlobal('window') : options.window
    this.doc = options.document === undefined ? safeGlobal('document') : options.document
    // Platform timers are WebIDL operations: they must be invoked with the
    // global as receiver, so wrap them instead of storing the bare function
    // (`this.setTimeoutFn(...)` would call it with the Scheduler as `this`
    // and Chromium throws "Illegal invocation").
    this.setTimeoutFn =
      options.setTimeoutFn ??
      ((handler, timeout, ...args) => setTimeout(handler, timeout, ...args))
    this.clearTimeoutFn = options.clearTimeoutFn ?? ((id) => clearTimeout(id))
  }

  start(): void {
    if (this.running) return
    this.running = true
    this.win?.addEventListener('online', this.onOnline)
    this.doc?.addEventListener('visibilitychange', this.onVisibility)
    this.arm(this.intervalMs)
  }

  stop(): void {
    this.running = false
    this.win?.removeEventListener('online', this.onOnline)
    this.doc?.removeEventListener('visibilitychange', this.onVisibility)
    if (this.timer !== null) {
      this.clearTimeoutFn(this.timer)
      this.timer = null
    }
    if (this.wakeTimer !== null) {
      this.clearTimeoutFn(this.wakeTimer)
      this.wakeTimer = null
    }
  }

  /** Fire a trigger immediately (deduplicated by the core's own throttle). */
  trigger(reason: TriggerReason): void {
    if (!this.running) return
    this.hooks.onTrigger(reason)
  }

  /** A network hint from the integrator (e.g. after a successful fetch). */
  hintOnline(): void {
    this.trigger('hint')
  }

  /**
   * Arm a one-shot wake-up at an absolute unix-seconds instant, as requested
   * by the core via `EFFECT_SCHEDULE_WAKE`. The periodic tick keeps running.
   *
   * Browsers clamp `setTimeout` delays above 2³¹−1 ms (~24.8 days) to ~1 ms,
   * so a far-future deadline (a 30-day grace) is armed in slices: on fire,
   * re-arm when the deadline is still in the future instead of waking early.
   */
  scheduleWake(atUnixSeconds: number, nowUnixSeconds: number): void {
    if (!this.running) return
    const MAX_DELAY_MS = 0x7fff_ffff
    const delayMs = Math.min(Math.max(0, (atUnixSeconds - nowUnixSeconds) * 1000), MAX_DELAY_MS)
    if (this.wakeTimer !== null) this.clearTimeoutFn(this.wakeTimer)
    this.wakeTimer = this.setTimeoutFn(() => {
      this.wakeTimer = null
      if (!this.running) return
      const now = Math.floor(Date.now() / 1000)
      if (atUnixSeconds > now) {
        this.scheduleWake(atUnixSeconds, now) // clamped slice elapsed; re-arm
        return
      }
      this.hooks.onTrigger('wake')
    }, delayMs)
  }

  /** Milliseconds between page hides, for the resume event's gap field. */
  resumeGapMs(): number {
    const now = Date.now()
    const gap = this.lastResumeAt === 0 ? 0 : Math.max(0, now - this.lastResumeAt)
    this.lastResumeAt = now
    return gap
  }

  private arm(delayMs: number): void {
    this.timer = this.setTimeoutFn(() => {
      this.timer = null
      if (!this.running) return
      this.hooks.onTrigger('tick')
      this.arm(this.intervalMs)
    }, delayMs)
  }
}

function safeGlobal<K extends 'window' | 'document'>(
  name: K,
): (K extends 'window' ? EventTargetLike : EventTargetLike & { hidden?: boolean }) | null {
  const value = (globalThis as Record<string, unknown>)[name]
  return (value ?? null) as never
}

/**
 * Optional fetch wrapper that reports connectivity to the scheduler. The
 * global `fetch` is deliberately NOT monkey-patched (design §4.3).
 */
export function wrapFetch(
  fetchFn: typeof fetch,
  hint: () => void,
): typeof fetch {
  const wrapped = (async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    try {
      const response = await fetchFn(input, init)
      hint()
      return response
    } catch (error) {
      hint()
      throw error
    }
  }) as typeof fetch
  return wrapped
}
