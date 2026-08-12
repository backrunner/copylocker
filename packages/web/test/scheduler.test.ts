import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Scheduler, wrapFetch, type TriggerReason } from '../src/scheduler.js'

const srcDir = dirname(dirname(fileURLToPath(import.meta.url)))

describe('scheduler', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  function harness(intervalMs = 1000) {
    const triggers: TriggerReason[] = []
    const win = new EventTarget()
    const doc = Object.assign(new EventTarget(), { hidden: false })
    const scheduler = new Scheduler(
      { onTrigger: (reason) => triggers.push(reason) },
      { intervalMs, window: win, document: doc },
    )
    return { triggers, win, doc, scheduler }
  }

  it('ticks via recursive setTimeout (fake timers)', () => {
    const { triggers, scheduler } = harness()
    scheduler.start()
    vi.advanceTimersByTime(3500)
    expect(triggers).toEqual(['tick', 'tick', 'tick'])
    scheduler.stop()
    vi.advanceTimersByTime(3000)
    expect(triggers).toHaveLength(3)
  })

  it('never uses setInterval (static check of the shipped source)', () => {
    const source = readFileSync(join(srcDir, 'src', 'scheduler.ts'), 'utf8')
    expect(source).not.toContain('setInterval')
  })

  it('triggers on online and visibilitychange (visible → resume)', () => {
    const { triggers, win, doc, scheduler } = harness()
    scheduler.start()
    win.dispatchEvent(new Event('online'))
    expect(triggers).toEqual(['network'])
    doc.hidden = true
    doc.dispatchEvent(new Event('visibilitychange'))
    expect(triggers).toEqual(['network'])
    doc.hidden = false
    doc.dispatchEvent(new Event('visibilitychange'))
    expect(triggers).toEqual(['network', 'resume'])
    scheduler.stop()
    win.dispatchEvent(new Event('online'))
    expect(triggers).toHaveLength(2)
  })

  it('hintOnline triggers a hint', () => {
    const { triggers, scheduler } = harness()
    scheduler.start()
    scheduler.hintOnline()
    expect(triggers).toEqual(['hint'])
    scheduler.stop()
  })

  it('scheduleWake arms a one-shot wake at the requested instant', () => {
    const { triggers, scheduler } = harness()
    scheduler.start()
    scheduler.scheduleWake(100 + 2, 100) // 2s from now
    vi.advanceTimersByTime(2100)
    // The periodic tick keeps running alongside the one-shot wake.
    expect(triggers).toEqual(['tick', 'wake', 'tick'])
    scheduler.stop()
  })

  it('scheduleWake clamps far-future deadlines to the 32-bit timer max and re-arms', () => {
    const { triggers, scheduler } = harness(86_400_000) // daily tick
    scheduler.start()
    const now = Math.floor(Date.now() / 1000)
    scheduler.scheduleWake(now + 40 * 86_400, now) // 40 days out (a long grace)
    // The first clamped slice (~24.8 days) elapses: no early wake, re-armed.
    vi.advanceTimersByTime(0x7fff_ffff)
    expect(triggers).not.toContain('wake')
    vi.advanceTimersByTime(20 * 86_400 * 1000)
    expect(triggers).toContain('wake')
    scheduler.stop()
  })

  it('wrapFetch reports hints without touching the global fetch', async () => {
    const globalBefore = globalThis.fetch
    let hints = 0
    const inner = vi.fn(async () => new Response('ok'))
    const wrapped = wrapFetch(inner, () => (hints += 1))
    await wrapped('https://example.test')
    expect(inner).toHaveBeenCalledOnce()
    expect(hints).toBe(1)
    expect(globalThis.fetch).toBe(globalBefore)
  })
})
