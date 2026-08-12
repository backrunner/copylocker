import { afterEach, describe, expect, it } from 'vitest'
import {
  GuardState,
  guarded,
  guardedFn,
  isToStringIntact,
  shouldSample,
} from '../src/guarded.js'

const ZERO32 = new Uint8Array(32)

afterEach(() => {
  GuardState.reset()
})

describe('shouldSample', () => {
  it('rate 0 never samples, rate 1 always samples', () => {
    expect(shouldSample(0, () => 0.0001)).toBe(false)
    expect(shouldSample(0)).toBe(false)
    expect(shouldSample(1, () => 0.9999)).toBe(true) // rate>=1 short-circuits before rng
    expect(shouldSample(1)).toBe(true)
    expect(shouldSample(0.5, () => 0.4)).toBe(true)
    expect(shouldSample(0.5, () => 0.6)).toBe(false)
  })
})

describe('guardedFn', () => {
  it('mixes the body digest into GuardState on sampled calls', async () => {
    GuardState.reset()
    expect(GuardState.getR()).toEqual(ZERO32)
    const f = guardedFn('compute', function compute(x: number) {
      return x * 2
    }, { sampleRate: 1 })
    expect(f(21)).toBe(42)
    await GuardState.settled()
    expect(GuardState.getR()).not.toEqual(ZERO32)
  })

  it('a replaced body produces a different mixed state', async () => {
    GuardState.reset()
    guardedFn('compute', function compute(x: number) {
      return x * 2
    }, { sampleRate: 1 })(1)
    await GuardState.settled()
    const original = GuardState.getR()

    GuardState.reset()
    guardedFn('compute', function compute(x: number) {
      return x * 3 // attacker-patched body
    }, { sampleRate: 1 })(1)
    await GuardState.settled()
    const tampered = GuardState.getR()

    expect(tampered).not.toEqual(ZERO32)
    expect(tampered).not.toEqual(original)
  })

  it('sampleRate 0 → no mix', async () => {
    GuardState.reset()
    const f = guardedFn('compute', (x: number) => x * 2, { sampleRate: 0 })
    f(1)
    f(2)
    await GuardState.settled()
    expect(GuardState.getR()).toEqual(ZERO32)
  })
})

describe('guarded decorator', () => {
  it('supports the legacy (target, key, descriptor) signature', async () => {
    GuardState.reset()
    class Engine {
      render(scene: number) {
        return scene + 1
      }
    }
    const descriptor = Object.getOwnPropertyDescriptor(Engine.prototype, 'render')
    expect(descriptor).toBeDefined()
    guarded('engine.render', { sampleRate: 1 })(Engine.prototype, 'render', descriptor)
    Object.defineProperty(Engine.prototype, 'render', descriptor as PropertyDescriptor)
    expect(new Engine().render(1)).toBe(2)
    await GuardState.settled()
    expect(GuardState.getR()).not.toEqual(ZERO32)
  })

  it('supports the TS 5 standard (value, context) signature', async () => {
    GuardState.reset()
    const method = function render(scene: number) {
      return scene + 1
    }
    const wrapped = guarded('engine.render', { sampleRate: 1 })(method, {
      kind: 'method',
      name: 'render',
    }) as typeof method
    expect(typeof wrapped).toBe('function')
    expect(wrapped(1)).toBe(2)
    await GuardState.settled()
    expect(GuardState.getR()).not.toEqual(ZERO32)
  })

  it('rejects unsupported targets', () => {
    expect(() => guarded('x')({} as object, { kind: 'field', name: 'x' })).toThrow(TypeError)
  })

  it('rejects a class target instead of silently wrapping the constructor', () => {
    class Engine {}
    expect(() => guarded('x')(Engine, { kind: 'class', name: 'Engine' })).toThrow(TypeError)
  })
})

describe('GuardState mix queue', () => {
  it('a failing WebCrypto digest falls back without killing the queue', async () => {
    GuardState.reset()
    const subtle = globalThis.crypto.subtle
    const realDigest = subtle.digest.bind(subtle)
    let fail = true
    ;(subtle as { digest: unknown }).digest = (algorithm: AlgorithmIdentifier, data: BufferSource) =>
      fail ? Promise.reject(new Error('digest unavailable')) : realDigest(algorithm, data)
    try {
      GuardState.mix('first', new Uint8Array(32)) // hash step rejects → deterministic fallback
      await GuardState.settled() // must resolve, not reject
      const afterFirst = GuardState.getR()
      expect(afterFirst).not.toEqual(ZERO32)
      fail = false
      GuardState.mix('second', new Uint8Array(32))
      await GuardState.settled()
      expect(GuardState.getR()).not.toEqual(afterFirst) // the queue survived
    } finally {
      ;(subtle as { digest: unknown }).digest = realDigest
    }
  })
})

describe('Function.prototype.toString hardening', () => {
  it('detects an override and mixes (never throws)', async () => {
    GuardState.reset()
    const native = Function.prototype.toString
    // eslint-disable-next-line no-extend-native
    Function.prototype.toString = function () {
      return 'function () { /* harmless */ }'
    }
    try {
      expect(isToStringIntact()).toBe(false)
      const f = guardedFn('compute', (x: number) => x * 2, { sampleRate: 0 })
      expect(f(2)).toBe(4) // call still works — detection must not break the app
      await GuardState.settled()
      expect(GuardState.getR()).not.toEqual(ZERO32) // …but the state moved
    } finally {
      // eslint-disable-next-line no-extend-native
      Function.prototype.toString = native
    }
    expect(isToStringIntact()).toBe(true)
  })
})
