import { describe, expect, it } from 'vitest'

/**
 * SSR / isomorphy (FR-WEB-009, design §4.5). These tests run in vitest's
 * default Node environment — no `window`, `document`, or `indexedDB` — which
 * is exactly the SSR loading condition.
 */
describe('SSR stub and import safety (FR-WEB-009)', () => {
  it('runs in an environment without DOM globals (precondition)', () => {
    const g = globalThis as Record<string, unknown>
    expect(typeof g['window']).toBe('undefined')
    expect(typeof g['document']).toBe('undefined')
    expect(typeof g['indexedDB']).toBe('undefined')
  })

  it('imports `@copylocker/web/ssr` and creates a marked no-op instance', async () => {
    const mod = await import('../src/ssr.js')
    const cl = await mod.CopyLocker.create({
      serverUrl: 'https://license.example.test',
      productId: 'demo',
      rootPins: ['ab'.repeat(32)],
    })
    expect(cl.isSsrStub).toBe(true)
    expect(cl.state).toBe('unlicensed')
    expect(cl.degradedFlags).toEqual({ storage: true, worker: true })

    await expect(cl.activate('CL-TEST-KEY')).rejects.toThrow(/server-side stub/)
    await expect(cl.activateWithAccount('token')).rejects.toThrow(/server-side stub/)
    await expect(cl.deactivate()).rejects.toThrow(/server-side stub/)
    await expect(cl.unseal('pro', new Uint8Array([1]))).rejects.toThrow(/server-side stub/)
    await expect(cl.loadSealed('/a.clx', 'pro')).rejects.toThrow(/server-side stub/)

    const off = cl.onStateChange(() => {})
    expect(typeof off).toBe('function')
    off()
    cl.hintOnline()
    cl.dispose()
  })

  it('imports the main entry `@copylocker/web` without DOM globals', async () => {
    // Module load must be side-effect-free w.r.t. the DOM: this throws if any
    // top-level code touches window/document/indexedDB.
    const mod = await import('../src/index.js')
    expect(typeof mod.CopyLocker.create).toBe('function')
  })

  it('CopyLocker.create fails with a clear error outside the browser', async () => {
    const { CopyLocker } = await import('../src/index.js')
    await expect(
      CopyLocker.create({
        serverUrl: 'https://license.example.test',
        productId: 'demo',
        rootPins: ['ab'.repeat(32)],
      }),
    ).rejects.toThrow(/browser environment/)
  })
})
