import { describe, expect, it } from 'vitest'
import { buildFingerprintAttributes, collectFingerprint } from '../src/fingerprint.js'

function memoryStorage(): Storage {
  const backing = new Map<string, string>()
  return {
    getItem: (k: string) => backing.get(k) ?? null,
    setItem: (k: string, v: string) => void backing.set(k, v),
    removeItem: (k: string) => void backing.delete(k),
    clear: () => backing.clear(),
    key: (i: number) => [...backing.keys()][i] ?? null,
    get length() {
      return backing.size
    },
  } as Storage
}

const nav = {
  userAgent: 'Mozilla/5.0 (Test)',
  platform: 'TestOS',
  language: 'en-US',
  languages: ['en-US', 'en'],
  hardwareConcurrency: 8,
  userAgentData: {
    brands: [{ brand: 'Test', version: '1' }],
    mobile: false,
    platform: 'TestOS',
  },
}

describe('fingerprint', () => {
  it('is deterministic for identical inputs', async () => {
    const storage = memoryStorage()
    const a = await collectFingerprint({ navigator: nav, storage })
    const b = await collectFingerprint({ navigator: nav, storage })
    expect(a.digest).toEqual(b.digest)
    expect(a.digest.byteLength).toBe(32)
    expect(a.deviceId).toBe(b.deviceId)
  })

  it('excludes canvas/WebGL fields by default (FR-WEB-006)', async () => {
    const result = await collectFingerprint({ navigator: nav, storage: memoryStorage() })
    expect(result.fields).not.toContain('canvas')
    expect(result.fields).toContain('device_id')
    expect(result.fields).toContain('ua')
    expect(result.fields).toContain('hardware_concurrency')
    expect(result.fields).toContain('ua_ch_platform')
  })

  it('buildFingerprintAttributes only includes canvas when probed', () => {
    const without = buildFingerprintAttributes(nav, 'id', null)
    expect(without.has('canvas')).toBe(false)
    const withCanvas = buildFingerprintAttributes(nav, 'id', 'data:image/png;base64,x')
    expect(withCanvas.has('canvas')).toBe(true)
  })

  it('changes when any attribute changes', async () => {
    const storage = memoryStorage()
    const base = await collectFingerprint({ navigator: nav, storage })
    const otherNav = await collectFingerprint({
      navigator: { ...nav, hardwareConcurrency: 4 },
      storage,
    })
    expect(base.digest).not.toEqual(otherNav.digest)
    const otherDevice = await collectFingerprint({ navigator: nav, storage: memoryStorage() })
    expect(base.digest).not.toEqual(otherDevice.digest)
  })
})
