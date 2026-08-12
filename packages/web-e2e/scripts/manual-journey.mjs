/* Manual smoke of the full activation journey against the live local backend. */
import { chromium } from '@playwright/test'
import { readFileSync } from 'node:fs'

const backend = JSON.parse(
  readFileSync('/Volumes/BRData/projects/copylocker/target/tmp/web-e2e/backend.json', 'utf8'),
)

const browser = await chromium.launch()
const page = await (await browser.newContext({ baseURL: 'http://127.0.0.1:4173' })).newPage()
page.on('console', (msg) => console.log(`[console:${msg.type()}]`, msg.text()))
page.on('pageerror', (err) => console.log('[pageerror]', String(err)))

await page.goto('/')
await page.waitForSelector('[data-testid="sdk-status"][data-ready="true"]', { timeout: 30_000 })
console.log('SDK ready')

await page.fill('[data-testid="license-key-input"]', backend.licenseKey)
await page.click('[data-testid="activate-button"]')
await page.waitForFunction(
  () => document.querySelector('[data-testid="status-log"]')?.textContent?.includes('activate ok'),
  null,
  { timeout: 30_000 },
)
console.log('activated, state =', await page.textContent('[data-testid="license-state"]'))

// Seal an asset in-page with the session's own FinalKey, then unseal via the UI.
const plaintext = 'hello from the copylocker e2e journey'
const sealedB64 = await page.evaluate(async (pt) => {
  const hook = window.__copylocker
  if (!hook) throw new Error('no __copylocker hook')
  const { cl, sealAsset, productId } = hook
  const featureId = 'demo-feature'
  const now = Math.floor(Date.now() / 1000)
  let m = null
  for (const kind of [1, 0]) {
    try {
      const result = await cl.ops.deriveM(featureId, kind, now)
      if (result.payload && result.payload.byteLength === 32) { m = result.payload; break }
    } catch (error) { console.log('deriveM kind', kind, 'failed', String(error)) }
  }
  if (!m) throw new Error('deriveM failed for both session kinds')
  const join = (parts) => {
    const total = parts.reduce((n, p) => n + p.byteLength, 0)
    const out = new Uint8Array(total)
    let off = 0
    for (const p of parts) { out.set(p, off); off += p.byteLength }
    return out
  }
  const finalKey = new Uint8Array(await crypto.subtle.digest('SHA-256',
    join([m, cl.constants.kBuild, cl.constants.manifestRoot, cl.wasmDigest])))
  const sealed = await sealAsset(finalKey, {
    productId, variantId: 0, featureId, assetId: 'e2e-asset',
  }, new TextEncoder().encode(pt))
  let binary = ''
  for (const byte of sealed) binary += String.fromCharCode(byte)
  return btoa(binary)
}, plaintext)

const sealedBytes = Buffer.from(sealedB64, 'base64')
await page.route('**/demo-asset.clx', (route) =>
  route.fulfill({ status: 200, contentType: 'application/octet-stream', body: sealedBytes }),
)
await page.click('[data-testid="unseal-button"]')
await page.waitForSelector('[data-testid="unseal-output"][data-kind="ok"]', { timeout: 15_000 })
const output = await page.textContent('[data-testid="unseal-output"]')
console.log('unseal ok:', JSON.stringify(output))

// Offline unseal.
await page.context().setOffline(true)
const offlineResult = await page.evaluate(async ({ b64, featureId }) => {
  const { cl } = window.__copylocker
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
  try {
    const plain = await cl.unseal(featureId, bytes)
    return { ok: true, text: new TextDecoder().decode(plain) }
  } catch (error) {
    return { ok: false, error: `${error.name}: ${error.message}` }
  }
}, { b64: sealedB64, featureId: 'demo-feature' })
console.log('offline unseal:', JSON.stringify(offlineResult))

await browser.close()
console.log(output === plaintext && offlineResult.ok ? 'JOURNEY OK' : 'JOURNEY MISMATCH')
