/**
 * Full acceptance journey against the real local backend (M3):
 * activate → reseal in-page → unseal → offline → unseal offline →
 * reconnect → automatic revalidation.
 *
 * The backend is the prebuilt CopyLocker Worker under `wrangler dev` (D1 +
 * Durable Objects + KV, ENVIRONMENT=test secret seam), provisioned by
 * scripts/backend-up.mjs through the real CLI + Admin API. When it could not
 * be started the whole suite skips with the recorded reason.
 */
import { expect, test, type Page } from '@playwright/test'
import { backend, SESSION_OFFLINE, SESSION_ONLINE } from '../helpers/backend'

const featureId = backend.featureId ?? 'demo-feature'
const PLAINTEXT = 'copylocker web e2e journey payload'

/** Derive the session FinalKey in-page and seal an asset bound to it. */
async function sealInPage(page: Page, plaintext: string): Promise<string> {
  return page.evaluate(
    async ({ pt, feature }) => {
      const hook = window.__copylocker
      if (!hook) throw new Error('window.__copylocker hook missing')
      const { cl, sealAsset, productId } = hook
      const now = Math.floor(Date.now() / 1000)
      let m: Uint8Array | undefined
      const errors: string[] = []
      // Same preference order as the SDK: online session root, then offline.
      for (const kind of [1, 0]) {
        try {
          const result = await cl.ops.deriveM(feature, kind, now)
          if (result.payload && result.payload.byteLength === 32) {
            m = result.payload
            break
          }
        } catch (error) {
          errors.push(`${kind}:${(error as Error).name}`)
        }
      }
      if (!m) throw new Error(`deriveM failed (${errors.join(',')})`)
      const joined = new Uint8Array(128)
      joined.set(m, 0)
      joined.set(cl.constants.kBuild, 32)
      joined.set(cl.constants.manifestRoot, 64)
      joined.set(cl.wasmDigest, 96)
      const finalKey = new Uint8Array(await crypto.subtle.digest('SHA-256', joined))
      const sealed = await sealAsset(
        finalKey,
        { productId, variantId: 0, featureId: feature, assetId: 'e2e-asset' },
        new TextEncoder().encode(pt),
      )
      let binary = ''
      for (const byte of sealed) binary += String.fromCharCode(byte)
      return btoa(binary)
    },
    { pt: plaintext, feature: featureId },
  )
}

async function activateThroughUi(page: Page): Promise<void> {
  await page.goto('/')
  await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
  await expect(page.getByTestId('license-state')).toHaveText('unlicensed')
  await page.getByTestId('license-key-input').fill(backend.licenseKey as string)
  await page.getByTestId('activate-button').click()
  await expect(page.getByTestId('status-log')).toContainText('activate ok', { timeout: 30_000 })
  await expect(page.getByTestId('license-state')).toHaveText('active')
}

test.describe('vite-spa against the real local backend', () => {
  test.skip(!backend.available, `local backend unavailable: ${backend.reason ?? 'unknown'}`)

  test.describe.configure({ mode: 'serial' })

  test('activation journey: activate → unseal → offline → reconnect revalidation', async ({
    page,
    context,
  }) => {
    test.setTimeout(180_000)
    await activateThroughUi(page)

    // Seal a fresh asset in-page with the session's derived FinalKey, serve
    // it as /demo-asset.clx, and unseal through the real UI path.
    const sealedB64 = await sealInPage(page, PLAINTEXT)
    const sealedBytes = Buffer.from(sealedB64, 'base64')
    await page.route('**/demo-asset.clx', (route) =>
      route.fulfill({ status: 200, contentType: 'application/octet-stream', body: sealedBytes }),
    )
    await page.getByTestId('unseal-button').click()
    await expect(page.getByTestId('unseal-output')).toHaveAttribute('data-kind', 'ok')
    await expect(page.getByTestId('unseal-output')).toHaveText(PLAINTEXT)

    // Snapshot persistence: a reload restores the activated session from
    // IndexedDB without any activation round-trip.
    await page.reload()
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    await expect(page.getByTestId('license-state')).toHaveText('active')

    // Offline: the network is gone but unseal must keep working (offline
    // session root). The UI button fetches the asset, so call the SDK with
    // the already-fetched bytes — this is the same unseal() code path.
    await context.setOffline(true)
    const offline = await page.evaluate(
      async ({ b64, feature }) => {
        const { cl } = window.__copylocker!
        const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
        try {
          const plain = await cl.unseal(feature, bytes)
          return { ok: true, text: new TextDecoder().decode(plain) }
        } catch (error) {
          return { ok: false, error: `${(error as Error).name}: ${(error as Error).message}` }
        }
      },
      { b64: sealedB64, feature: featureId },
    )
    expect(offline, 'offline unseal must succeed via the offline session root').toEqual({
      ok: true,
      text: PLAINTEXT,
    })

    // Reconnect: the policy's short refresh_after (30s) makes the session
    // due; the scheduler (5s tick + online event) must validate within 60s.
    await context.setOffline(false)
    const validation = await page.waitForResponse(
      (response) =>
        response.url().includes('/v1/validate') && response.request().method() === 'POST',
      { timeout: 60_000 },
    )
    expect(validation.status()).toBe(200)
    await expect(page.getByTestId('license-state')).toHaveText('active')
  })

  test('loadSealed opens an asset sealed under the credential-wrapped KEK', async ({ page }) => {
    test.setTimeout(180_000)
    await activateThroughUi(page)

    // Seal in-page with the raw feature KEK the backend registered (the
    // `@copylocker/seal` shape); the runtime must unwrap the same KEK from the
    // credential's wrapped_keks via the unseal-asset op.
    const sealedB64 = await page.evaluate(
      async ({ pt, feature, kekHex }) => {
        const hook = window.__copylocker
        if (!hook) throw new Error('window.__copylocker hook missing')
        const kek = new Uint8Array(
          (kekHex.match(/../g) as string[]).map((b) => parseInt(b, 16)),
        )
        const sealed = await hook.sealAsset(
          kek,
          { productId: hook.productId, variantId: 0, featureId: feature, assetId: 'e2e-kek-asset' },
          new TextEncoder().encode(pt),
        )
        let binary = ''
        for (const byte of sealed) binary += String.fromCharCode(byte)
        return btoa(binary)
      },
      { pt: PLAINTEXT, feature: featureId, kekHex: backend.featureKekHex as string },
    )
    await page.route('**/kek-asset.clx', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/octet-stream',
        body: Buffer.from(sealedB64, 'base64'),
      }),
    )

    const opened = await page.evaluate(
      async ({ feature }) => {
        const { cl } = window.__copylocker!
        try {
          const plain = await cl.loadSealed('/kek-asset.clx', feature)
          return { ok: true, text: new TextDecoder().decode(plain) }
        } catch (error) {
          return { ok: false, error: `${(error as Error).name}` }
        }
      },
      { feature: featureId },
    )
    expect(opened, 'loadSealed must unwrap the KEK and open the container').toEqual({
      ok: true,
      text: PLAINTEXT,
    })

    // The same container is opaque to any other feature id.
    const denied = await page.evaluate(async () => {
      const { cl } = window.__copylocker!
      try {
        await cl.loadSealed('/kek-asset.clx', 'not-a-feature')
        return 'ACCEPTED'
      } catch (error) {
        return `${(error as Error).name}`
      }
    })
    expect(denied).toBe('NotEntitledError')
  })

  test('a one-byte tamper in the sealed payload fails unseal (AEAD)', async ({ page }) => {    await activateThroughUi(page)
    const sealedB64 = await sealInPage(page, PLAINTEXT)
    const tampered = Buffer.from(sealedB64, 'base64')
    tampered[tampered.byteLength - 1] ^= 0x01 // flip one bit in the GCM tag
    const result = await page.evaluate(
      async ({ b64, feature }) => {
        const { cl } = window.__copylocker!
        const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
        try {
          await cl.unseal(feature, bytes)
          return 'ACCEPTED'
        } catch (error) {
          return `${(error as Error).name}`
        }
      },
      { b64: tampered.toString('base64'), feature: featureId },
    )
    expect(result).toBe('UnsealError')
  })

  test('wiping IndexedDB forces re-activation', async ({ page }) => {
    await activateThroughUi(page)

    await page.reload()
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    await expect(page.getByTestId('license-state')).toHaveText('active')

    // Attacker/curious-user wipes local state: the credential snapshot is
    // gone, so the session must fail closed to unlicensed.
    await page.evaluate(async () => {
      const databases = await indexedDB.databases()
      await Promise.all(
        databases.map(
          (db) =>
            new Promise<void>((resolve) => {
              const request = indexedDB.deleteDatabase(db.name as string)
              request.onsuccess = () => resolve()
              request.onerror = () => resolve()
              request.onblocked = () => resolve()
            }),
        ),
      )
    })
    await page.reload()
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    await expect(page.getByTestId('license-state')).toHaveText('unlicensed')
    await page.getByTestId('unseal-button').click()
    await expect(page.getByTestId('unseal-output')).toHaveAttribute('data-kind', 'error')
    await expect(page.getByTestId('unseal-output')).toContainText('NotEntitledError')
  })
})
