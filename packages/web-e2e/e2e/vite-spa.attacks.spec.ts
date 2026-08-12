/**
 * Attack simulation (design doc §9).
 *
 * The honest security model for the web build is "raise the bar": every one
 * of these attacks must fail closed — never produce plaintext, never crash
 * into an undefined state.
 */
import { expect, test } from '@playwright/test'

test.describe('vite-spa attack simulation', () => {
  test('replacing the wasm module with a stub fails initialization', async ({ page }) => {
    // Attacker swaps the .wasm for bytes they control. The SHA-256 of the
    // wasm feeds the two-stage key transform, so a swapped module can never
    // derive the right FinalKey — and a non-wasm payload cannot even
    // instantiate, so create() must fail closed.
    await page.route('**/copylocker-wasm/copylocker_wasm_bg.wasm', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/wasm',
        body: Buffer.from('attacker-controlled stub module', 'utf8'),
      }),
    )
    await page.goto('/')
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'false')
    await expect(page.getByTestId('sdk-status')).toHaveText('failed to initialize')
    await expect(page.getByTestId('status-log')).toContainText('create failed')
  })

  test('a forged wasm module with valid header still cannot initialize a session', async ({
    page,
  }) => {
    // A *valid* empty wasm module: instantiation may succeed but the session
    // constructor has nothing to bind to — create() must still fail closed.
    await page.route('**/copylocker-wasm/copylocker_wasm_bg.wasm', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/wasm',
        body: Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
      }),
    )
    await page.goto('/')
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'false')
  })

  test('tampering with a sealed asset container is rejected', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    const result = await page.evaluate(async () => {
      const hook = window.__copylocker
      if (!hook) return { sealed: false, reason: 'no hook' }
      const key = globalThis.crypto.getRandomValues(new Uint8Array(32))
      const sealed = await hook.sealAsset(
        key,
        { productId: hook.productId, variantId: 0, featureId: 'demo-feature', assetId: 'atk' },
        new TextEncoder().encode('secret payload'),
      )
      const outcomes: string[] = []
      // Flip one byte in the CBOR header (schema field).
      const headerTampered = sealed.slice()
      headerTampered[1] ^= 0xff
      try {
        hook.decodeSealedAsset(headerTampered)
        outcomes.push('header tamper ACCEPTED')
      } catch (error) {
        outcomes.push(`header tamper rejected: ${(error as Error).name}`)
      }
      // Truncate the payload (nonce ‖ ciphertext ‖ tag bound).
      try {
        hook.decodeSealedAsset(sealed.slice(0, sealed.byteLength - 8))
        outcomes.push('truncation ACCEPTED')
      } catch (error) {
        outcomes.push(`truncation rejected: ${(error as Error).name}`)
      }
      return { sealed: true, outcomes }
    })
    expect(result.sealed).toBe(true)
    for (const outcome of result.outcomes ?? []) {
      expect(outcome).toContain('rejected: UnsealError')
    }
  })

  test('overriding Function.prototype.toString does not affect the SDK', async ({ page }) => {
    // Classic anti-tamper probe: attackers mask patched functions as native.
    // The SDK must not depend on source introspection anywhere.
    await page.addInitScript(() => {
      // eslint-disable-next-line no-extend-native
      Function.prototype.toString = function toString() {
        return 'function () { [native code] }'
      }
    })
    await page.goto('/')
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    // Behavior is unchanged: unlicensed unseal fails with the typed error.
    await page.getByTestId('unseal-button').click()
    await expect(page.getByTestId('unseal-output')).toHaveAttribute('data-kind', 'error')
    await expect(page.getByTestId('unseal-output')).toContainText('NotEntitledError')
  })
})
