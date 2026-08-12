/**
 * Deterministic no-backend paths (M3 acceptance, fallback tier).
 *
 * These specs never depend on the local Worker: the SDK is offline-tolerant
 * at create() time, and every failure must surface as a typed error in the
 * UI (never a hang or an unhandled rejection).
 */
import { expect, test } from '@playwright/test'

test.describe('vite-spa, no backend', () => {
  test('SDK initializes offline and reports unlicensed', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    await expect(page.getByTestId('license-state')).toHaveText('unlicensed')
    // Worker isolation must be active (no degradation note in the log).
    await expect(page.getByTestId('status-log')).not.toContainText('degraded: Worker')
  })

  test('unseal without activation fails with NotEntitledError', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    await page.getByTestId('unseal-button').click()
    const output = page.getByTestId('unseal-output')
    await expect(output).toHaveAttribute('data-kind', 'error')
    await expect(output).toContainText('NotEntitledError')
  })

  test('activate without a server surfaces TransportError after retries', async ({ page }) => {
    // Simulate "no server" deterministically: every protocol request fails at
    // the network layer, whether or not a backend happens to be running.
    await page.route('**/v1/**', (route) => route.abort())
    await page.goto('/')
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')

    await page.getByTestId('license-key-input').fill('CL1-AAAAA-AAAAA-AAAAA-AAAAA')
    await page.getByTestId('activate-button').click()
    // The transport retries with backoff (4 attempts) before giving up.
    await expect(page.getByTestId('status-log')).toContainText(
      'activate failed: TransportError',
      { timeout: 30_000 },
    )
    await expect(page.getByTestId('license-state')).toHaveText('unlicensed')
  })

  test('SDK loads under the strict CSP (wasm compile + Worker isolation)', async ({
    page,
  }) => {
    const response = await page.goto('/')
    expect(response).toBeTruthy()
    const csp = response!.headers()['content-security-policy']
    // The example's documented strict policy must actually be served.
    expect(csp).toContain("default-src 'self'")
    expect(csp).toContain("'wasm-unsafe-eval'")
    expect(csp).toContain("worker-src 'self'")
    expect(csp).toContain("object-src 'none'")

    const cspViolations: string[] = []
    page.on('console', (message) => {
      if (message.type() === 'error' && /Content Security Policy/i.test(message.text())) {
        cspViolations.push(message.text())
      }
    })
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    await expect(page.getByTestId('status-log')).not.toContainText('degraded')
    expect(cspViolations).toEqual([])
  })
})
