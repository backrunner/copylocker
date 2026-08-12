/**
 * Next.js example smoke test (M3 SSR acceptance).
 *
 * The server render must use the `@copylocker/web/ssr` no-op stub (advisory
 * state `unlicensed`, zero side effects); after hydration the real SDK boots
 * on the client under the nonce-based CSP.
 */
import { expect, test } from '@playwright/test'

test.describe('nextjs-app smoke', () => {
  test('SSR renders the stub state, hydration boots the real SDK', async ({ page, request }) => {
    // 1. The raw SSR HTML: the stub rendered `unlicensed` on the server and
    //    no real SDK code ran there.
    const response = await request.get('/')
    expect(response.ok()).toBe(true)
    const html = await response.text()
    expect(html).toContain('data-testid="ssr-state"')
    const ssrMatch = /data-testid="ssr-state"[^>]*>([^<]*)</.exec(html)
    expect(ssrMatch?.[1]).toBe('unlicensed')

    // 2. Hydration: the real client boots (wasm + Worker) and reports ready.
    await page.goto('/')
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    // The SSR panel is a static record of the server render — still the stub.
    await expect(page.getByTestId('ssr-state')).toHaveText('unlicensed')
    await expect(page.getByTestId('license-state')).toHaveText('unlicensed')
  })
})
