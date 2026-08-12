import type { Page } from '@playwright/test'
import { expect } from '@playwright/test'
import { backend } from './device'

/**
 * Log in through the real login form and select the seeded product. Every
 * Playwright test gets a fresh browser context, so the sessionStorage token
 * and product selection must be re-established per test.
 */
export async function loginAndSelectProduct(page: Page): Promise<void> {
  if (!backend.adminToken || !backend.productId) throw new Error('backend state incomplete')
  await page.goto('/login')
  await page.getByLabel('Admin token').fill(backend.adminToken)
  await page.getByRole('button', { name: '登录' }).click()
  await expect(page).toHaveURL(/\/$/)
  const picker = page.getByLabel('product_id')
  await picker.fill(backend.productId)
  await picker.blur()
  await expect(
    page.getByRole('banner').getByText(backend.productId, { exact: true }),
  ).toBeVisible()
}
