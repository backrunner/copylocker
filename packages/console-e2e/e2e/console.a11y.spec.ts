import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { expect, test, type Page } from '@playwright/test'
import { backend } from '../helpers/device'
import { loginAndSelectProduct } from '../helpers/console'

/**
 * M7 acceptance line 3a: axe-core scan of the data-driven console pages —
 * zero critical/serious violations.
 */

test.skip(!backend.available, `backend unavailable: ${backend.reason ?? 'unknown'}`)

const require = createRequire(import.meta.url)
const axePath = require.resolve('axe-core/axe.min.js')
const axeSource = readFileSync(axePath, 'utf8')

interface AxeViolation {
  id: string
  impact: string
  nodes: unknown[]
}

async function expectNoSeriousViolations(page: Page, label: string) {
  // The console enforces script-src 'self' (+nonce); injecting axe inline or
  // from a file URL is blocked. Serve axe from the app origin instead — the
  // scan itself runs through CDP evaluate, which CSP does not restrict.
  await page.route('**/axe-e2e-inject.js', (route) =>
    route.fulfill({ contentType: 'application/javascript', body: axeSource }),
  )
  await page.addScriptTag({ url: '/axe-e2e-inject.js' })
  await page.unroute('**/axe-e2e-inject.js')
  const results = await page.evaluate(async () => {
    const axe = (window as unknown as { axe: { run: (ctx: Document) => Promise<unknown> } }).axe
    return (await axe.run(document)) as { violations: AxeViolation[] }
  })
  const serious = results.violations.filter(
    (violation) => violation.impact === 'critical' || violation.impact === 'serious',
  )
  expect(
    serious.map((violation) => `${violation.id}(${violation.impact})`),
    `${label}: ${JSON.stringify(
      serious.map((violation) => ({ id: violation.id, impact: violation.impact })),
    )}`,
  ).toEqual([])
}

test('axe: login and overview', async ({ page }) => {
  await page.goto('/login')
  await expectNoSeriousViolations(page, '/login')
  await loginAndSelectProduct(page)
  await expectNoSeriousViolations(page, '/')
})

test('axe: licenses list and issue form', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto('/licenses')
  await expect(page.locator('tbody')).toBeVisible()
  await expectNoSeriousViolations(page, '/licenses')
  await page.goto('/licenses/new')
  await expect(page.getByRole('button', { name: '签发' })).toBeVisible()
  await expectNoSeriousViolations(page, '/licenses/new')
})

test('axe: license detail with the machines tab', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto('/licenses')
  const firstLicense = page.locator('tbody tr td a').first()
  await expect(firstLicense).toBeVisible()
  await firstLicense.click()
  await page.getByRole('tab', { name: '设备' }).click()
  await expect(page.locator('tbody')).toBeVisible()
  await expectNoSeriousViolations(page, '/licenses/[id]')
})

test('axe: releases', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto('/releases')
  // The backend seeds the `dev` release row.
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await expectNoSeriousViolations(page, '/releases')
})

test('axe: analytics with a rendered report and meta states', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto('/analytics')
  await expect(page.locator('text=T0 · 签名计量')).toBeVisible()
  // Render the report + meta card (source / error_pct / suppressed_buckets).
  await page.locator('label', { hasText: 'act.new' }).first().click()
  await page.getByRole('button', { name: '运行查询' }).click()
  await expect(page.getByText('结果元信息')).toBeVisible()
  await expectNoSeriousViolations(page, '/analytics')
})

test('axe: audit table and the chain-verify result', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto('/audit')
  await expect(page.locator('tbody')).toBeVisible()
  await page.getByRole('button', { name: '验证链完整性' }).click()
  await expect(page.getByText('链验证结果')).toBeVisible()
  await expectNoSeriousViolations(page, '/audit')
})

test('axe: settings DSR console and machine directory', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto('/settings')
  await expect(page.locator('tbody')).toBeVisible()
  await expectNoSeriousViolations(page, '/settings')
})

test('axe: offline portal (public route)', async ({ page }) => {
  await page.goto('/offline')
  await expectNoSeriousViolations(page, '/offline')
})
