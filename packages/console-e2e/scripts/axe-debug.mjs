// One-off axe debug: print the color-contrast violation targets on /login and /.
import { chromium } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8')
const backend = JSON.parse(
  readFileSync(new URL('../../../target/tmp/web-e2e/backend.json', import.meta.url), 'utf8'),
)

const browser = await chromium.launch()
const page = await (await browser.newContext({ baseURL: 'http://127.0.0.1:4174' })).newPage()
await page.route('**/axe-e2e-inject.js', (route) =>
  route.fulfill({ contentType: 'application/javascript', body: axeSource }),
)

for (const path of ['/login']) {
  await page.goto(path)
  await page.addScriptTag({ url: '/axe-e2e-inject.js' })
  const results = await page.evaluate(async () => await window.axe.run(document))
  for (const violation of results.violations.filter((v) =>
    ['critical', 'serious'].includes(v.impact),
  )) {
    console.log(path, violation.id, violation.impact)
    for (const node of violation.nodes) {
      console.log('  target:', node.target, '\n  html:', node.html.slice(0, 200))
      console.log('  summary:', node.failureSummary?.slice(0, 300))
    }
  }
}

// Log in, pick the product, then scan the overview and licenses pages.
await page.getByLabel('Admin token').fill(backend.adminToken)
await page.getByRole('button', { name: '登录' }).click()
await page.waitForURL(/\/$/)
const picker = page.getByLabel('product_id')
await picker.fill(backend.productId)
await picker.blur()

for (const path of ['/', '/licenses']) {
  await page.goto(path)
  await page.locator('main').first().waitFor()
  await page.addScriptTag({ url: '/axe-e2e-inject.js' })
  const results = await page.evaluate(async () => await window.axe.run(document))
  for (const violation of results.violations.filter((v) =>
    ['critical', 'serious'].includes(v.impact),
  )) {
    console.log(path, violation.id, violation.impact)
    for (const node of violation.nodes) {
      console.log('  target:', node.target, '\n  html:', node.html.slice(0, 200))
      console.log('  summary:', node.failureSummary?.slice(0, 400))
    }
  }
}

// License detail with the machines tab open.
await page.goto('/licenses')
await page.locator('tbody tr td a').first().click()
await page.getByRole('tab', { name: '设备' }).click()
await page.locator('tbody').first().waitFor()
await page.addScriptTag({ url: '/axe-e2e-inject.js' })
{
  const results = await page.evaluate(async () => await window.axe.run(document))
  for (const violation of results.violations.filter((v) =>
    ['critical', 'serious'].includes(v.impact),
  )) {
    console.log('/licenses/[id]', violation.id, violation.impact)
    for (const node of violation.nodes) {
      console.log('  target:', node.target, '\n  html:', node.html.slice(0, 200))
      console.log('  summary:', node.failureSummary?.slice(0, 400))
    }
  }
}
await browser.close()
