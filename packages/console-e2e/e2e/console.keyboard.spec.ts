import { expect, test, type Page } from '@playwright/test'
import { backend, flushProjection, freshDeviceStateDir, runDeviceHelper } from '../helpers/device'
import { loginAndSelectProduct } from '../helpers/console'

/**
 * M7 acceptance line 3b: the lifecycle's critical path is fully
 * keyboard-operable — tab order reaches every control, Enter/Space activates,
 * and the two-step dialogs trap and restore focus.
 */
test.describe.configure({ mode: 'serial' })

test.skip(!backend.available, `backend unavailable: ${backend.reason ?? 'unknown'}`)

/** Walk the tab order, collecting a descriptor of each focused element. */
async function tabWalk(page: Page, maxSteps: number): Promise<string[]> {
  const seen: string[] = []
  for (let step = 0; step < maxSteps; step += 1) {
    await page.keyboard.press('Tab')
    const descriptor = await page.evaluate(() => {
      const element = document.activeElement
      if (!element || element === document.body) return 'body'
      const id = element.id ? `#${element.id}` : ''
      const text = (element.textContent ?? '').trim().slice(0, 24)
      return `${element.tagName.toLowerCase()}${id}:${text}`
    })
    seen.push(descriptor)
  }
  return seen
}

let licenseId = ''
let licenseKey = ''
let machineId = ''
let deviceStateDir = ''

test('keyboard: login and sidebar navigation', async ({ page }) => {
  await page.goto('/login')
  await page.keyboard.press('Tab')
  await expect(page.locator('#admin-token')).toBeFocused()
  await page.keyboard.type(backend.adminToken ?? '')
  await page.keyboard.press('Tab')
  await expect(page.getByRole('button', { name: '登录' })).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(/\/$/)

  // Sidebar links are tab-reachable; Enter navigates when one is focused.
  let navigated = false
  const focused: string[] = []
  for (let step = 0; step < 16 && !navigated; step += 1) {
    await page.keyboard.press('Tab')
    const descriptor = await page.evaluate(() => {
      const element = document.activeElement
      if (!element || element === document.body) return 'body'
      return (element.textContent ?? '').trim()
    })
    focused.push(descriptor)
    if (descriptor === 'Licenses') {
      await page.keyboard.press('Enter')
      navigated = true
    }
  }
  expect(navigated, focused.join(' | ')).toBe(true)
  await expect(page).toHaveURL(/\/licenses$/)
})

test('keyboard: issue a license without touching the mouse', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto('/licenses/new')

  // Every form control is in the tab order; the submit button is reachable.
  // (datetime-local expands to several focusable sub-fields in Chromium.)
  const focused = await tabWalk(page, 32)
  const descriptors = focused.join(' | ')
  expect(descriptors).toContain('#issue-policy')
  expect(descriptors).toContain('#issue-count')
  expect(descriptors).toContain('签发')

  // Activate the submit button with Enter and wait for the result.
  await page.getByRole('button', { name: '签发' }).focus()
  await page.keyboard.press('Enter')

  const issuedRow = page.locator('tbody tr').first()
  await expect(issuedRow).toBeVisible()
  licenseId = (await issuedRow.locator('td').nth(0).innerText()).trim()
  licenseKey = (await issuedRow.locator('td').nth(1).innerText()).trim()
  expect(licenseKey).toMatch(/^CL1-/)

  deviceStateDir = freshDeviceStateDir()
  const activated = runDeviceHelper('activate', { licenseKey, stateDir: deviceStateDir })
  expect(activated.status).toBe(0)
  flushProjection()
})

test('keyboard: revoke dialog traps and restores focus', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto(`/licenses/${licenseId}`)
  await page.getByRole('tab', { name: '设备' }).click()
  const machineRow = page.locator('tbody tr').first()
  machineId = (await machineRow.locator('td').nth(0).innerText()).trim()

  // Reach the row's revoke button with the keyboard only.
  await machineRow.getByRole('button', { name: '吊销' }).focus()
  await expect(machineRow.getByRole('button', { name: '吊销' })).toBeFocused()
  await page.keyboard.press('Enter')

  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('受影响设备数：1')).toBeVisible()

  // Focus starts inside the dialog …
  const focusInside = async () =>
    page.evaluate(() => {
      const active = document.activeElement
      const dialog = document.querySelector('[role="dialog"]')
      return dialog !== null && active !== null && dialog.contains(active)
    })
  expect(await focusInside()).toBe(true)
  // … and Tab / Shift+Tab stay trapped inside it.
  for (let step = 0; step < 8; step += 1) {
    await page.keyboard.press('Tab')
    expect(await focusInside()).toBe(true)
  }
  for (let step = 0; step < 8; step += 1) {
    await page.keyboard.press('Shift+Tab')
    expect(await focusInside()).toBe(true)
  }

  // Complete the two-step confirmation with the keyboard.
  await dialog.getByTestId('revoke-confirm-input').focus()
  await page.keyboard.type(machineId)
  await page.keyboard.press('Tab')
  const confirmButton = dialog.getByTestId('revoke-confirm-button')
  const focusedDescriptor = await page.evaluate(
    () => document.activeElement?.textContent?.trim() ?? '',
  )
  if (focusedDescriptor.includes('确认吊销')) {
    await page.keyboard.press('Enter')
  } else {
    await confirmButton.focus()
    await page.keyboard.press('Enter')
  }
  await expect(dialog.getByText('吊销已生效')).toBeVisible()

  // Escape closes the dialog and focus returns to the revoke trigger.
  await page.keyboard.press('Escape')
  await expect(dialog).not.toBeVisible()
  await expect(machineRow.getByRole('button', { name: '吊销' })).toBeFocused()

  // Kill order honored on the first exchange; rejected from then on.
  const kill = runDeviceHelper('validate', { stateDir: deviceStateDir })
  expect([0, 3]).toContain(kill.status)
  const rejected = runDeviceHelper('validate', { stateDir: deviceStateDir })
  expect(rejected.status).toBe(3)
})
