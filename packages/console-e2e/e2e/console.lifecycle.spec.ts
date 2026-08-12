import { expect, test } from '@playwright/test'
import { backend, flushProjection, freshDeviceStateDir, runDeviceHelper } from '../helpers/device'
import { loginAndSelectProduct } from '../helpers/console'

/**
 * M7 acceptance line 1: 签发 → 激活 → 查看设备 → 吊销 → 验证生效.
 *
 * The license is issued through the real console UI, the device activates
 * against the real local Worker backend (the device-helper runs the actual
 * CL-STD-1 protocol — no mocks), the machine is viewed in the console (per-
 * license detail and the cross-license directory), revoked through the UI's
 * two-step confirmation, and enforcement is proven by a rejected validation.
 */
test.describe.configure({ mode: 'serial' })

test.skip(!backend.available, `backend unavailable: ${backend.reason ?? 'unknown'}`)

let licenseId = ''
let licenseKey = ''
let machineId = ''
let deviceStateDir = ''

test('issue a license via the console UI', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto('/licenses/new')
  // The seeded policy (policy_e2e) is pre-selected once policies load.
  const submit = page.getByRole('button', { name: '签发' })
  await expect(submit).toBeEnabled()
  await submit.click()

  const issuedRow = page.locator('tbody tr').first()
  await expect(issuedRow).toBeVisible()
  licenseId = (await issuedRow.locator('td').nth(0).innerText()).trim()
  licenseKey = (await issuedRow.locator('td').nth(1).innerText()).trim()
  expect(licenseId).toMatch(/^[0-9a-f]{32}$/)
  expect(licenseKey).toMatch(/^CL1-[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$/)
})

test('activate a device through the real local backend', () => {
  deviceStateDir = freshDeviceStateDir()
  const result = runDeviceHelper('activate', { licenseKey, stateDir: deviceStateDir })
  expect(result.stderr + result.stdout).not.toContain('error')
  expect(result.status).toBe(0)
  expect(result.stdout).toContain('"ok":"true"')
  // The dev backend's outbox → queue → consumer projection does not land under
  // wrangler dev; flush it deterministically (idempotent, exact consumer SQL).
  flushProjection()
})

test('view the machine in the console (list + detail)', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto('/licenses')
  const link = page.getByRole('link', { name: licenseId })
  await expect(link).toBeVisible()
  await link.click()
  await expect(page).toHaveURL(new RegExp(`/licenses/${licenseId}$`))

  await page.getByRole('tab', { name: '设备' }).click()
  const machineRow = page.locator('tbody tr').first()
  await expect(machineRow.getByText('active')).toBeVisible()
  machineId = (await machineRow.locator('td').nth(0).innerText()).trim()
  expect(machineId).toMatch(/^[0-9a-f]{32}$/)

  // The cross-license machine directory (GET /v1/admin/machines) also lists it.
  await page.goto('/settings')
  await expect(page.getByText(machineId)).toBeVisible()
})

test('revoke the machine via the UI with two-step confirmation', async ({ page }) => {
  await loginAndSelectProduct(page)
  await page.goto(`/licenses/${licenseId}`)
  await page.getByRole('tab', { name: '设备' }).click()
  const machineRow = page.locator('tbody tr', { hasText: machineId })
  await machineRow.getByRole('button', { name: '吊销' }).click()

  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  // Step one: the dry-run impact preview.
  await expect(dialog.getByText('受影响设备数：1')).toBeVisible()
  const confirmButton = dialog.getByTestId('revoke-confirm-button')
  await expect(confirmButton).toBeDisabled()
  // Step two: the typed-id confirmation gate.
  await dialog.getByTestId('revoke-confirm-input').fill(machineId.slice(0, -1))
  await expect(confirmButton).toBeDisabled()
  await dialog.getByTestId('revoke-confirm-input').fill(machineId)
  await expect(confirmButton).toBeEnabled()
  await confirmButton.click()

  await expect(dialog.getByText('吊销已生效')).toBeVisible()
  await dialog.getByRole('button', { name: '关闭' }).click()

  // The revoked status reaches the D1 machines projection through the same
  // outbox pipeline; flush it, then the console shows the new state.
  flushProjection()
  await page.reload()
  await page.getByRole('tab', { name: '设备' }).click()
  await expect(page.locator('tbody tr', { hasText: machineId }).getByText('revoked')).toBeVisible()
})

test('verify enforcement: validation for the revoked machine is rejected', () => {
  // The first post-revocation exchange returns the signed KillOrder; honoring
  // it (credential wipe) is itself a successful protocol call. Every
  // subsequent exchange is rejected: the credential is gone.
  const kill = runDeviceHelper('validate', { stateDir: deviceStateDir })
  expect([0, 3]).toContain(kill.status)
  const rejected = runDeviceHelper('validate', { stateDir: deviceStateDir })
  expect(rejected.status).toBe(3)
  expect(rejected.stdout).toContain('"verdict":"rejected"')
})
