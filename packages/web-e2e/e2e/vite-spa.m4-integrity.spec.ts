/**
 * M4-A acceptance: the vite-spa build is integrity-protected by
 * `@copylocker/unplugin`, and `@copylocker/web` consumes the guard contract.
 *
 * Scenarios (design §6 / `50-unplugin-integrity.md`):
 *  1. contract — a clean build publishes `__CL_GUARD_R__` (actually-computed
 *     root) equal to the injected expected root, plus the sharded K_BUILD and
 *     the fail-closed `__CL_REQUIRE_INTEGRITY_PROOF__` flag.
 *  2. control — the untampered build unseals (real backend).
 *  3. delete-the-guard — the guard bootstrap is stripped from the served
 *     entry chunk (constants block kept, the fallback-enabling move);
 *     `requireIntegrityProof` fails derivation closed. Without the flag this
 *     attack succeeds: both seal-side constants and the unseal fallback
 *     collapse to the all-zeros development default.
 *  4. one-byte tamper — a covered chunk modified on disk changes the
 *     recomputed root R → wrong FinalKey → unseal fails (real backend).
 *  5. `copylocker-unplugin verify` — clean dist exits 0; tampered copy exits
 *     non-zero (FR-BLD-010, CI gate).
 *
 * Backend-dependent scenarios skip when the local Worker is unavailable.
 */
import { spawnSync } from 'node:child_process'
import { cpSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test, type Page } from '@playwright/test'
import { BOOTSTRAP_SOURCE } from '../../unplugin/dist/generated/bootstrap-source.js'
import { backend } from '../helpers/backend'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../../..')
const distDir = path.join(repoRoot, 'examples', 'vite-spa', 'dist')
const signingKeyFile = path.join(repoRoot, 'examples', 'vite-spa', '.copylocker', 'signing-key.json')
const unpluginCli = path.join(repoRoot, 'packages', 'unplugin', 'dist', 'cli.js')

const featureId = backend.featureId ?? 'demo-feature'
const PLAINTEXT = 'copylocker m4 integrity e2e payload'

/** The signing public key (hex) from the local dev signer's JWK (`x`). */
function signerPublicHex(): string {
  const jwk = JSON.parse(readFileSync(signingKeyFile, 'utf8')) as { x: string }
  return Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('hex')
}

/** A covered non-entry chunk (no excludedRanges — any byte counts). */
function pickCoveredChunk(dir: string): string {
  const assetsDir = path.join(dir, 'assets')
  for (const file of readdirSync(assetsDir)) {
    if (!file.endsWith('.js')) continue
    const full = path.join(assetsDir, file)
    if (!readFileSync(full, 'utf8').includes('__CL_GUARD_CONFIG__')) return full
  }
  throw new Error(`no non-entry covered chunk found in ${assetsDir}`)
}

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
        { productId, variantId: 0, featureId: feature, assetId: 'e2e-m4-asset' },
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
  await page.getByTestId('license-key-input').fill(backend.licenseKey as string)
  await page.getByTestId('activate-button').click()
  await expect(page.getByTestId('status-log')).toContainText('activate ok', { timeout: 30_000 })
  await expect(page.getByTestId('license-state')).toHaveText('active')
}

/** Seal in-page, serve the bytes as /demo-asset.clx, unseal through the UI. */
async function sealAndUnsealThroughUi(page: Page): Promise<void> {
  const sealedB64 = await sealInPage(page, PLAINTEXT)
  const sealedBytes = Buffer.from(sealedB64, 'base64')
  await page.route('**/demo-asset.clx', (route) =>
    route.fulfill({ status: 200, contentType: 'application/octet-stream', body: sealedBytes }),
  )
  await page.getByTestId('unseal-button').click()
}

test.describe('M4 build integrity (vite-spa + @copylocker/unplugin)', () => {
  test('clean build publishes the guard runtime contract', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')
    const contract = await page.evaluate(async () => {
      const g = globalThis as Record<string, unknown>
      const toHex = (bytes: Uint8Array): string =>
        [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
      const R = await (g.__CL_GUARD_R__ as Promise<Uint8Array> | undefined)
      return {
        rHex: R instanceof Uint8Array ? toHex(R) : null,
        expectedRoot: g.__COPYLOCKER_MANIFEST_ROOT__ as string | undefined,
        requireProof: g.__CL_REQUIRE_INTEGRITY_PROOF__,
        singleKBuild: (g.__COPYLOCKER_K_BUILD__ as string | undefined) ?? null,
        shardHex: [0, 1, 2, 3]
          .map((i) => (g[`__CL_K_BUILD_${i}__`] as string | undefined) ?? '')
          .join(''),
      }
    })
    // The actually-computed root equals the signed manifest's expected root.
    expect(contract.rHex).toMatch(/^[0-9a-f]{64}$/)
    expect(contract.rHex).toBe(contract.expectedRoot)
    // Fail-closed default for @copylocker/web's requireIntegrityProof.
    expect(contract.requireProof).toBe(true)
    // splitConstants: 4 — only shards, no single K_BUILD global.
    expect(contract.singleKBuild).toBeNull()
    expect(contract.shardHex).toMatch(/^[0-9a-f]{64}$/)
  })

  test('verify CLI: clean dist exits 0, tampered copy exits non-zero', async () => {
    test.setTimeout(120_000)
    const pubkey = signerPublicHex()
    const runVerify = (dir: string, withPubkey: boolean) =>
      spawnSync(
        process.execPath,
        [unpluginCli, 'verify', dir, ...(withPubkey ? ['--pubkey', pubkey] : [])],
        { encoding: 'utf8' },
      )

    const clean = runVerify(distDir, true)
    expect(clean.status, `clean verify failed:\n${clean.stdout}\n${clean.stderr}`).toBe(0)
    expect(clean.stdout).toContain('signature:     verified')
    expect(clean.stdout).toContain('RESULT: OK')

    const tamperedDir = path.join(repoRoot, 'target', 'tmp', 'web-e2e', 'tampered-dist')
    rmSync(tamperedDir, { recursive: true, force: true })
    cpSync(distDir, tamperedDir, { recursive: true })
    try {
      // One appended byte in a covered artifact — the CI gate must trip.
      const target = pickCoveredChunk(tamperedDir)
      writeFileSync(target, Buffer.concat([readFileSync(target), Buffer.from([0x0a])]))
      const tampered = runVerify(tamperedDir, true)
      expect(tampered.status, `tampered verify passed:\n${tampered.stdout}`).toBe(1)
      expect(tampered.stdout).toContain('[mismatch]')
      expect(tampered.stdout).toContain('RESULT: FAILED')
    } finally {
      rmSync(tamperedDir, { recursive: true, force: true })
    }
  })

  test.describe('against the real local backend', () => {
    test.skip(!backend.available, `local backend unavailable: ${backend.reason ?? 'unknown'}`)
    test.describe.configure({ mode: 'serial' })

    test('control: the untampered build unseals with the guard-computed R', async ({ page }) => {
      test.setTimeout(180_000)
      await activateThroughUi(page)
      await sealAndUnsealThroughUi(page)
      await expect(page.getByTestId('unseal-output')).toHaveAttribute('data-kind', 'ok')
      await expect(page.getByTestId('unseal-output')).toHaveText(PLAINTEXT)
    })

    test('deleting the guard bootstrap fails derivation closed', async ({ page }) => {
      test.setTimeout(180_000)
      // Attack: strip the guard bootstrap from the served entry chunk but
      // keep the __CL_GUARD_CONFIG__ constants block — the move that would
      // silently re-enable the static-constant fallback.
      let stripped = 0
      await page.route('**/*.js', async (route) => {
        const response = await route.fetch()
        const body = await response.text()
        if (body.includes('__CL_GUARD_CONFIG__')) {
          if (!body.includes(BOOTSTRAP_SOURCE)) {
            throw new Error('bootstrap source not found in the entry chunk — prelude drifted?')
          }
          stripped += 1
          await route.fulfill({
            response,
            body: body.replace(BOOTSTRAP_SOURCE, '/* guard bootstrap deleted (attack) */'),
          })
          return
        }
        await route.fulfill({ response, body })
      })
      await activateThroughUi(page)
      expect(stripped).toBeGreaterThan(0)

      const globals = await page.evaluate(() => {
        const g = globalThis as Record<string, unknown>
        return {
          config: g.__CL_GUARD_CONFIG__ !== undefined,
          requireProof: g.__CL_REQUIRE_INTEGRITY_PROOF__,
          R: g.__CL_GUARD_R__,
          manifestRoot: (g.__COPYLOCKER_MANIFEST_ROOT__ as string | undefined) ?? null,
        }
      })
      // Constants block survived (attacker keeps it for the fallback)…
      expect(globals.config).toBe(true)
      expect(globals.requireProof).toBe(true)
      // …but the bootstrap never ran: no R, not even the static root.
      expect(globals.R).toBeUndefined()
      expect(globals.manifestRoot).toBeNull()

      // sealInPage derives with the all-zeros development constants (nothing
      // was published); without requireIntegrityProof the unseal fallback
      // would land on the same zeros and OPEN the asset — the M4 hole. With
      // the flag, derivation fails closed before any decryption happens.
      await sealAndUnsealThroughUi(page)
      await expect(page.getByTestId('unseal-output')).toHaveAttribute('data-kind', 'error')
      await expect(page.getByTestId('unseal-output')).toContainText('NotEntitledError')
    })

    test('a one-byte tamper in a covered chunk fails unseal (R changes)', async ({ page }) => {
      test.setTimeout(180_000)
      const target = pickCoveredChunk(distDir)
      const original = readFileSync(target)
      // A trailing newline: one byte, still parses — the bundle "works", only
      // the integrity proof changes. The digest must notice.
      writeFileSync(target, Buffer.concat([original, Buffer.from([0x0a])]))
      try {
        await activateThroughUi(page)
        // sealInPage uses the static (expected) constants; unseal derives
        // with the guard's actually-computed R over the tampered bytes.
        await sealAndUnsealThroughUi(page)
        await expect(page.getByTestId('unseal-output')).toHaveAttribute('data-kind', 'error')
        await expect(page.getByTestId('unseal-output')).toContainText('UnsealError')
      } finally {
        writeFileSync(target, original)
      }
    })
  })
})
