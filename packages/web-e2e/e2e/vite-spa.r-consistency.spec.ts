/**
 * M4 multi-engine acceptance (50-unplugin-integrity.md §3.2): the SAME
 * vite-spa build must produce the identical integrity state on every
 * browser engine — no false positives.
 *
 * Two paths are asserted per browser, each anchored to a build-time truth
 * decoded from the signed manifest carried by the page itself:
 *
 *  1. Chunk Merkle root: the guard's ACTUALLY-COMPUTED root
 *     (`__CL_GUARD_R__`) equals the manifest's expected root
 *     (`__COPYLOCKER_MANIFEST_ROOT__` / manifest key 9).
 *  2. Guarded function body digest (the §3.2 false-positive hotspot): the
 *     runtime digest of `e2e.probe` — `SHA-256(utf8(normalizeSource(
 *     Function.prototype.toString.call(fn))))` — equals the build-time
 *     digest collected into the manifest (`guarded['e2e.probe']`, key 7),
 *     and the GuardState value after one isolated mix matches the
 *     Node-recomputed `SHA-256(0²⁵⁶ ‖ utf8(id) ‖ digest)`.
 *
 * Each project (chromium via `vite-spa`, plus `vite-spa-firefox` and
 * `vite-spa-webkit`) also writes its measurements to
 * `output/playwright/r-consistency/<browser>.json` (wiped by globalSetup)
 * and compares them byte-for-byte against every sibling artifact already
 * written this run — a direct cross-engine equality check. `raw` toString
 * output is recorded but NOT compared: engines may legitimately differ
 * there as long as `normalizeSource` absorbs the difference (a raw
 * difference with equal normalized output is reported as a finding, not a
 * failure).
 *
 * If a browser ever fails the normalized/digest comparison that is a REAL
 * engine `toString` false positive: do not silence it — diagnose with the
 * printed raw/normalized pair, and only then mark that browser's project
 * as a known issue with the reason recorded here.
 */
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test } from '@playwright/test'
import { decodeManifest, toHex } from '../../guard/dist/index.js'
import { rConsistencyArtifactDir } from './global-setup.js'

const here = path.dirname(fileURLToPath(import.meta.url))

interface ProbeResult {
  id: string
  raw: string
  normalized: string
  digestHex: string
  guardStateHex: string
  wrappedResult: number
  userAgent: string
}

interface BrowserMeasurement {
  browser: string
  rHex: string
  expectedRoot: string
  manifestRootHex: string
  guardedExpectedHex: string
  probe: ProbeResult
}

/** Fields that MUST be byte-identical across engines. */
const CROSS_BROWSER_FIELDS = ['rHex', 'guardedExpectedHex'] as const
const CROSS_BROWSER_PROBE_FIELDS = ['normalized', 'digestHex', 'guardStateHex'] as const

function sha256Hex(...parts: Uint8Array[]): string {
  const hash = createHash('sha256')
  for (const part of parts) hash.update(part)
  return hash.digest('hex')
}

test.describe('M4 multi-engine R consistency (no false positives)', () => {
  test('R and guarded digests match the signed manifest and every other engine', async ({
    page,
  }, testInfo) => {
    await page.goto('/')
    await expect(page.getByTestId('sdk-status')).toHaveAttribute('data-ready', 'true')

    const data = await page.evaluate(async () => {
      const g = globalThis as Record<string, unknown>
      const hex = (bytes: Uint8Array): string =>
        [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
      const R = await (g.__CL_GUARD_R__ as Promise<Uint8Array> | undefined)
      if (!(R instanceof Uint8Array)) throw new Error('__CL_GUARD_R__ did not resolve to bytes')
      const hook = g.__CL_E2E_GUARD_PROBE__ as { probe(): Promise<ProbeResult> } | undefined
      if (!hook) throw new Error('__CL_E2E_GUARD_PROBE__ hook missing (vite-spa fixture not built?)')
      return {
        rHex: hex(R),
        expectedRoot: g.__COPYLOCKER_MANIFEST_ROOT__ as string | undefined,
        manifestBytes: [...(g.__CL_MANIFEST__ as Uint8Array)],
        probe: await hook.probe(),
      }
    })

    const browser = page.context().browser()?.browserType().name() ?? 'unknown'

    // Build-time truth, decoded from the page's own signed manifest.
    const signed = decodeManifest(new Uint8Array(data.manifestBytes))
    const guardedExpected = signed.manifest.guarded.get('e2e.probe')
    expect(
      guardedExpected,
      "manifest carries no guarded['e2e.probe'] entry — the vite-spa fixture " +
        '(src/e2e-guard-probe.ts) was not collected; check the unplugin transform',
    ).toBeDefined()
    const guardedExpectedHex = toHex(guardedExpected as Uint8Array)
    const manifestRootHex = toHex(signed.manifest.root)

    const measurement: BrowserMeasurement = {
      browser,
      rHex: data.rHex,
      expectedRoot: data.expectedRoot ?? '',
      manifestRootHex,
      guardedExpectedHex,
      probe: data.probe,
    }

    // 1. Chunk Merkle root path.
    expect(measurement.expectedRoot).toMatch(/^[0-9a-f]{64}$/)
    expect(measurement.rHex).toBe(measurement.expectedRoot)
    expect(measurement.rHex).toBe(manifestRootHex)

    // 2. Guarded body digest path: runtime toString+normalize on THIS engine
    // must land on the build-time digest — the §3.2 false-positive check.
    expect(
      measurement.probe.digestHex,
      `engine toString/normalize divergence on ${browser}:\n` +
        `raw:        ${JSON.stringify(measurement.probe.raw)}\n` +
        `normalized: ${JSON.stringify(measurement.probe.normalized)}\n` +
        `runtime digest ${measurement.probe.digestHex} != manifest ${guardedExpectedHex}`,
    ).toBe(guardedExpectedHex)
    // The wrapped probe still computes the right answer.
    expect(measurement.probe.wrappedResult).toBe(e2eProbeExpectedResult())
    // GuardState after one isolated mix: H(0²⁵⁶ ‖ utf8(id) ‖ digest).
    const expectedState = sha256Hex(
      new Uint8Array(32),
      new TextEncoder().encode(measurement.probe.id),
      guardedExpected as Uint8Array,
    )
    expect(measurement.probe.guardStateHex).toBe(expectedState)

    // 3. Cross-engine byte equality against every artifact written this run.
    mkdirSync(rConsistencyArtifactDir, { recursive: true })
    const ownFile = path.join(rConsistencyArtifactDir, `${browser}.json`)
    writeFileSync(ownFile, JSON.stringify(measurement, null, 2))

    const others = readdirSync(rConsistencyArtifactDir)
      .filter((file) => file.endsWith('.json') && file !== `${browser}.json`)
      .map((file) => ({
        file,
        value: JSON.parse(
          readFileSync(path.join(rConsistencyArtifactDir, file), 'utf8'),
        ) as BrowserMeasurement,
      }))
    if (others.length === 0) {
      console.log(
        `[r-consistency] no sibling browser artifacts yet — cross-engine compare deferred to later projects`,
      )
    }
    for (const other of others) {
      for (const field of CROSS_BROWSER_FIELDS) {
        expect(
          measurement[field],
          `${browser} vs ${other.value.browser}: ${field} differs`,
        ).toBe(other.value[field])
      }
      for (const field of CROSS_BROWSER_PROBE_FIELDS) {
        expect(
          measurement.probe[field],
          `${browser} vs ${other.value.browser}: probe.${field} differs\n` +
            `${browser} normalized: ${JSON.stringify(measurement.probe.normalized)}\n` +
            `${other.value.browser} normalized: ${JSON.stringify(other.value.probe.normalized)}`,
        ).toBe(other.value.probe[field])
      }
      if (measurement.probe.raw !== other.value.probe.raw) {
        // normalizeSource absorbed an engine toString difference — exactly
        // the §3.2 scenario working as designed. Report it as a finding.
        const note =
          `[r-consistency] engine toString difference absorbed by normalizeSource ` +
          `(${other.value.browser} vs ${browser}):\n` +
          `${other.value.browser}: ${JSON.stringify(other.value.probe.raw)}\n` +
          `${browser}: ${JSON.stringify(measurement.probe.raw)}`
        console.log(note)
        await testInfo.attach('engine-tostring-difference', { body: note, contentType: 'text/plain' })
      }
    }
    await testInfo.attach(`r-consistency-${browser}`, {
      body: JSON.stringify(measurement, null, 2),
      contentType: 'application/json',
    })
  })
})

/** Reference implementation of the e2e.probe body (see vite-spa fixture). */
function e2eProbeExpectedResult(): number {
  const x = 41
  const label = `probe:${x}`
  const digits = /^\d+$/u.test(String(x)) ? x : 0
  const bump = (n: number) => n + 1
  const snowman = '☃\u2603'
  return bump(digits) + label.length + snowman.length
}
