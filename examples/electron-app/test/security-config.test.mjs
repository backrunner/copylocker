import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import {
  FuseV1Options,
  FuseVersion,
} from '@electron/fuses'

import {
  ASAR_OPTIONS,
  FUSE_OPTIONS,
  ICON_FILENAMES,
} from '../scripts/package-config.mjs'

const mainSource = await readFile(new URL('../src/main/index.ts', import.meta.url), 'utf8')
const preloadSource = await readFile(new URL('../src/preload/index.ts', import.meta.url), 'utf8')
const html = await readFile(new URL('../index.html', import.meta.url), 'utf8')
const packageSource = await readFile(new URL('../scripts/package.mjs', import.meta.url), 'utf8')

test('packaging preserves the native binding outside ASAR', () => {
  assert.equal(ASAR_OPTIONS.unpack, '**/*.node')
  assert.deepEqual(ICON_FILENAMES, {
    darwin: 'copylocker-seal.icns',
    win32: 'copylocker-seal.ico',
    linux: 'copylocker-seal.png',
  })
})

test('Electron bypass fuses are disabled', () => {
  assert.equal(FUSE_OPTIONS.version, FuseVersion.V1)
  assert.equal(FUSE_OPTIONS[FuseV1Options.RunAsNode], false)
  assert.equal(FUSE_OPTIONS[FuseV1Options.EnableCookieEncryption], true)
  assert.equal(FUSE_OPTIONS[FuseV1Options.EnableNodeOptionsEnvironmentVariable], false)
  assert.equal(FUSE_OPTIONS[FuseV1Options.EnableNodeCliInspectArguments], false)
  assert.equal(FUSE_OPTIONS[FuseV1Options.EnableEmbeddedAsarIntegrityValidation], true)
  assert.equal(FUSE_OPTIONS[FuseV1Options.OnlyLoadAppFromAsar], true)
  assert.equal(FUSE_OPTIONS[FuseV1Options.LoadBrowserProcessSpecificV8Snapshot], false)
  assert.equal(FUSE_OPTIONS[FuseV1Options.GrantFileProtocolExtraPrivileges], false)
  assert.equal(FUSE_OPTIONS[FuseV1Options.WasmTrapHandlers], true)
  assert.match(packageSource, /resetAdHocDarwinSignature:/)
  assert.match(packageSource, /strictlyRequireAllFuses:\s*true/)
})

test('BrowserWindow and IPC policy stay least-privilege', () => {
  assert.match(mainSource, /contextIsolation:\s*true/)
  assert.match(mainSource, /nodeIntegration:\s*false/)
  assert.match(mainSource, /sandbox:\s*true/)
  assert.match(mainSource, /allowedFeatures:\s*\['pro-config'\]/)
  assert.match(mainSource, /allowChallenge:\s*false/)
  assert.match(mainSource, /setWindowOpenHandler\(\(\) => \(\{ action: 'deny' \}\)\)/)
  assert.match(mainSource, /if \(url !== initialUrl\) event\.preventDefault\(\)/)
  assert.match(mainSource, /protocol\.registerSchemesAsPrivileged/)
  assert.match(mainSource, /protocol\.handle\(RENDERER_SCHEME/)
  assert.match(mainSource, /window\.loadURL\(RENDERER_URL\)/)
  assert.doesNotMatch(mainSource, /window\.loadFile/)
})

test('sandboxed preload exposes only the CopyLocker bridge', () => {
  assert.match(preloadSource, /installCopyLockerBridge\(\)/)
  assert.doesNotMatch(preloadSource, /ipcRenderer/)
  assert.doesNotMatch(preloadSource, /contextBridge/)
})

test('renderer has a restrictive static CSP', () => {
  assert.match(html, /default-src 'self'/)
  assert.match(html, /object-src 'none'/)
  assert.match(mainSource, /frame-ancestors 'none'/)
  assert.match(mainSource, /Content-Security-Policy/)
  assert.match(mainSource, /X-Content-Type-Options/)
  assert.doesNotMatch(html, /unsafe-inline|unsafe-eval/)
})
