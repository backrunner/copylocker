import { join, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

import { CopyLocker } from '@copylocker/electron/main'
import { app, BrowserWindow, net, protocol, type WebContents } from 'electron'

import { COPYLOCKER_BUILD_CONFIG } from './generated-config'

let detachCopyLocker: (() => void) | undefined
const RENDERER_SCHEME = 'copylocker'
const RENDERER_ORIGIN = `${RENDERER_SCHEME}://bundle`
const RENDERER_URL = `${RENDERER_ORIGIN}/index.html`
const RENDERER_ROOT = resolve(__dirname, '../renderer')
const RENDERER_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; " +
  "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

protocol.registerSchemesAsPrivileged([
  {
    scheme: RENDERER_SCHEME,
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
    },
  },
])

async function initializeCopyLocker(): Promise<void> {
  const config = COPYLOCKER_BUILD_CONFIG
  const copyLocker = await CopyLocker.create({
    serverUrl: config.serverUrl,
    appId: config.appId,
    productId: config.productId,
    appVersion: config.appVersion,
    releaseId: config.releaseId,
    buildFingerprint: config.buildFingerprint,
    currentRootKey: Buffer.from(config.currentRootKeyHex, 'hex'),
    fingerprintSalt: Buffer.from(config.fingerprintSaltHex, 'hex'),
    variantId: config.variantId,
    variantConst: Buffer.from(config.variantConstHex, 'hex'),
    expectedModuleDigest: Buffer.from(config.expectedModuleDigestHex, 'hex'),
    allowInsecureLocalhost: config.allowInsecureLocalhost,
  })

  detachCopyLocker = copyLocker.attachIpc({
    allowedFeatures: ['pro-config'],
    allowChallenge: false,
    rateLimit: {
      windowMs: 60_000,
      maxRequests: 120,
      maxBytes: 8 * 1024 * 1024,
    },
  })
}

async function createWindow(): Promise<void> {
  const window = new BrowserWindow({
    title: 'CopyLocker Native Lab',
    width: 1024,
    height: 720,
    minWidth: 640,
    minHeight: 600,
    show: false,
    webPreferences: {
      preload: join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      devTools: false,
    },
  })

  hardenNavigation(window.webContents, RENDERER_URL)
  window.removeMenu()
  window.once('ready-to-show', () => window.show())
  await window.loadURL(RENDERER_URL)
}

function hardenNavigation(contents: WebContents, initialUrl: string): void {
  contents.setWindowOpenHandler(() => ({ action: 'deny' }))
  contents.on('will-navigate', (event, url) => {
    if (url !== initialUrl) event.preventDefault()
  })
}

function installRendererProtocol(): void {
  protocol.handle(RENDERER_SCHEME, async (request) => {
    const filePath = rendererFilePath(request.url)
    if (!filePath) return new Response('Not found', { status: 404 })
    const response = await net.fetch(pathToFileURL(filePath).toString())
    const headers = new Headers(response.headers)
    headers.set('Content-Security-Policy', RENDERER_CSP)
    headers.set('X-Content-Type-Options', 'nosniff')
    return new Response(response.body, {
      headers,
      status: response.status,
      statusText: response.statusText,
    })
  })
}

function rendererFilePath(rawUrl: string): string | undefined {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    return undefined
  }
  if (
    url.protocol !== `${RENDERER_SCHEME}:` ||
    url.hostname !== 'bundle' ||
    url.username.length !== 0 ||
    url.password.length !== 0 ||
    url.port.length !== 0
  ) {
    return undefined
  }

  let relative: string
  try {
    relative = decodeURIComponent(url.pathname).replace(/^\/+/, '')
  } catch {
    return undefined
  }
  if (relative.length === 0) relative = 'index.html'
  if (relative.includes('\0')) return undefined

  const filePath = resolve(RENDERER_ROOT, relative)
  if (filePath !== RENDERER_ROOT && !filePath.startsWith(`${RENDERER_ROOT}${sep}`)) {
    return undefined
  }
  return filePath
}

void app.whenReady().then(async () => {
  installRendererProtocol()
  await initializeCopyLocker()
  await createWindow()
}).catch((error: unknown) => {
  const direct = (error as { code?: unknown } | null)?.code
  const code = Number.isSafeInteger(direct) ? direct : 3999
  console.error(`CopyLocker Electron example failed (${code})`)
  app.quit()
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0 && detachCopyLocker) {
    void createWindow()
  }
})

app.on('before-quit', () => {
  detachCopyLocker?.()
  detachCopyLocker = undefined
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
