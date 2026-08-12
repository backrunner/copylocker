import { randomBytes } from 'node:crypto'
import { NextResponse, type NextRequest } from 'next/server'

/**
 * Nonce-based CSP (Next.js "proxy" convention, formerly `middleware.ts`).
 *
 * Next.js App Router serializes its RSC payload through inline scripts, so a
 * bare `script-src 'self'` would break hydration. Following the official
 * pattern, every response gets a per-request nonce (`'nonce-…'` +
 * `'strict-dynamic'`); Next picks the nonce up from the request headers and
 * applies it to its own scripts.
 *
 * The CopyLocker-relevant directives mirror `packages/web/README.md`:
 * `script-src … 'wasm-unsafe-eval'` for WASM instantiation, `worker-src
 * 'self'` for the session Worker (FR-WEB-008), and `connect-src` covering the
 * licensing Worker (default http://localhost:8787) plus the dev HMR socket.
 */
export default function proxy(request: NextRequest) {
  const nonce = randomBytes(16).toString('base64')
  const isDev = process.env.NODE_ENV !== 'production'
  const serverUrl = process.env.NEXT_PUBLIC_CL_SERVER_URL ?? 'http://localhost:8787'

  const contentSecurityPolicy = [
    `default-src 'self'`,
    [
      `script-src 'self' 'wasm-unsafe-eval' 'nonce-${nonce}' 'strict-dynamic'`,
      isDev ? `'unsafe-eval'` : '', // react-refresh in development
    ]
      .filter(Boolean)
      .join(' '),
    `worker-src 'self'`,
    `connect-src 'self' ${serverUrl}${isDev ? ' ws:' : ''}`,
    `img-src 'self' data:`,
    `style-src 'self' 'unsafe-inline'`, // Next injects critical CSS inline
    `object-src 'none'`,
    `base-uri 'self'`,
  ].join('; ')

  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-nonce', nonce)
  requestHeaders.set('Content-Security-Policy', contentSecurityPolicy)

  const response = NextResponse.next({ request: { headers: requestHeaders } })
  response.headers.set('Content-Security-Policy', contentSecurityPolicy)
  return response
}

export const config = {
  matcher: [
    // Skip Next internals and static files (images, wasm, sealed assets).
    {
      source: '/((?!_next/static|_next/image|favicon.ico|copylocker-wasm|.*\\.(?:svg|png|ico|clx|wasm)$).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
}
