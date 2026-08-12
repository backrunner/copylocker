import { CopyLocker as SsrCopyLocker } from '@copylocker/web/ssr'
import { copyLockerOptions, productId, serverUrl } from '../lib/config'
import LabLoader from './LabLoader'

// Nonce-based CSP (proxy.ts) requires dynamic rendering: Next applies the
// per-request nonce to its scripts only during server-side rendering.
export const dynamic = 'force-dynamic'

/**
 * Server component: demonstrates the `@copylocker/web/ssr` no-op stub
 * (FR-WEB-009). The stub renders with zero side effects — no DOM, storage,
 * network, or wasm — and reports `state === 'unlicensed'`. The real SDK is
 * client-only and mounted below via `dynamic(..., { ssr: false })`.
 */
export default async function Page() {
  const stub = await SsrCopyLocker.create(copyLockerOptions)

  return (
    <main>
      <header className="topbar">
        <strong>CopyLocker</strong> <span>Web Lab / Next.js</span>
      </header>

      <section className="panel" data-testid="ssr-panel">
        <h1>SSR render</h1>
        <p>
          Server-rendered with the <code>@copylocker/web/ssr</code> stub —{' '}
          isSsrStub: <code data-testid="ssr-is-stub">{String(stub.isSsrStub)}</code>, advisory
          state: <code data-testid="ssr-state">{stub.state}</code>
        </p>
        <p className="meta">
          Server <code data-testid="server-url">{serverUrl}</code> · Product{' '}
          <code data-testid="product-id">{productId}</code>
        </p>
      </section>

      <LabLoader />
    </main>
  )
}
