import { join } from 'node:path'
import type { NextConfig } from 'next'
import copylocker from '@copylocker/unplugin/webpack'

/**
 * Build integrity (M4) via `@copylocker/unplugin`'s webpack adapter.
 *
 * Next 16 builds with Turbopack by default, which has no post-emit plugin
 * hook the pipeline can tap (its plugin surface is Rust-side), so the
 * integrity build is the webpack one: `next build --webpack` (wired as
 * `npm run build`; `npm run build:turbopack` keeps a plain Turbopack build
 * for comparison — its output carries no guard bootstrap). See README.
 */
const nextConfig: NextConfig = {
  // CSP is set per request in proxy.ts (nonce-based; see that file).

  // `@copylocker/web` is a `file:../../packages/web` symlink that lives
  // outside this example's directory; point Turbopack at the monorepo root
  // so it resolves through the link.
  turbopack: {
    root: join(import.meta.dirname, '..', '..'),
  },

  webpack(config, { dev, isServer }) {
    // Only the production CLIENT compilation — the bytes the browser actually
    // loads from `/_next/static/...`. The server/edge compilations and dev
    // builds are left untouched. The plugin taps `afterEmit` and digests the
    // final files on disk (`.next/`), injecting the guard bootstrap into the
    // entry chunks (webpack runtime + main-app) and writing the signed
    // manifest to `.next/.copylocker/manifest.cbor`. Keep it LAST: tap order
    // follows plugin order, and the digests must cover the terminal bytes.
    if (!dev && !isServer) {
      ;(config.plugins ??= []).push(
        copylocker({
          productId: process.env.NEXT_PUBLIC_CL_PRODUCT_ID ?? 'kat-product',
          signer: {
            kind: 'local',
            keyFile: '.copylocker/signing-key.json', // created by scripts/ensure-build-keys.mjs
            // This example builds with NODE_ENV=production for the E2E suite;
            // a real project uses a remote signer in CI instead of this
            // override.
            allowLocalInProduction: true,
          },
          // The client out dir (`.next/`) is served at `/_next/`; the guard
          // bootstrap fetches chunk URLs verbatim, so they need this prefix.
          urlBase: '/_next/',
          // Cover the browser-served bytes only: `static/**` is what
          // `/_next/static` serves, and the guard bootstrap fetches every
          // listed chunk at boot — server-compilation artifacts would 404
          // and derail R. `_ssgManifest.js` is excluded because Next writes
          // it AFTER the client compilation (page-optimization phase), so
          // an `afterEmit` digest cannot cover it. (Note: `static/**/*.js`
          // would be wrong here — @copylocker/seal's globToRegExp requires
          // `**` right after the leading slash; `static/**` is the working
          // anchored form.)
          include: ['static/**'],
          exclude: ['**/*.map', '**/_ssgManifest.js'],
          splitConstants: 4,
          guard: {
            // 'sync' so `__CL_GUARD_R__` settles right after boot —
            // deterministic for the E2E suite. 'idle' (the default) is fine
            // for production.
            strategy: 'sync',
          },
          // The unplugin webpack factory returns unplugin's structural
          // WebpackPluginInstance; Next types `config.plugins` against its
          // bundled webpack — same runtime shape, different type identity.
        }) as unknown as NonNullable<typeof config.plugins>[number],
      )
    }
    return config
  },
}

export default nextConfig
