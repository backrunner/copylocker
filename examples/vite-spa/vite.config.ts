import { defineConfig, type PluginOption } from 'vite'
import copylocker from '@copylocker/unplugin/vite'

/**
 * CSP recommended by `packages/web/README.md`: WASM instantiation needs
 * `script-src 'wasm-unsafe-eval'`; the SDK itself uses no eval and no inline
 * scripts. `connect-src` must allow the licensing Worker (wrangler dev
 * defaults to http://localhost:8787) and, during development, the Vite HMR
 * websocket. The session Worker and the fetched .wasm come from 'self'.
 */
const serverUrl = process.env.VITE_CL_SERVER_URL ?? 'http://localhost:8787'
const productId = process.env.VITE_CL_PRODUCT_ID ?? 'kat-product'

const contentSecurityPolicy = [
  `default-src 'self'`,
  `script-src 'self' 'wasm-unsafe-eval'`,
  `worker-src 'self'`,
  `connect-src 'self' ${serverUrl} ws://127.0.0.1:* ws://localhost:*`,
  `img-src 'self' data:`,
  `style-src 'self'`,
  `object-src 'none'`,
  `base-uri 'self'`,
].join('; ')

const headers = { 'Content-Security-Policy': contentSecurityPolicy }

// E2E LCP control group (packages/web-e2e vite-spa.lcp spec): build the exact
// same app WITHOUT the copylocker plugin so the guard's LCP delta
// (NFR-PERF-006) can be measured against a real control build.
const copylockerDisabled = process.env.CL_E2E_DISABLE_COPYLOCKER === '1'

export default defineConfig({
  server: { strictPort: true, headers },
  preview: { strictPort: true, headers },
  // The SDK spawns its session Worker as an ES module (FR-WEB-008).
  worker: { format: 'es' },
  plugins: [
    ...(copylockerDisabled
      ? []
      : [
          // M4-A build integrity: digests every covered output into a signed
          // manifest, injects the guard bootstrap (publishes the
          // actually-computed root as `__CL_GUARD_R__`, consumed in
          // src/main.ts), and seals the demo asset through the KEK registry.
          // Runs on the final bytes in writeBundle, so it stays LAST.
          // Build-only (the vite adapter sets `apply: 'build'`); `vite dev`
          // is untouched.
          copylocker({
            productId,
            signer: {
              kind: 'local',
              keyFile: '.copylocker/signing-key.json', // created by scripts/ensure-build-keys.mjs
              // This example builds with NODE_ENV=production for the E2E
              // suite; a real project uses a remote signer in CI instead of
              // this override.
              allowLocalInProduction: true,
            },
            splitConstants: 4,
            seal: { assets: [{ globs: ['sealed-assets/pro-*.json'], feature: 'pro' }] },
            guard: {
              // 'sync' so `__CL_GUARD_R__` settles right after boot —
              // deterministic for the E2E suite. 'idle' (the default) is fine
              // for production.
              strategy: 'sync',
            },
            // The unplugin dist is typed against its own vite 8 (rolldown)
            // dev dependency while this example pins vite 7 — the runtime
            // plugin API is identical (writeBundle), only the structural
            // Plugin types differ.
          }) as unknown as PluginOption,
        ]),
  ],
})
