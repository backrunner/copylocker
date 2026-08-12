import { DEV_ROOT_PIN } from './dev-root-pin'

/**
 * Shared SDK configuration. `NEXT_PUBLIC_*` variables are inlined at build
 * time; the defaults target the local development setup (`wrangler dev` of
 * `server-template/` plus the CL-STD-1 KAT).
 */
export const serverUrl = process.env.NEXT_PUBLIC_CL_SERVER_URL ?? 'http://localhost:8787'
export const productId = process.env.NEXT_PUBLIC_CL_PRODUCT_ID ?? 'kat-product'
export const rootPin = process.env.NEXT_PUBLIC_CL_ROOT_PIN ?? DEV_ROOT_PIN

export const copyLockerOptions = {
  serverUrl,
  productId,
  rootPins: [rootPin],
  worker: true, // FR-WEB-008: session core in a dedicated Worker
  // Turbopack rewrites the package-internal `new Worker(new URL(...,
  // import.meta.url))` into a bootstrap that never starts, which hangs the
  // INIT handshake. Construct the Worker from a runtime URL instead — the
  // entry module graph is served statically from public/copylocker-sdk/
  // (see scripts/copy-wasm.mjs).
  workerFactory: () =>
    new Worker(new URL('./copylocker-sdk/worker/entry.js', window.location.href), {
      type: 'module',
    }),
  // M4 build integrity (webpack production build): the unplugin-injected
  // guard bootstrap publishes the ACTUALLY-COMPUTED manifest root as
  // `globalThis.__CL_GUARD_R__` (Promise<Uint8Array>). A tampered bundle
  // computes a different R → wrong FinalKey → sealed assets fail to open.
  // The build also injects `__CL_REQUIRE_INTEGRITY_PROOF__ = true`, so
  // deleting the bootstrap (no R at all) fails derivation closed instead of
  // falling back to the static constant. In `next dev` / Turbopack builds
  // there is no injection and the SDK falls back to the development
  // defaults, as before.
  integrity: { manifestRoot: () => globalThis.__CL_GUARD_R__ },
}
