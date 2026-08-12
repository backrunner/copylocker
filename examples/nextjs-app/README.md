# CopyLocker Next.js example

Next.js (App Router) app demonstrating `@copylocker/web` (M3 Web SDK) with
SSR: the server render uses the `@copylocker/web/ssr` no-op stub, and the
real SDK is mounted client-only via `dynamic(..., { ssr: false })`. The
production build additionally wires in `@copylocker/unplugin` (M4 build
integrity) — see "Build integrity" below.

## Run from scratch

```bash
npm install
npm run build && npm start   # http://localhost:3000
# or: npm run dev
```

`npm run build` is `next build --webpack` and needs the local development
signing key; the `prebuild` script creates it on first run
(`scripts/ensure-build-keys.mjs`, `.copylocker/` is gitignored).

The SDK talks to a CopyLocker Worker at `http://localhost:8787` by default —
the `wrangler dev` address of the `server-template/` project. Configuration
via environment (inlined at build time, so set before `next build`):

| Variable | Default | Notes |
|---|---|---|
| `NEXT_PUBLIC_CL_SERVER_URL` | `http://localhost:8787` | CopyLocker Worker base URL |
| `NEXT_PUBLIC_CL_PRODUCT_ID` | `kat-product` | matches the CL-STD-1 KAT |
| `NEXT_PUBLIC_CL_ROOT_PIN` | CL-STD-1 KAT Root verifying key | hex; development fallback only |

The development root pin is the public Root verifying key from the committed
CL-STD-1 KAT (`vectors/CL-STD-1/kat.json`), the same key the Tauri/Electron
examples embed.

## Build integrity (M4, `@copylocker/unplugin`)

`npm run build` runs `next build --webpack`, and `next.config.ts` pushes the
`@copylocker/unplugin/webpack` plugin into the **production client
compilation only** (`!dev && !isServer`). The plugin taps `afterEmit`,
digests the final bytes under `.next/`, injects the guard bootstrap into the
client entry chunks (webpack runtime, framework, main, main-app — the first
evaluated bootstrap wins, the rest no-op), and writes the signed manifest to
`.next/.copylocker/manifest.cbor`. At runtime the bootstrap publishes the
actually-computed Merkle root as `globalThis.__CL_GUARD_R__`, which
`lib/config.ts` wires into `CopyLocker.create({ integrity: { manifestRoot } })`.

Verify the built output (exits non-zero on any tampered byte):

```bash
npx copylocker-unplugin verify .next --pubkey <64-hex>   # pubkey printed by ensure-build-keys
```

### Why webpack and not Turbopack

Next 16 builds with Turbopack by default, and `@copylocker/unplugin` has no
Turbopack adapter: Turbopack's plugin surface is Rust-side, and its JS config
exposes loaders/rules but **no post-emit hook** the integrity pipeline could
tap. This was verified empirically — `npm run build:turbopack` (plain
`next build`) succeeds but its output carries no guard bootstrap and no
`.copylocker/` manifest. The Turbopack build remains useful for fast local
checks; the SDK then runs with the development fallback (no `R`, no
fail-closed flag), exactly like `next dev`. Only the webpack build carries
build integrity. This is a known limitation until a Turbopack adapter exists.

### Next-specific coverage notes

- `include: ['static/**']` — only `/_next/static` bytes are covered. The
  guard bootstrap fetches every listed chunk at boot, and `server/`
  compilation artifacts are not publicly served (they would 404 and derail
  `R`). The `urlBase: '/_next/'` option prefixes the runtime chunk URLs
  accordingly.
- `exclude: ['**/_ssgManifest.js']` — Next writes `_ssgManifest.js` AFTER the
  client compilation (page-optimization phase), so an `afterEmit` digest can
  never match it. It is a data manifest (`self.__SSG_MANIFEST`), not
  application code.
- Content-hashed chunk names are computed over the pre-injection bytes; the
  prelude backfill does not rename files. Cosmetic only — the manifest
  records real names and bytes (see the unplugin README).
- The webpack build prints `Critical dependency: the request of a dependency
  is an expression` warnings for `@copylocker/web`'s internal dynamic Worker
  construction. Benign here: the app always passes `workerFactory` with a
  runtime URL (`lib/config.ts`), so that code path never executes.

## SSR / hydration notes

- `app/page.tsx` is an async **server component**: it creates the
  `@copylocker/web/ssr` stub (`isSsrStub === true`, advisory state always
  `'unlicensed'`, zero side effects) and renders it — this demonstrates the
  isomorphic pattern from `packages/web` README §SSR (FR-WEB-009).
- `app/LabLoader.tsx` is a client component that loads `CopyLockerLab` via
  `next/dynamic` with `ssr: false` — the real SDK requires a browser (wasm,
  WebCrypto, IndexedDB), so it never participates in the server render.
  `CopyLocker.create()` runs inside `useEffect`, after hydration.
- Turbopack rewrites the package-internal `new Worker(new URL(...,
  import.meta.url))` Worker construction into a bootstrap that never starts,
  which would hang the SDK's INIT handshake. The app therefore passes a
  `workerFactory` (`lib/config.ts`) with a runtime URL; the Worker entry
  module graph is served statically from `public/copylocker-sdk/`, copied by
  `npm run copy-wasm` alongside the wasm/glue pair.
- The demo asset and the wasm/glue pair are static files under `public/`
  (`demo-asset.clx`, `copylocker-wasm/`), refreshed by `npm run seal-asset`
  / `npm run copy-wasm` (both wired into predev/prebuild/prestart). The
  demo `FinalKey` is a fixed placeholder, so without a genuinely activated
  session the unseal button exercises the error path — that failure, not
  the advisory state, is the entitlement signal.

## CSP

`proxy.ts` (the Next.js 16 successor of `middleware.ts`) sets a per-request
nonce-based policy, following the official Next.js CSP guide:

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval' 'nonce-<per-request>' 'strict-dynamic' ['unsafe-eval' in dev];
worker-src 'self';                       # session Worker (FR-WEB-008)
connect-src 'self' <NEXT_PUBLIC_CL_SERVER_URL> [ws: in dev];
img-src 'self' data:; style-src 'self' 'unsafe-inline';
object-src 'none'; base-uri 'self'
```

Two things to know:

- `'wasm-unsafe-eval'` is required for WASM instantiation (see
  `packages/web` README §CSP). The SDK itself uses no `eval`.
- Next.js only applies the nonce to its scripts during **server-side**
  rendering, so `app/page.tsx` sets `export const dynamic = 'force-dynamic'`
  — a statically prerendered page would ship scripts without nonces and
  hydration would be blocked by the policy.
- The injected guard prelude needs no CSP allowance: it is prepended to the
  entry-chunk FILES served from `/_next/static/chunks/` (`script-src
  'self'`), never an inline script, so it does not interact with the
  per-request nonce. Verified with the nonce policy active: the bootstrap
  runs, `__CL_GUARD_R__` resolves to the manifest root, and the browser
  reports zero CSP violations.

## E2E hooks

Stable `data-testid` selectors: `ssr-panel`, `ssr-is-stub`, `ssr-state`
(server-rendered stub output), `lab-loading`, `license-key-input`,
`activate-button`, `deactivate-button`, `license-state` (advisory),
`sdk-status` (`data-ready="true"` when the client is up),
`feature-id-input`, `unseal-button`, `unseal-output` (`data-kind` =
`ok` / `error` / `pending`), `status-log`, `server-url`, `product-id`.

## License

GPL-3.0-only.
