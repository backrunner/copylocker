# CopyLocker Vite SPA example

Minimal Vite + TypeScript single-page app demonstrating `@copylocker/web`
(M3 Web SDK): create (with Worker isolation), `activate()`, the advisory
state badge, `loadSealed()` / `unseal()` of a web v1 sealed asset, and
`deactivate()`.

## Run from scratch

```bash
npm install
npm run seal-asset   # writes public/demo-asset.clx (already committed)
npm run dev          # http://127.0.0.1:5173
```

The SDK talks to a CopyLocker Worker at `http://localhost:8787` by default —
the `wrangler dev` address of the `server-template/` project. Configuration
via environment (Vite `import.meta.env`):

| Variable | Default | Notes |
|---|---|---|
| `VITE_CL_SERVER_URL` | `http://localhost:8787` | CopyLocker Worker base URL |
| `VITE_CL_PRODUCT_ID` | `kat-product` | matches the CL-STD-1 KAT |
| `VITE_CL_ROOT_PIN` | CL-STD-1 KAT Root verifying key | hex; development fallback only |
| `VITE_CL_RELEASE_ID` | `dev` | release id the client reports |
| `VITE_CL_BUILD_FINGERPRINT` | `dev` | build fingerprint evidence |
| `VITE_CL_VARIANT_ID` | `0` | numeric variant id |
| `VITE_CL_SCHEDULER_INTERVAL_MS` | SDK default (60000) | scheduler tick interval |
| `VITE_CL_MIN_VALIDATION_INTERVAL_SECS` | core default (60) | minimum validation interval |

The development root pin is the public Root verifying key from the committed
CL-STD-1 KAT (`vectors/CL-STD-1/kat.json`), the same key the Tauri/Electron
examples embed. Without a running Worker, `CopyLocker.create()` still
succeeds (it is offline-tolerant), but `activate()` fails with a
`TransportError` and `unseal()` fails with `NotEntitledError` — both paths
are exercised by the UI.

## Sealed asset

`scripts/seal-asset.mjs` produces `public/demo-asset.clx` in the web v1
container (AES-256-GCM payload, CBOR layout — see `packages/web` README
"Sealed asset format") via the SDK's `sealAsset()` fixture helper. The demo
`FinalKey` is a fixed placeholder (`CL_DEMO_FINAL_KEY` to override); a real
unseal requires an activated session whose derived key matches, so against a
plain `wrangler dev` the unseal button demonstrates the error path.

## WASM assets

`scripts/copy-wasm.mjs` (wired into predev/prebuild/prepreview) copies the
wasm-bindgen glue + `.wasm` from `packages/web/dist/wasm/` into
`public/copylocker-wasm/`, and the app passes that URL as `glueBaseUrl`.
The SDK fetches the raw `.wasm` (its SHA-256 feeds the two-stage key
transform) and imports the glue at runtime; serving fixed copies keeps dev,
`vite preview`, and static hosting identical. Re-run after rebuilding
`packages/web`.

## CSP

`vite.config.ts` sets the recommended policy on both `dev` and `preview`
servers:

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';   # WASM instantiation needs this
worker-src 'self';                      # session Worker (FR-WEB-008)
connect-src 'self' <VITE_CL_SERVER_URL> ws://127.0.0.1:* ws://localhost:*;
img-src 'self' data:; style-src 'self'; object-src 'none'; base-uri 'self'
```

The SDK uses no `eval` and no inline scripts; the `ws:` entries exist only
for Vite's dev HMR socket.

## Build integrity (`@copylocker/unplugin`, M4-A)

`vite.config.ts` adds the CopyLocker plugin **last** (build-only; `vite dev`
is untouched). A production build:

- digests every covered output (`**/*.js` / `**/*.css` / `**/*.wasm` bundle
  files) into a **signed** integrity manifest (`dist/.copylocker/manifest.cbor`,
  local dev signer — `.copylocker/signing-key.json`, created by
  `scripts/ensure-build-keys.mjs` and gitignored; `allowLocalInProduction`
  is set because the E2E builds with `NODE_ENV=production`),
- prepends the guard bootstrap to the entry chunk: it publishes the build
  constants (`__CL_K_BUILD_<i>__` shards, `splitConstants: 4`), the expected
  root, and the **actually-computed** root as `__CL_GUARD_R__`
  (`guard.strategy: 'sync'` so the promise settles right after boot),
- injects `__CL_REQUIRE_INTEGRITY_PROOF__ = true`, so `@copylocker/web`
  fails key derivation closed when no guard root exists (bootstrap deleted)
  instead of falling back to the static constant,
- seals `sealed-assets/pro-demo.json` through the `@copylocker/seal` KEK
  registry (`.copylocker/seal-registry.json` + `wrapping-key`, both local and
  gitignored) into `dist/sealed-assets/pro-demo.json.sealed`. Runtime KEK
  wrapping is the M4-B server flow — this demonstrates the build-time half.

`src/main.ts` completes the loop with
`integrity: { manifestRoot: () => globalThis.__CL_GUARD_R__ }`: the
actually-computed `R` replaces the static constant in the `FinalKey`
derivation, so a one-byte tamper in any covered artifact makes sealed assets
fail to open. Verify a build with:

```bash
npx copylocker-unplugin verify dist --pubkey <signing key public hex>
```

Build prerequisite: the sibling packages must be built first
(`packages/guard`, `packages/seal`, `packages/unplugin`, `packages/web` —
`npm run build` in each; `packages/web-e2e/scripts/run-e2e.mjs` does this).

## E2E hooks

Stable `data-testid` selectors: `license-key-input`, `activate-button`,
`deactivate-button`, `license-state` (advisory), `state-dot`,
`sdk-status` (`data-ready="true"` when the client is up), `feature-id-input`,
`unseal-button`, `unseal-output` (`data-kind` = `ok` / `error` / `pending`),
`status-log`, `server-url`, `product-id`.

The page also exposes `window.__copylocker` (the live client plus the
`sealAsset` / `decodeSealedAsset` helpers) as a debug and E2E hook; the
Playwright suite in `packages/web-e2e` drives it to reseal an asset with the
activated session's derived `FinalKey`.

## License

GPL-3.0-only.
