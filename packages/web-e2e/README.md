# @copylocker/web-e2e

Playwright E2E suite for the M3 Web SDK (`@copylocker/web`), driving the
`examples/vite-spa` and `examples/nextjs-app` apps in a real Chromium, with an
optional **real backend**: the prebuilt CopyLocker Worker under `wrangler dev`
(D1 + Durable Objects + KV + Queues), provisioned through the real CLI and
Admin API.

## Run

```bash
npm install
npx playwright install chromium firefox webkit   # once; installs into the user cache
npm run test:e2e                  # full run (backend attempted)
CL_E2E_BACKEND=0 npm run test:e2e # deterministic no-backend tier only
npm run test:e2e -- --grep attack # extra args are forwarded to playwright
```

Firefox and WebKit are required: the default run executes the multi-engine
R-consistency spec on all three engines (Chromium runs the whole suite; the
`vite-spa-firefox` / `vite-spa-webkit` projects match only that one spec, so
the full scenario matrix is not tripled). The LCP spec is Chromium-only —
`largest-contentful-paint` is a Chromium-only PerformanceObserver entry type.

`npm run test:e2e` (`scripts/run-e2e.mjs`) does, in order:

1. `npm run build` in `packages/web` (tsc + wasm glue copy), then
   `packages/guard`, `packages/seal`, `packages/unplugin` — the vite-spa
   build loads the M4-A plugin and its sibling dists.
2. `scripts/backend-up.mjs --serve` — the local backend chain below. On any
   failure it records the reason and the backend-dependent specs **skip
   explicitly**; the no-backend and attack tiers still run.
3. `npm run build` in `examples/vite-spa` with `VITE_CL_*` env matching the
   backend (server URL, product, freshly generated Root pin, fast scheduler
   cadence). `examples/nextjs-app` is rebuilt only when `.next` is missing or
   older than its inputs (the `@copylocker/web`/`@copylocker/unplugin` dists
   and the example's own `app/`, `lib/`, `next.config.ts`, `proxy.ts`).
4. `playwright test` — serial (`workers: 1`), traces/videos retained on
   failure only, artifacts under `output/playwright/` (gitignored).

## The backend chain (`scripts/backend-up.mjs`)

Everything runs on `127.0.0.1`; nothing leaves the machine.

1. `copylocker keygen root` / `keygen epoch` — real CL-STD-1 key material;
   the client's `rootPins` is the freshly generated Root verifying key.
2. `copylocker bootstrap prepare` — the Admin credential bundle.
   `bootstrap apply` is `--remote`-only by design, so its D1 seed SQL
   (vendor / product / `admin_tokens` HMAC) is replicated against
   `wrangler d1 execute --local`.
3. `wrangler dev` serves the **prebuilt** worker bundle
   (`crates/copylocker-worker/build/`) with a generated config:
   `ENVIRONMENT=test` switches secret loading from the (remote-only) Secrets
   Store to plain `TEST_*` vars — the same seam the worker's own vitest
   suite uses. D1 migrations are applied with `--local`.
4. Catalog, policy, and the epoch certificate go through the **real Admin
   API**: `catalog push`, `policy create --preset perpetual` + `policy push`,
   `epoch upload` (which also publishes the `/v1/keys` keyset to KV). The
   policy's `refresh_after_sec` is then shortened to 30 s so the
   offline→online revalidation scenario fits inside a test.
5. Release administration is post-M1 (no Admin endpoints), so the `releases`
   and `release_feature_keks` rows are seeded directly. The at-rest blobs are
   encrypted by `seed-helper/` (a tiny standalone Rust crate) with exactly
   the AAD maps `crates/copylocker-worker/src/bindings/authorization.rs`
   opens them with.
6. `copylocker license issue` — the plaintext key exists only in
   `target/tmp/web-e2e/backend.json` (gitignored) and stdout.

For manual debugging: `npm run backend:up` keeps the backend alive;
`npm run backend:down` stops it. Wrangler logs land in
`output/playwright/wrangler-dev.log`.

## Specs

| File | Tier | Covers |
|---|---|---|
| `e2e/vite-spa.nobackend.spec.ts` | deterministic | offline create, unlicensed unseal → `NotEntitledError`, activate without a server → `TransportError` after retries, strict-CSP load (wasm compile + Worker isolation) |
| `e2e/vite-spa.attacks.spec.ts` | deterministic | stub/forged wasm swap → init fails closed, sealed-container header tamper/truncation → `UnsealError`, `Function.prototype.toString` override → no effect |
| `e2e/vite-spa.backend.spec.ts` | real backend | full journey: activate → in-page reseal → unseal ok → reload persistence → offline unseal → reconnect → automatic `/v1/validate` within 60 s; AEAD payload tamper → `UnsealError`; IndexedDB wipe → back to unlicensed |
| `e2e/vite-spa.m4-integrity.spec.ts` | mixed | M4-A acceptance: guard contract published (`__CL_GUARD_R__` == expected root, sharded K_BUILD, `__CL_REQUIRE_INTEGRITY_PROOF__`); `copylocker-unplugin verify` exits 0 on clean dist / non-zero on tampered; with the real backend: untampered control unseal ok, deleted guard bootstrap → derivation fails closed, one-byte chunk tamper → `UnsealError` |
| `e2e/vite-spa.r-consistency.spec.ts` | deterministic, **chromium + firefox + webkit** | M4 multi-engine acceptance (no false positives): the same build's actually-computed root `R`, the guarded `e2e.probe` body digest, and the isolated GuardState mix equal the signed manifest's build-time values on every engine, plus byte-for-byte cross-engine comparison via `output/playwright/r-consistency/<browser>.json` (wiped by global setup); engine `toString` differences absorbed by `normalizeSource` are attached as findings, not failures |
| `e2e/vite-spa.lcp.spec.ts` | deterministic, chromium-only | NFR-PERF-006: guard bootstrap LCP impact < 20 ms, measured against a real control build (`CL_E2E_DISABLE_COPYLOCKER=1`, served from `target/tmp/web-e2e/control-dist` on port 4174); median of 5 iterations per group, distributions attached |
| `e2e/nextjs.smoke.spec.ts` | deterministic | SSR renders the `@copylocker/web/ssr` stub (`unlicensed`); hydration boots the real SDK under the nonce CSP |

The in-page reseal (journey step 3) uses the `window.__copylocker` debug hook
exposed by `examples/vite-spa/src/main.ts`: it derives `M` from the live
session (op 9), completes the two-stage transform
(`SHA-256(M ‖ K_BUILD ‖ MANIFEST_ROOT ‖ H(wasmBytes))`) with page crypto, and
calls the SDK's exported `sealAsset()` — so no pre-baked asset is needed and
the unseal path is exercised end to end.

## Toolchain notes

- The worker bundle and the web wasm are rebuilt only when their sources
  change. Rebuilding needs the `worker-release` cargo profile, the
  `wasm32-unknown-unknown` target, `worker-build@0.8.5`, and a `wasm-bindgen`
  CLI matching the workspace `Cargo.lock` — local installs under
  `target/tmp/` (e.g. `cargo install --root target/tmp/worker-build
  worker-build@0.8.5`) are enough; nothing global is required. On machines
  where Homebrew's plain Rust shadows rustup, put the rustup toolchain bin
  directory first in `PATH`.
- `target/tmp/web-e2e/` holds all generated key material and Wrangler state;
  it is wiped on every bring-up. It is a **test fixture root**, never
  production material.

## License

GPL-3.0-only.
