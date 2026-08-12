# @copylocker/console-e2e

Playwright E2E suite for the admin console (`apps/console`) against the **real**
local Worker backend — the M7 acceptance gate:

1. **Lifecycle** (`e2e/console.lifecycle.spec.ts`): issue a license through the
   console UI → activate a device through the real backend → view the machine
   in the console (per-license detail + cross-license directory) → revoke via
   the UI's two-step confirmation → prove enforcement (validation rejected).
2. **axe** (`e2e/console.a11y.spec.ts`): axe-core scan of the data-driven
   pages; zero critical/serious violations.
3. **Keyboard** (`e2e/console.keyboard.spec.ts`): the lifecycle's critical
   path is fully keyboard-operable; dialogs trap and restore focus.

## Hermetic operation

`npm run test:e2e` (`scripts/run-e2e.mjs`) does everything locally, no
external network:

- builds the Rust **device-helper** fixture (`device-helper/`, a real
  CL-STD-1 protocol client over `copylocker-client`, file-backed state);
- brings up the real Worker backend with the shared web-e2e harness
  (`packages/web-e2e/scripts/backend-up.mjs`);
- builds `apps/console` and serves it with `wrangler dev`, proxying
  `/admin-api` to the backend via the `API_UPSTREAM` platform var;
- runs Playwright, then tears everything down.

## Ports

Both ports are configurable (8787 is commonly taken by other local services):

| Variable              | Purpose              | Default |
| --------------------- | -------------------- | ------- |
| `CL_E2E_BACKEND_PORT` | backend wrangler dev | `8797`  |
| `CL_E2E_CONSOLE_PORT` | console wrangler dev | `4174`  |

## Prerequisites (built once by the repo's standard gates)

- `target/debug/copylocker` (`cargo build -p copylocker-cli`)
- `crates/copylocker-worker/build/worker/shim.mjs` (`npm test` in
  `crates/copylocker-worker`)
- `packages/web/dist/wasm/copylocker_wasm_bg.wasm` (`npm run build` in
  `packages/web`)
- Playwright browsers (`npx playwright install chromium`)

Artifacts are gitignored: `target/tmp/web-e2e/`, `target/tmp/console-e2e/`,
`output/playwright/`.
