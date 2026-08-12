# Generated wasm-bindgen glue

This directory holds the output of `npm run build:wasm`:

- `copylocker_wasm.js` / `copylocker_wasm.d.ts` — wasm-bindgen JS glue
- `copylocker_wasm_bg.wasm` — the compiled `copylocker-wasm` core

The artifacts are git-ignored and regenerated from
`crates/copylocker-wasm` with the `worker-release` profile (the workspace
`release` profile's `strip = "symbols"` removes the `target_features`
section wasm-bindgen needs). The wasm-bindgen CLI version must match the
`wasm-bindgen` crate version in the workspace `Cargo.lock`.

`npm run build` copies these files into `dist/wasm/`; the TypeScript layer
loads them at runtime relative to `dist/session.js`. `npm run check` and
`npm test` do NOT require these artifacts (tests inject a mock session).
