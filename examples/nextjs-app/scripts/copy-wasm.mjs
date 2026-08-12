/**
 * Copy the wasm-bindgen glue + wasm bytes from `@copylocker/web` into
 * `public/copylocker-wasm/` so they are served at a stable URL in both dev
 * and production builds.
 *
 * Why: the SDK fetches the raw `.wasm` (its SHA-256 feeds the two-stage key
 * transform) and dynamically imports the glue from `glueBaseUrl`. The
 * package-internal default (`new URL('./wasm/', import.meta.url)`) resolves
 * inside `node_modules` — served by the Vite dev server via `/@fs/`, but not
 * reliably present in a bundled `dist/`. Serving fixed copies keeps dev,
 * `vite preview`, and any static host identical.
 *
 * Re-run after rebuilding `packages/web` (`npm run copy-wasm`, also wired
 * into predev/prebuild/prepreview).
 */

import { copyFile, mkdir } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const src = join(here, '..', '..', '..', 'packages', 'web', 'dist', 'wasm')
const dest = join(here, '..', 'public', 'copylocker-wasm')

await mkdir(dest, { recursive: true })
for (const file of ['copylocker_wasm.js', 'copylocker_wasm_bg.wasm']) {
  await copyFile(join(src, file), join(dest, file))
  console.log(`copied ${file} → public/copylocker-wasm/`)
}

// The session-Worker entry and its module graph, served statically.
// Turbopack rewrites `new Worker(new URL('./worker/entry.js', import.meta.url))`
// inside the package in a way that never starts the Worker (the SDK's create
// then hangs on the INIT handshake), so the app passes a `workerFactory`
// pointing at these copies with a runtime URL the bundler cannot rewrite.
const dist = join(here, '..', '..', '..', 'packages', 'web', 'dist')
const sdkDest = join(here, '..', 'public', 'copylocker-sdk')
await mkdir(join(sdkDest, 'worker'), { recursive: true })
for (const [from, to] of [
  ['worker/entry.js', 'worker/entry.js'],
  ['worker/protocol.js', 'worker/protocol.js'],
  ['errors.js', 'errors.js'],
  ['cbor.js', 'cbor.js'],
]) {
  await copyFile(join(dist, from), join(sdkDest, to))
  console.log(`copied ${from} → public/copylocker-sdk/${to}`)
}
