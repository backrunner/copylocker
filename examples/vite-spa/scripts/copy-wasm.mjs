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
