#!/usr/bin/env node
/**
 * Copy the generated wasm-bindgen glue from `src/wasm/` into `dist/wasm/`
 * after `tsc`. A no-op when the glue has not been generated yet, so
 * `npm run build` works on checkouts where `build:wasm` has never run.
 */
import { copyFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const pkgDir = dirname(dirname(fileURLToPath(import.meta.url)))
const src = join(pkgDir, 'src', 'wasm')
const dest = join(pkgDir, 'dist', 'wasm')

if (!existsSync(src)) process.exit(0)
const artifacts = readdirSync(src).filter((name) => /\.(js|ts|wasm)$/.test(name))
if (artifacts.length === 0) process.exit(0)
mkdirSync(dest, { recursive: true })
for (const name of artifacts) {
  copyFileSync(join(src, name), join(dest, name))
}
console.log(`copy-wasm: ${artifacts.length} artifact(s) copied to dist/wasm/`)
