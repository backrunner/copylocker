#!/usr/bin/env node
/**
 * Build the copylocker-wasm core and generate the wasm-bindgen glue into
 * `packages/web/src/wasm/`.
 *
 * Two deliberate choices:
 *
 * 1. The cargo build uses the `worker-release` profile. The workspace
 *    `release` profile sets `strip = "symbols"`, which removes the wasm
 *    `target_features` section that wasm-bindgen needs; `worker-release`
 *    (`strip = "debuginfo"`) preserves it.
 *
 * 2. The wasm-bindgen CLI version MUST equal the `wasm-bindgen` crate version
 *    in Cargo.lock (the glue and the runtime library are version-locked).
 *    The script reads the required version from Cargo.lock instead of
 *    hardcoding it.
 */
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const pkgDir = dirname(dirname(fileURLToPath(import.meta.url)))
const root = dirname(dirname(pkgDir))
const outDir = join(pkgDir, 'src', 'wasm')

function fail(message) {
  console.error(`build:wasm: ${message}`)
  process.exit(1)
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: 'inherit', cwd: root, ...options })
  if (result.error) return result
  if (result.status !== 0) fail(`\`${command} ${args.join(' ')}\` exited with ${result.status}`)
  return result
}

// --- 1. required wasm-bindgen CLI version, from Cargo.lock -----------------

const lock = readFileSync(join(root, 'Cargo.lock'), 'utf8')
const match = lock.match(/name = "wasm-bindgen"\nversion = "([^"]+)"/)
if (!match) fail('could not find the wasm-bindgen version in Cargo.lock')
const requiredVersion = match[1]

// --- 2. wasm32 target --------------------------------------------------------

let targets
try {
  targets = execFileSync('rustup', ['target', 'list', '--installed'], { encoding: 'utf8' })
} catch {
  fail('rustup is not available; install the wasm32-unknown-unknown target first')
}
if (!targets.split('\n').includes('wasm32-unknown-unknown')) {
  fail(
    'the wasm32-unknown-unknown target is not installed.\n' +
      'Install it with: rustup target add wasm32-unknown-unknown',
  )
}

// --- 3. cargo build ----------------------------------------------------------

console.log(`build:wasm: cargo build (worker-release, wasm32-unknown-unknown)`)
run('cargo', [
  'build',
  '--profile',
  'worker-release',
  '--target',
  'wasm32-unknown-unknown',
  '-p',
  'copylocker-wasm',
])

const wasmFile = join(
  root,
  'target',
  'wasm32-unknown-unknown',
  'worker-release',
  'copylocker_wasm.wasm',
)
if (!existsSync(wasmFile)) fail(`expected artifact missing: ${wasmFile}`)

// --- 4. wasm-bindgen glue ------------------------------------------------------

function cliVersion(command, args) {
  const result = spawnSync(command, [...args, '--version'], { encoding: 'utf8' })
  if (result.error || result.status !== 0) return null
  const found = /wasm-bindgen (\S+)/.exec(result.stdout ?? '')
  return found ? found[1] : null
}

mkdirSync(outDir, { recursive: true })
const glueArgs = ['--target', 'web', '--out-dir', outDir, wasmFile]

const candidates = []
if (process.env.WASM_BINDGEN) candidates.push([process.env.WASM_BINDGEN, []])
candidates.push(['wasm-bindgen', []])
// The npm package only exists on registries that mirror it; keep the attempt
// but never let it fail silently.
candidates.push(['npx', ['--yes', `wasm-bindgen-cli@${requiredVersion}`]])

for (const [command, prefix] of candidates) {
  const version = cliVersion(command, prefix)
  if (version === null) continue
  if (version !== requiredVersion) {
    console.error(
      `build:wasm: ignoring ${command} ${prefix.join(' ')} — version ${version} ` +
        `!= Cargo.lock ${requiredVersion}`,
    )
    continue
  }
  console.log(`build:wasm: wasm-bindgen ${version} (${command} ${prefix.join(' ')})`)
  run(command, [...prefix, ...glueArgs])
  console.log(`build:wasm: glue written to ${outDir}`)
  process.exit(0)
}

fail(
  `no wasm-bindgen CLI at version ${requiredVersion} found.\n` +
    `Install it with one of:\n` +
    `  cargo install wasm-bindgen-cli --version ${requiredVersion} --locked\n` +
    `  npx --yes wasm-bindgen-cli@${requiredVersion}  (if your registry mirrors it)\n` +
    `or point WASM_BINDGEN at a matching binary.`,
)
