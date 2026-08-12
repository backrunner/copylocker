/**
 * Ensure the local development signing key the `@copylocker/unplugin` build
 * needs exists under `.copylocker/` (gitignored, mode 0600):
 *
 * - `signing-key.json` — Ed25519 JWK for the local manifest signer
 *   (`copylocker-unplugin keygen`); its public key is auto-added to the
 *   injected `__CL_ROOT_PINS__`.
 *
 * Unlike the vite-spa example no KEK wrapping key is needed: this example's
 * demo asset is pre-sealed by `scripts/seal-asset.mjs`, not through the
 * unplugin's `seal.assets`.
 *
 * This is a DEVELOPMENT key for the example/E2E loop — a real project
 * generates it per build machine (or uses a remote signer) and never commits
 * it. An existing file is left untouched so repeated builds keep the same
 * identity.
 */

import { existsSync } from 'node:fs'
import { mkdir } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const exampleRoot = join(here, '..')
const keyDir = join(exampleRoot, '.copylocker')
const signingKey = join(keyDir, 'signing-key.json')
const unpluginCli = join(exampleRoot, 'node_modules', '@copylocker', 'unplugin', 'dist', 'cli.js')

await mkdir(keyDir, { recursive: true })

if (!existsSync(signingKey)) {
  if (!existsSync(unpluginCli)) {
    throw new Error(
      '@copylocker/unplugin dist not found — build the sibling packages first ' +
        '(packages/guard, packages/seal, packages/unplugin: `npm run build`)',
    )
  }
  const result = spawnSync(process.execPath, [unpluginCli, 'keygen', signingKey], {
    encoding: 'utf8',
  })
  if (result.status !== 0) {
    throw new Error(`copylocker-unplugin keygen failed: ${result.stderr || result.stdout}`)
  }
  process.stdout.write(result.stdout)
} else {
  console.log('signing key exists, keeping it:', signingKey)
}
