/**
 * Ensure the local development key material the `@copylocker/unplugin` build
 * needs exists under `.copylocker/` (gitignored, mode 0600):
 *
 * - `signing-key.json` — Ed25519 JWK for the local manifest signer
 *   (`copylocker-unplugin keygen`); its public key is auto-added to the
 *   injected `__CL_ROOT_PINS__`.
 * - `wrapping-key` — 32-byte KEK-registry wrapping key for `seal.assets`
 *   (64 hex chars; `COPYLOCKER_SEAL_WRAPPING_KEY` env wins when set).
 *
 * These are DEVELOPMENT keys for the example/E2E loop — a real project
 * generates them per build machine (or uses a remote signer) and never
 * commits them. Existing files are left untouched so repeated builds keep
 * the same identity.
 */

import { existsSync } from 'node:fs'
import { chmod, mkdir, writeFile } from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const exampleRoot = join(here, '..')
const keyDir = join(exampleRoot, '.copylocker')
const signingKey = join(keyDir, 'signing-key.json')
const wrappingKey = join(keyDir, 'wrapping-key')
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

if (!existsSync(wrappingKey)) {
  await writeFile(wrappingKey, `${randomBytes(32).toString('hex')}\n`, { mode: 0o600 })
  await chmod(wrappingKey, 0o600)
  console.log('wrote', wrappingKey, '(mode 0600)')
} else {
  console.log('wrapping key exists, keeping it:', wrappingKey)
}
