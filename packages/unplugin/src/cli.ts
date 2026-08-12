#!/usr/bin/env node
/**
 * `copylocker-unplugin` CLI.
 *
 *   copylocker-unplugin verify <distDir> [--pubkey <hex>]...
 *   copylocker-unplugin keygen <keyFile>
 *
 * `verify` (FR-BLD-010) exits non-zero when any artifact digest, the Merkle
 * root, or the signature check fails — wire it into CI to catch publishing
 * accidents. `keygen` creates a local Ed25519 signer key file (mode 0600)
 * and prints the public key hex for `rootPins`.
 */

import { generateLocalKeyFile } from './signer.js'
import { formatVerifyResult, verifyDist } from './verify.js'
import { stat } from 'node:fs/promises'

function usage(): void {
  console.error(
    [
      'usage:',
      '  copylocker-unplugin verify <distDir> [--pubkey <64-hex>]...',
      '  copylocker-unplugin keygen <keyFile>',
    ].join('\n'),
  )
}

function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`invalid public key '${hex}' — expected 64 hex characters`)
  }
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv
  if (command === 'verify') {
    const distDir = rest[0]
    if (!distDir) {
      usage()
      return 2
    }
    const publicKeys: Uint8Array[] = []
    for (let i = 1; i < rest.length; i += 1) {
      if (rest[i] === '--pubkey' && rest[i + 1]) {
        publicKeys.push(fromHex(rest[i + 1] as string))
        i += 1
      } else {
        usage()
        return 2
      }
    }
    try {
      const result = await verifyDist({ distDir, publicKeys })
      console.log(formatVerifyResult(result))
      return result.ok ? 0 : 1
    } catch (error) {
      console.error(`copylocker-unplugin verify: ${error instanceof Error ? error.message : String(error)}`)
      return 1
    }
  }
  if (command === 'keygen') {
    const keyFile = rest[0]
    if (!keyFile) {
      usage()
      return 2
    }
    // Never silently overwrite an existing key: the old key is unrecoverable
    // and every build signed with it becomes unverifiable against the new pin.
    if (await stat(keyFile).catch(() => undefined)) {
      console.error(`copylocker-unplugin keygen: '${keyFile}' already exists — remove it first to rotate`)
      return 2
    }
    const publicHex = await generateLocalKeyFile(keyFile)
    console.log(`wrote ${keyFile} (mode 0600)`)
    console.log(`public key (rootPins): ${publicHex}`)
    return 0
  }
  usage()
  return 2
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code
  })
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 1
  })
