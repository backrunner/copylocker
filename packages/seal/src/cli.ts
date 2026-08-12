#!/usr/bin/env node
/**
 * `copylocker-seal` — build-time asset sealing CLI (M4-A).
 *
 * Commands:
 *   init                                  Create .copylocker/ + wrapping key (0600), gitignore both
 *   seal <glob...> --feature <id>         Seal assets under the feature KEK (dry-run without --out)
 *   registry list                         Show features and KEK fingerprints (never key bytes)
 *   derive-final-key --m <hex> ...        Dev bridge: reproduce the runtime FinalKey
 *   wrap-kek --feature <id> --final-key <hex>   Dev bridge: seal a KEK under a FinalKey
 *
 * Destructive defaults: nothing is written unless an explicit output is
 * given (`--out`). Key material is never printed.
 */

import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { realpathSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { decodeSealedAsset, sealBytes } from './container.js'
import { deriveFinalKey, sha256 } from './derive.js'
import { SealError, configError } from './errors.js'
import {
  DEFAULT_REGISTRY_DIR,
  DEFAULT_REGISTRY_FILE,
  DEFAULT_WRAPPING_KEY_FILE,
  WRAPPING_KEY_ENV,
  generateWrappingKey,
  getKek,
  getOrCreateKek,
  hexDecode,
  hexEncode,
  kekFingerprint,
  loadRegistry,
  resolveWrappingKey,
  saveRegistry,
} from './keystore.js'
import { sealAssets } from './seal.js'

const WRAPPED_KEK_ASSET_PREFIX = 'copylocker/kek/'

interface ParsedArgs {
  command: string | undefined
  positional: string[]
  flags: Map<string, string | true>
}

function parseArgs(argv: string[]): ParsedArgs {
  const [command, ...rest] = argv
  const positional: string[] = []
  const flags = new Map<string, string | true>()
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i] as string
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=')
      if (eq !== -1) {
        // Support the conventional --flag=value form; without this the value
        // is silently swallowed (e.g. `--out=sealed` degrades to a dry-run).
        flags.set(arg.slice(2, eq), arg.slice(eq + 1))
        continue
      }
      const name = arg.slice(2)
      const next = rest[i + 1]
      if (next !== undefined && !next.startsWith('--')) {
        flags.set(name, next)
        i += 1
      } else {
        flags.set(name, true)
      }
    } else {
      positional.push(arg)
    }
  }
  return { command, positional, flags }
}

function flag(args: ParsedArgs, name: string): string | undefined {
  const value = args.flags.get(name)
  return typeof value === 'string' ? value : undefined
}

function requireFlag(args: ParsedArgs, name: string): string {
  const value = flag(args, name)
  if (!value) throw configError(`CopyLocker seal: --${name} is required`)
  return value
}

function registryPath(args: ParsedArgs): string {
  return flag(args, 'registry') ?? join(DEFAULT_REGISTRY_DIR, DEFAULT_REGISTRY_FILE)
}

function keyFilePath(args: ParsedArgs): string {
  return flag(args, 'key-file') ?? join(DEFAULT_REGISTRY_DIR, DEFAULT_WRAPPING_KEY_FILE)
}

async function cliWrappingKey(args: ParsedArgs): Promise<Uint8Array> {
  return resolveWrappingKey({ keyFile: keyFilePath(args) })
}

function out(message: string): void {
  process.stdout.write(`${message}\n`)
}

async function cmdInit(args: ParsedArgs): Promise<void> {
  const dir = flag(args, 'dir') ?? DEFAULT_REGISTRY_DIR
  await mkdir(dir, { recursive: true })
  await chmod(dir, 0o700).catch(() => {})

  const keyFile = join(dir, DEFAULT_WRAPPING_KEY_FILE)
  let created = false
  try {
    await readFile(keyFile)
  } catch {
    await writeFile(keyFile, hexEncode(generateWrappingKey()), { mode: 0o600 })
    await chmod(keyFile, 0o600)
    created = true
  }

  // Ensure the registry and wrapping key can never be committed. The entries
  // follow the ACTUAL --dir, not the default — gitignoring `.copylocker/`
  // while the key lives in a custom dir would leave it commit-able.
  const posixDir = dir.replace(/\\/g, '/').replace(/\/+$/, '')
  const gitignoreLines = [
    `${posixDir}/${DEFAULT_REGISTRY_FILE}`,
    `${posixDir}/${DEFAULT_WRAPPING_KEY_FILE}`,
  ]
  const gitignore = '.gitignore'
  let existing = ''
  try {
    existing = await readFile(gitignore, 'utf8')
  } catch {
    /* no .gitignore yet */
  }
  const missing = gitignoreLines.filter(
    (line) => !existing.split('\n').some((l) => l.trim() === line),
  )
  if (missing.length > 0) {
    const prefix = existing.length > 0 && !existing.endsWith('\n') ? '\n' : ''
    await writeFile(
      gitignore,
      `${existing}${prefix}\n# CopyLocker seal — NEVER commit key material\n${missing.join('\n')}\n`,
    )
  }

  out(`CopyLocker seal initialized in ${dir}/`)
  out(created ? `  wrapping key created: ${keyFile} (mode 0600)` : `  wrapping key already exists: ${keyFile}`)
  out(missing.length > 0 ? `  .gitignore updated (${missing.length} entries)` : '  .gitignore already covers key material')
  out('')
  out('Red lines: the registry and wrapping key are encrypted/local-only artifacts.')
  out('Never commit them, never copy them into CI artifacts, never print them.')
}

async function cmdSeal(args: ParsedArgs): Promise<void> {
  const featureId = requireFlag(args, 'feature')
  const productId = flag(args, 'product-id') ?? process.env.COPYLOCKER_PRODUCT_ID
  if (!productId) {
    throw configError('CopyLocker seal: --product-id is required (or set COPYLOCKER_PRODUCT_ID)')
  }
  if (args.positional.length === 0) {
    throw configError('CopyLocker seal: at least one glob is required')
  }
  const variantId = Number(flag(args, 'variant-id') ?? '0')
  if (!Number.isSafeInteger(variantId) || variantId < 0) {
    throw configError('CopyLocker seal: --variant-id must be a non-negative integer')
  }
  const outDir = flag(args, 'out')
  const chunkSize = flag(args, 'chunk-size') ? Number(flag(args, 'chunk-size')) : undefined
  if (chunkSize !== undefined && (!Number.isSafeInteger(chunkSize) || chunkSize < 0)) {
    throw configError('CopyLocker seal: --chunk-size must be a non-negative integer')
  }

  const wrappingKey = await cliWrappingKey(args)
  const registryFile = registryPath(args)
  const registry = await loadRegistry({ path: registryFile, wrappingKey })
  const { kek, created } = getOrCreateKek(registry, featureId)

  // Persist a newly created KEK BEFORE sealing (and even in dry-run so repeat
  // runs are stable): outputs encrypted under a KEK whose registry save later
  // failed would be permanently unopenable. The registry file is encrypted,
  // mode 0600, and gitignored.
  if (created) {
    await saveRegistry({ path: registryFile, wrappingKey, registry })
  }

  const results = await sealAssets({
    cwd: process.cwd(),
    globs: args.positional,
    featureId,
    productId,
    variantId,
    kek,
    outDir,
    chunkSize,
  })

  const fingerprint = await kekFingerprint(kek)
  const mode = outDir ? `sealing into ${outDir}/` : 'dry-run (pass --out <dir> to write)'
  out(`copylocker-seal: ${mode}`)
  out(`  feature: ${featureId}  (KEK fingerprint ${fingerprint}${created ? ', newly created' : ''})`)
  if (results.length === 0) out('  no files matched')
  for (const result of results) {
    const chunked = result.chunking
      ? `, chunked ${result.chunking.chunkCount}×${result.chunking.chunkSize}`
      : ''
    out(
      `  ${result.source} → ${result.output}  (${result.plaintextBytes} → ${result.sealedBytes} bytes${chunked})`,
    )
  }

  // The KEK was already persisted above (before any output was written).
  if (created) {
    out(`  registry updated: ${registryFile}`)
  }
}

async function cmdRegistryList(args: ParsedArgs): Promise<void> {
  const wrappingKey = await cliWrappingKey(args)
  const registry = await loadRegistry({ path: registryPath(args), wrappingKey })
  const features = Object.keys(registry.features).sort()
  if (features.length === 0) {
    out('copylocker-seal registry: empty')
    return
  }
  out('copylocker-seal registry (key bytes are never shown):')
  for (const feature of features) {
    const entry = registry.features[feature]
    if (!entry) continue
    const fingerprint = await kekFingerprint(hexDecode(entry.kek, 'registry KEK'))
    out(`  ${feature}  kek-sha256:${fingerprint}…  created ${entry.createdAt}`)
  }
}

async function cmdDeriveFinalKey(args: ParsedArgs): Promise<void> {
  const m = hexDecode(requireFlag(args, 'm'), '--m')
  const kBuild = flag(args, 'k-build')
  const manifestRoot = flag(args, 'manifest-root')
  const wasmDigestFlag = flag(args, 'wasm-digest')
  const wasmPath = flag(args, 'wasm')
  if (!wasmDigestFlag && !wasmPath) {
    throw configError('CopyLocker seal: --wasm-digest <hex> or --wasm <path> is required')
  }
  const wasmDigest = wasmDigestFlag
    ? hexDecode(wasmDigestFlag, '--wasm-digest')
    : await sha256([new Uint8Array(await readFile(resolve(wasmPath as string)))])
  const finalKey = await deriveFinalKey({
    m,
    kBuild: kBuild ? hexDecode(kBuild, '--k-build') : undefined,
    manifestRoot: manifestRoot ? hexDecode(manifestRoot, '--manifest-root') : undefined,
    wasmDigest,
  })
  out(hexEncode(finalKey))
}

async function cmdWrapKek(args: ParsedArgs): Promise<void> {
  const featureId = requireFlag(args, 'feature')
  const productId = flag(args, 'product-id') ?? process.env.COPYLOCKER_PRODUCT_ID
  if (!productId) {
    throw configError('CopyLocker seal: --product-id is required (or set COPYLOCKER_PRODUCT_ID)')
  }
  const finalKey = hexDecode(requireFlag(args, 'final-key'), '--final-key')
  const variantId = Number(flag(args, 'variant-id') ?? '0')

  const wrappingKey = await cliWrappingKey(args)
  const registry = await loadRegistry({ path: registryPath(args), wrappingKey })
  const kek = getKek(registry, featureId)
  if (!kek) {
    throw configError(
      `CopyLocker seal: no KEK registered for feature "${featureId}" — seal an asset first`,
    )
  }

  const meta = {
    productId,
    variantId,
    featureId,
    assetId: `${WRAPPED_KEK_ASSET_PREFIX}${featureId}`,
  }
  const wrapped = await sealBytes(finalKey, meta, kek)
  const header = decodeSealedAsset(wrapped)
  const fingerprint = await kekFingerprint(kek)

  const outFile = flag(args, 'out')
  if (!outFile) {
    out('copylocker-seal wrap-kek: dry-run (pass --out <path> to write)')
    out(`  feature: ${featureId}  (KEK fingerprint ${fingerprint})`)
    out(`  wrapped container: ${wrapped.byteLength} bytes, assetId ${header.assetId}`)
    out('  runtime bridge: cl.unseal(feature, wrapped) → KEK, then openSealedAsset(KEK, asset)')
    return
  }
  await writeFile(resolve(outFile), wrapped, { mode: 0o600 })
  out(`wrote ${outFile} (${wrapped.byteLength} bytes, mode 0600)`)
}

const USAGE = `copylocker-seal — CopyLocker build-time asset sealing (M4-A dev bridge)

Usage:
  copylocker-seal init [--dir .copylocker]
  copylocker-seal seal <glob...> --feature <id> --product-id <id>
                       [--variant-id <n>] [--chunk-size <bytes>] [--out <dir>]
  copylocker-seal registry list
  copylocker-seal derive-final-key --m <hex> [--k-build <hex>]
                       [--manifest-root <hex>] (--wasm-digest <hex> | --wasm <path>)
  copylocker-seal wrap-kek --feature <id> --product-id <id> --final-key <hex> [--out <path>]

Common flags: --registry <path>  --key-file <path>
Wrapping key: $${WRAPPING_KEY_ENV} (64 hex) or ${DEFAULT_REGISTRY_DIR}/${DEFAULT_WRAPPING_KEY_FILE}

All commands are dry-run unless an explicit output (--out) is given.
Key material is never printed; registries are encrypted and mode 0600.
`

export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv)
  try {
    switch (args.command) {
      case 'init':
        await cmdInit(args)
        return 0
      case 'seal':
        await cmdSeal(args)
        return 0
      case 'registry':
        if (args.positional[0] !== 'list') throw configError('CopyLocker seal: only "registry list" exists')
        await cmdRegistryList(args)
        return 0
      case 'derive-final-key':
        await cmdDeriveFinalKey(args)
        return 0
      case 'wrap-kek':
        await cmdWrapKek(args)
        return 0
      case undefined:
      case 'help':
      case '--help':
        out(USAGE)
        return args.command === undefined ? 1 : 0
      default:
        throw configError(`CopyLocker seal: unknown command "${args.command}"`)
    }
  } catch (error) {
    if (error instanceof SealError) {
      process.stderr.write(`${error.message} [${error.code}]\n`)
      return 2
    }
    throw error
  }
}

// CLI entry point (guarded so tests can import main() without side effects).
// Node realpaths the main module by default, so an npm-installed (symlinked)
// bin arrives with a symlinked argv[1] but a realpath'd import.meta.url —
// compare realpaths on both sides or the CLI silently no-ops.
const invokedAs = process.argv[1] ? realpathSync(resolve(process.argv[1])) : ''
if (invokedAs && import.meta.url === pathToFileURL(invokedAs).href) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code
    },
    (error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
      process.exitCode = 1
    },
  )
}
