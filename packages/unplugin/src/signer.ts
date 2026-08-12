/**
 * Manifest signer abstraction (`50-unplugin-integrity.md §2.5, FR-BLD-003).
 *
 * Three branches:
 * - `local`  — Ed25519 key file (JWK JSON, mode 0600). Development-oriented:
 *   `NODE_ENV=production` makes it an error unless `allowLocalInProduction`
 *   is set (then it warns). The matching public key is auto-added to the
 *   injected `__CL_ROOT_PINS__`.
 * - `remote` — POST the raw tbs bytes to the endpoint with a bearer token;
 *   the response body must be the 64-byte Ed25519 signature. Errors are
 *   classified (`http` / `timeout` / `network` / `bad-response`). Pair with
 *   explicit `rootPins` so the runtime can verify provenance.
 * - custom   — `(tbs) => Promise<signature>`.
 *
 * The signed message is always `"copylocker/im-sig/v1" ‖ tbs` — exactly what
 * `@copylocker/guard`'s `verifyManifestSignature` checks. Local signing goes
 * through the guard package's own `signManifestTbs`, so the domain separator
 * cannot drift. Remote/custom signers receive the RAW tbs and must apply the
 * domain separator themselves (the CopyLocker signing service does).
 */

import { chmod, readFile, writeFile } from 'node:fs/promises'
import { signManifestTbs } from '@copylocker/guard'
import { ConfigError, type SignerConfig } from './config.js'

export type SignerErrorCode = 'http' | 'timeout' | 'network' | 'bad-response' | 'key'

export class SignerError extends Error {
  constructor(
    public readonly code: SignerErrorCode,
    message: string,
  ) {
    super(message)
    this.name = 'SignerError'
  }
}

export interface ResolvedSigner {
  /** Signature length in bytes — fixes the manifest container size upfront. */
  readonly signatureLength: number
  /** Public keys (raw 32-byte) proven by this signer, for root pins. */
  readonly publicKeys: Uint8Array[]
  sign(tbs: Uint8Array): Promise<Uint8Array>
}

export interface SignerEnvironment {
  env?: NodeJS.ProcessEnv
  warn?: (message: string) => void
  fetchImpl?: typeof fetch
}

const ED25519_SIGNATURE_BYTES = 64

function assertSignature(bytes: Uint8Array, origin: string): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== ED25519_SIGNATURE_BYTES) {
    throw new SignerError(
      'bad-response',
      `CopyLocker unplugin: ${origin} must produce a ${ED25519_SIGNATURE_BYTES}-byte Ed25519 signature, got ${bytes?.byteLength ?? 'n/a'}`,
    )
  }
  return bytes
}

interface Ed25519Jwk extends JsonWebKey {
  kty?: string
  crv?: string
  d?: string
  x?: string
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/')
  const bin = Buffer.from(padded, 'base64')
  return new Uint8Array(bin)
}

/** Load a local Ed25519 key file (JWK JSON written by {@link generateLocalKeyFile}). */
async function loadLocalKey(keyFile: string): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  let raw: string
  try {
    raw = await readFile(keyFile, 'utf8')
  } catch {
    throw new SignerError('key', `CopyLocker unplugin: cannot read signer key file ${keyFile}`)
  }
  let jwk: Ed25519Jwk
  try {
    jwk = JSON.parse(raw) as Ed25519Jwk
  } catch {
    throw new SignerError('key', `CopyLocker unplugin: signer key file ${keyFile} is not valid JSON`)
  }
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.d !== 'string' || typeof jwk.x !== 'string') {
    throw new SignerError(
      'key',
      `CopyLocker unplugin: signer key file ${keyFile} must be an Ed25519 JWK (kty OKP, crv Ed25519, with d and x)`,
    )
  }
  const privateKey = await globalThis.crypto.subtle.importKey(
    'jwk',
    { kty: 'OKP', crv: 'Ed25519', d: jwk.d, x: jwk.x, key_ops: ['sign'], ext: false },
    'Ed25519',
    false,
    ['sign'],
  )
  return { privateKey, publicKey: base64UrlDecode(jwk.x) }
}

/**
 * Generate a fresh Ed25519 key pair and write the private JWK to `keyFile`
 * (mode 0600). Returns the public key as hex (for `rootPins`).
 */
export async function generateLocalKeyFile(keyFile: string): Promise<string> {
  const pair = await globalThis.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const jwk = (await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey)) as Ed25519Jwk
  await writeFile(keyFile, `${JSON.stringify(jwk)}\n`, { mode: 0o600 })
  await chmod(keyFile, 0o600)
  const publicKey = base64UrlDecode(jwk.x as string)
  let hex = ''
  for (const byte of publicKey) hex += byte.toString(16).padStart(2, '0')
  return hex
}

/**
 * Resolve the configured signer. Returns `undefined` for an unsigned
 * development build (warned). May add public keys to `pins` (local signer).
 */
export async function resolveSigner(
  config: SignerConfig | undefined,
  pins: Uint8Array[],
  environment: SignerEnvironment = {},
): Promise<ResolvedSigner | undefined> {
  const env = environment.env ?? process.env
  const warn = environment.warn ?? ((message: string) => console.warn(message))

  if (config === undefined) {
    warn('CopyLocker unplugin: no signer configured — emitting an UNSIGNED development manifest')
    return undefined
  }

  if (typeof config === 'function') {
    return {
      signatureLength: ED25519_SIGNATURE_BYTES,
      publicKeys: [],
      sign: async (tbs) => assertSignature(await config(tbs), 'custom signer'),
    }
  }

  if (config.kind === 'local') {
    if (env.NODE_ENV === 'production') {
      if (!config.allowLocalInProduction) {
        throw new SignerError(
          'key',
          "CopyLocker unplugin: signer 'local' is forbidden when NODE_ENV=production " +
            '(set allowLocalInProduction: true to override, or use a remote signer)',
        )
      }
      warn("CopyLocker unplugin: signer 'local' used with NODE_ENV=production (allowLocalInProduction)")
    }
    const { privateKey, publicKey } = await loadLocalKey(config.keyFile)
    pins.push(publicKey)
    return {
      signatureLength: ED25519_SIGNATURE_BYTES,
      publicKeys: [publicKey],
      // The guard package's own signer — domain separator cannot drift.
      sign: (tbs) => signManifestTbs(tbs, privateKey),
    }
  }

  if (config.kind === 'remote') {
    if (!config.endpoint || !config.token) {
      throw new ConfigError('CopyLocker unplugin: remote signer needs endpoint and token')
    }
    const fetchImpl = environment.fetchImpl ?? globalThis.fetch
    if (!fetchImpl) throw new SignerError('network', 'CopyLocker unplugin: fetch is not available')
    const timeoutMs = config.timeoutMs ?? 10_000
    return {
      signatureLength: ED25519_SIGNATURE_BYTES,
      publicKeys: [],
      sign: async (tbs) => {
        let response: Response
        try {
          response = await fetchImpl(config.endpoint, {
            method: 'POST',
            headers: {
              authorization: `Bearer ${config.token}`,
              'content-type': 'application/octet-stream',
            },
            body: tbs.slice().buffer as ArrayBuffer,
            signal: AbortSignal.timeout(timeoutMs),
          })
        } catch (error) {
          const name = error instanceof Error ? error.name : ''
          if (name === 'TimeoutError' || name === 'AbortError') {
            throw new SignerError('timeout', `CopyLocker unplugin: signer endpoint timed out after ${timeoutMs}ms`)
          }
          throw new SignerError(
            'network',
            `CopyLocker unplugin: signer endpoint unreachable: ${error instanceof Error ? error.message : String(error)}`,
          )
        }
        if (!response.ok) {
          throw new SignerError('http', `CopyLocker unplugin: signer endpoint returned HTTP ${response.status}`)
        }
        const body = new Uint8Array(await response.arrayBuffer())
        return assertSignature(body, 'remote signer')
      },
    }
  }

  throw new ConfigError(`CopyLocker unplugin: unsupported signer kind '${String((config as { kind?: unknown }).kind)}'`)
}
