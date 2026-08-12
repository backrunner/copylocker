/**
 * Build-time error taxonomy for `@copylocker/seal`.
 *
 * The runtime (`@copylocker/web`) deliberately collapses every open failure
 * into a single `UnsealError` so probing reveals nothing. At build time —
 * and in the M4-A development bridge — we instead keep the two failure
 * classes the design requires operators to distinguish
 * (`60-instrumentation-guard.md` §4.3):
 *
 * - `CORRUPT`: structural failure — bad CBOR, truncated payload, invalid
 *   chunk layout. The file is damaged or was never a sealed asset.
 * - `NOT_ENTITLED`: the container is well-formed but the AEAD tag did not
 *   verify under the given key — wrong KEK/FinalKey, wrong feature, or a
 *   tampered ciphertext. Cryptographically these are indistinguishable, and
 *   all of them mean "this key is not entitled to this content".
 * - `CONFIG`: operator error — missing wrapping key, bad hex, unknown
 *   feature in the registry.
 * - `IO`: filesystem failure.
 */
export type SealErrorCode = 'CORRUPT' | 'NOT_ENTITLED' | 'CONFIG' | 'IO'

export class SealError extends Error {
  readonly code: SealErrorCode

  constructor(code: SealErrorCode, message: string) {
    super(message)
    this.name = 'SealError'
    this.code = code
  }
}

export function corrupt(message = 'CopyLocker seal: malformed sealed asset'): SealError {
  return new SealError('CORRUPT', message)
}

export function notEntitled(
  message = 'CopyLocker seal: key does not open this sealed asset',
): SealError {
  return new SealError('NOT_ENTITLED', message)
}

export function configError(message: string): SealError {
  return new SealError('CONFIG', message)
}

export function ioError(message: string): SealError {
  return new SealError('IO', message)
}
