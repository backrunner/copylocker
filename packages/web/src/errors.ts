/**
 * Typed errors for the numeric wasm error contract (NFR-SEC-011).
 *
 * The wasm core surfaces failures as bare numbers. This module maps them onto
 * a small set of typed errors whose messages deliberately carry no internal
 * detail — nothing greppable about the licensing internals leaks to the page.
 */

/** Broad category of a failure, safe to branch UI on. */
export type ErrorKind =
  | 'malformed'
  | 'config'
  | 'entropy'
  | 'lifecycle'
  | 'not-entitled'
  | 'fatal'
  | 'unknown'

/** Stable numeric codes, mirroring `crates/copylocker-wasm/src/codes.rs`. */
export const ERR_MALFORMED = 1
export const ERR_UNKNOWN_OP = 2
export const ERR_BAD_FIELD = 3
export const ERR_BAD_CONFIG = 4
export const ERR_ENTROPY = 5
export const ERR_NO_DEVICE_KEYS = 10
export const ERR_ALREADY_ACTIVATED = 11
export const ERR_NO_CREDENTIAL = 12
export const ERR_NOT_ENTITLED = 13
export const ERR_NO_CHAIN = 14
export const ERR_NO_PENDING = 15
export const ERR_BAD_SNAPSHOT = 16
export const ERR_DERIVATION = 17
export const ERR_BAD_STATE = 18

const MESSAGES: Record<ErrorKind, string> = {
  malformed: 'CopyLocker: malformed data',
  config: 'CopyLocker: invalid configuration',
  entropy: 'CopyLocker: secure randomness unavailable',
  lifecycle: 'CopyLocker: operation not valid in the current lifecycle phase',
  'not-entitled': 'CopyLocker: feature not available',
  fatal: 'CopyLocker: license verification failed',
  unknown: 'CopyLocker: unknown failure',
}

export class CopyLockerError extends Error {
  readonly code: number
  readonly kind: ErrorKind

  constructor(code: number, kind: ErrorKind) {
    super(MESSAGES[kind])
    this.name = 'CopyLockerError'
    this.code = code
    this.kind = kind
  }
}

export class MalformedError extends CopyLockerError {
  constructor(code: number) {
    super(code, 'malformed')
    this.name = 'MalformedError'
  }
}

export class ConfigError extends CopyLockerError {
  constructor(code: number) {
    super(code, 'config')
    this.name = 'ConfigError'
  }
}

export class EntropyError extends CopyLockerError {
  constructor(code: number) {
    super(code, 'entropy')
    this.name = 'EntropyError'
  }
}

export class LifecycleError extends CopyLockerError {
  constructor(code: number) {
    super(code, 'lifecycle')
    this.name = 'LifecycleError'
  }
}

/**
 * The feature is not entitled, or the state forbids derivation — deliberately
 * one indistinguishable failure so probing reveals nothing about the license.
 */
export class NotEntitledError extends CopyLockerError {
  constructor(code: number) {
    super(code, 'not-entitled')
    this.name = 'NotEntitledError'
  }
}

/** Fail-closed verification failure (codes >= 100). Local material is wiped. */
export class FatalLicenseError extends CopyLockerError {
  constructor(code: number) {
    super(code, 'fatal')
    this.name = 'FatalLicenseError'
  }
}

function kindOf(code: number): ErrorKind {
  if (code >= 100) return 'fatal'
  switch (code) {
    case ERR_MALFORMED:
    case ERR_UNKNOWN_OP:
    case ERR_BAD_FIELD:
    case ERR_BAD_SNAPSHOT:
      return 'malformed'
    case ERR_BAD_CONFIG:
      return 'config'
    case ERR_ENTROPY:
      return 'entropy'
    case ERR_NOT_ENTITLED:
    case ERR_DERIVATION:
      return 'not-entitled'
    case ERR_NO_DEVICE_KEYS:
    case ERR_ALREADY_ACTIVATED:
    case ERR_NO_CREDENTIAL:
    case ERR_NO_CHAIN:
    case ERR_NO_PENDING:
    case ERR_BAD_STATE:
      return 'lifecycle'
    default:
      return 'unknown'
  }
}

/** Map a numeric wasm error code onto a typed error. */
export function errorFromCode(code: number): CopyLockerError {
  switch (kindOf(code)) {
    case 'malformed':
      return new MalformedError(code)
    case 'config':
      return new ConfigError(code)
    case 'entropy':
      return new EntropyError(code)
    case 'lifecycle':
      return new LifecycleError(code)
    case 'not-entitled':
      return new NotEntitledError(code)
    case 'fatal':
      return new FatalLicenseError(code)
    default:
      return new CopyLockerError(code, 'unknown')
  }
}

/** True when the thrown value looks like a wasm numeric error code. */
export function isErrorCode(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 && value <= 0xffff
}
