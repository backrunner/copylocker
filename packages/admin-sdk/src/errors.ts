import type { ErrorEnvelope } from './types.js'

/**
 * Typed error for every non-2xx Admin API response.
 *
 * The worker answers errors with the envelope
 * `{ ok: false, error: { code, message } }`
 * (`response::api_error_no_store` in `crates/copylocker-worker/src/response.rs`);
 * `code` and `message` mirror that envelope, `status` is the HTTP status.
 */
export class AdminApiError extends Error {
  /** The worker's stable error code, e.g. `invalid_token`, `idempotency_conflict`. */
  readonly code: string
  /** The HTTP status code. */
  readonly status: number

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'AdminApiError'
    this.code = code
    this.status = status
  }

  /** Parse an error envelope from a response body of unknown shape. */
  static fromBody(status: number, body: unknown): AdminApiError {
    if (
      typeof body === 'object' &&
      body !== null &&
      'error' in body &&
      typeof (body as ErrorEnvelope).error === 'object' &&
      (body as ErrorEnvelope).error !== null
    ) {
      const { code, message } = (body as ErrorEnvelope).error
      if (typeof code === 'string' && typeof message === 'string') {
        return new AdminApiError(status, code, message)
      }
    }
    return new AdminApiError(
      status,
      'unexpected_response',
      `Admin API returned HTTP ${status} with an unrecognized error body`,
    )
  }
}
