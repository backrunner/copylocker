/**
 * Consent gating for T1 telemetry (`privacy-and-legal-pack.md` §5).
 *
 * The vendor supplies a {@link ConsentProvider} — typically a synchronous
 * read of the app's consent store. The hook calls it **before every report**,
 * so a withdrawal stops the very next upload. The provider returns the
 * privacy-notice version the user agreed to; that version travels as
 * `consent_version` (key 0) and becomes the vendor's compliance evidence.
 *
 * `consent_version = 0` means "no valid consent": the hook produces no block
 * at all (it does not even emit a zeroed block — the server counts zero-
 * consent blocks as SDK integration errors).
 */

/** Returns the consented privacy-notice version; 0 (or any falsy value) means no consent. */
export type ConsentProvider = () => number

/**
 * Read the current consent version, fail-safe: a provider that throws or
 * returns garbage (NaN, negative, non-integer) is treated as **no consent**.
 * Privacy failures always resolve toward not reporting.
 */
export function resolveConsentVersion(provider: ConsentProvider): number {
  let version: number
  try {
    version = provider()
  } catch {
    return 0
  }
  if (!Number.isSafeInteger(version) || version < 0) return 0
  return version
}

/** A consent provider that always returns a fixed version (tests, simple integrations). */
export function staticConsent(version: number): ConsentProvider {
  return () => version
}
