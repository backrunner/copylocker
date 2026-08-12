/**
 * Browser fingerprint provider (FR-WEB-006).
 *
 * A deliberately **low-strength**, privacy-preserving signal: the persistent
 * `device_id` plus stable navigator attributes (UA, platform, languages,
 * hardware concurrency, optional UA-CH), folded into one SHA-256 digest that
 * becomes the session's device binding. Canvas/WebGL probing is OFF by
 * default (`privacy.canvasFingerprint`) and must be opted into explicitly.
 *
 * This is device *recognition*, not device *attestation* — the README states
 * the strength honestly.
 */

import { encode, type CborValue } from './cbor.js'
import { getPersistentDeviceId } from './storage.js'

export interface FingerprintNavigator {
  userAgent?: string
  platform?: string
  language?: string
  languages?: readonly string[]
  hardwareConcurrency?: number
  userAgentData?: {
    brands?: readonly { brand: string; version: string }[]
    mobile?: boolean
    platform?: string
  }
}

export interface FingerprintOptions {
  /** Injectable navigator (defaults to the global). */
  navigator?: FingerprintNavigator
  /** Injectable localStorage for the device_id redundancy. */
  storage?: Storage
  privacy?: {
    /** Canvas/WebGL probing. Default false (FR-WEB-006). */
    canvasFingerprint?: boolean
  }
}

export interface FingerprintResult {
  /** SHA-256 over the canonical attribute encoding (32 bytes). */
  digest: Uint8Array
  /** The persistent, non-sensitive device identifier. */
  deviceId: string
  /** Attribute names that fed the digest (for transparency/tests). */
  fields: string[]
}

/**
 * Build the fingerprint attribute map. Pure given its inputs — identical
 * inputs always produce identical output.
 */
export function buildFingerprintAttributes(
  nav: FingerprintNavigator,
  deviceId: string,
  canvas: string | null,
): Map<string, CborValue> {
  const attrs = new Map<string, CborValue>()
  attrs.set('device_id', deviceId)
  if (nav.userAgent) attrs.set('ua', nav.userAgent)
  if (nav.platform) attrs.set('platform', nav.platform)
  const languages = nav.languages?.length ? nav.languages : nav.language ? [nav.language] : []
  if (languages.length > 0) attrs.set('languages', languages.slice())
  if (typeof nav.hardwareConcurrency === 'number' && nav.hardwareConcurrency > 0) {
    attrs.set('hardware_concurrency', nav.hardwareConcurrency)
  }
  const ch = nav.userAgentData
  if (ch) {
    if (ch.platform) attrs.set('ua_ch_platform', ch.platform)
    if (typeof ch.mobile === 'boolean') attrs.set('ua_ch_mobile', ch.mobile)
    if (ch.brands && ch.brands.length > 0) {
      attrs.set(
        'ua_ch_brands',
        ch.brands.map((b) => `${b.brand}/${b.version}`),
      )
    }
  }
  // Only present when the integrator explicitly opted into canvas probing.
  if (canvas !== null) attrs.set('canvas', canvas)
  return attrs
}

function probeCanvas(): string | null {
  try {
    const doc = globalThis.document
    if (!doc) return null
    const canvas = doc.createElement('canvas')
    canvas.width = 64
    canvas.height = 16
    const ctx = canvas.getContext('2d')
    if (!ctx) return null
    ctx.textBaseline = 'top'
    ctx.font = '14px sans-serif'
    ctx.fillText('copylocker', 2, 1)
    return canvas.toDataURL()
  } catch {
    return null
  }
}

/** Collect the browser fingerprint digest. */
export async function collectFingerprint(options: FingerprintOptions = {}): Promise<FingerprintResult> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    throw new Error('CopyLocker: WebCrypto SubtleCrypto is required (secure context)')
  }
  const nav: FingerprintNavigator = options.navigator ?? globalThis.navigator ?? {}
  const deviceId = getPersistentDeviceId(options.storage)
  const canvas = options.privacy?.canvasFingerprint === true ? probeCanvas() : null
  const attrs = buildFingerprintAttributes(nav, deviceId, canvas)

  // The canonical encoder sorts map keys by their encoded bytes, so the
  // digest is deterministic regardless of attribute insertion order.
  const ordered = new Map<CborValue, CborValue>(attrs)
  const digest = new Uint8Array(
    await subtle.digest('SHA-256', encode(ordered) as unknown as ArrayBuffer),
  )
  return { digest, deviceId, fields: [...attrs.keys()] }
}
