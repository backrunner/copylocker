/**
 * In-memory mock of the wasm session's op semantics (minimal subset), used
 * to drive `@copylocker/web` tests without the wasm artifact.
 */
import { encode, decode, mapGet, type CborValue } from '../../src/cbor.js'
import type { SessionDriver } from '../../src/session.js'

export interface MockSessionOptions {
  /** Features the mock credential entitles. */
  entitled?: string[]
  /** Whether an online session root is armed (kind 1 derivations succeed). */
  onlineRoot?: boolean
  /** The 32-byte half-baked material returned by op 9. */
  m?: Uint8Array
  /** The 32-byte asset KEK returned by op 13 for entitled features. */
  kek?: Uint8Array
  /** When set, ingest-validate-response throws this (fatal, ≥100) core code. */
  fatalValidateCode?: number
}

function num(value: CborValue | undefined): number {
  return typeof value === 'number' ? value : 0
}

function text(value: CborValue | undefined): string {
  return typeof value === 'string' ? value : ''
}

export class MockSessionDriver implements SessionDriver {
  entitled: string[]
  onlineRoot: boolean
  m: Uint8Array
  kek: Uint8Array
  fatalValidateCode: number | undefined
  activated = false
  state = 0
  refreshAfter = 0
  /** Last exported snapshot blob (raw, as the core would emit). */
  exported: Uint8Array | null = null
  /** Ops seen, for assertions. */
  readonly ops: number[] = []
  /** Telemetry block bytes from the last build-validate-request op input (key 1). */
  lastValidateTelemetry: CborValue | undefined = undefined

  constructor(options: MockSessionOptions = {}) {
    this.entitled = options.entitled ?? []
    this.onlineRoot = options.onlineRoot ?? true
    this.m = options.m ?? new Uint8Array(32).fill(7)
    this.kek = options.kek ?? new Uint8Array(32).fill(9)
    this.fatalValidateCode = options.fatalValidateCode
  }

  private summary(effects: number[] = [], extra: Map<number, CborValue> = new Map()): Uint8Array {
    const map = new Map<number, CborValue>([
      [1, this.state],
      [2, 0],
      [3, this.refreshAfter],
      [4, 0],
      [5, 0],
      [6, this.activated ? 1 : 0],
      [90, effects],
    ])
    for (const [key, value] of extra) map.set(key, value)
    return encode(map)
  }

  private snapshotBytes(): Uint8Array {
    return encode(
      new Map<number, CborValue>([
        [0, 1],
        [1, this.activated ? 1 : 0],
        [2, this.entitled.slice()],
        [3, this.refreshAfter],
      ]),
    )
  }

  step(input: Uint8Array): Uint8Array {
    const value = decode(input)
    const op = num(mapGet(value, 0))
    this.ops.push(op)
    const now = num(mapGet(value, 2)) || num(mapGet(value, 3))
    switch (op) {
      case 1: // device-keygen (also absorbs the constructor config call)
        return this.summary()
      case 2: {
        // snapshot-export
        this.exported = this.snapshotBytes()
        return this.summary([], new Map([[8, this.exported]]))
      }
      case 3: {
        // snapshot-import {1: blob, 2: now}
        const blob = mapGet(value, 1)
        if (!(blob instanceof Uint8Array)) throw 16
        const snap = decode(blob)
        if (num(mapGet(snap, 0)) !== 1) throw 16
        this.activated = num(mapGet(snap, 1)) === 1
        const entitled = mapGet(snap, 2)
        if (Array.isArray(entitled)) this.entitled = entitled.map(text)
        this.refreshAfter = num(mapGet(snap, 3))
        this.state = this.activated ? 2 : 0
        return this.summary(this.activated ? [4] : [])
      }
      case 4: {
        // build-activate-request
        if (this.activated) throw 11
        const key = mapGet(value, 1)
        const token = mapGet(value, 3)
        if (typeof key !== 'string' && !(token instanceof Uint8Array)) throw 3
        return this.summary([], new Map([[8, encode(new Map([[1, 'activation-request']]))]]))
      }
      case 5: // ingest-keyset
        return this.summary()
      case 6: {
        // ingest-activate-response
        if (this.activated) throw 11
        this.activated = true
        this.state = 2
        this.refreshAfter = now + 3600
        return this.summary([1, 4])
      }
      case 7: {
        // build-validate-request {1: ? telemetry_block, 2: now}
        if (!this.activated) throw 12
        this.lastValidateTelemetry = mapGet(value, 1)
        const request = new Map<number, CborValue>([[1, 'validate-request']])
        if (this.lastValidateTelemetry !== undefined) {
          if (!(this.lastValidateTelemetry instanceof Uint8Array)) throw 3
          // The real core decodes the canonical block and rejects it with a
          // numeric error when malformed; mirror that so bad input never
          // becomes a built request.
          try {
            request.set(11, decode(this.lastValidateTelemetry))
          } catch {
            throw 3
          }
        }
        return this.summary([], new Map([[8, encode(request)]]))
      }
      case 8: // ingest-validate-response
        if (this.fatalValidateCode !== undefined) throw this.fatalValidateCode
        if (!this.activated) throw 12
        this.state = 2
        this.refreshAfter = now + 3600
        return this.summary([1])
      case 9: {
        // derive-m {1: feature, 2: kind, 3: now}
        const feature = text(mapGet(value, 1))
        const kind = num(mapGet(value, 2))
        if (!this.activated || !this.entitled.includes(feature)) throw 13
        if (kind === 1 && !this.onlineRoot) throw 17
        if (kind !== 0 && kind !== 1) throw 3
        return this.summary([], new Map([[8, this.m]]))
      }
      case 10: {
        // event {1: kind, 2: now}
        const kind = num(mapGet(value, 1))
        if (kind === 5) {
          this.activated = false
          this.state = 0
          this.refreshAfter = 0
          return this.summary([3, 4])
        }
        return this.summary()
      }
      case 11: // state-query
        return this.summary()
      case 12: // build-deactivate-request
        if (!this.activated) throw 12
        return this.summary([], new Map([[8, encode(new Map([[1, 'deactivate-request']]))]]))
      case 13: {
        // unseal-asset {1: feature, 2: now}
        const feature = text(mapGet(value, 1))
        if (!this.activated) throw 12
        if (!this.entitled.includes(feature)) throw 13
        return this.summary([], new Map([[8, this.kek]]))
      }
      default:
        throw 2
    }
  }
}

/** A fetch stub routing the Worker endpoints to canned CBOR responses. */
export function mockWorkerFetch(
  log: string[] = [],
): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  const ok = (body: Uint8Array) =>
    new Response(body as unknown as ArrayBuffer, {
      status: 200,
      headers: { 'Content-Type': 'application/cbor' },
    })
  return async (input, init) => {
    const url = String(input)
    log.push(`${init?.method ?? 'GET'} ${url}`)
    if (url.endsWith('/v1/keys')) return ok(encode(new Map([[0, 'keyset']])))
    if (url.endsWith('/v1/activate')) return ok(encode(new Map([[0, 'credential']])))
    if (url.endsWith('/v1/validate')) return ok(encode(new Map([[0, 'ticket']])))
    if (url.endsWith('/v1/deactivate')) return ok(encode(new Map([[0, 'ack']])))
    return new Response('not found', { status: 404 })
  }
}

/** 64 hex chars of pinned-root filler for tests. */
export const TEST_ROOT_PIN = 'ab'.repeat(32)
