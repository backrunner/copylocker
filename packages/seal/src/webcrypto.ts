/**
 * Node's WebCrypto types live under the `webcrypto` namespace in
 * `@types/node` (no DOM lib in this package). Re-export the ones we use.
 */
import type { webcrypto } from 'node:crypto'

export type KeyUsage = webcrypto.KeyUsage
