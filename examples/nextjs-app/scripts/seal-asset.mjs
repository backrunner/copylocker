/**
 * Generate the demo sealed asset `public/demo-asset.clx` (web v1 container).
 *
 * Uses `sealAsset()` from `@copylocker/web` — the fixture producer documented
 * in the package README (production sealing is a build-time operation owned
 * by the M4 `@copylocker/seal` package).
 *
 * NOTE: the demo `FinalKey` below is a fixed placeholder. The real `FinalKey`
 * is `H(M ‖ K_BUILD ‖ R ‖ H(wasmBytes))`, where `M` only exists inside an
 * activated wasm session — so this asset unseals successfully only when the
 * app runs against a backend whose session derives the matching key. Without
 * a real activation, the unseal button in the demo exercises the failure
 * path (`NotEntitledError` / `UnsealError`), which is itself part of the SDK
 * contract.
 *
 * Config via env: CL_DEMO_PRODUCT_ID, CL_DEMO_FEATURE_ID, CL_DEMO_FINAL_KEY
 * (64 hex chars).
 */

import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { sealAsset } from '@copylocker/web'

const here = dirname(fileURLToPath(import.meta.url))
const outDir = join(here, '..', 'public')

const productId = process.env.CL_DEMO_PRODUCT_ID ?? 'kat-product'
const featureId = process.env.CL_DEMO_FEATURE_ID ?? 'demo-feature'
const assetId = 'demo-asset'

const finalKeyHex =
  process.env.CL_DEMO_FINAL_KEY ??
  '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
if (!/^[0-9a-fA-F]{64}$/.test(finalKeyHex)) {
  throw new Error('CL_DEMO_FINAL_KEY must be 64 hex characters (32 bytes)')
}
const finalKey = new Uint8Array(finalKeyHex.match(/../g).map((b) => parseInt(b, 16)))

const plaintext = new TextEncoder().encode(
  `CopyLocker demo asset\nproduct=${productId} feature=${featureId}\n` +
    'This text only appears after a successful unseal().\n',
)

const sealed = await sealAsset(finalKey, { productId, variantId: 0, featureId, assetId }, plaintext)

await mkdir(outDir, { recursive: true })
const outPath = join(outDir, 'demo-asset.clx')
await writeFile(outPath, sealed)
console.log(`wrote ${outPath} (${sealed.byteLength} bytes, web v1 container)`)
