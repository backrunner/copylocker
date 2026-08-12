# @copylocker/seal

Build-time asset sealing for CopyLocker web targets (M4-A). Seals plaintext
assets into the **web v1 sealed-asset container** that `@copylocker/web`
opens at runtime, and manages the per-feature `KEK_asset` registry that makes
"build-time ciphertext only" possible.

- Zero runtime dependencies. Node ≥ 20 (WebCrypto).
- Byte-compatible with `packages/web/src/unseal.ts` — cross-tested against
  the web package's own `sealAsset` / `openSealedAsset` in both directions.

## Threat model position

This package runs **at build time**, where `FinalKey` does not exist yet (it
depends on runtime wasm material `M`). The design
(`.agents/03-modules/50-unplugin-integrity.md` §4) therefore splits sealing
in two layers:

```
build time:  asset_ct = AES-256-GCM(KEK_asset, plaintext)   ← this package
issuance:    wrapped_kek = AEAD(FK_device, KEK_asset)       ← M4-B, server-side
runtime:     FK → unwrap KEK_asset → open asset_ct          ← @copylocker/web
```

M4-A (this package) ships the build-time half plus a **development bridge**
(`derive-final-key` + `wrap-kek`) that reproduces the runtime chain without a
server, for E2E and local integration. **Production KEK wrapping semantics
are defined by M4-B (MC `wrapped_keks`); the bridge is not a production
mechanism.**

## Security red lines

- The KEK registry is **always encrypted** (AES-256-GCM under a deployment
  wrapping key) and written with mode `0600`. Plaintext KEKs never touch disk.
- The wrapping key comes from `COPYLOCKER_SEAL_WRAPPING_KEY` (64 hex chars)
  or `.copylocker/wrapping-key` (mode `0600`). `copylocker-seal init` creates
  it and adds both files to `.gitignore`.
- **Never commit the registry or the wrapping key. Never print them. Never
  copy them into CI artifacts.** `registry list` shows only a truncated
  SHA-256 fingerprint.
- Losing the registry means the sealed assets can never be opened again —
  back it up through your secret manager, not through git.

## CLI

```text
copylocker-seal init [--dir .copylocker]
copylocker-seal seal <glob...> --feature <id> --product-id <id>
                     [--variant-id <n>] [--chunk-size <bytes>] [--out <dir>]
copylocker-seal registry list
copylocker-seal derive-final-key --m <hex> [--k-build <hex>]
                     [--manifest-root <hex>] (--wasm-digest <hex> | --wasm <path>)
copylocker-seal wrap-kek --feature <id> --product-id <id> --final-key <hex> [--out <path>]
```

All commands are **dry-run by default**; nothing is written unless `--out` is
given. (`seal` persists a newly created feature KEK even in dry-run so repeat
runs stay stable — the registry is encrypted and mode `0600`.)

Glob syntax is deliberately minimal: literals, `*` (within a segment), `**`
(across segments). `node_modules` and `.git` are never descended into.

### The development bridge loop

```bash
# 1. build machine: seal assets under a fresh per-feature KEK
copylocker-seal init
copylocker-seal seal 'assets/pro/**' --feature pro --product-id my-app --out public

# 2. dev loop: reproduce the runtime FinalKey from M + build constants
FK=$(copylocker-seal derive-final-key --m <hex-from-runtime> \
       --k-build <hex> --manifest-root <hex> --wasm dist/app.wasm)

# 3. wrap the feature KEK under that FinalKey (assetId: copylocker/kek/pro)
copylocker-seal wrap-kek --feature pro --product-id my-app --final-key "$FK" \
       --out public/kek.pro.sealed
```

```ts
// 4. runtime: exactly the production chain, minus the server
const kek = await cl.unseal('pro', await (await fetch('/kek.pro.sealed')).arrayBuffer())
const bytes = await openSealedAsset(kek, sealedAssetBytes, { productId: 'my-app', featureId: 'pro' })
```

## Container format

Byte-identical to `@copylocker/web` (web v1):

```cddl
web-sealed-asset = {
  0: 1, 1: "AES-256-GCM", 2: product_id, 3: variant_id,
  4: feature_id, 5: asset_id,
  6: nonce(12) ‖ ciphertext ‖ tag(16),
  ? 7: uint,   ; chunk_size  (chunked extension)
  ? 8: uint,   ; chunk_count (chunked extension)
}
aad = {0: "copylocker/web-asset-aad/v1", 1: alg, 2: product_id,
       3: variant_id, 4: feature_id, 5: asset_id}
```

**Chunked extension.** Assets larger than the chunk size (default 4 MiB) are
sealed as `chunk_count` records of `nonce(12) ‖ ct ‖ tag(16)`. Chunk `i`
uses nonce `prefix(8) ‖ uint32be(i)` and AAD extended with
`{6: chunk_index, 7: chunk_count}` — reordering, dropping, or truncating a
chunk fails authentication. Small assets always use the plain form, so older
decoders keep working on them.

> Deviation from the design sketch (§4.1): the AAD binds
> product/variant/feature/asset ids, not `assetId‖buildFingerprint`. Byte
> compatibility with the shipped web runtime wins; the build fingerprint
> flows into `MANIFEST_ROOT` (hence FinalKey) instead.

## Error classification

`@copylocker/web` collapses every open failure into `UnsealError` on purpose.
At build time the design requires operators to distinguish failure classes
(`60-instrumentation-guard.md` §4.3), so `openSealedBytes` throws `SealError`
with:

- `CORRUPT` — structural failure: bad CBOR, truncation, invalid chunk layout
  (a dropped chunk). ≙ the web decode-stage `UnsealError`.
- `NOT_ENTITLED` — well-formed container, AEAD tag did not verify: wrong
  KEK/FinalKey, wrong feature, tampered bytes. ≙ the web decrypt-stage
  `UnsealError` / runtime `NotEntitledError`.
- `CONFIG` — operator error (missing wrapping key, unknown feature).
- `IO` — filesystem failure.

## L3 code-chunk sealing (opt-in)

`sealChunk()` encrypts a JS chunk and returns the loader stub that replaces
it in the bundle (design §5.1):

```js
export default async function load() {
  const code = await __cl.loadSealed('/chunks/pro-x7f2.js.sealed', 'pro')
  return import(URL.createObjectURL(new Blob([code], { type: 'text/javascript' })))
}
```

**CSP trade-off:** the Blob-URL dynamic import requires `script-src blob:`.
Deployments that cannot allow it must use the WASM-segment variant (seal a
`.wasm` asset and `WebAssembly.instantiate` the opened bytes — only
`wasm-unsafe-eval` needed). Chunk sealing is off by default; the unplugin
must enable it explicitly. The stub expects the runtime client at
`globalThis.__cl` (injected by the M4 unplugin).

## API for the unplugin integration

```ts
import {
  sealAssets, sealChunk, chunkLoaderStub,        // sealing
  loadRegistry, saveRegistry, getOrCreateKek,    // KEK registry
  resolveWrappingKey, generateWrappingKey,
  sealBytes, openSealedBytes, decodeSealedAsset, // container primitives
  deriveFinalKey,                                // dev bridge
  SealError,                                     // error taxonomy
} from '@copylocker/seal'

const wrappingKey = await resolveWrappingKey({ keyFile: '.copylocker/wrapping-key' })
const registry = await loadRegistry({ path: '.copylocker/seal-registry.json', wrappingKey })
const { kek, created } = getOrCreateKek(registry, featureId)
if (created) await saveRegistry({ path, wrappingKey, registry })

const results = await sealAssets({
  cwd, globs, featureId, productId, kek,
  outDir,              // omit for a dry-run plan
  chunkSize,           // default 4 MiB, 0 disables
  variantId, assetId,  // optional overrides
})

const { sealed, stub } = await sealChunk({
  code, featureId, productId, kek, assetId, sealedUrl,
})
```

`sealAssets` returns per-file `{ source, assetId, output, plaintextBytes,
sealedBytes, chunking?, written }` records so the plugin can log or wire the
integrity manifest entry.
