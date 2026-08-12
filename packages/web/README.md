# @copylocker/web

CopyLocker Web SDK (M3) — the TypeScript shell over the `copylocker-wasm`
licensing core. It owns scheduling, transport, storage, environment probes,
the second stage of the key transform, and asset unsealing. All license
verification (certificate chains, hybrid PQ signatures, KEM decapsulation,
the state machine) happens inside the WASM core.

> **Read this first — honest security statement.**
> In a browser the attacker has DevTools, can rewrite any JS, and can
> decompile and patch the WASM. Every client-side scheme only *raises the
> bar*. **The web build is inherently weaker than the native builds.**
> Specifically:
>
> - The two-stage transform (`FinalKey = H(M ‖ K_BUILD ‖ R ‖ H(wasmBytes))`)
>   is **engineering inseparability, not cryptographic protection** — every
>   input is present on the client. It forces an attacker to reimplement the
>   cryptography instead of stubbing one function; it does not make the
>   assets mathematically safe. The real cryptographic protection is the KEM
>   seal plus the signature chain inside the core.
> - The ML-KEM part of the device private key is **software-custodied**
>   (WebCrypto cannot hold ML-KEM keys); it lives inside the encrypted
>   snapshot in IndexedDB. This is a platform-inherent weakness.
> - The browser fingerprint is a **low-strength** device-recognition signal,
>   not attestation.

## Install & build

```bash
npm install
npm run build:wasm   # cargo (worker-release, wasm32) + wasm-bindgen glue → src/wasm/
npm run build        # tsc → dist/, copies the glue to dist/wasm/
npm test             # vitest; does NOT require the wasm artifact
```

`build:wasm` requires the `wasm32-unknown-unknown` rustup target and a
wasm-bindgen CLI whose version matches the `wasm-bindgen` crate in the
workspace `Cargo.lock` (currently 0.2.126). The script checks both and fails
with an explicit message instead of skipping silently. The `worker-release`
cargo profile is mandatory: the workspace `release` profile sets
`strip = "symbols"`, which removes the wasm `target_features` section that
wasm-bindgen needs.

## Usage

```ts
import { CopyLocker } from '@copylocker/web'

if (typeof window !== 'undefined') {
  const cl = await CopyLocker.create({
    serverUrl: 'https://license.example.com',
    productId: 'my-product',
    rootPins: ['<hex of pinned root verifying key>'], // build-time injected
    onStateChange: (s) => renderBadge(s),             // advisory UI only
  })

  await cl.activate('CL-XXXX-…')              // or activateWithAccount(token)

  // The ONLY "use the license" entry points:
  // unseal() opens assets sealed against the session FinalKey (the two-stage
  // transform H(M ‖ K_BUILD ‖ R ‖ WASM_DIGEST)):
  const bytes = await cl.unseal('pro-feature', sealedAssetBytes)
  // loadSealed() fetches and opens an asset sealed by `@copylocker/seal`
  // under the per-feature asset KEK — the KEK is unwrapped inside the core
  // from the credential's wrapped_keks (the `unseal-asset` op):
  const chunk = await cl.loadSealed('/assets/pro.clx', 'pro-feature')
}
```

There is deliberately **no** `isLicensed()` / `check(): boolean`. `state` is
advisory-only (its TSDoc carries `@deprecated for gating — advisory only` on
purpose so IDEs warn): it can be stale or spoofed, and must never gate
features. Gating happens implicitly: `unseal()` either returns plaintext or
throws `NotEntitledError` / `UnsealError`.

### Options

| Option | Default | Notes |
|---|---|---|
| `serverUrl`, `productId`, `rootPins` | — | required; `rootPins[0]` current root, optional `[1]` successor |
| `storage` | `'indexeddb'` | `'memory'` forces per-load re-activation |
| `worker` | `true` | Worker isolation (FR-WEB-008): the wasm core runs in a dedicated Web Worker, reached over opaque byte frames. Falls back to the main thread and sets `degradedFlags.worker` when Workers are unavailable |
| `privacy.canvasFingerprint` | `false` | canvas/WebGL probing stays off unless explicitly enabled (FR-WEB-006) |
| `buildConstants` | injection points | overrides `__COPYLOCKER_K_BUILD__` / `__COPYLOCKER_MANIFEST_ROOT__` |
| `integrity.manifestRoot` | — | M4 `@copylocker/guard` hook: actually-computed root `R` replaces the injected `MANIFEST_ROOT` at derive time (see "Build-time constants") |
| `requireIntegrityProof` | `__CL_REQUIRE_INTEGRITY_PROOF__` injection | fail closed when no guard `R` is available instead of falling back to the injected constant (see "Build-time constants") |

### Network hints

The SDK never monkey-patches the global `fetch`. Call `cl.hintOnline()` after
your own requests succeed, or opt into the wrapper:

```ts
import { wrapFetch } from '@copylocker/web'
const fetch = wrapFetch(globalThis.fetch, () => cl.hintOnline())
```

### Degradation

`cl.degradedFlags` records environment degradations (`storage`: IndexedDB
missing → in-memory store, every cold start re-activates; `worker`: Worker
isolation requested but not active — the core fell back to the main thread).

### Worker isolation

With `worker: true` (default) the wasm core runs inside a dedicated Web
Worker spawned via `new Worker(new URL('./worker/entry.js', import.meta.url),
{ type: 'module' })`, which Vite/webpack recognize and re-bundle. The main
thread fetches the raw `.wasm` once (its SHA-256 feeds the constructor config
and the two-stage key transform), transfers the bytes plus the session config
to the Worker in an INIT frame, and afterwards shuttles opaque `step` request
and response bytes (`src/worker/protocol.ts`). Core failures come back as the
same bare numeric codes `ClSession.step` throws on the main thread, so typed
errors behave identically on both paths. `cl.dispose()` terminates the Worker.

## CSP

Loading WASM requires `script-src 'wasm-unsafe-eval'`. The SDK itself uses no
`eval` and no inline scripts; a recommended policy:

```
script-src 'self' 'wasm-unsafe-eval';
connect-src 'self' https://license.example.com;
```

The M4 `@copylocker/unplugin` adds SRI for the JS chunks; the `.wasm` is
loaded as bytes and its SHA-256 feeds the key transform, so a replaced wasm
silently fails to unseal.

## SSR

The main entry is import-safe under SSR: no top-level code touches
`window`/`document`/`indexedDB`, but `CopyLocker.create()` requires a browser
and throws a clear error otherwise. Use the dedicated no-op stub during
server rendering (design §4.5, FR-WEB-009):

```ts
import { CopyLocker as SsrCopyLocker } from '@copylocker/web/ssr'

let cl = await SsrCopyLocker.create(opts) // zero side effects, cl.isSsrStub === true
if (typeof window !== 'undefined') {
  const { CopyLocker } = await import('@copylocker/web')
  cl = await CopyLocker.create(opts) // real client, on the client only
}
```

The stub mirrors the public API; every licensing operation rejects with a
`server-side stub` error, and `state` stays `'unlicensed'`. With Next.js,
prefer `dynamic(() => import(...), { ssr: false })` for the real SDK.

## Storage & privacy

- The opaque session snapshot (credential envelope + device key material) is
  encrypted with a **non-extractable AES-GCM CryptoKey** before landing in
  IndexedDB; the CryptoKey itself is stored in IndexedDB via structured
  clone, so raw key bytes never exist in page-reachable memory.
- `localStorage` holds only the non-sensitive `device_id` redundancy.
- The fingerprint is the persistent `device_id` + UA/platform/languages/
  hardwareConcurrency + optional UA-CH, folded into one SHA-256. No
  canvas/WebGL by default, no raw device attributes are reported (the
  activation request always omits `device_attrs`).

## Sealed asset format

**Web v1 container.** The native `SealedAsset` format
(`crates/copylocker-proto/src/sealed_asset.rs`) uses XChaCha20-Poly1305 with a
24-byte nonce, which WebCrypto does not implement. The web container keeps
the native CBOR layout and AAD discipline but uses AES-256-GCM
(12-byte nonce, WebCrypto `nonce ‖ ciphertext ‖ tag` layout):

```cddl
{ 0: 1, 1: "AES-256-GCM", 2: product_id, 3: variant_id,
  4: feature_id, 5: asset_id, 6: nonce ‖ ciphertext ‖ tag }
aad = { 0: "copylocker/web-asset-aad/v1", 1: alg, 2: product_id,
        3: variant_id, 4: feature_id, 5: asset_id }
```

**Chunked extension.** Assets larger than the chunk size (default 4 MiB at
build time) add header keys `7: chunk_size` / `8: chunk_count`; field 6 then
holds `chunk_count` concatenated `nonce(12) ‖ ct ‖ tag(16)` records, one per
`chunk_size`-byte plaintext block. Chunk `i` uses nonce
`prefix(8) ‖ uint32be(i)` and AAD extended with `{6: chunk_index,
7: chunk_count}`, so reordering, dropping, or truncating a chunk fails
authentication. Assets that fit in one chunk always use the plain form, so
older decoders keep working on them.

The M4 `@copylocker/seal` package emits both forms at build time.
`sealAsset()` in this package produces compatible fixtures (production
sealing is a build-time operation).

## Build-time constants

`K_BUILD` / `MANIFEST_ROOT` are read from the `__COPYLOCKER_K_BUILD__` /
`__COPYLOCKER_MANIFEST_ROOT__` globals (hex string or 32-byte
`Uint8Array`), can be overridden via options, and default to **all zeros in
development**. The M4 unplugin performs the real injection; a production
build without injection provides no binding between bundle and key.

When the unplugin is configured with `splitConstants: N > 1`, `K_BUILD` is
instead injected as N hex shard globals `__CL_K_BUILD_0__` …
`__CL_K_BUILD_<N-1>__`, concatenated here in order; a malformed shard set
throws `TypeError` (build-integration bug) rather than silently defaulting.

Optionally, `CopyLockerOptions.integrity.manifestRoot` wires in the M4
`@copylocker/guard` runtime: when set, its **actually-computed** root `R`
(the value published by the unplugin bootstrap as `__CL_GUARD_R__`) replaces
the injected constant during key derivation. `R` is not a boolean — a
tampered or partially-missing bundle simply computes a different root,
derives a different `FinalKey`, and sealed assets fail to open.

```ts
const cl = await CopyLocker.create({
  ...options,
  // The unplugin bootstrap publishes a Promise; the hook awaits it.
  integrity: { manifestRoot: () => globalThis.__CL_GUARD_R__ },
})
```

**Default fallback semantics:** when the hook is absent or yields `undefined`
(e.g. a dev build without the unplugin), derivation silently uses the
injected `MANIFEST_ROOT` constant. That fallback re-opens a hole in
production: an attacker who deletes the guard bootstrap while keeping the
constants block removes `R`, and derivation quietly falls back. Close it
with `requireIntegrityProof: true` — then a missing `R` fails derivation
closed with the same indistinguishable `NotEntitledError` (code 17) the wasm
core uses, instead of falling back. Apps built with `@copylocker/unplugin`
get the strict behavior automatically: the plugin injects
`__CL_REQUIRE_INTEGRITY_PROOF__ = true` into the entry prelude (outside the
guard bootstrap, so deleting the bootstrap cannot disable it), and the SDK
treats that constant as the default for `requireIntegrityProof`. An explicit
option value always wins over the injected constant.

**WASM_DIGEST comparison.** When the build covers exactly one `.wasm`
asset, the unplugin also injects `__CL_WASM_DIGEST__` — the build-time
SHA-256 of that artifact. At `create()` the SDK compares it against the
digest of the wasm bytes it actually loaded; a swapped or patched artifact
fails closed with the same indistinguishable `NotEntitledError` (code 17)
instead of proceeding to key derivation. A build without the injection
(development, or several covered `.wasm` files — then only the
`__CL_WASM_DIGESTS__` map is published, for custom wiring) skips the
comparison.

## License

GPL-3.0-only.
