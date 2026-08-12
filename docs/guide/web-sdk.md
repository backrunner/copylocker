# Web SDK Guide

`@copylocker/web` is the TypeScript shell over the `copylocker-wasm` licensing core. The shell
owns scheduling, transport, storage, environment probes, the second stage of the key transform,
and asset unsealing; **all** license verification (certificate chains, hybrid PQ signatures, KEM
decapsulation, the state machine) happens inside the WASM core. This page condenses
`packages/web/README.md` and the build-tooling READMEs.

::: warning Read this first — honest security statement
In a browser the attacker has DevTools, can rewrite any JS, and can decompile and patch the WASM.
Every client-side scheme only *raises the bar*. **The web build is inherently weaker than the
native builds.**

- The two-stage transform (`FinalKey = H(M ‖ K_BUILD ‖ R ‖ H(wasmBytes))`) is **engineering
  inseparability, not cryptographic protection** — every input is present on the client. It
  forces an attacker to reimplement the cryptography instead of stubbing one function; the real
  cryptographic protection is the KEM seal plus the signature chain inside the core.
- The ML-KEM part of the device private key is **software-custodied** (WebCrypto cannot hold
  ML-KEM keys); it lives inside the encrypted snapshot in IndexedDB. A platform-inherent weakness.
- The browser fingerprint is a **low-strength** device-recognition signal, not attestation.
:::

## Creating a client

```ts
import { CopyLocker } from '@copylocker/web'

const cl = await CopyLocker.create({
  serverUrl: 'https://license.example.com',
  productId: 'my-product',
  rootPins: ['<hex of pinned root verifying key>'], // [0] current, optional [1] successor
  onStateChange: (s) => renderBadge(s),             // advisory UI only
})

await cl.activate('CL-XXXX-…')              // or activateWithAccount(token)
// unseal(): open bytes sealed against the session FinalKey (two-stage transform)
const bytes = await cl.unseal('pro-feature', sealedAssetBytes)
// loadSealed(): fetch + open an asset sealed by @copylocker/seal under the
// per-feature asset KEK (unwrapped from the credential's wrapped_keks)
const chunk = await cl.loadSealed('/assets/pro.clx', 'pro-feature')
```

There is deliberately **no** `isLicensed()` / `check(): boolean`. `state` is advisory-only (its
TSDoc carries `@deprecated for gating` so IDEs warn): it can be stale or spoofed, and must never
gate features. Gating is implicit — `unseal()` returns plaintext or throws `NotEntitledError` /
`UnsealError`.

Key options (defaults in parentheses): `storage` (`'indexeddb'`; `'memory'` forces per-load
re-activation), `worker` (`true`; Worker isolation with main-thread fallback recorded in
`degradedFlags.worker`), `privacy.canvasFingerprint` (`false`; canvas/WebGL probing stays off
unless explicitly enabled), `buildConstants` (overrides for the injected
`__COPYLOCKER_K_BUILD__` / `__COPYLOCKER_MANIFEST_ROOT__`), `integrity.manifestRoot` (the guard
hook, below), `requireIntegrityProof` (fail closed when no guard `R` is available).

The SDK never monkey-patches global `fetch`. Call `cl.hintOnline()` after your own requests
succeed, or use the opt-in wrapper: `wrapFetch(globalThis.fetch, () => cl.hintOnline())`.

## Worker isolation

With `worker: true` (default) the WASM core runs in a dedicated Web Worker
(`new Worker(new URL('./worker/entry.js', import.meta.url), { type: 'module' })`, which
Vite/webpack re-bundle). The main thread fetches the raw `.wasm` once — its SHA-256 feeds the
constructor config and the two-stage key transform — transfers bytes plus session config in an
INIT frame, and afterwards shuttles opaque `step` request/response bytes. Typed errors behave
identically on both paths. `cl.dispose()` terminates the Worker.

## CSP

Loading WASM requires `script-src 'wasm-unsafe-eval'`. The SDK itself uses no `eval` and no
inline scripts. Recommended policy:

```text
script-src 'self' 'wasm-unsafe-eval';
connect-src 'self' https://license.example.com;
```

The M4 unplugin adds SRI for JS chunks; the `.wasm` is loaded as bytes and its SHA-256 feeds the
key transform, so a replaced WASM silently fails to unseal. L3 sealed **chunks** additionally
need `script-src blob:` (see [Protection Levels](./protection-levels#l3-sealed-code)); the
WASM-segment variant does not.

## SSR

The main entry is import-safe under SSR (no top-level `window`/`document`/`indexedDB` access),
but `CopyLocker.create()` requires a browser and throws otherwise. Use the dedicated no-op stub
during server rendering:

```ts
import { CopyLocker as SsrCopyLocker } from '@copylocker/web/ssr'

let cl = await SsrCopyLocker.create(opts) // zero side effects, cl.isSsrStub === true
if (typeof window !== 'undefined') {
  const { CopyLocker } = await import('@copylocker/web')
  cl = await CopyLocker.create(opts)      // real client, on the client only
}
```

Every licensing operation on the stub rejects with a `server-side stub` error and `state` stays
`'unlicensed'`. With Next.js, prefer `dynamic(() => import(...), { ssr: false })` for the real
SDK. A working SSR smoke setup lives in `examples/nextjs-app`.

## Storage and privacy

- The opaque session snapshot (credential envelope + device key material) is encrypted with a
  **non-extractable AES-GCM CryptoKey** before landing in IndexedDB; the CryptoKey itself is
  stored via structured clone, so raw key bytes never exist in page-reachable memory.
- `localStorage` holds only the non-sensitive `device_id` redundancy.
- The fingerprint is the persistent `device_id` + UA/platform/languages/hardwareConcurrency +
  optional UA-CH, folded into one SHA-256. No canvas/WebGL by default; no raw device attributes
  are reported (activation requests always omit `device_attrs`).

## Sealed asset format

**Web v1 container.** The native `SealedAsset` format
(`crates/copylocker-proto/src/sealed_asset.rs`) uses XChaCha20-Poly1305 with a 24-byte nonce,
which WebCrypto does not implement. The web container keeps the native CBOR layout and AAD
discipline but uses AES-256-GCM (12-byte nonce, `nonce ‖ ciphertext ‖ tag`):

```text
{ 0: 1, 1: "AES-256-GCM", 2: product_id, 3: variant_id,
  4: feature_id, 5: asset_id, 6: nonce ‖ ciphertext ‖ tag,
  ? 7: chunk_size, ? 8: chunk_count }        ; chunked extension

aad = { 0: "copylocker/web-asset-aad/v1", 1: alg, 2: product_id,
        3: variant_id, 4: feature_id, 5: asset_id }
```

Assets larger than the chunk size (default 4 MiB at build time) become `chunk_count` records of
`nonce(12) ‖ ct ‖ tag(16)`; chunk `i` uses nonce `prefix(8) ‖ uint32be(i)` and AAD extended with
`{6: chunk_index, 7: chunk_count}`, so reordering, dropping, or truncating a chunk fails
authentication. Single-chunk assets always use the plain form, so older decoders keep working.

`@copylocker/seal` emits both forms at build time and is byte-compatible with this package
(cross-tested). The SDK's own `sealAsset()` produces compatible fixtures; production sealing is a
build-time operation.

## Build-time integration: unplugin + guard + seal

Three packages work together (M4-A status; Vite/Rollup/esbuild integration-tested,
webpack/rspack/farm pending in M4-B):

- **`@copylocker/unplugin`** digests every build artifact, assembles a signed
  `IntegrityManifest` (two-round placeholder scheme over the final on-disk bytes), injects the
  guard bootstrap into each entry chunk, and optionally seals assets/chunks. Ship it **last** in
  your plugin list.
- **`@copylocker/guard`** is the runtime half: `bootGuard()` returns `R` — the actually-computed
  Merkle root over the bundle — never a boolean. Integrity failure never throws; it changes `R`,
  which changes the derived key, which makes sealed assets fail to open.
- **`@copylocker/seal`** seals plaintext assets into the web v1 container at build time and
  manages the per-feature KEK registry (always encrypted, mode `0600`, never committed).

```ts
// vite.config.ts
import copylocker from '@copylocker/unplugin/vite'

export default defineConfig({
  plugins: [
    // …minify, obfuscators, SRI…
    copylocker({
      productId: 'my-app',
      signer: { kind: 'remote', endpoint: process.env.CL_SIGN_URL!, token: process.env.CL_SIGN_TOKEN! },
      rootPins: [process.env.CL_ROOT_PIN!],
      splitConstants: 4,
      seal: { assets: [{ globs: ['assets/pro-*.json'], feature: 'pro' }] },
      guard: { sampleRate: 0.15 },
    }), // LAST
  ],
})
```

At runtime the bootstrap publishes `globalThis.__CL_GUARD_R__` (a `Promise<Uint8Array>`); wire it
into the SDK:

```ts
const cl = await CopyLocker.create({
  ...options,
  integrity: { manifestRoot: () => globalThis.__CL_GUARD_R__ },
})
```

**The fallback hole, and why the plugin closes it:** without the hook (or if the guard bootstrap
is deleted while the constants block survives), derivation silently falls back to the injected
`MANIFEST_ROOT` constant. `requireIntegrityProof: true` fails derivation closed instead — with
the same indistinguishable `NotEntitledError` (code 17) the WASM core uses. Apps built with the
unplugin get this automatically: the plugin injects `__CL_REQUIRE_INTEGRITY_PROOF__ = true` into
the entry prelude, outside the guard bootstrap, so deleting the bootstrap cannot disable it. An
explicit option value always wins over the injected constant.

Signer modes: `local` (dev; Ed25519 JWK file, mode `0600`, created by `copylocker-unplugin
keygen`; an **error** under `NODE_ENV=production` unless `allowLocalInProduction` is set),
`remote` (CI; POSTs tbs bytes, expects a 64-byte Ed25519 signature), or a custom async function.
Verify build output in CI:

```bash
copylocker-unplugin verify dist --pubkey <64-hex>   # exits non-zero on any one-byte tamper
```

Guard strategies: `'sync'`, `'idle'` (default; entry chunk inline, the rest one per
`requestIdleCallback` slice — keeps LCP impact under 20 ms, NFR-PERF-006), `'lazy'` (weakest;
boot-latency-critical only), and `'report-only'` (same `R` semantics as `'sync'` plus
diagnostics; use it to observe a release before enforcement).

## Degradation and errors

`cl.degradedFlags` records environment degradations: `storage` (IndexedDB missing → in-memory
store, every cold start re-activates) and `worker` (isolation requested but the core fell back to
the main thread).

Errors are typed classes with stable numeric codes (NFR-SEC-011 — no greppable strings):
`NotEntitledError` (the gate), `UnsealError` (corrupt/tampered bytes), `TransportError`
(network), `LifecycleError`, `MalformedError`, `ConfigError`, `EntropyError`, and
`FatalLicenseError` (codes ≥ 100; fail-closed, local material wiped). Handle them per the
[failure UX guidance](./protection-levels#failure-ux-matters).
