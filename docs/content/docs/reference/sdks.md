---
title: SDK Reference
navTitle: SDK Reference
order: 13
description: Public API surface of every CopyLocker client SDK — web, framework bindings, build tooling, and the native stacks.
---

# SDK Reference

Exact public surfaces, taken from each package's entry point. Consumer-facing walkthroughs live in
[Web SDK](/docs/guide/web-sdk) and [Protection Levels](/docs/guide/protection-levels); this page
is the lookup table.

One design invariant holds across every SDK: **there is no boolean "is licensed" API**. Access is
productive — `unseal`, `feature_key`, `challenge`, `loadSealed` return bytes or throw. `state` /
`onStateChange` / `subscribe` are advisory UI signals only (ADR-0004) and are marked
`@deprecated for gating`.

## `@copylocker/web` — browser SDK

TypeScript shell over the `copylocker-wasm` core. Main entry `@copylocker/web`, SSR stub at
`@copylocker/web/ssr`.

### `class CopyLocker`

| Member | Signature | Notes |
|---|---|---|
| `create` | `static async create(options: CopyLockerOptions): Promise<CopyLocker>` | Collects the fingerprint, loads the WASM session (in a dedicated Web Worker by default), verifies `__CL_WASM_DIGEST__` against the actually-loaded WASM, restores the persisted snapshot or runs `deviceKeygen`, starts the scheduler. Throws during SSR without test seams. |
| `activate` | `(key: string): Promise<void>` | Activate with a license key. |
| `activateWithAccount` | `(token: string): Promise<void>` | Activate with an account token. |
| `deactivate` | `(): Promise<void>` | Server acknowledgement first, then local wipe. |
| `unseal` | `(featureId: string, sealed: BufferSource): Promise<Uint8Array>` | Derives `M` inside the core, completes the two-stage key transform, opens the sealed asset. Throws `NotEntitledError` / `UnsealError`. |
| `loadSealed` | `(url: string, featureId: string): Promise<Uint8Array>` | Fetches a `@copylocker/seal` asset and opens it with the per-feature KEK unwrapped inside the core. |
| `state` | `get state(): LicenseState` | **Advisory only — never gate on it.** |
| `onStateChange` | `(listener: (s: LicenseState) => void): () => void` | Returns the unsubscribe function. |
| `hintOnline` | `(): void` | Nudge the scheduler after connectivity returns. |
| `dispose` | `(): void` | Tear down worker, scheduler, listeners. |
| `degradedFlags` | `readonly { storage: boolean; worker: boolean }` | Reports fallback to memory storage / main-thread session. |

### `CopyLockerOptions`

Required: `serverUrl`, `productId`, `rootPins` (hex-encoded pinned root verifying keys; first is
current, optional second is the successor). Optional, in roughly the order you will meet them:

- `storage: 'indexeddb' | 'memory'`, `worker: boolean` (default `true`)
- `privacy: { reportAttrs?: boolean; canvasFingerprint?: boolean }`
- `telemetry: TelemetryHooks` — see `@copylocker/telemetry` below
- `buildConstants: Partial<BuildConstants>` (`kBuild`, `manifestRoot`) and
  `integrity: IntegrityHooks`; `requireIntegrityProof` defaults to the
  `__CL_REQUIRE_INTEGRITY_PROOF__` constant injected by `@copylocker/unplugin`
- `variantConst: Uint8Array` (32 bytes), `buildFingerprint`, `appVersion`, `releaseId`,
  `variantId: number`
- `minValidationIntervalSecs`, `glueBaseUrl`, `onStateChange`

### Errors and helpers

`CopyLockerError` carries `code: number` and `kind: ErrorKind`
(`'malformed' | 'config' | 'entropy' | 'lifecycle' | 'not-entitled' | 'fatal'`); subclasses
`MalformedError`, `ConfigError`, `EntropyError`, `LifecycleError`, `NotEntitledError`,
`FatalLicenseError`; `errorFromCode(code)` maps numeric codes `1–18`. `TransportError` and
`UnsealError` are separate.

Asset container helpers (schema 1, AES-256-GCM, 64 MiB cap):
`sealAsset(finalKey, meta, plaintext, { chunkSize? })`,
`openSealedAsset(finalKey, sealed, { productId, featureId })`,
`decodeSealedAsset(sealed)`. Scheduler helper: `wrapFetch(fetchFn, hint)`.

### `@copylocker/web/ssr`

A no-op stub class with `readonly isSsrStub = true` and structurally identical methods — every
licensing operation rejects. Lets isomorphic apps import one symbol; the real client is created
on the client side only.

## Framework bindings

Thin wrappers that forward verbatim to a `CopyLocker` instance; each exposes exactly
`{ state, activate, deactivate, unseal, loadSealed }`.

| Package | Surface |
|---|---|
| `@copylocker/react` | `<CopyLockerProvider options? instance?>` + `useCopyLocker()`. Peer: `react >= 18`. SSR-safe; the instance is created in an effect. |
| `@copylocker/svelte` | `createCopyLockerStore(options)` → `{ state: Readable<LicenseState>, …, dispose() }`. Peer: `svelte >= 4 \|\| >= 5`. Nothing is created without `window`. |
| `@copylocker/vue` | `app.use(createCopyLocker({ options? instance? }))` + `useCopyLocker()` → `state: Readonly<Ref<LicenseState>>`. Peer: `vue >= 3`. |

## `@copylocker/guard` — runtime integrity

Injected into the bundle entry by `@copylocker/unplugin`. The contract that matters:
`bootGuard` returns the **actually-computed Merkle root `R`**, not a boolean — `R` feeds key
derivation, so patching the guard changes the derived keys.

- `bootGuard(options: BootGuardOptions): Promise<BootResult>` — options:
  `manifest`, `rootPins?`, `strategy: 'sync'|'idle'|'lazy'|'report-only'` (default `'idle'`),
  `chunks?: { url, pattern }[]` (entry chunk first), `fetchImpl?`, `log?`.
  `BootResult = { R: Uint8Array; report: GuardReport; settled: Promise<GuardReport> }`;
  per-entry status is `'ok'|'mismatch'|'missing'|'fetch-error'|'unmatched'`.
- Manifest: `decodeManifest`, `verifyManifestSignature`, `signManifestTbs` (domain
  `copylocker/im-sig/v1`), `ManifestError`.
- Merkle: `leafHash`, `merkleRoot`, `merkleRootFromEntries`.
- Guarded functions: `guardedFn(id, fn, options?)` / `guarded(...)`, `shouldSample(rate)`,
  `startToStringWatch(intervalMs = 5000)`.
- `zeroExcludedRanges(bytes, ranges)` — the runtime half of the two-round self-reference scheme.
- `@copylocker/guard/diagnose`: `diagnose(...)` + `formatDiagnosis(...)` for support bundles.

## `@copylocker/seal` — build-time sealing

Library plus the `copylocker-seal` CLI. Container: schema 1, AES-256-GCM, 12-byte nonces,
default 4 MiB chunks, 64 MiB total cap; bound to `{ productId, variantId, featureId, assetId }`.

- `sealBytes(kek, meta, plaintext, { chunkSize? })` / `openSealedBytes(kek, sealed, expected?)` /
  `decodeSealedAsset(sealed)`.
- `sealAssets({ cwd, globs, featureId, productId, variantId?, kek, outDir?, chunkSize?, assetId? })`
  — no `outDir` means dry-run.
- `sealChunk(options)` — L3 code-chunk sealing; returns `{ sealed, stub, meta }`.
  `chunkLoaderStub(sealedUrl, featureId)` emits the loader, which expects the client at
  `globalThis.__cl` and requires CSP `script-src blob:`.
- KEK registry: `getOrCreateKek(registry, featureId)`, `getKek`, `generateKek`,
  `kekFingerprint`, `loadRegistry` / `saveRegistry`. Defaults: `.copylocker/seal-registry.json`,
  wrapping key from `COPYLOCKER_SEAL_WRAPPING_KEY` or `.copylocker/wrapping-key`.
  **Never commit the registry directory** — it holds plaintext KEKs.
- `SealError` with codes `'CORRUPT' | 'NOT_ENTITLED' | 'CONFIG' | 'IO'`.

## `@copylocker/unplugin` — build integration

One factory, entries per bundler: `@copylocker/unplugin` plus `./vite`, `./rollup`, `./esbuild`,
`./webpack`, `./rspack`, `./farm`, and `./verify`; CLI bin `copylocker-unplugin`. Runs on final
bytes on disk — Vite/Rollup `writeBundle` (`enforce: 'post'`, keep it last in `plugins`), esbuild
`onEnd`, webpack/rspack `afterEmit`, farm `finalizeResources`.

Key options (`CopyLockerOptions` from the plugin, not the web SDK):

| Option | Default | Purpose |
|---|---|---|
| `productId` | — | **Required.** |
| `include` / `exclude` | `**/*.js`, `**/*.css`, `**/*.wasm` / `**/*.map` | Files covered by the integrity manifest. |
| `hasher` | `'sha256'` | `'blake3'` is rejected in M4-A; a custom `(bytes) => Promise<Uint8Array>` is accepted. |
| `signer` | — | `{ kind: 'local', keyFile }`, `{ kind: 'remote', endpoint, token }`, or `(tbs) => Promise<Uint8Array>`. Omitting it produces an unsigned dev build with a warning. |
| `rootPins` | — | 64-hex Ed25519 keys → injected as `__CL_ROOT_PINS__`. |
| `suiteId` | `'01000001'` | 8 hex chars; CL-STD-1. |
| `seal` | — | `{ assets?, feature?, chunks?: { match, feature }[], registryFile?, wrappingKeyFile?, cwd? }`. |
| `guard` | — | `{ decorator?, sampleRate? (0.15), strategy? ('idle') }`. |
| `splitConstants` | — | 1–32; splits `K_BUILD` into `__CL_K_BUILD_<i>__` shards. |
| `randomizeWasmExports` | `false` | Rename WASM exports per build. |
| `urlBase` | — | Chunk-URL prefix; the Vite adapter derives it from `base`. |

Helpers: `generateLocalKeyFile(keyFile)` (returns the public key hex), `resolveSigner`,
`makeBuildFingerprint`, `makeBuildSeed`. Per build the plugin creates a fresh `BuildIdentity`,
rewrites `guardedFn` markers, hashes covered files, injects the guard prelude (two-round
self-reference backfill), signs the manifest, seals configured assets/chunks, and injects the
`__CL_*` constants.

`@copylocker/unplugin/verify`: `verifyDist({ distDir, publicKeys?, manifestPath? })` →
`VerifyResult { ok, signature, expectedRoot, actualRoot, rootMatches, … }`, plus
`formatVerifyResult`. Wire this into CI: with `publicKeys` set, an unsigned or wrongly-signed
`dist/` fails the check.

## `@copylocker/telemetry`

`createTelemetryHook(config)` → a hook to pass as `CopyLockerOptions.telemetry`; the block
piggybacks on `/v1/validate` (max 512 bytes).

- Config: `tier: 'off'|'T0'|'T1'` (T1 requires a `consent` provider returning the privacy-notice
  version; `0` = no consent), `featureWhitelist`, `sessionBuckets` (default `[300, 1800, 7200]`),
  `windowSecs` (default 7 days), `maxBlockBytes`. Illegal combinations throw
  `TelemetryConfigError`.
- Hook: `track(featureId)`, `recordSession(durationSecs)`, `buildBlock(now?)` (consent is
  consulted before **every** report; the window resets at build time), `stats()` →
  `{ blocksBuilt, consentSkips, clippedFields, droppedFeatures, droppedFeatureHits }`.
- Hard caps (`clipBlock`): 64 features, 10,000 hits/sessions, 28 days active, 128-char feature
  ids. What the server does with the block is in
  [Operations → Telemetry & DSR](/docs/operations/privacy).

## Native stacks

### `@copylocker/node` (NAPI binding over the Rust core)

`CopyLockerNative.create(config: NativeConfig)` →
`activate(key)`, `deactivate()`, `state()` (advisory), `unseal(feature, data): Promise<Buffer>`,
`challenge(input)`, `offlineRequest(key)`, `offlineImport(data)`, `importOlk(armored)`.
`NativeConfig`: `serverUrl, appId, productId, appVersion, releaseId, buildFingerprint,
currentRootKey, nextRootKey?, fingerprintSalt, variantId, variantConst (32B), evidence,
allowUnboundOlk?, allowInsecureLocalhost?`. `collectEvidence({ modulePath, asarPath?,
expectedModuleDigest })` computes the non-boolean evidence digest at construction.

### `copylocker-client` (Rust desktop core)

`CopyLockerClient::new(config) -> Result<Self, ClientInitError>` (generic over the crypto suite,
default `ClStd1`), or `with_components(config, transport, store, fingerprint_provider)` for full
control. Methods: `activate(key)`, `activate_with_account(token)`,
`build_offline_request(key)` / `import_offline_response(bytes)` / `import_olk(armored)`,
`validate()`, `deactivate()`, **`feature_key(feature) -> Result<Secret<[u8; 32]>, CoreError>`**
(the key-derivation entry point), `unseal(feature, sealed)`, `challenge(input)`,
`state()` (advisory), `subscribe()` (stream of `StateChange`), `hint_online()`.
`Config::new(server_url, app_id, product_id, client_info, current_root_key, fingerprint_salt,
variant_const, evidence)` with builders `with_next_root_key`, `with_device_attribute_reporting`
(requires an explicit privacy acknowledgement), `with_unbound_olk`, `with_insecure_localhost`,
`with_request_timeout`, `with_scheduler`.

### `copylocker-ffi` (C ABI)

Opaque `cl_client` from `cl_create(*const cl_config, *mut cl_error)`, released by `cl_destroy`.
Functions: `cl_activate`, `cl_deactivate`, `cl_state` (numeric code),
`cl_unseal` / `cl_challenge` / `cl_offline_request` (return `cl_buf`; free with `cl_free_buf`),
`cl_offline_import`, `cl_import_olk`. `cl_config` carries the same fields as `NativeConfig`;
`variant_const` and `module_digest` are exactly 32 bytes.

### `@copylocker/tauri`

JS commands under `plugin:copylocker|`: `activate`, `deactivate`, `state`, `unseal`,
`challenge`, `offlineRequest`, `offlineImport`, `importOlk`, and `onStateChanged(handler)`
(event `copylocker://state-changed`). Failures normalize to `CopyLockerCommandError { code }`.
Rust host: `copylocker_tauri::init(CopyLockerConfig::new(server_url, app_id, product_id,
app_version, release_id, build_fingerprint, current_root_key, fingerprint_salt, variant_id,
variant_const, expected_module_digest))` with builders `with_next_root_key`,
`with_unbound_olk`, `with_insecure_localhost`.

### `@copylocker/electron`

Three entries. **Main**: `CopyLocker.create(config, dependencies?)` +
`attachIpc(policy?)` — asserts every `webContents` runs with `contextIsolation=true,
nodeIntegration=false, sandbox=true` and destroys insecure new ones; `IpcPolicy` gates
activation, per-feature unseal, challenge, and rate limits (defaults 60 s / 120 req / 8 MiB).
**Preload**: `installCopyLockerBridge()` exposes a frozen `window.__cl` (throws unless
context-isolated and sandboxed). **Renderer**: `new CopyLockerRendererClient()` with the same
method set; IPC channels are `cl:activate`, `cl:unseal`, etc.
