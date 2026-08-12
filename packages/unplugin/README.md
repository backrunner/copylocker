# @copylocker/unplugin

Build-time integrity plugin for CopyLocker web targets — Vite, Rollup,
esbuild, webpack, rspack, and farm. It digests every build artifact,
assembles a signed `IntegrityManifest`, injects the `@copylocker/guard`
runtime bootstrap into the entry chunk, and (optionally) seals assets/code
chunks through `@copylocker/seal`.

**The one-sentence contract:** at runtime the injected bootstrap boots
`bootGuard()` and publishes the **actually-computed** Merkle root as
`globalThis.__CL_GUARD_R__` (a `Promise<Uint8Array>`). A tampered bundle
computes a different `R`; wiring `R` into `@copylocker/web`'s
`integrity.manifestRoot` hook makes the derived `FinalKey` wrong, so sealed
assets simply fail to open. The prelude additionally injects
`__CL_REQUIRE_INTEGRITY_PROOF__ = true` so that deleting the guard bootstrap
(no `R` at all) fails derivation closed instead of falling back to the
static constant — see "Injected runtime contract". The reference integration
lives in `examples/vite-spa`.

- Runtime dependency: `unplugin` only (plus the sibling `@copylocker/guard`
  and `@copylocker/seal` build-time libraries). Vite/Rollup/esbuild/
  webpack/rspack/farm are optional peer dependencies — install the one(s)
  you build with. Node ≥ 20.

```ts
// vite.config.ts
import copylocker from '@copylocker/unplugin/vite'

export default defineConfig({
  plugins: [
    // …everything else (minify, obfuscators, SRI)…
    copylocker({
      productId: 'my-app',
      signer: { kind: 'remote', endpoint: process.env.CL_SIGN_URL!, token: process.env.CL_SIGN_TOKEN! },
      rootPins: [process.env.CL_ROOT_PIN!],
      randomizeWasmExports: true,
      splitConstants: 4,
      seal: { assets: [{ globs: ['assets/pro-*.json'], feature: 'pro' }] },
      guard: { sampleRate: 0.15 },
    }), // LAST — see "Plugin order"
  ],
})
```

Rollup: `import copylocker from '@copylocker/unplugin/rollup'` (same options
object). esbuild: `import copylocker from '@copylocker/unplugin/esbuild'`
(requires `outdir`; the plugin forces `metafile: true` to find entry chunks).

```js
// webpack.config.js — same options object
const copylocker = require('@copylocker/unplugin/webpack').default
module.exports = { plugins: [/* …everything else…, */ copylocker({ /* … */ })] }

// rspack.config.mjs
import copylocker from '@copylocker/unplugin/rspack'
export default { plugins: [copylocker({ /* … */ })] }

// farm.config.ts
import copylocker from '@copylocker/unplugin/farm'
export default defineConfig({ plugins: [copylocker({ /* … */ })] })
```

For webpack/rspack/farm keep the plugin LAST in the `plugins` array — tap
order follows registration order, and the digests must cover the final bytes
(see "Plugin order"). Farm forces `NODE_ENV=production` during `build()`, so
a local signer needs `allowLocalInProduction: true` there (or use a remote
signer).

The `urlBase` option prefixes the runtime chunk URLs baked into
`__CL_CHUNKS__` (the guard bootstrap fetches them verbatim). The Vite adapter
derives it from the vite `base` config; everywhere else it defaults to
output-relative URLs, so set it when the out dir is served under a sub-path
(e.g. Next.js serves the webpack client output at `/_next/`).

## What a build produces

- Every covered output (default `**/*.js`, `**/*.css`, `**/*.wasm`, minus
  `**/*.map`) is digested and recorded in the manifest under its
  output-relative POSIX path.
- Each entry chunk gets a **prelude** prepended: a
  `globalThis.__CL_GUARD_CONFIG__` assignment followed by the self-contained
  guard bootstrap (the `@copylocker/guard` runtime, prebundled — no import
  rewriting, no extra chunks).
- `<outdir>/.copylocker/manifest.cbor` — the signed manifest (FR-BLD-010
  input for the verify CLI).

The pipeline runs on the **final bytes** — `writeBundle` for Vite/Rollup,
`onEnd` + outdir reads for esbuild, `afterEmit` + outdir reads for
webpack/rspack, and `finalizeResources` for farm (farm writes the returned
bytes verbatim; it has no awaited post-write hook) — after the host's own
internal finalization passes (e.g. Vite's module-preload placeholder
resolution), so the digests always cover what is actually served. Sourcemaps
are fine: the `//# sourceMappingURL` comment is part of the digested bytes.

## Two-round self-reference (design §2.3)

The manifest contains the entry chunk's digest, and the entry chunk embeds
the manifest — a cycle, broken with fixed-length placeholders:

1. The prelude is emitted with the `manifest` and `root` config fields
   filled with ASCII `'0'` placeholders of their exact final length
   (`2 × <manifest CBOR bytes>` and 64 hex chars). The placeholder length is
   found by fixpoint iteration (≤ 8 rounds; all backfilled values are
   fixed-size, so it converges in 2–3).
2. **Round 1:** the entry chunk is digested with the two placeholder spans
   **zeroed**; the spans are recorded as the entry's `excludedRanges`
   `[start, end)` — byte offsets, exact because the prelude is pure ASCII
   (non-ASCII output file names are rejected with a clear error).
3. **Round 2:** the real manifest hex and Merkle-root hex are written into
   the spans. Lengths never change, so no other offset moves.
4. Runtime: `@copylocker/guard` zeroes `excludedRanges` before digesting →
   the recomputed digest (and root `R`) matches the manifest.

The tests prove the round-trip on real Vite/Rollup/esbuild/webpack/rspack/
farm output: the backfilled chunk, zeroed at the manifest's
`excludedRanges`, digests to the manifest's recorded digest, and `bootGuard`
over the dist bytes returns `R === manifest.root`. Flipping one byte in any
chunk changes `R`; writing inside the placeholder spans does not.

## Injected runtime contract

The prelude/bootstrap publishes these globals (consumed by `@copylocker/web`
and `@copylocker/guard`):

| global | type | meaning |
|---|---|---|
| `__CL_GUARD_CONFIG__` | object | raw prelude config (hex manifest, pins, chunk map, kbuild, wasmDigests, strategy, sampleRate) |
| `__CL_MANIFEST__` | `Uint8Array` | CBOR `signed_integrity_manifest` (guard's v1 wire format) |
| `__CL_ROOT_PINS__` | `string[]` | hex Ed25519 public keys |
| `__CL_CHUNKS__` | `{url, pattern}[]` | static chunk map, **entry chunk first**; patterns are the manifest key-6 keys |
| `__COPYLOCKER_K_BUILD__` | string | 64-hex K_BUILD (when `splitConstants` is 1) |
| `__CL_K_BUILD_<i>__` | string | K_BUILD hex shards (when `splitConstants: N > 1`); `@copylocker/web` concatenates `0..N-1` |
| `__COPYLOCKER_MANIFEST_ROOT__` | string | expected root (64 hex) — fallback constant for `resolveBuildConstants` |
| `__CL_WASM_DIGEST__` | string | build-time SHA-256 (64 hex) of the covered `.wasm` artifact — published only when **exactly one** `.wasm` asset is covered; `@copylocker/web` compares it against the digest of the wasm it actually loaded and fails closed on mismatch |
| `__CL_WASM_DIGESTS__` | `{file: hex}` | the same digest for every covered `.wasm` asset (the map form, for custom wiring) |
| `__CL_GUARD_FN__` | function | `guardedFn` wrapper with the configured `sampleRate`; target of the `@guarded` marker rewrite |
| `__CL_GUARD_R__` | `Promise<Uint8Array>` | **the actually-computed root** — wire into `CopyLocker.create({ integrity: { manifestRoot: () => __CL_GUARD_R__ } })` |
| `__CL_REQUIRE_INTEGRITY_PROOF__` | `true` | emitted by the **prelude** (not the bootstrap), between the config assignment and the bootstrap. `@copylocker/web` reads it as the default for `requireIntegrityProof`: when set, key derivation fails closed if no guard `R` is available, instead of falling back to the static `MANIFEST_ROOT` constant. Deleting the bootstrap removes `R` but not this flag, so the "delete the guard" attack derails derivation instead of silently succeeding |

Do not import `@copylocker/guard` from application code for `bootGuard`
— the plugin bundles its own copy; use `guardedFn` in source (the transform
rewires it to `__CL_GUARD_FN__` and the import is tree-shaken away).

## Signer (FR-BLD-003, design §2.5)

```ts
signer: { kind: 'local', keyFile: '.copylocker/signing-key.json' }        // dev
signer: { kind: 'remote', endpoint: '…', token: '…', timeoutMs: 10000 }   // CI
signer: async (tbs) => Uint8Array                                          // custom
```

- `local` — Ed25519 key file (JWK JSON, mode `0600`; create one with
  `copylocker-unplugin keygen <file>`). Its public key is automatically added
  to the injected root pins. With `NODE_ENV=production` this is an **error**
  unless `allowLocalInProduction: true` (then it warns). Note `vite build`
  sets `NODE_ENV=production` by default — for a signed local development
  build use `vite build --mode development` or the override flag.
- `remote` — POSTs the raw tbs bytes (`application/octet-stream`,
  `Authorization: Bearer <token>`) and expects the 64-byte Ed25519 signature
  as the response body. Failures are classified: `SignerError.code` is
  `'http' | 'timeout' | 'network' | 'bad-response'`. Pair with explicit
  `rootPins`.
- custom function — receives the raw tbs, must return 64 bytes.

The signed message is always `"copylocker/im-sig/v1" ‖ tbs` — exactly what
the guard runtime's `verifyManifestSignature` checks. Local signing goes
through the guard package's own `signManifestTbs`; remote/custom signers
must apply the same domain separator (the CopyLocker signing service does).
Omitting `signer` emits an **unsigned development manifest** (warned).

`hasher`: `'sha256'` (the only algorithm the guard runtime computes) or a
custom `(bytes) => Promise<Uint8Array(32)>`. `'blake3'` is rejected in M4-A —
the runtime would compute SHA-256 anyway (documented in `@copylocker/guard`).

## `@guarded` collection

Write guarded functions with the functional form:

```ts
import { guardedFn } from '@copylocker/guard'
export const compute = guardedFn('engine.compute', (x) => { /* … */ })
```

The transform rewrites these call sites to the minify-proof global marker
`__CL_GUARD_FN__` (an undeclared global — minifiers never rename it), and the
pipeline digests each function body **from the final minified chunk text**
using the guard package's own `normalizeSource`:
`SHA-256(utf8(normalizeSource(fnSource)))` → manifest key 7. `guard:
{ sampleRate }` tunes the runtime sampling rate (default 0.15).
`guard.decorator: true` is accepted but reserved: decorator-syntax body
collection depends on the transpiler's emit and lands in M4-B — use
`guardedFn` for guaranteed collection.

## Sealing (`@copylocker/seal`)

```ts
seal: {
  assets: [{ globs: ['assets/pro-*.json'], feature: 'pro' }], // or bare strings + `seal.feature`
  chunks: [{ match: /pro-features/, feature: 'pro' }],        // L3, opt-in
  registryFile: '.copylocker/seal-registry.json',             // defaults
  wrappingKeyFile: '.copylocker/wrapping-key',
  cwd: process.cwd(),                                          // glob root
}
```

- `assets` are sealed into `<outdir>/<asset>.sealed` during the build; the
  KEK registry lifecycle is entirely the seal package's (encrypted registry,
  mode `0600`, `COPYLOCKER_SEAL_WRAPPING_KEY` env or key file). Asset ids are
  registered in manifest key 8.
- `chunks` (L3) replaces matched non-entry chunks with the seal package's
  loader stub and emits `<chunk>.sealed` payloads. **CSP trade-off:** the
  stub needs `script-src blob:` and a runtime client at `globalThis.__cl`
  (see the `@copylocker/seal` README). Off by default. Matching the entry
  chunk is an error (the entry carries the guard bootstrap).

## WASM export randomization (build-time hardening)

```ts
copylocker({ productId: 'my-app', randomizeWasmExports: true })
```

Post-processes `wasm-bindgen` output on the final build bytes: every covered
`.wasm` asset gets new export names derived from the per-build seed
(`__cl_<16 hex of SHA-256(seed ‖ name)>`), the binary's export section is
re-encoded (a minimal LEB128 section rewriter in `src/wasm-randomize.ts` —
no wasm toolchain dependency), and every covered JS chunk that references
those exports — the generated glue — is rewritten to match. Same seed → same
names; a different seed (i.e. every build) → different names. The custom
`name` section is stripped while rewriting: it duplicates exactly the symbol
names this pass hides, and nothing at runtime reads it.

**This is obfuscation / diversification, not cryptographic protection**
(design `40-web-sdk-wasm-ts.md` §5): a name-based generic patch script can
no longer locate `clsession_step` & friends, and every published build has
different symbol names; a determined human attacker is unaffected.

Mechanics and deliberate limits:

- The rename runs **before** any digest is computed, so the manifest, the
  guard runtime, and `verifyDist` all cover the renamed bytes unchanged.
- Glue references are rewritten in the forms wasm-bindgen actually emits:
  `.<name>` property access (property names survive minification even when
  the `wasm` variable itself is mangled) and `["<name>"]` / `['<name>']`
  bracket access. String literals and unrelated identifiers are never
  touched.
- The `memory` export keeps its name (`.memory` is too generic to rewrite
  textually without risking unrelated code) — it carries no CopyLocker
  semantics. Export names shorter than 4 characters or not valid JS
  identifiers are likewise kept.
- A `.wasm` asset whose exports are referenced by **no** covered chunk is
  skipped with a warning: renaming without rewriting the glue would break
  the runtime. If you see that warning, the glue is outside your `include`
  set (or the wasm is loaded by hand) — widen `include` or keep the option
  off for that build.
- Round-trip tested: the renamed verifier wasm plus rewritten glue
  initializes and behaves identically to the original build.

## WASM digest injection (WASM_DIGEST, design §5)

No option — always on. Every covered `.wasm` asset is digested (SHA-256, the
same algorithm `@copylocker/web` uses at load time, regardless of the
configured `hasher`) and the map rides in the prelude config; the bootstrap
publishes `__CL_WASM_DIGESTS__` (file → hex) and, when exactly one `.wasm`
asset is covered, the singular `__CL_WASM_DIGEST__`. The digest is computed
**after** export randomization, so the constant binds the final emitted
bytes.

`@copylocker/web` compares the injected constant against the SHA-256 of the
wasm bytes it actually loaded: a swapped or patched `.wasm` fails `create()`
closed with the indistinguishable `NotEntitledError` (code 17, NFR-SEC-011).
When no covered `.wasm` asset exists the plugin warns and injects an empty
map (no constant is published — a dev build without the unplugin behaves the
same way). Like everything in this section, this is tamper evidence, not
cryptographic protection.

## `copylocker-unplugin verify` (FR-BLD-010)

```bash
copylocker-unplugin verify dist --pubkey <64-hex>
copylocker-unplugin keygen .copylocker/signing-key.json
```

`verify` reads `dist/.copylocker/manifest.cbor`, recomputes every artifact
digest from disk (zeroing `excludedRanges`), rebuilds the Merkle root, and
optionally verifies the Ed25519 signature. It prints a per-entry
expected/actual comparison and exits non-zero on any mismatch — wire it into
CI between build and publish. Tampering with one byte of any artifact fails
the run (tested).

## Plugin order

The digest must cover the final served bytes, so the plugin must run **after**
minifiers, obfuscators, and SRI/banner plugins:

| plugin | order guidance |
|---|---|
| vite minify (esbuild/oxc) | internal — safe: this pipeline reads final bytes from disk in `writeBundle` |
| terser / obfuscator plugins | put `copylocker` AFTER them in `plugins` (`enforce: 'post'` is set) |
| SRI / banner / license plugins | put `copylocker` after them, or their additions are not covered |
| gzip/brotli precompressors | unaffected (they emit new files; exclude or include via glob as desired) |

## Multi-bundler status

| bundler | pipeline hook | status |
|---|---|---|
| Vite | `writeBundle` (disk) | ✅ integration-tested (real build → bootGuard R == manifest.root → tamper detected) |
| Rollup | `writeBundle` (disk) | ✅ integration-tested |
| esbuild | `onEnd` + outdir (disk) | ✅ integration-tested (requires `outdir`, forces `metafile`) |
| webpack ≥ 5 | `afterEmit` + outdir (disk) | ✅ integration-tested (incl. a watch-mode rebuild test) |
| rspack ≥ 1 | `afterEmit` + outdir (disk) | ✅ integration-tested |
| farm ≥ 1 | `finalizeResources` (in-memory, written verbatim) | ✅ integration-tested |

### Next.js (webpack adapter)

Next 16 builds with Turbopack by default; there is no Turbopack adapter
(Turbopack's plugin surface is Rust-side and exposes no post-emit hook), so
integrity builds use `next build --webpack` and push the plugin in
`next.config.ts` for the production **client** compilation only:

```ts
webpack(config, { dev, isServer }) {
  if (!dev && !isServer) {
    config.plugins.push(
      copylocker({
        productId: 'my-app',
        signer: { kind: 'remote', endpoint: process.env.CL_SIGN_URL!, token: process.env.CL_SIGN_TOKEN! },
        urlBase: '/_next/',                 // `.next/` is served at /_next/
        include: ['static/**'],             // only browser-served bytes are fetchable at runtime
        exclude: ['**/*.map', '**/_ssgManifest.js'], // written by Next AFTER the client compilation
      }),
    )
  }
  return config
}
```

The full reference integration (including the `__CL_GUARD_R__` wiring and
the nonce-CSP interplay) is `examples/nextjs-app`. Turbopack builds
(`next build`, `next dev`) run without injection and fall back to the
development defaults.

### Known differences between bundlers

- **webpack/rspack hook choice.** `compilation.hooks.processAssets` (even at
  `PROCESS_ASSETS_STAGE_REPORT`) runs *before* emit, so anything written
  later — `emit`-hook writers, and on some setups plugins that rewrite
  assets at the last moment — would escape the digests. The plugin therefore
  taps `compiler.hooks.afterEmit` (which receives the `compilation` for
  entry discovery via `compilation.entrypoints`) and reads the terminal
  bytes back from `output.path`, identical in spirit to the esbuild adapter.
  Consequence: with `webpack-dev-server`'s in-memory output nothing is on
  disk — the pipeline skips with a warning instead of crashing (dev output
  is out of scope, like the Vite adapter's `apply: 'build'`). Watch mode
  (`webpack --watch`, real disk) re-runs the full pipeline per rebuild;
  there is a regression test for this.
- **Content-hashed file names.** webpack/rspack `[contenthash]` and farm's
  hashed chunk names are computed over the *pre-injection* bytes; the
  prelude backfill deliberately does not rename files, so the hash in a name
  no longer matches the final content. This is cosmetic — the manifest
  records the real bytes under the real names and `bootGuard`/`verifyDist`
  validate those. If a CDN or SRI-like gate revalidates name hashes, disable
  filename hashing.
- **rspack hashing.** rspack's built-in hash/SRI functions are irrelevant
  here: all integrity digests are computed by the plugin itself (SHA-256),
  never by the bundler.
- **farm specifics.** `finalizeResources` is farm's only awaited hook late
  enough (its `writeResources` fires after the disk write but is not
  awaited, and `finish` fires before it); the pipeline patches entry-chunk
  bytes in memory and farm writes them verbatim, while the manifest copy is
  written to `<outdir>/.copylocker/manifest.cbor` by the plugin itself
  (farm's output cleaning runs before compile, so it survives). Farm's
  `build()` forces `NODE_ENV=production` in-process — pair a `local` signer
  with `allowLocalInProduction: true` or use a remote signer. A farm plugin
  error during build aborts the process via farm's own logger (farm
  behavior, not the plugin's).

## Wire-format alignment

The manifest is encoded with a local canonical CBOR encoder
(`src/cbor.ts`, RFC 7049 §3.9) that exists only because `@copylocker/guard`
does not export its codec. Alignment is proven, not assumed: every test
manifest round-trips through the guard package's strict `decodeManifest`,
Merkle roots are computed by the guard package's `merkleRootFromEntries`,
placeholder zeroing uses its `zeroExcludedRanges`, and local signing uses its
`signManifestTbs`. Merkle leaf order is canonical CBOR key order
(`src/cbor.ts` `canonicalTextKeyOrder`), matching the decoder's enforcement.

## Limitations and deferred work

- **M4-B remainder:** `guard.decorator` syntax collection; custom
  `verifierRuntime`; optional manifest upload to R2; `loadSealed` client
  injection (`globalThis.__cl`) for sealed chunks.
- **M5 remainder:** `blake3` hasher.
- **`splitConstants` dispersion.** Shards are injected as N separate
  `__CL_K_BUILD_<i>__` values, but all of them currently live in the
  entry-chunk prelude — the design's "shards spread across different
  chunks" (design §5 常量分散) is NOT implemented. The pipeline works on
  final disk bytes and has no import-graph/eager-load information, so a
  shard appended to a lazily-loaded chunk might not exist when the first
  key derivation runs — and derivation fails closed, locking out paying
  users (the worst failure mode, design §3.3). A safe version needs the
  guard runtime to collect shards from the chunk bytes it already fetches
  during verification, which is a cross-package change
  (`@copylocker/guard` + `@copylocker/web`), deliberately not
  half-implemented here.
- Output file names must be ASCII (byte-exact `excludedRanges`).
- The bootstrap is injected into every entry chunk; code-split setups where a
  shared chunk evaluates before the entry prelude are covered by a microtask
  retry, but exotic multi-entry HTML builds should verify with
  `copylocker-unplugin verify` in CI.
- The build half of `@guarded` records digests; combining `GuardState` into
  key derivation is the web integration task that consumes `__CL_GUARD_R__`.

## License

GPL-3.0-only.
