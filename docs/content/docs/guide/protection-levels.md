---
title: Protection Levels (L0–L4)
navTitle: Protection Levels (L0–L4)
order: 3
description: How to actually integrate CopyLocker, and how much work each protection level forces an attacker to redo.
---

# Protection Levels (L0–L4)

How to actually integrate CopyLocker, and how much work each choice forces an attacker to redo.
This guide is the consumer-facing version of `.agents/03-modules/60-instrumentation-guard.md`,
with code aligned to the shipped SDKs (`packages/web`, `crates/copylocker-client`).

## The mental model

**Wrong:** "I call the SDK to check whether a license exists, and exit if not."

**Right:** "Part of my application physically cannot be decrypted until a valid credential
derives its key."

```ts
// ❌ one `if` between the attacker and your product
if (!license.valid) return
doExpensiveWork()

// ✅ no key, no content
const key = await cl.unseal('pro', sealedConfig)
doExpensiveWork(JSON.parse(decode(key)))
```

## The levels

| Level | Technique | Integration cost | Cracking cost | Use for |
|---|---|---|---|---|
| **L0** | Single `if (!valid) exit()` | 5 minutes | Minutes | ❌ Not recommended; demos only |
| **L1** | Multi-point async instrumentation + delayed, randomized failure | Half a day | Hours | Cheap tools, trial limits |
| **L2** | Critical **config/data** sealed under a feature key | 1 day | Requires one legitimate credential | ✅ **Default recommendation** |
| **L3** | Critical **code chunks / WASM segments** sealed | 2–3 days | A legitimate credential + repeated per-version work | High-value software |
| **L4** | Critical computation server-side | Business-dependent | Cannot be cracked offline | SaaS-shaped, AI-shaped products |

Pick L2 to start. Every level below has complete, copyable examples.

## L1: instrumentation discipline (when L2+ does not apply)

Principles:

| Principle | Meaning |
|---|---|
| Multi-point | At least 5–10 instrumentation points across different modules |
| Async | Points are hints; validation happens asynchronously, never blocking the user |
| Delayed | On failure, degrade after a random delay (minutes to hours), never crash instantly |
| Diverse | Different points fail differently (missing feature, wrong result, silent degradation) |
| Deep | Inside core business flows, not at startup |
| No strings | No greppable strings like `"license"` or `"trial expired"` |

Anti-patterns: a single `checkLicense()` choke point, a one-time startup check, user-visible
license strings, and blocking synchronous validation.

Recommended shape — the hint is a side effect; the seal is the gate:

```ts
async function exportProject(project: Project) {
  cl.hintOnline()                                        // opportunistic revalidation hint
  const key = await cl.unseal('export', SEALED_EXPORT_PROFILE)  // ← the actual gate
  return runExport(project, decodeProfile(key))
}
```

## L2: sealed data (default)

### What to seal

Good candidates: configuration/parameter tables, pro templates and assets, model weights, API
endpoints and credentials for your own backend (this also stops free users from abusing it), and
business rules (pricing, tax tables, format mappings).

Poor candidates: anything recoverable from the UI, huge rarely-changing assets (decrypt cost on
every run — use KEK caching), and open-source code.

### Web

Seal at build time with `@copylocker/unplugin` (which drives `@copylocker/seal`):

```ts
// vite.config.ts
copylocker({
  // …
  seal: { assets: [{ globs: ['assets/pro-*.json'], feature: 'pro' }] },
})
```

Open at runtime with the real `@copylocker/web` API — `loadSealed(url, featureId)`:

```ts
const preset = JSON.parse(new TextDecoder().decode(
  await cl.loadSealed('/assets/pro-presets.json.sealed', 'pro')
))
```

### Desktop (Rust client core)

`crates/copylocker-client` exposes `unseal(&self, feature: &str, sealed: &[u8])`:

```rust
let bytes = client.unseal("pro", include_bytes!("../assets/pro/presets.sealed"))?;
```

### Failure UX matters

When a seal does not open, the user must see a meaningful prompt, not a crash. Distinguish "not
entitled" from "corrupt file / network problem" — otherwise a paying user with a CDN hiccup
concludes you treated them as a pirate. On the web SDK, errors are typed classes
(`packages/web/src/errors.ts`):

```ts
import { NotEntitledError, UnsealError, TransportError } from '@copylocker/web'

try {
  data = await cl.loadSealed(url, 'pro')
} catch (e) {
  if (e instanceof NotEntitledError) showUpgradePrompt()        // no entitlement
  else if (e instanceof TransportError) showConnectPrompt()     // network / offline
  else if (e instanceof UnsealError) showReinstallPrompt()      // corrupt or tampered bytes
  else showGenericError()
}
```

<details class="cl-details">
<summary>Why the internal design sketch differs</summary>
<p>The internal module doc shows string codes (<code>e.code === 'NOT_ENTITLED'</code>). The shipped web SDK instead throws typed errors carrying a numeric <code>code</code> (NFR-SEC-011: no greppable feature strings). The classes above are the real contract.</p>
</details>

## L3: sealed code

### Web chunks (opt-in)

```ts
copylocker({
  seal: { chunks: [{ match: /features\/pro\//, feature: 'pro' }] },
})
```

The matched chunk is replaced by a loader stub at build time:

```js
export default async function load() {
  const code = await __cl.loadSealed('/chunks/pro-x7f2.js.sealed', 'pro')
  return import(URL.createObjectURL(new Blob([code], { type: 'text/javascript' })))
}
```

**CSP trade-off:** the Blob-URL dynamic import needs `script-src blob:`. If that is unacceptable,
use the WASM variant.

### WASM segments (no eval, recommended)

Compile the pro functionality to a standalone `.wasm` and seal it whole:

```ts
const wasmBytes = await cl.loadSealed('/pro.wasm.sealed', 'pro')
const { instance } = await WebAssembly.instantiate(wasmBytes, imports)
```

`WebAssembly.instantiate` from an `ArrayBuffer` only needs `wasm-unsafe-eval` — no
`unsafe-eval` — and suits compute-heavy core logic.

### Desktop

```rust
// Ship critical logic as a sealed .wasm or data-driven bytecode module.
let module = client.unseal("pro", PRO_MODULE_SEALED)?;
let engine = wasmtime::Module::from_binary(&engine, &module)?;
```

Or simpler: seal the critical data tables and keep code in plaintext that cannot run without
them.

## Using feature keys correctly

`feature_key` exists for cases where you decrypt with your own AEAD instead of `unseal`. The
Rust client signature is
`feature_key(&self, feature: &str) -> Result<Secret<[u8; 32]>, CoreError>`:

```rust
// ✅ correct: the key does real work
let key = client.feature_key("pro")?;
let plaintext = aead_open(&key, &sealed_data)?;

// ❌ wrong: collapsing the key to a boolean is L0 again
let has_pro = client.feature_key("pro").is_ok();
if has_pro { /* … */ }
```

SDK guardrails:

- `feature_key()` returns `Secret<[u8; 32]>` with no `Debug`/`Display`/`PartialEq`, so it cannot
  be casually printed or compared.
- Every `feature_key` example should be followed by a real decryption use.
- After a transition to `Locked`/`Revoked`, `feature_key()` fails and **cached plaintext is
  yours to clear**:

```ts
cl.onStateChange((s) => {
  if (s === 'Locked' || s === 'Revoked') assetCache.clear()
})
```

## Trials

No special mechanism — entitlements plus `not_after`:

```text
Policy: validity = Trial(14d, once_per = fingerprint), seats = 1, features = ['trial']
```

Trial assets are sealed under the `trial` feature; paid assets under `pro`. Expiry → `Locked` →
no key. Re-trial abuse is bounded server-side by fingerprint dedup (one trial per fingerprint,
with tolerance matching so a new NIC does not reset it). Trials are pinned to one seat and cannot
transfer machines.

## Go-live checklist

- [ ] Picked a protection level (start at L2)
- [ ] At least one genuinely necessary asset is sealed
- [ ] Every `feature_key()` call is followed by real decryption use
- [ ] No `if (state === 'Active')`-style gate anywhere
- [ ] Error UX distinguishes *not entitled* / *needs online* / *corrupt file*
- [ ] `grace_secs` is sane (≥ 30 days for a first launch)
- [ ] The guard ran one full release in `'report-only'`-equivalent observation before enforcement
- [ ] Staged rollout 1% → 10% → 100%, watching `/v1/integrity/report` and the activation failure rate
- [ ] Support scripts and a manual credential re-issue process are ready
- [ ] The Root public key is pinned and `root_next` is pre-provisioned
- [ ] The production signer is not `local` (see [signer modes](/docs/guide/web-sdk#build-time-integration-unplugin--guard--seal))
