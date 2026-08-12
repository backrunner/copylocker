# What is CopyLocker

CopyLocker is a licensing and anti-tamper toolkit for software vendors. It has two halves:

- **A licensing server you self-host** on Cloudflare (Workers + D1 + Durable Objects + KV +
  R2 + Queues), deployed from the `server-template/` in this repository and operated through the
  `copylocker` CLI. It issues, renews, and revokes licenses; resolves entitlements; and keeps an
  immutable audit trail.
- **Client SDKs** — native (Rust core with C ABI, Node-API, Tauri, Electron) and web
  (`@copylocker/web` on a WASM core, plus the `@copylocker/unplugin` / `@copylocker/guard` /
  `@copylocker/seal` build tooling) — that activate a machine, hold its credential, and derive
  per-feature keys.

## The one idea that matters

Most licensing systems reduce to a boolean the client checks and an attacker patches:

```ts
// ❌ one `if` between the attacker and your product
if (!license.valid) return
doExpensiveWork()
```

CopyLocker's model is **productive verification** (ADR-0004): the check produces the key material
that decrypts the content. There is no branch to remove:

```ts
// ✅ no key, no content
const key = await cl.unseal('pro', sealedConfig)
doExpensiveWork(JSON.parse(decode(key)))
```

`unseal()` either returns plaintext or throws. The [Protection Levels](./protection-levels) guide
explains how far to take this (L0–L4) and when each level is appropriate.

## What the cryptography does — and does not do

The cryptography is real: hybrid post-quantum signatures (ML-DSA 44/65/87 + Ed25519), X-Wing
(ML-KEM-768 + X25519) key encapsulation, XChaCha20-Poly1305 AEAD, domain-separated KDFs, and
canonical CBOR throughout, with public known-answer vectors in `vectors/CL-STD-1/`.

The client-side hardening (integrity manifests, two-stage key derivation, symbol randomization) is
**engineering inseparability, not mathematical protection**. It forces an attacker to redo real
work for every build, on every machine, instead of writing one patch. The exact limits are written
down in the [Security & Threat Model](../security/threat-model) — read it before you ship.

## Repository map

| Path | Contents |
|---|---|
| `crates/` | Rust workspace: protocol (`copylocker-proto`), crypto suites, client core, server core, Worker, CLI, FFI/Node bindings, WASM core |
| `packages/` | TypeScript: `@copylocker/web`, React/Vue/Svelte bindings, `unplugin`, `guard`, `seal`, Tauri/Electron packages |
| `server-template/` | The deployable Worker project rendered by `copylocker init` |
| `examples/` | Runnable apps: `vite-spa`, `nextjs-app`, `tauri-app`, `electron-app` |
| `vectors/CL-STD-1/` | Public known-answer test vectors |
| `.agents/` | Internal design authority (Chinese); where docs disagree with code, code wins |

## Where to go next

- [5-Minute Quickstart](./quickstart) — server up, license issued, first `unseal()`.
- [Protection Levels (L0–L4)](./protection-levels) — how to actually use the SDK.
- [The Licensing Model](./licensing-model) — the five-axis policy system.
- [Deployment](./deployment) and [Operations](../operations/runbook) — running it in production.
