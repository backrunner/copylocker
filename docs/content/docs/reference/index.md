---
title: Reference
navTitle: Reference
order: 10
description: Exact reference material — the CLI command surface, the HTTP wire APIs, and every SDK's public surface.
---

# Reference

Lookup material with exact flags, paths, scopes, and signatures. Everything here is written
against the shipped code; where the code and this section disagree, the code wins and the page is
a bug — file an issue.

- [CLI Reference](/docs/reference/cli) — every `copylocker` command with its flags, the
  connection rules, and the production-mutation guards.
- [HTTP API](/docs/reference/admin-api) — the CBOR client protocol, the JSON Admin API with
  scopes and idempotency rules, and the billing webhooks.
- [SDK Reference](/docs/reference/sdks) — `@copylocker/web`, the framework bindings, the build
  tooling (`guard` / `seal` / `unplugin`), telemetry, and the native stacks (Node, Rust, C FFI,
  Tauri, Electron).

For the *why* behind the shapes, start at the [Guide](/docs/guide) instead.
