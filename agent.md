# CopyLocker Agent Context

Last updated: 2026-07-30

## Purpose

Use this file as the current repository handoff. Read the relevant design authority under
`.agents/` before changing behavior, and use `.agents/skills/develop-copylocker/SKILL.md` for the
development, validation, licensing, submodule, and commit workflow.

Implementation and executable migrations take precedence when a historical roadmap checkbox is
stale. Update this file whenever a change alters the implemented milestone, release evidence,
repository boundary, accepted risk, or immediate plan.

## Repository and License Model

- This repository is the public repository and is licensed `GPL-3.0-only`.
- Proprietary code belongs in a second access-controlled repository named
  `copylocker-suite-priv`.
- The reserved mount point is `private/copylocker-suite-priv` as an optional Git submodule.
- The real submodule is not configured yet because no private remote URL has been supplied.
- Public source, default manifests, lockfiles, CI, tests, and releases must work without the
  private submodule.
- Never copy private source, private KATs, vendor parameters, credentials, or private build output
  into this repository.
- A submodule does not waive GPL obligations. Combined proprietary distribution requires a
  separate commercial license, process/service isolation, or explicit legal approval.
- Treat `LICENSING.md` and `.agents/00-overview/open-closed-boundary.md` as the boundary authority.

## Current Implementation State

| Area | State | Evidence / boundary |
|---|---|---|
| M0 protocol and cryptography | Implemented locally | CL-STD-1, canonical CBOR, 47 KAT vectors, ML-DSA 44/65/87 matrix |
| M1 server core | Implemented locally | Policy engine, licensing lifecycle, Worker, D1, DO, KV, Queue, R2, Admin API, recovery journals |
| M1 operations | Implemented locally | CLI bootstrap/admin flows, eight migrations, generated server template |
| M2 client core | Implemented locally | State machine, protected store, fingerprinting, transport, offline artifacts |
| M2 native SDKs | Implemented locally | C ABI, Node-API, Tauri and Electron packages plus runnable examples |
| Native platform evidence | Partially complete | Three-OS CI matrix exists; current checkout was validated on macOS, remote matrix evidence remains required |
| M3 Web SDK | Not implemented | Only the browser verifier size/performance harness exists |
| M4 build tooling | Not implemented | unplugin, guard, seal packages remain roadmap work |
| M5 private suite and release variants | Not implemented | Private repository and submodule remote are not yet created/configured |
| M6 analytics and telemetry | Not implemented | Roadmap only |
| M7 admin console | Not implemented | Roadmap only |
| M8 GA | Not complete | External audit, red team, legal review, provenance and production operations remain |

## Last Verified Release Baseline

- Rust formatting, workspace check, Clippy, workspace tests, architecture boundary, host no_std,
  and wasm no_std checks passed.
- ML-DSA parameter sets 44, 65, and 87 each passed 60 tests.
- Workerd passed 54 tests.
- Worker release WASM: 2,453,399 raw bytes and 910,764 gzip bytes; limit 1,500,000 gzip bytes.
- Worker cold startup: p95 10.639 ms; limit less than 50 ms.
- Worker npm tarball: 926,046 packed bytes; expected file set accepted.
- Browser verifier WASM: 170,355 raw bytes and 72,001 gzip bytes; p95 verification 1.028 ms.
- FFI, Node, Tauri, Electron, template, package, npm audit, cargo-deny, cargo-audit, KAT, and
  workflow lint gates passed locally.
- No npm package has been published and no Cloudflare deploy/bootstrap confirmation has run.

## Accepted Risks and External Blockers

- `.cargo/audit.toml` contains exact advisory IDs for Tauri 2.11.5's GTK3 and `urlpattern` chains.
  Any unlisted future warning remains release-blocking. Remove exceptions when upstream removes the
  dependency chains.
- The affected `glib::VariantStrIter` API is not used by CopyLocker source, but the GTK3 dependency
  remains a transitive Linux runtime risk.
- `copylocker-worker@0.1.0` and `@copylocker/node@0.1.0` are not in their public registries. Local
  tarballs validate artifacts but are not evidence of registry availability.
- The private repository URL, access policy, commercial license, and submodule gitlink are pending.
- GPL/private combined-distribution policy requires qualified legal review before a private binary
  is delivered to customers.

## Immediate Plan

1. Create the access-controlled `copylocker-suite-priv` remote, add its proprietary license and CI,
   then mount it at `private/copylocker-suite-priv` with a relative or canonical authenticated URL.
2. Preserve a public CI path that does not initialize the private submodule; add a separate
   authorized integration pipeline in the private repository.
3. Close remaining M0-M2 evidence: remote Linux/Windows/macOS matrix, sustained fuzzing, memory
   budget, and the documented deployment/activation usability exercise.
4. Continue the original roadmap at M3: Web SDK, worker isolation, browser storage, framework
   bindings, examples, CSP checks, and browser E2E.
5. Implement M4 build tooling, then M5 release variants/offline flows/private suite integration.
6. Continue M6 analytics, M7 console, and M8 GA only after their prerequisite gates are complete.

## Non-Negotiable Engineering Contracts

- Keep cryptographic security independent of proprietary implementation secrecy.
- Keep Worker and `server-template` migrations byte-identical and register every migration in the
  CLI scaffold.
- Keep Admin credentials in the configured environment variable; never print them or place them in
  argv, URLs, redirects, fixtures, or commits.
- Keep mutation idempotency, two-actor Epoch approval, dry-run defaults, immutable journals, and
  revocation ordering intact.
- Do not deploy, publish, confirm bootstrap, or mutate production without explicit authorization.
- Use English commit subjects in `type(scope): description` form as defined by the repository skill.
