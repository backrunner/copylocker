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
- The public remote is `https://github.com/backrunner/copylocker`; the private remote is
  `https://github.com/backrunner/copylocker-suite-priv`.
- `.gitmodules` uses `../copylocker-suite-priv.git` and currently pins private commit `fefac42`.
- The private workspace pins its public contract dependencies to `71bc771`, intentionally before
  the public submodule gitlink to avoid recursive private-submodule fetching by Cargo Git sources.
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
| M5 private suite and release variants | Private suite core implemented; release integration pending | CL-PRIV-1, vendor profile generator, private KAT, fuzz/timing gates, independent CI, and commercial templates exist at private commit `fefac42`; application release variants and authorized combined-build evidence remain pending |
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

## Private Suite Evidence

- Local macOS arm64 verification passed locked formatting, workspace check, Clippy with warnings
  denied, 15 tests with one controlled KAT-generation test ignored, and wasm `no_std`.
- The private KAT, explicit release-profile enforcement, `cargo deny`, and
  `cargo audit --deny warnings` passed. Release builds reject missing, repository-contained, and
  development profiles; an external generated profile passed the release build.
- Ten-second sanitizer fuzz smoke runs completed without crashes: the codec target ran 207,262
  executions with coverage 682, and the profile target ran 1,350,537 executions with coverage
  1,280. These are smoke results, not sustained fuzzing evidence.
- The local DudeCT binder regression harness sampled 0.008 million observations with maximum
  `|t| = 1.53935`, below its threshold of 5; this is not an external side-channel audit.
- Private GitHub Actions run `30485459664` passed Ubuntu quality/conformance/KAT,
  release-profile, timing, and supply-chain jobs at commit `fefac42`.
- CL-PRIV-1 keeps standard X-Wing. A custom ML-KEM-1024 hybrid combiner remains rejected until a
  reviewed standard or independent cryptographic review supports a new suite identifier.
- No private crate has been published, no combined proprietary binary has been distributed, and
  no commercial agreement has been executed as part of this work.

## Accepted Risks and External Blockers

- `.cargo/audit.toml` contains exact advisory IDs for Tauri 2.11.5's GTK3 and `urlpattern` chains.
  Any unlisted future warning remains release-blocking. Remove exceptions when upstream removes the
  dependency chains.
- The affected `glib::VariantStrIter` API is not used by CopyLocker source, but the GTK3 dependency
  remains a transitive Linux runtime risk.
- Private `.cargo/audit.toml` ignores exactly `RUSTSEC-2021-0139`, `RUSTSEC-2021-0145`, and
  `RUSTSEC-2024-0375` from the `clap 2` chain used only by the non-distributed
  `dudect-bencher 0.7.0` timing harness. Remove these exceptions when upstream drops the chain;
  any new advisory remains release-blocking.
- `copylocker-worker@0.1.0` and `@copylocker/node@0.1.0` are not in their public registries. Local
  tarballs validate artifacts but are not evidence of registry availability.
- The private suite and independent CI exist, but authorized application integration, executed
  commercial terms, vendor release operations, and combined-distribution evidence remain pending.
- GPL/private combined-distribution policy requires qualified legal review before a private binary
  is delivered to customers.

## Immediate Plan

1. Preserve the private suite at its reviewed public-contract pin, then build the authorized
   application integration, vendor-profile lifecycle, migration process, and release evidence.
2. Preserve a public CI path that does not initialize the private submodule; keep private suite CI
   independent and add an authorized combined-build pipeline before any integrated release.
3. Close remaining M0-M2 evidence: remote Linux/Windows/macOS matrix, sustained fuzzing, memory
   budget, and the documented deployment/activation usability exercise.
4. Continue the original roadmap at M3: Web SDK, worker isolation, browser storage, framework
   bindings, examples, CSP checks, and browser E2E.
5. Implement M4 build tooling, then finish M5 release variants, offline flows, and private suite
   application integration.
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
