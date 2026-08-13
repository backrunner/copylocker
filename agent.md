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
| M1 operations | Implemented locally | CLI bootstrap/admin flows, ten migrations, generated server template |
| M2 client core | Implemented locally | State machine, protected store, fingerprinting, transport, offline artifacts |
| M2 native SDKs | Implemented locally | C ABI, Node-API, Tauri and Electron packages plus runnable examples |
| Native platform evidence | Complete for the current M2 baseline | GitHub Actions run `30493941556` passed the full SDK flow on macOS 14, Ubuntu 24.04, and Windows 2022 at public commit `52ed666` |
| M3 Web SDK | Implemented locally | `copylocker-wasm` opaque `step()` core (116,357 gzip bytes, limit 358,400), `@copylocker/web` (two-stage derivation, IndexedDB non-extractable-key storage, Worker isolation, SSR stub), React/Vue/Svelte bindings, `examples/vite-spa` and `examples/nextjs-app`, Playwright E2E against a real local Worker backend |
| M4 build tooling | Implemented locally | `@copylocker/unplugin` (6 bundlers: Vite/Rollup/esbuild/Webpack/Rspack/Farm, two-round placeholder manifest, signer abstraction, `--verify`), `@copylocker/guard` (runtime R, `@guarded`, toString-override detection), `@copylocker/seal` (web v1 + chunked containers, encrypted KEK registry); server-side KEK chain (`/v1/admin/asset-keks`, `wrapped_keks` in credentials), remote integrity signer (`/v1/admin/integrity/keys` + `/sign`) with GitHub OIDC; tamper/remove-guard E2E, multi-browser R consistency (chromium/firefox/webkit byte-identical), and the LCP gate (Δ ≤ 0 ms) all green |
| M5 release variants and lifecycle | Release registry, version-level revocation, offline-upgrade policies, anomaly scoring, Mode E accounts, offline activation, multi-suite request dispatch, and web unseal implemented locally | `/v1/admin/releases` (idempotent register, deprecate/mark-compromised with dry-run impact), variant params AEAD-sealed at rest, `preload_n`/`variant_stable`/`require_online` honored at issuance, suspicion scoring wired into LicenseDO with alert webhooks, 1007 error text carries the register command; Mode E (`AccountDO` sessions, device limits, `/v1/account/*`, `AccountToken` activation branch) and the offline loop (`/v1/offline/request`, productive OLK issuance with CLK1 armor, CLI `offline request/redeem/import/qr/issue`) implemented; server suite dispatch de-hardcoded via the `RequestSuite` registry (CL-STD-1 production + test-only CL-TST-1); wasm `unseal-asset` op + `@copylocker/web` `loadSealed` on the KEK path; cross-variant unseal negative test; CLR1 `.clar` armor and the R2 AResp archive closed the M5-B deviations; private suite core stays at private commit `fefac42` |
| M6 analytics and telemetry | Implemented locally | Proof-covered-telemetry bug fixed (wasm `build-validate-request` op injects the `TelemetryBlock` before signing; `@copylocker/web` `attachTelemetry` removed); `@copylocker/telemetry` (34 tests); server pipeline (tier gate, consent=0 drop, poisoning clamps with counters, pepper-derived machine keys, R2 detail archive, idempotent D1 rollup on cron `15 0 * * *`); 4 admin analytics endpoints under `analytics:r` with `meta.source/error_pct/suppressed_buckets/warning`; DSR export/delete + telemetry purge under new `dsr:rw` scope with CLI `dsr export|delete` / `telemetry purge`; legal-sync CI gate; all seven acceptance criteria test-covered. Analytics Engine leg and subscription delivery remain pending (see the M6 evidence) |
| M7 admin console | Implemented locally | `apps/console` SvelteKit (52 tests + svelte-check clean) fully on `packages/admin-sdk` (76 tests, every admin route incl. machines/audit, dry-run discipline, 4 MiB cap); ts-rs drift-check CI (26 wire types); Simulator three-way consistency locked; offline activation portal; worker global endpoints (`GET /v1/admin/machines`, `GET /v1/admin/audit`, `POST /v1/admin/audit/verify`, `DELETE /v1/admin/machines/:id` GDPR alias) under `machines:r`/`audit:r`; releases/analytics/audit/settings pages with two-step parity (typed-id + dry-run impact preview); hermetic Playwright E2E 16/16 (issue → activate → revoke → enforce, axe zero critical/serious on all pages, keyboard-only flows) |
| M8 GA | Partially prepared | `SECURITY.md` with the honest residual-risk statement, `.github/workflows/release.yml` (reproducible WASM double-build verified locally, SBOM, Sigstore keyless provenance), VitePress docs site with operations guides and a Pages deploy workflow, and the legal template pack exist. External audit, red team, legal review, npm publication, and production operations remain external-party items |

## Last Verified Release Baseline

- Public GitHub Actions run `30493940780` passed all nine quality, conformance, no_std, Worker,
  size, and supply-chain jobs at commit `52ed666`; Native SDK run `30493941556` passed all three
  platform jobs at the same commit.
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
- The Apple M4 reference crypto profile retains the 3 ms signing and 5 ms verification product
  gates. The pinned Ubuntu 24.04 quality job uses the documented 12 ms and 8 ms shared-runner
  regression ceilings; that profile is not product-SLO evidence.
- Clean-runner blockers are resolved for Worker runtime generation, Tauri bundle icons, Linux
  desktop dependencies, supported action runtimes, hardware-specific performance calibration,
  and Windows ASAR path handling.
- No npm package has been published and no Cloudflare deploy/bootstrap confirmation has run.

## M3 Web SDK Local Evidence

The M3 work is local and uncommitted; the CI baseline above predates it.

- `copylocker-wasm`: 9 integration tests; WASM 344,580 raw bytes and 116,357 gzip bytes against
  the 350 KiB gzip budget (`scripts/check-web-wasm-size.sh`). The opaque `step()` interface keeps
  numeric error codes only (NFR-SEC-011); `derive-m` yields half-cooked material, never a feature
  key.
- `@copylocker/web`: 81 vitest tests, including two-stage-derivation tamper failures, IndexedDB
  non-extractable-key storage, scheduler, and transport retry behavior. React/Vue/Svelte binding
  packages pass 19 tests.
- `packages/web-e2e`: 17 Playwright tests pass against a real local
  backend (`wrangler dev` plus CLI-driven keygen, bootstrap, catalog/policy/epoch upload, and
  license issue): activate → reseal → unseal → reload recovery → offline unseal → automatic
  revalidation on network restore, plus attack simulations (stub WASM, tampered asset, cleared
  IndexedDB, `Function.prototype.toString` override), the M4 integrity attacks below, and the
  Next.js SSR smoke test.
- E2E-driven fixes landed in `packages/web` (suite id, scheduler receiver, persist-on-activate,
  error normalization, protocol headers), `crates/copylocker-wasm` (summary contract on four
  ops), and `crates/copylocker-worker` (CORS for protocol endpoints only; admin stays without
  CORS). Worker workerd tests: 55 passed.
- Web sealed assets use the documented web v1 AES-256-GCM container (WebCrypto-aligned) pending
  M4 `@copylocker/seal` unification; the ML-KEM private key is software-held and wrapped by a
  non-extractable AES-GCM key, an inherent web-platform weakness recorded in the module doc.
- `worker-build` and `wasm-bindgen` CLI are installed under `target/tmp/` (not globally) for the
  wasm build chain.
- The E2E observation that `derive-m` with the online root returns NotEntitled right after
  activation is by design, not a bug: `set_online_session` is armed only by a validation ticket
  (session.rs ticket ingest), so the SDK's online→offline fallback covers the window between
  activation and the first validation.

## M4 Build Tooling Local Evidence (Phase A)

The M4-A work is local and uncommitted.

- `@copylocker/guard` (46 tests): `bootGuard` returns the actually computed Merkle root `R`, never
  a boolean; excluded-range zeroing, Ed25519 manifest verification with a documented
  unsupported-browser downgrade, `@guarded` mixing digests into `GuardState` instead of throwing,
  native `Function.prototype.toString` capture and override detection.
- `@copylocker/seal` (45 tests): build-time sealing byte-compatible with `@copylocker/web`
  (cross-package round-trip tests), chunked AEAD extension (reordering and truncation detected),
  encrypted KEK registry with 0600 permissions and no-plaintext-KEK assertions, dry-run CLI.
- `@copylocker/unplugin` (45 tests): real Vite/Rollup/esbuild builds produce a signed
  IntegrityManifest via the two-round placeholder scheme; the pipeline digests on-disk final
  bytes (a deliberate deviation from the design's `generateBundle` hook, because Vite rewrites
  chunks afterwards); `copylocker-unplugin verify` exits non-zero on any one-byte tamper.
- vite-spa builds with the plugin; the integrity E2E proves the two headline properties against a
  real backend: tampering any chunk by one byte fails unseal, and removing the guard while
  keeping the fallback constants fails unseal because `requireIntegrityProof` is injected into
  the constants prelude (this fallback hole was found and closed by the E2E).
- M4-B (also local and uncommitted): `/v1/admin/asset-keks` plus `/v1/admin/integrity/keys`
  and `/sign` remote signer endpoints are live in the Worker (migration
  `0009_integrity_signer_keys.sql`, byte-identical in `server-template`), with GitHub OIDC JWT
  verification for CI signing; `copylocker asset-kek` CLI commands manage the chain. The
  `wrapped_keks` issuance chain is consumed by the desktop client; the web consumption side
  (`unseal-asset` wasm op) remains open. Webpack/Rspack/Farm adapters landed (webpack/rspack
  digest on `afterEmit` final bytes, farm patches assets in `finalizeResources`), and nextjs-app
  builds through the unplugin via `next build --webpack` (Turbopack proven infeasible, recorded).
  Multi-browser R consistency passed: chromium, firefox, and webkit produce byte-identical R,
  guarded-function digests, and GuardState for the same build (`packages/web-e2e`
  r-consistency spec). The LCP gate passed with Δ ≤ 0 ms median over 5 runs under the most
  pessimistic `strategy: 'sync'` configuration. A seal `globToRegExp` bug that dropped the
  separator for patterns like `static/**/*.js` was fixed with regression assertions.

## M5 Release Registry Local Evidence (Phase A)

The M5-A work is local and uncommitted.

- `/v1/admin/releases` (scope `releases:rw`, Idempotency-Key journaled): idempotent register
  (`already_registered` on exact re-register, 409 on fingerprint reuse with different
  attributes), list/show projections that never expose `variant_params`, and
  `deprecate`/`mark-compromised` with dry-run impact (affected devices, 7-day check-ins,
  security-floor preview) defaulting to true. `revoke` requires `acknowledge_revoke: true`.
- Variant params are CBOR-encoded per ADR-0013 and AEAD-sealed at rest; logs and responses carry
  only the seed's SHA-256 fingerprint. `variant_stable` products reuse the first active
  release's variant with an explicit warning; migration `0010_release_admin.sql` (byte-identical
  in `server-template`) downgrades the variant index accordingly.
- The three compromise states are wired through the existing decision mapping: warn issues
  tickets with `release_status=2`, force_upgrade blocks new activations (1009) and returns
  NeedsReactivation, revoke returns KillOrder; deprecate issues `release_status=1`. The 1007
  unregistered-release error now embeds the exact `copylocker release register` command.
- Offline upgrade policies are honored at issuance: `preload_n` embeds entitled KEKs for the N
  newest active sibling releases in proto field 22 (`preloaded_keks`); `require_online`
  preloads nothing; `variant_stable` shares wrapped KEKs by construction.
- Anomaly detection is wired into LicenseDO: validate/reserve paths score suspicion (24h
  distinct fingerprints, seats, validation-count vs refresh prediction, distinct app versions;
  `impossible_travel` and `attr_churn` documented as zero pending trustworthy sources), persist
  it on `activations.suspicion`, and apply the authoritative `security_floor_log` maximum to
  tickets. `PATCH /v1/admin/products/:id/alert-webhook` configures an https-only alert webhook
  with a suspicion threshold; rising-edge crossings enqueue a `suspicion_alert` event delivered
  by the queue consumer with retries, never blocking issuance.
- Gates: cargo workspace 615 tests; worker 72/72 plus size (1,004,915 gzip bytes vs the
  1,500,000 limit) and startup (p95 17.8 ms); `check-server-template.sh` green.
- Known deviations: the variant seed is generated CLI-side and uploaded (the server cannot hand
  plaintext to a build pipeline without logging it); a missing `module_digest_hex` defaults to
  32 zero bytes; suspicion alerts fire only on the validate path; the `variant.lock` pipeline
  file from the design doc is out of scope for this CLI contract.
- WASM export-symbol randomization (`randomizeWasmExports`) is implemented in
  `@copylocker/unplugin` (61 tests): seed-derived `__cl_<hex>` export names via a minimal
  LEB128 export-section rewriter with matching JS glue rewrites, the `name` section stripped,
  and fail-closed behavior without a build seed. Rename runs before digests so the manifest and
  guard cover the renamed bytes. WASM_DIGEST injection is implemented too (68 tests): the
  pipeline SHA-256-digests every covered `.wasm` asset after randomization, the prelude carries
  the map, and the bootstrap publishes `__CL_WASM_DIGESTS__` plus the singular
  `__CL_WASM_DIGEST__` when exactly one wasm is covered; `@copylocker/web` fails `create()`
  closed (code 17) when the loaded wasm digest mismatches the injected constant. Constant
  splitting across chunks remains pending with the documented rationale (shard placement needs
  import-graph knowledge the final-bytes pipeline lacks; the safe variant is a cross-package
  guard-runtime change), tracked as an open M5 hardening item.

## M5 Mode E and Offline Activation Evidence (Phase B)

The M5-B work is local and uncommitted.

- Mode E: `AccountDO` durable object with a versioned self-migrating schema (session kind +
  refresh-pair rotation), Argon2id password hashing with dummy-hash timing equalization,
  exponential-backoff login throttling, concurrent-session device limits (`accounts.max_devices`,
  bounded 0..=1000), atomic refresh rotation, logout revocation, and alarm-driven reclaim.
  Endpoints `POST /v1/account/login|refresh|logout`; activation accepts `Credential::AccountToken`
  (proto key 1) resolved via the account session, with `EnforcedOnline` policy rejecting
  license-key-only activation. Admin surface `/v1/admin/accounts` is journaled and idempotent and
  never journals the password; only SHA-256 token hashes reach storage.
- Offline activation: `POST /v1/offline/request` relays an air-gapped activation request through
  the same authorization and seat-reservation path as `/v1/activate`; productive OLK issuance at
  `POST /v1/admin/licenses/:id/offline-key` (ADR-0015: `key_seed`/`machine_id`/`offline_nonce`/
  wrapped KEKs, policy gates `allow_olk`/`allow_unbound_olk`, CLK1 armor returned once per
  idempotency key, `max_seats` advisory). CLI `offline request|redeem|import|qr|issue` closes the
  air-gapped loop with root-pinned chain verification, nonce echo and fingerprint binding checks,
  a mode-0600 device key file with zeroizing `Drop`, and QR rendering (ascii + SVG) of the CLK1
  armor. The air-gapped loop is covered end to end by `cli_workflows.rs`
  `offline_commands_cover_the_air_gapped_loop` against a mock server (the offline device itself
  makes no network calls) and by six new worker vitest scenarios.
- No migration 0011: the `accounts` D1 table already exists in `0001_initial.sql` with every
  column the code uses, and AccountDO/OLK state lives in DO storage; migrations 0001-0010 remain
  byte-identical between the worker and `server-template` (diff-verified).
- Gates (re-run by the parent after handoff): cargo fmt/clippy clean (one post-handoff fmt drift
  fixed), `cargo test --workspace` 627 passed + 1 ignored (35 suites), worker tsc clean and
  vitest 78/78, size 1,070,635 gzip bytes vs the 1,500,000 limit, startup p95 24.2 ms vs 50 ms,
  package check accepted, `check-server-template.sh` green, `cargo deny --locked check` and
  `cargo audit --deny warnings` clean.
- Known deviations: endpoints are `/v1/account/*` rather than the protocol-spec's `/v1/auth/*`
  table entry; one worker test
  ("grants exactly 3 seats through 100 concurrent public activations") timed out at 5 s once
  under concurrent cargo load and passed on a quiet rerun — worth watching on loaded CI machines.
  The `.clar` armor and the R2 archive deviations recorded here at M5-B are closed in Phase C
  (see the next section).
- Pending acceptance evidence: the literal disconnected-VM air-gapped exercise (the code path is
  fully test-covered). The cross-variant unseal negative test and multi-suite coexistence are
  closed in Phase C (see the next section).

## M5 Multi-Suite, Web Unseal, and Offline-Carrier Evidence (Phase C)

The M5-C work is local and uncommitted.

- Multi-suite request dispatch: `crates/copylocker-worker/src/suites.rs` introduces the
  `RequestSuite` registry — `resolve` fails closed outside the supported set, `resolve_persisted`
  covers at-rest data, and a `suite_dispatch!` macro binds the concrete suite type at each call
  site. Credential-state seal/open (`bindings/authorization.rs`), activation parsing, encap,
  `KeyMaterial::bind`/`wrap_kek`, online-artifact signing (`router.rs`, `bindings/signing.rs`),
  IssuerDO `validate_tbs`/`sign_envelope`, offline responses, and OLK issuance
  (`admin_resources/offline_key.rs`) all take the suite from the request or the persisted release
  row instead of the CL-STD-1 constant; unknown suites are rejected with the same 403/1000 on
  activate and validate. A synthetic `CL-TST-1` (`0x02000001`, every algorithm slot aliasing
  CL-STD-1) resolves only under `ENVIRONMENT == "test"` and exercises the dispatch end to end
  (worker.test.ts: activate → wrapped KEKs → validate with fast-sig verification under TST1);
  production traffic for it fails closed. CL-STD-1 behavior is byte-identical — all 90
  pre-existing worker vitest passed unchanged. Epoch signing keys and admin release/asset-KEK
  registration stay CL-STD-1-only (per-suite epoch issuance is an admin-side axis, out of scope).
- wasm `unseal-asset` op (`OP_UNSEAL_ASSET = 13`): ports the desktop KEK chain into
  `crates/copylocker-wasm/src/session.rs` — Tick clock guard, `ERR_NO_CREDENTIAL` before
  activation, online-ticket refreshed KEKs preferred, then the credential's offline
  `wrapped_keks`, or the `preloaded_keks` entry for this build's variant after an offline upgrade
  (proto field 22 semantics); every failure is the indistinguishable `ERR_NOT_ENTITLED`.
  `open_machine_credential` deliberately extends the desktop by accepting a
  variant/build-fingerprint-mismatched credential only when preloaded KEKs cover this build's
  variant, binding key material to this build's wrap context. `@copylocker/web` gains
  `SessionOps.unsealAsset` and a rewired `loadSealed` (integrity gate → op unwrap → fetch via the
  configured `fetchFn` seam → `openSealedAsset`); the two-stage `unseal()` M path is unchanged.
  The desktop client still has no `preloaded_keks` consumption (it revalidates) — a documented
  candidate follow-up.
- Cross-variant unseal negative test: `copylocker-client`
  `keks_from_an_older_variant_cannot_unseal_a_newer_releases_asset` — a variant-7 activation's
  wrapped KEKs fail a variant-8 sealed asset at the metadata gate and with a forged variant-7
  header (AAD + wrong KEK), with a same-variant positive control.
- M5-B deviation closure: `crates/copylocker-proto/src/offline_armor.rs` adds the `CLR1:`
  Crockford Base32 armor (PEM-boundary tolerant, ASCII-whitespace tolerant, bounded decode at the
  protocol body cap, QR alphanumeric-mode eligible) — CLI `offline request --armor-out` emits
  `.clar`, `offline redeem` accepts CLR1 or CBOR and posts identical bytes (the endpoint stays
  CBOR-only), `offline qr` renders both carriers, all proven in the extended
  `offline_commands_cover_the_air_gapped_loop`. The worker archives every signed activation
  response to R2 `offline/<license_id_hex>/<nonce_c_hex>.aresp` with a conditional
  same-bytes-tolerant put (idempotent replays re-archive cleanly; archive failure fails the
  request safely — issuance is idempotent, so no response reaches a relay unarchived). The 7-day
  retention requires a bucket lifecycle rule (ops configuration, not expressible in
  wrangler.jsonc) — same status as the other §14 retention rules.
- Gates (re-run by the parent after handoff): cargo fmt/check/clippy clean, `cargo test
  --workspace` 693 passed + 1 ignored (39 suites, 35.78s, exit 0); worker tsc clean, vitest
  92/92, size 1,187,423 gzip bytes vs 1,500,000, startup p95 9.787 ms vs 50 ms,
  `check-server-template.sh` green (no new migration, 0001-0010 byte-identical, package check
  accepted at 1,203,894 packed bytes); web wasm 118,912 gzip bytes vs 358,400; packages/web
  98/98; web-e2e 22/22 passed (47.2s, run with `CL_E2E_BACKEND_PORT=8788` because an unrelated
  local process holds 8787).

## M6 Analytics and Telemetry Evidence

The M6 work is local and uncommitted.

- Proof bug fix: `ValidateRequest.proof` has always covered proto key 11 (telemetry)
  (`crates/copylocker-proto/src/requests.rs:344`), but the wasm built requests with
  `telemetry: None` and `@copylocker/web` injected key 11 after signing, so any
  proof-verifying server rejected telemetry-carrying validates. The `build-validate-request`
  op now accepts optional op key 1 (canonical-CBOR `TelemetryBlock`, 512-byte cap checked
  before parse at `requests.rs:374,407`) and sets it on the request before `proof_input()`
  is signed (`crates/copylocker-wasm/src/session.rs:801-805,1307`); `@copylocker/web`
  deleted `attachTelemetry` and passes the block through the op
  (`packages/web/src/index.ts:550,580`). An absent key keeps the byte-identical legacy
  shape (`crates/copylocker-wasm/tests/e2e.rs:509`); malformed/oversized blocks fail with
  code 3 without panic (`e2e.rs:528`); proof verification over the telemetry-inclusive
  input is locked at `e2e.rs:475`. Desktop keeps `telemetry: None` by design (no desktop
  T1 collector exists; proto field and server path are client-agnostic).
- Compute layer (`crates/copylocker-server-core/src/analytics/`, no_std/alloc-clean, zero
  new deps): 36-metric catalog, nine fixed cubes with validated `CubeKey` codec, HLL++ p=14
  (16,384 registers, versioned 16,385-byte blob), k-anonymity suppression (k=5), source
  selection (exact under 1M rows, HLL merge above), poisoning clamps (10,000/28 caps,
  allow-list, consent gate).
- Worker pipeline (`crates/copylocker-worker/src/analytics.rs`): tier gate
  (`policies.telemetry_tier`), consent=0 drop, clipping, pepper-derived machine keys
  (double-HMAC), R2 detail archive `analytics/raw/<product>/<date>/<record_id>.json`,
  idempotent D1 rollup (`INSERT OR REPLACE`) on cron `15 0 * * *` dispatched at
  `src/lib.rs:78-81` (`* * * * *` kept for dev only). Counters `t1.dropped_no_consent`,
  `t1.dropped_tier_gate`, `t1.clipped_*`, `t1.dropped_feature_key`.
- Admin surface: `GET /v1/admin/analytics/definitions|metrics|export` and `GET|POST
  /v1/admin/analytics/subscriptions` under `analytics:r`, responses carry
  `meta.{source,error_pct,suppressed_buckets,warning}`. DSR under the new `dsr:rw` scope:
  `POST /v1/admin/dsr/export`, `POST /v1/admin/dsr/delete` (dry-run default, journal replay
  before subject resolution, LicenseDO `/admin-forget` cascade), `POST
  /v1/admin/telemetry/purge`. CLI `copylocker dsr export|delete` and `copylocker telemetry
  purge` (env-only zeroized token; `--confirm` requires `--idempotency-key`) with
  `crates/copylocker-cli/tests/dsr_workflows.rs` (5 tests).
- legal-sync gate: `scripts/check-legal-sync.mjs` hard-fails on TelemetryBlock-field /
  T1-metric / rollup-table drift against `docs/legal/data-inventory.md` (T0 ids warn-only);
  registered in `.github/workflows/ci.yml`; a drift injection was proven to exit 1 naming
  both drifted items, then reverted.
- Acceptance criteria evidence: exact-vs-HLL within ±1% (`analytics/hll.rs:255`, measured
  0.000%/0.800%/0.370%/0.122% at n=100/1k/10k/50k; merge equivalence at `:283`); rollup
  idempotent (worker vitest, byte-identical tables after re-run); k<5 suppressed
  (server-core unit + API meta test); poisoning clipped and counted (10^9 → 10,000 flagged
  plus `t1.clipped_session_count`); consent=0 dropped with validate still 200
  (`t1.dropped_no_consent`); 7d-refresh day-granularity `meta.warning`; legal-sync exit 0
  positive and exit 1 negative.
- Gates (re-run by the parent after handoff): cargo fmt/check/clippy clean; `cargo test
  --workspace` 676 passed + 1 ignored (36 suites); worker tsc clean, vitest 90/90, size
  1,184,835 gzip bytes vs the 1,500,000 limit, startup p95 9.37 ms vs 50 ms; package check
  and `check-server-template.sh` green (migrations 0001-0010 still byte-identical; no new
  migration); `cargo deny --locked check` clean; packages/web 92/92; packages/telemetry
  34/34; packages/admin-sdk tsc clean + 34/34; web wasm rebuilt at 117,080 gzip bytes vs
  358,400; legal-sync exit 0; web-e2e Playwright suite exit 0 (21 tests).
- Known deviations: the Analytics Engine leg is not implemented (no binding in
  wrangler.jsonc; the D1 rollup path is complete and the integration point is documented at
  `enqueue_detail`); exports are inline row-capped, not R2-presigned (Workers R2 cannot
  presign without S3 credentials); subscription configs are stored/listed with
  `"delivery":"pending"` (no webhook push); DSR delete does not tombstone content-hashed
  audit chains (`audit_tombstone:false` in responses); `dsr/export` is not journaled
  (read-only); the tier column is `policies.telemetry_tier`, not `products.telemetry_tier`
  as the design doc stated; heartbeats emit no analytics detail (`HeartbeatRequest` has no
  client_info; `dev.checked_in` counts validate check-ins only and `act.reactivation` is
  not computed); consent/poisoning worker coverage is two-legged (vitest-pool-workers
  cannot read queue-sink messages: e2e validate contract plus synthetic consumer dispatch,
  gate logic covered by 7 Rust host unit tests). Two en-route bugs were fixed by the
  implementer: HLL cube range end byte `{`→`}` and DSR replay-after-commit 404.

## M7 Console Group-B Evidence

The M7-B work is local and uncommitted.

- admin-sdk complete (`packages/admin-sdk`, 67/67 vitest + tsc clean): every admin route —
  releases, licenses, accounts, asset-keks, integrity, offline-key, catalog, policies,
  epochs (two-actor revoke), license/machine revoke, products alert-webhook, analytics
  (definitions/metrics/export/subscriptions with `QueryMeta`), DSR export/delete,
  telemetry purge — with dry-run-first discipline, `Idempotency-Key` propagation, a 4 MiB
  `maxResponseBytes` cap, and relative-base-URL support.
- ts-rs drift-check CI: feature-gated `#[derive(TS)]` on 26 wire types in
  `copylocker-types` and `copylocker-server-core` (both keep `#![no_std]` unless the
  host-only `ts-rs` feature is on); `TS_RS_LARGE_INT=number` generation into
  `packages/admin-sdk/bindings/` (byte-deterministic, sha256-verified);
  `npm run check:bindings` pins the hand-written types against the bindings (drift
  injection proven to fail at the right line after fixing a `never extends true` hole);
  `scripts/check-admin-sdk-bindings.sh` (regenerate + fail-on-git-diff) is wired into the
  ci.yml quality job, and an admin-sdk step is in the web-sdk job. Caveat: the git-diff
  half cannot pass while the tree is uncommitted (bindings untracked); determinism was
  proven by hash instead.
- Simulator three-way consistency: new `crates/copylocker-simulator-wasm` calls
  `simulator::simulate` directly (zero reimplementation, 256 KiB input cap);
  `tests/consistency.rs` locks wrapper == direct `simulate` == checked-in fixture for the
  licensing-model §11 worked example (regenerate with `COPYLOCKER_UPDATE_FIXTURES=1`);
  the console `src/lib/simulator/consistency.test.ts` replays the same fixture through
  the wasm artifact (3 tests); the CLI shares the same `simulate`, so all three surfaces
  are pinned. Simulator page: scenario library + step editor + timeline visualization.
  The copylocker-wasm op map and its size gate are untouched (separate crate).
- Offline activation portal: public `apps/console/src/routes/offline/+page.svelte` — AR
  relay (file/paste → `/offline-api/request` proxy with CBOR-only 16 KiB in / 2 MiB out,
  Idempotency-Key UUID, Retry-After cooldown, AResp `.cbor` download) and CLK1 armor → QR
  SVG (Crockford validation, 3,000-char cap); `src/lib/offline/armor.ts` + 11 tests;
  Turnstile optional and off by default (`TURNSTILE_SECRET_KEY` /
  `PUBLIC_TURNSTILE_SITE_KEY` gated). Deviations: camera scanning, QR-for-AR, and AResp QR
  are not implemented (consistent with the recorded M5-B armor deviations; AResp far
  exceeds single-QR capacity).
- Console swap: `src/lib/api/client.ts` rewritten as an adapter over `createAdminClient`
  preserving every page-facing contract (the 8 pre-existing client tests pass unchanged);
  source-aliased via `kit.alias`; 37/37 console vitest + svelte-check 0 errors + vite
  build exit 0.
- Acceptance hardening: `src/lib/a11y.test.ts` axe gate (jsdom, critical/serious) on login
  + offline portal — it caught and fixed a real `aria-required-children` violation; CSP
  `script-src 'self'` without unsafe-inline verified compatible with the new pages;
  published-feature rename stays disabled with the reason strengthened to the design
  wording; two-step revoke parity intact where pages exist. Keyboard-only flow is not
  automated (deferred to Playwright E2E with the data-driven pages' axe coverage).
- Gates (re-run by the parent after handoff): cargo fmt/check/clippy clean; `cargo test
  --workspace` 677 passed + 1 ignored (39 suites); `cargo check --locked -p
  copylocker-server-core --all-features` clean (ML-DSA matrix untouched, no
  `--all-features` on the workspace); admin-sdk check/check:bindings/vitest 67/67;
  console svelte-check 0 + 37/37 + vite build; worker gates and
  `check-server-template.sh` not applicable (no worker/migration changes);
  `check-web-wasm-size.sh` and packages/web untouched.
- Follow-ups (next pass): camera QR scanning needs a QR-for-AR wire format first.
  Environment note: `rtk npx tsc` resolves a broken global TypeScript — tsc runs go
  through the packages' `npm run check*` scripts.

## M7 Console Group-C Evidence (Worker Global Endpoints, Data Pages, Playwright E2E)

The M7-C work is local and uncommitted. All gates below were re-run independently by the
parent after the implementing agent's report (15/15 PASS).

- Worker global endpoints (`crates/copylocker-worker`, vitest 96/96):
  `GET /v1/admin/machines` (`src/admin_resources/machines.rs`) — cross-license listing
  scoped to a required `product_id`, `license_id`/`status` filters, keyset pagination over
  `(first_seen_at, id)`, limit 1–100; `GET /v1/admin/audit` + `POST
  /v1/admin/audit/verify` (`src/admin_resources/audit_admin.rs`) — vendor-scoped
  newest-first chain projection, and read-only full-chain verification (seq contiguity,
  prev_hash link, hash recomputation via `AdminAuditEvent::is_valid`, 10,000-event cap →
  413); `DELETE /v1/admin/machines/:id` — thin journaled GDPR alias over the M6
  `dsr:delete` cascade (scope-parameterized `delete_impl`, dry-run default,
  `Idempotency-Key`, replay-after-deletion reconstruction). New read scopes `machines:r`
  and `audit:r` registered; `machines:rw` implies read for bootstrap-token compatibility.
- admin-sdk: `machines.list/delete` and `audit.list/verify` namespaces + 9 new tests
  (76/76, `check`/`check:bindings` clean); binding regeneration proven byte-deterministic
  by hash (the git-diff half of `check-admin-sdk-bindings.sh` stays red until the tree is
  committed — pre-existing, unchanged).
- Console group-B pages (52/52 vitest + svelte-check 0/0): releases (register +
  deprecate/mark-compromised with dry-run impact preview, typed-id confirm,
  `acknowledge_revoke` gate), analytics (definitions-driven metric picker, T0/T1 split
  labelled, `meta.source/error_pct/suppressed_buckets/warning` surfaced), audit (paginated
  table + verify-chain card), settings (DSR export/delete with receipt, telemetry purge,
  cross-license machine directory with per-row GDPR delete). All on admin-sdk via the
  adapter, dry-run → generated-Idempotency-Key discipline throughout.
- Two pre-existing console bugs fixed (required by the E2E): the `admin-api` proxy
  double-prefixed `/v1/admin/` (404-ing every proxied call; mock dev had masked it) and
  lacked a `DELETE` passthrough; two contrast violations (sidebar milestone badges 2.71:1
  removed, Tabs muted-on-muted 4.34:1 → `text-foreground/70`) caught by the new real-browser
  axe gate — the M7-B jsdom axe gate could not compute color-contrast.
- Playwright E2E (`packages/console-e2e`, hermetic; real backend via `backend-up.mjs`,
  console served by `wrangler dev`, real CL-STD-1 device-helper crate over
  `copylocker-client`): **16/16 (8.9 s)** — lifecycle 5 (issue via UI → real activation →
  machine visible in both the license tab and the cross-license directory → two-step
  revoke with mismatched-id rejection → KillOrder honored and subsequent validate rejected
  `NotActivated`), axe 8 (all pages incl. data-driven: zero critical/serious), keyboard 3
  (keyboard-only login + sidebar + issuance, dialog focus trap 8 cycles both directions,
  Escape restores focus).
- Gates (parent re-run): cargo fmt/check/clippy clean; `cargo test --workspace` 693
  passed + 1 ignored (40 suites); worker `check`/`test` 96/96, size 3,296,326 raw /
  1,205,630 gzip bytes (limit 1,500,000), startup 20 samples p95 9.994 ms (limit 50 ms);
  `check-server-template.sh` accepted (tarball 1,220,974 packed bytes); admin-sdk 76/76;
  console svelte-check 0/0 + 52/52; Playwright 16/16.
- Flagged for follow-up (pre-existing backend pipeline gaps, not M7-C scope): (a)
  `LicenseDO::flush_outbox` only runs from the DO alarm, which fires late under `wrangler
  dev` (local projection stall; the E2E works around it honestly via
  `scripts/flush-projection.mjs` applying `projection::apply`'s exact SQL); (b) CLOSED —
  the live queue round-trip mangled `AnalyticsDetailEvent.machine_key` (`serde_bytes` →
  `Uint8Array` → JSON object, consumer ACK-discarded every detail event): fixed by
  dropping `serde_bytes` on the queue payload (`events.rs:182`, plain `Vec<u8>` is a JSON
  number array both ways and byte-identical on the R2 `serde_json` path), with a
  regression test driving the real producer serialization (`serde_wasm_bindgen::to_value`
  + `JSON.stringify`/`parse`) through the consumer via a test-only hook — proven to fail
  pre-fix and pass post-fix; all six queue send sites audited, no other field can hit this
  bug class (worker vitest 97/97). (c) CLOSED — the offline relay's idempotent replay was
  not idempotent across a second boundary: `/v1/offline/request` re-signs the outer
  `ActivationResponse` (fresh `server_time`) around the identical journaled credential, so
  the conditional archive write collided and the request 500'd (found by the final
  validation matrix; had been a latent flake since M5-B). Fixed in `offline.rs`: on an
  archive-key conflict the relay now returns the archived original response
  byte-identically, with a deterministic regression test pre-seeding a conflicting archive
  object (worker vitest 98/98).

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

## Post-M8 Adversarial Review Evidence (2026-08)

A full-repo adversarial review covered the SvelteKit console, the web/guard/seal/telemetry/
unplugin packages, the React/Svelte/Vue bindings, all four examples, and the uncommitted
Rust/worker diffs. Every fix below carries a regression test; all package and crate suites
were re-run green after the fixes.

Security-relevant fixes:

- `copylocker-wasm` snapshot restore failed open: a denied validation ticket
  (`NeedsReactivation`/`VersionOutOfScope`) was not replayed as `TicketDenied` on snapshot
  import, so a `Locked` web session came back `Active` after a page reload and kept deriving
  key material. Fixed to mirror the desktop client restore ordering exactly; regression test
  `a_denied_ticket_stays_denied_across_a_snapshot_round_trip` fails without the fix.
- `seal` glob walk descended into `.copylocker/` (could seal the wrapping key into shippable
  output) and literal `..` patterns escaped `cwd`; both fixed. `init --dir <custom>` left the
  custom key dir commit-able; gitignore now follows `--dir`. `keygen` no longer silently
  overwrites an existing key. npm-symlinked `copylocker-seal` bin silently no-oped (exit 0).
- `unplugin verify --pubkey` passed unsigned dists; now requires `verified` when keys are
  given. Default config emitted `hash_alg: 'custom'`, causing a spurious runtime warning on
  every default build; now `sha256`. The `@guarded` scanner rewrote markers inside string
  literals/comments and dropped nested-paren/regex-literal sources; now literal-aware with
  balanced scanning.

Correctness fixes (selected): console Svelte-5 effect races across nine routes (duplicate
fetches, stale responses winning) via teardown stale-flags; license extend/seats accepted
`NaN`/0/negative; admin-api proxy dropped `Retry-After`; `no-store` was stamped on
fingerprinted `/_app/immutable/*` assets. React/Svelte/Vue wrappers re-threw nothing on
`CopyLocker.create()` failure (permanent "not ready" + unhandled rejection) and the Vue
plugin ran `create()` during SSR; both fixed cross-SDK. Web `unseal()` mangled
non-`Uint8Array` BufferSources; background `validateNow` could raise an unhandled rejection
(new `validateInBackground`); `restore()` failed open on undecryptable snapshots (now
catches, wipes, starts fresh); snapshot writes are serialized through a write queue; the
session Worker no longer leaks when `create()` throws; `scheduleWake` overflowed the 32-bit
`setTimeout` delay beyond ~24.8 days. Guard `verifyEntry` escaped mid-stream aborts, lazy
mode lost non-`ok` evidence from derived keys, the first root pin masked later valid pins,
and `report.entries` leaked the raw digest field. Telemetry rejected garbage `now()` only
deep in the reporting path and allowed regressing `window_start`s; `__proto__` feature ids
were silently dropped by plain-object assignment. Worker `telemetry:purge` confirmed-replay
returned zeros instead of the journaled result (replay moved before the no-op early return).
Electron/Tauri examples revoked download blob URLs synchronously after `click()`.

Review totals after fixes: cargo 694+1 (40 suites), worker vitest 98/98, console 61/61
(+9), web 102/102, guard 53/53, seal 51/51, telemetry 37/37, unplugin 75/75, react/svelte/
vue 8/8 each, examples build green (electron 5/5, tauri cargo check 333 crates).

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
- The M5 cross-version compatibility matrix (4 historical versions x current server) cannot run
  yet: the repository has no tags and no published releases, so no historical versions exist.
  The matrix activates once at least four versions have been released; npm/registry publication
  itself remains an external-party item.
- M2 residual acceptance evidence pending-external: the timed 30-minute zero-to-activated
  deployment exercise (recorded session) and the desktop 60-second network-recovery timing
  capture. The underlying behavior is test-covered (`copylocker-client` grace/recovery state
  machine; web-side recovery proven by Playwright E2E); only the literal timed evidence
  artifacts are missing.

## Immediate Plan

1. Preserve the private suite at its reviewed public-contract pin, then build the authorized
   application integration, vendor-profile lifecycle, migration process, and release evidence.
2. Preserve a public CI path that does not initialize the private submodule; keep private suite CI
   independent and add an authorized combined-build pipeline before any integrated release.
3. Close remaining M0-M2 evidence: the documented deployment/activation usability exercise
   (external). Fuzzing is closed: codec fuzz ran crash-free for a cumulative 4 h — an
   initial 2 h run (8,063,012 execs) plus a segmented 40x180 s top-up (47,235,544 execs,
   per-segment peak RSS <= 2,023 MB). The segmentation was required because
   libFuzzer/ASAN shows a ~1.8 KB/exec RSS ratchet on this machine once the corpus grew
   large inputs; a standalone probe running all 12 decodes over 2M mutated rounds held
   RSS flat at 5.8 MB, proving the growth is fuzzer-infrastructure behavior, not a codec
   defect. Server endpoints: `fuzz_server_activate` 43,202,002 runs/1 h and
   `fuzz_server_validate` 8,451,251 runs/1 h, both crash-free. The memory budget is
   closed: `tools/client-memory-budget` measures a 624 KiB RSS increment for one
   initialized `CopyLockerClient<ClStd1>` (three runs consistent, 8 MiB budget) and
   69-71 KiB per extra client with no leak slope.
4. M3 CI coverage is wired: the `web-sdk` job (WASM gzip budget, `@copylocker/web` and the
   React/Vue/Svelte binding tests) and the `web-e2e` job (real-backend Playwright suite) are in
   `.github/workflows/ci.yml`. They are validated locally step-by-step but have not yet run in
   GitHub Actions; the first push is the real proof. The < 15 ms local verification budget is
   closed: `bench-wasm-verifier.mjs` reports p95 0.987 ms for the CL-STD-1 chain verification
   path.
5. M4-B is closed (see the M4 evidence above). M5 is closed: Phases A and B (release registry;
   Mode E accounts and the offline AR/OLK loop) and Phase C (multi-suite request dispatch, the
   wasm `unseal-asset` op + web `loadSealed`, the cross-variant unseal negative test, and the
   CLR1 armor / R2 AResp archive closing the M5-B deviations — see the M5-C evidence above). M6
   is closed (telemetry proof-cover fix, server rollup pipeline, admin analytics and DSR
   surfaces, legal-sync CI gate — see the M6 evidence below). The cross-version compatibility
   matrix stays blocked on published versions, and the CL-PRIV-1 acceptance lines stay
   pending-external. Private suite application integration stays pending on authorized
   combined-build evidence.
6. M7 is closed: group-B (admin-sdk complete, drift-check CI, Simulator three-way
   consistency, offline portal, console on admin-sdk) and group-C (worker global
   machines/audit endpoints, releases/analytics/audit/settings pages with DSR UIs, and the
   hermetic Playwright E2E 16/16 covering the full lifecycle, axe on all pages, and
   keyboard-only flows — see the M7-B and M7-C evidence above). M8's repository-internal
   parts are done; the external audit, red team, legal review, npm publication, and
   production operations stay pending-external. The live queue byte-array mangling flagged
   by M7-C is fixed (see the M7-C evidence); the DO outbox flush timing under `wrangler
   dev` remains a documented local-dev limitation.
7. Review follow-ups accepted as non-blocking (from the post-M8 adversarial review): the
   worker `releases.rs` variant-id allocation reads `MAX+1` outside the register transaction,
   so two concurrent same-product registrations can collide and corrupt the sibling→variant
   KEK mapping; a proper fix needs an atomic counter or schema change and the variant-id
   sequence asserted by tests (admin-only, low probability). `@copylocker/web` permits manual
   ops after `dispose()` (background paths are `stopped`-gated; the wrappers unsubscribe, so
   only direct consumers are affected) — a design decision to revisit if misuse is reported.
   A mid-session web Worker respawn is a feature, not a bug fix. Unplugin's guarded-marker
   transform ships `map: null` (needs `magic-string` to fix properly). The seal/web CBOR
   encoder builds per-byte `number[]` near the 64 MiB cap (perf, not correctness).

## Publication and Docs Platform State (2026-08-13)

- The public repository `github.com/backrunner/copylocker` is pushed through the M3-M8
  milestone work, the post-M8 adversarial review fixes, and the open-source readiness
  fixes. The first public CI runs exposed and fixed: the fuzz RSS-ratchet (segmented
  scheduled runs), missing guard/seal dist builds before unplugin tests, js-yaml
  CVE-2026-59870 (node binding lockfile), nanoid GHSA-2v37-7h3g-55p8 (four audited
  lockfiles), and a shared-runner vitest timeout in the 100-way concurrent activation
  test (now 30 s). CI, Native SDK CI (3 platforms), and the Fuzz workflow (dispatch
  validation) are green on GitHub-hosted runners.
- Open-source readiness fixes shipped: README brought to the current state, every
  publishable manifest's repository URL corrected to `github.com/backrunner/copylocker`,
  the workspace homepage points at the GitHub repo (copylocker.dev was unresolving),
  local machine paths removed from tracked files, and the console ACCESS_ENFORCE/JWKS
  limitation documented in English in `docs/guide/deployment.md` (console section).
- The docs site moved from VitePress to svedocs 0.1.0 (exact-pinned, npm) with a custom
  CopyLocker theme and landing page. Build: `npm run build` in `docs/` (edge mode,
  `.svelte-kit/cloudflare`); deploy: `npm run deploy` (Cloudflare Pages project
  `copylocker-docs`). The production target is `https://copylocker.pwp.sh`.
  2026-08-13: the Pages project was created and the first production deployment was
  shipped from the local checkout with
  `wrangler pages deploy .svelte-kit/cloudflare --project-name copylocker-docs --branch main`
  (wrangler OAuth login, account "Alkinum"); `https://copylocker-docs.pages.dev`
  serves landing, docs pages, sitemap, search API, and the static OG SVGs, and the
  rendered `og:image` tags already point at `https://copylocker.pwp.sh`. Per the
  owner, deploys run locally via wrangler, not from CI. The remaining step is a
  Cloudflare dashboard action: Pages -> copylocker-docs -> Custom domains -> add
  `copylocker.pwp.sh` (the pwp.sh zone lives on the same account, so DNS and the
  certificate are automatic; wrangler has no Pages domain command). The
  `CL_DOCS_DEPLOY` CI gate stays off. GitHub Pages stays disabled.
  2026-08-13 (second pass): the blueprint grid backgrounds were removed theme-wide
  (`.sd-root` / reading-mode `::after` / home-hero `::before` overrides in
  `src/lib/styles/copylocker.css`, plus frosted topbar, sidebar/prose/table/footer polish);
  the landing was redesigned (editorial hero with a CSS-only credential card, numbered
  feature cards, full-bleed dark command band, stepper levels); the footer GitHub-icon
  duplication was fixed by pointing Licensing/Threat model at internal pages (svedocs
  FooterLinks renders any github.com href as a GitHub icon). New content, all verified
  against source: `docs/reference/{cli,admin-api,sdks}.md`, `docs/guide/console.md`,
  `docs/operations/privacy.md`; deployment.md gained the OIDC vars, `BUILD_SIGNING_KEY`,
  the migration list, and the daily-rollup cron; the stale "console is M7" FAQ answer was
  corrected. Sidebar ordering is weight-driven (section weight = min of page `order`
  values, ties by path), so sections use disjoint order ranges: docs 0, guide 1-9,
  reference 10-13, operations 20-24, security 30-31. Gotcha: svedocs 0.1.0's TOC slugger
  disagrees with the heading slugger on headings containing `<...>` (e.g. `### init
  <path>`) — avoid angle brackets in headings. Deployed to production; all new routes
  verified 200 on `copylocker-docs.pages.dev`.
- Commits up to the wasm commit are GPG-signed; later commits are unsigned per the
  owner's authorization (non-interactive gpg-agent).

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
