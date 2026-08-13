---
title: HTTP API Reference
navTitle: HTTP API
order: 12
description: The CopyLocker wire APIs — the CBOR client protocol, the JSON Admin API with its scopes and idempotency rules, and the billing webhooks.
---

# HTTP API Reference

The server (the `copylocker-worker` npm package, re-exported by your `server-template` project)
speaks **two disjoint wire stacks**:

- **Client protocol** (`/v1/*` except `/v1/admin/*`): canonical CBOR bodies
  (`Content-Type: application/cbor`) with integer map keys, gated by the `X-CL-Proto: 1` header,
  permissive CORS (`Access-Control-Allow-Origin: *`). You normally never hand-write these — the
  SDKs implement them — but the shapes are stable and specified here.
- **Admin API and billing webhooks**: JSON bodies, JSON error envelope, no CORS headers,
  `Cache-Control: no-store` on everything.

Unhandled errors surface as CBOR `500`/`5000` on client endpoints and JSON
`500 internal_error` on admin/webhook endpoints.

## Conventions

- **Idempotency.** Client `POST /v1/activate`, `/v1/offline/request`, and `/v1/deactivate`
  require an `Idempotency-Key` header (≤ 128 chars). Every confirmed Admin mutation requires one
  too (1–128 ASCII-graphic characters); replays return the stored journaled response verbatim,
  and reusing a key with a different request body is `409 idempotency_conflict`.
- **Body limits.** Client protocol: 16 KiB CBOR (`gzip`/`br` accepted with a 64 KiB compressed
  cap). Admin JSON: 256 KiB (4 KiB for revoke endpoints); integrity signing: 256 KiB raw;
  webhooks: 64 KiB.
- **Caching.** `GET /v1/keys` is `public, max-age=300`; `GET /v1/revocations` is
  `public, max-age=31536000, immutable`; everything else is `no-store`.
- **Destructive Admin endpoints** default to `?dry_run=true`. Confirming means
  `?dry_run=false` **plus** an `Idempotency-Key`.
- **Vendor isolation.** Every Admin query is scoped to the token's vendor; cross-vendor targets
  answer `404 not_found`, not `403`.

## Client protocol endpoints

All require `X-CL-Proto: 1` (anything else → `426` + code `1004`).

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | JSON `{ok, service, version}` liveness. |
| GET | `/v1/keys` | CBOR keyset: epoch certificates + revocation epoch. `503`/`5000` + `Retry-After: 1` while the KV cache is cold. |
| GET | `/v1/revocations?since=<u64>` | CBOR revocation batch stream; immutable once published. |
| POST | `/v1/activate` | `ActivationRequest` (license key **or** account token, fingerprint, device KEM key, nonce, `client_info`, proof) → signed `MachineCredential` envelope. Idempotency-Key required. |
| POST | `/v1/validate` | `ValidateRequest` → signed `ValidationTicket` — or a `KillOrder` at the same status code; the artifact kind distinguishes them. Telemetry rides here (key 11). |
| POST | `/v1/heartbeat` | Cheap liveness/renewal ping → `{ok, next_after}`. |
| POST | `/v1/deactivate` | Releases the seat; Idempotency-Key required. |
| POST | `/v1/offline/request` | Air-gapped activation (license-key credentials only). Replays of the same nonce return the archived byte-identical response. `valid_until` = server time + 7 days. |
| POST | `/v1/account/login` | Email/password → `AccountSession` (access + refresh tokens). The only rate-limited endpoint (per-account gate). |
| POST | `/v1/account/refresh` | Rotates the token pair. |
| POST | `/v1/account/logout` | Always succeeds; idempotent. |

### Protocol error codes

Error body: CBOR `{0: code, 1?: message, 2?: retry_after}` with an HTTP `Retry-After` header when
applicable.

| Code | Name | HTTP | Meaning |
|---|---|---|---|
| 1000 | `invalid_credential` | 400/401→403/405/413/415 | Deliberately generic malformed/unauthorized bucket. |
| 1001 | `seat_exhausted` | 409 | No seats left (also the account device limit). |
| 1003 | `needs_login` | 401 | Account session required or expired. |
| 1004 | `unsupported_proto` | 426 | Missing/bad `X-CL-Proto` or unknown `proto_ver`. |
| 1005 | `rate_limited` | 429 | Account login gate; honor `retry_after`. |
| 1007 | `release_not_registered` | 403 | The build's release is unknown; the message names the exact `copylocker release register …` fix. |
| 1008 | `version_out_of_scope` | 409 | App version outside the policy's version scope. |
| 1009 | `release_compromised` | 403 | Release marked compromised. |
| 5000 | `server_error` | 500/503 | `retry_after: 1` on 503. |

## Admin authentication

`Authorization: Bearer <token>` where the token is `clat_` + 43 base64url characters (48 total).
The server stores only `HMAC-SHA256(ADMIN_TOKEN_PEPPER, token)`; raw tokens never touch D1.
Failures: missing/bad/expired → `401 invalid_token` with
`WWW-Authenticate: Bearer realm="copylocker-admin"`; valid token without the scope →
`403 insufficient_scope`.

Scope catalog: `products:rw`, `catalog:rw`, `policies:rw`, `licenses:rw`, `machines:rw`,
`machines:r`, `accounts:rw`, `revoke`, `releases:rw`, `epochs:rw`, `audit:r`, `analytics:r`,
`dsr:rw`, `sign:manifest`. Read scopes are satisfied by their `:rw` counterpart.

There is **no HTTP endpoint to mint Admin tokens** — the bootstrap ceremony
(`copylocker bootstrap prepare` / `apply`) creates the first one; see
[CLI Reference → bootstrap](/docs/reference/cli#bootstrap).

**Second auth mode, one endpoint only:** `POST /v1/admin/integrity/sign` also accepts a GitHub
Actions OIDC JWT (RS256 against GitHub's JWKS), so CI can sign integrity manifests without an
Admin token. Configured with the `INTEGRITY_OIDC_*` vars — see
[Deployment → Environment variables](/docs/guide/deployment#what-you-deploy).

## Admin API endpoints

Envelope on error: `{"ok":false,"error":{"code","message"}}`. Success bodies always include
`"ok": true`. Ids in paths are lowercase hex (license/machine = 16 bytes, epoch = 8 bytes).

### Licenses, machines, accounts

| Method | Path | Scope | Notes |
|---|---|---|---|
| GET, POST | `/v1/admin/licenses` | `licenses:rw` | List (`product_id`, `status?`, `limit?`) / issue (`policy_id`, `count`, `account_id?`, `seats_override?`, `expires_at?`, `metadata?`). **Plaintext keys are returned only by issuance.** |
| GET, PATCH | `/v1/admin/licenses/{id}` | `licenses:rw` | Detail / patch status, expiry, seats, entitlement and version-scope overrides. Revoked → `409 already_revoked`. |
| POST | `/v1/admin/licenses/{id}/change-tier` | `licenses:rw` | Body `{tier}`. |
| GET | `/v1/admin/licenses/{id}/preview-fallback` | `licenses:rw` | Subscription fallback preview; 404 when no subscription. |
| GET | `/v1/admin/licenses/{id}/machines` | `licenses:rw` | Machine views (≤ 1000). |
| POST | `/v1/admin/licenses/{id}/offline-key` | `licenses:rw` | Mint an OLK bundle: `{release_id, bound_fingerprint_hex?, max_seats?}`. Errors include `409 license_not_active`, `422 olk_not_allowed`. |
| POST | `/v1/admin/licenses/{id}/revoke` | `revoke` | Dry-run first; body `{reason?: u8}`. `409 already_revoked` / `409 revocation_in_progress`. |
| GET | `/v1/admin/machines` | `machines:r` | Filters `license_id?`, `status?`, cursor pagination. |
| DELETE | `/v1/admin/machines/{id}` | `machines:rw` | GDPR erasure cascade (alias of DSR delete); dry-run first. |
| POST | `/v1/admin/machines/{id}/revoke` | `revoke` | Same handler and contract as license revoke. |
| GET, POST | `/v1/admin/accounts` | `accounts:rw` | List / create `{product_id, email, password, max_devices?}`. |

### Epochs

| Method | Path | Scope | Notes |
|---|---|---|---|
| GET, POST | `/v1/admin/epochs` | `epochs:rw` | List / upload a Root-signed certificate `{certificate_hex, root_verifying_key_hex}`; publishes the keyset side effect. |
| GET | `/v1/admin/epochs/{id}` | `epochs:rw` | Detail and replacement readiness. |
| POST | `/v1/admin/epochs/{id}/revoke` | `epochs:rw` + `revoke` | Two-actor approval — below. |

Epoch revocation is the strongest guard in the API:

1. `?dry_run=true` reports `affected_machines_upper_bound`, `replacement_ready`, and
   `requires_distinct_actors: 2`.
2. Confirming requires the body `{confirm_epoch_id}` to repeat the path id exactly
   (`409 confirmation_mismatch` otherwise), both scopes on one token, and an active replacement
   (`409 replacement_epoch_required`).
3. The first confirm persists a time-boxed pending approval (`approval_pending: true`). The same
   actor confirming again is `409 second_actor_required`; a **different** Admin actor confirming
   within the window executes the revocation.

### Catalog and policies

| Method | Path | Scope | Notes |
|---|---|---|---|
| GET, POST, PATCH | `/v1/admin/catalog/features` · `/groups` · `/tiers` | `catalog:rw` | Identifiers are immutable once published; deletes are refused. |
| POST | `/v1/admin/catalog/resolve` | `catalog:rw` | Deterministic entitlement snapshot; `422 invalid_entitlement`. |
| GET, POST | `/v1/admin/policies` | `policies:rw` | POST takes a full Policy document → `{ok, policy, version, warnings}`. |
| GET, PATCH | `/v1/admin/policies/{id}` | `policies:rw` | PATCH body is a full Policy whose `id` must equal the URL id. |

### Releases and asset KEKs

| Method | Path | Scope | Notes |
|---|---|---|---|
| GET, POST | `/v1/admin/releases` | `releases:rw` | Register: `{app_version, build_fingerprint, channel, manifest_root_hex?, module_digest_hex?, variant_seed_hex?}`. The server assigns `release_id`/`variant_id`. |
| GET | `/v1/admin/releases/{id}` | `releases:rw` | Detail. |
| POST | `/v1/admin/releases/{id}/deprecate` | `releases:rw` | Dry-run reports impacted devices. |
| POST | `/v1/admin/releases/{id}/mark-compromised` | `releases:rw` | `{action: warn\|force_upgrade\|revoke, bump_security_floor?, acknowledge_revoke?}`. |
| GET, POST | `/v1/admin/asset-keks` | `releases:rw` | Register a 32-byte KEK per `(release, feature)`; list returns fingerprints only. |
| DELETE | `/v1/admin/asset-keks/{release}/{feature}` | `releases:rw` | Dry-run first. |

### Integrity signing

| Method | Path | Scope | Notes |
|---|---|---|---|
| GET, POST | `/v1/admin/integrity/keys` | `sign:manifest` | List/register signer public keys. |
| POST | `/v1/admin/integrity/keys/{fingerprint}/revoke` | `sign:manifest` | Dry-run first. |
| POST | `/v1/admin/integrity/sign` | `sign:manifest` **or GitHub OIDC** | Body is the raw CBOR manifest TBS (`application/octet-stream`); response is raw signature bytes with `X-CL-Signer-Key: <fingerprint>`. `403 signer_key_not_registered` when the build key is not registered for the product. |

### Analytics, audit, DSR, telemetry

| Method | Path | Scope | Notes |
|---|---|---|---|
| GET | `/v1/admin/analytics/definitions` | `analytics:r` | Metric catalog. |
| GET | `/v1/admin/analytics/metrics` | `analytics:r` | `ids`, `from`/`to`, `granularity`, `group_by` → series. |
| GET | `/v1/admin/analytics/export` | `analytics:r` | Raw detail export. |
| GET, POST | `/v1/admin/analytics/subscriptions` | `analytics:r` | Metric subscriptions with webhook delivery. |
| GET | `/v1/admin/audit` | `audit:r` | Filter by `target`, cursor pagination. |
| POST | `/v1/admin/audit/verify` | `audit:r` | Hash-chain verification → `{verified, event_count, head, first_broken}` (≤ 10,000 events). |
| POST | `/v1/admin/dsr/export` | `dsr:rw` | Exactly one of `machine_id` / `license_id`. Not journaled. |
| POST | `/v1/admin/dsr/delete` | `dsr:rw` | Journaled cascade; dry-run first. Audit entries are never tombstoned — see [Telemetry & DSR](/docs/operations/privacy#what-delete-does-not-do--documented-deviations). |
| POST | `/v1/admin/telemetry/purge` | `dsr:rw` | Default cutoff now − 30 days; `before` also removes rollups. Dry-run first. |
| GET, PATCH | `/v1/admin/products/{id}/alert-webhook` | `products:rw` | Suspicion-alert webhook config `{url, threshold 1..100}`. |

## Billing webhooks (inbound)

`POST /webhooks/stripe`, `/webhooks/paddle`, `/webhooks/lemonsqueezy` — provider-signed,
JSON, ≤ 64 KiB. Stripe/Paddle use timestamped HMAC with a 5-minute tolerance; LemonSqueezy uses
a plain HMAC over the body. Bad signatures are `401 invalid_signature`; unrecognized events are
`200 {"ok":true,"accepted":false,"ignored":true}`; accepted events are `202` and queued.
Processing is idempotent by `(provider, event_id)`. Secrets live in the
`*_WEBHOOK_SECRET` Secrets Store bindings.

## The typed Admin SDK

`@copylocker/admin-sdk` maps this API one-to-one:
`createAdminClient({ baseUrl, token, maxResponseBytes? })` returns grouped clients —
`releases`, `licenses`, `accounts`, `assetKeks`, `integrity`, `offlineKey`, `catalog`,
`policies`, `epochs`, `revoke`, `products`, `analytics`, `dsr`, `machines`, `audit`,
`telemetry`. Mutation options mirror the wire rules: `idempotencyKey` everywhere,
`TransitionOptions { dryRun? }` on destructive calls (server default `true`),
`RevokeEpochOptions { confirmEpochId }` for epoch revocation. Errors throw `AdminApiError` with
the server's `error.code`; responses over the byte cap fail with `response_too_large`.
