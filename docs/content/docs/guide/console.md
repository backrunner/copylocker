---
title: Admin Console
navTitle: Admin Console
order: 7
description: The CopyLocker admin console — an untrusted SvelteKit frontend over the Admin API, its pages, environment variables, and the Cloudflare Access checklist.
---

# Admin Console

The console (`apps/console`, deployed as the `copylocker-admin` Worker) is the browser UI for
operating a CopyLocker deployment. It is deliberately an **untrusted frontend** (ADR-0010): it
holds no D1/Durable Object/KV/R2 bindings and no signing keys. Every request is proxied to the
API Worker through a Service Binding, where the real Bearer-token and scope checks happen again.

## Deploying and authenticating

The console deploys separately from the API Worker (`npm run build && wrangler deploy` in
`apps/console`). There are two authentication layers, and they answer different questions:

- **Cloudflare Access** sits at the edge and decides who may load the console at all. In
  production set `ACCESS_ENFORCE=true` and complete the JWKS verification described in
  [Deployment → The admin console](/docs/guide/deployment#the-admin-console) — presence checking
  of the `Cf-Access-Jwt-Assertion` header alone is not an authorization boundary.
- **The Admin token** (`clat_…`) authorizes individual operations. In development it is entered
  at `/login` and kept in `sessionStorage` only; requests go out through the `/admin-api` proxy
  with the Bearer header, and the token never appears in URLs or logs.

Public paths — `/login`, `/offline`, `/offline-api`, and `/admin-api` — bypass the Access guard
by design. `/offline` is the customer-facing offline activation portal and shares nothing with
the admin authentication path.

## What each page does

| Route | Capability |
|---|---|
| `/` | Overview: license counts by status, policy count, catalog version and feature/group/tier counts, epoch summary with next expiry |
| `/licenses` | License list with status filter |
| `/licenses/new` | Issue licenses (policy, count, account, seats, expiry); plaintext keys are shown once, downloadable as CSV, then cleared from memory |
| `/licenses/[id]` | License detail: machines, tier change, fallback preview, license/machine revocation via a dry-run dialog with typed-ID confirmation |
| `/catalog` | Feature/group/tier CRUD with guardrail alerts for dangerous configurations; catalog resolve preview |
| `/policies` | Policy list |
| `/policies/new`, `/policies/[id]` | Five-axis policy form; the eleven presets expand inline |
| `/policies/[id]/simulate` | Policy simulator (WASM): activate/renew/cancel/payment-fail/credential-expire scenario steps on a timeline |
| `/releases` | Register releases; deprecate and mark-compromised actions, dry-run first |
| `/keys` | Signing epochs: list, upload a Root-signed certificate, revoke (dry-run plus two distinct actors within 15 minutes) |
| `/analytics` | Metrics explorer over `/v1/admin/analytics/*`: date range, day/week/month granularity, group-by |
| `/audit` | Admin audit log with target/kind filters and cursor pagination; one-click audit-chain verification (`/v1/admin/audit/verify`) |
| `/settings` | DSR export, DSR delete cascade, telemetry purge, machine list with per-machine GDPR delete |
| `/offline` | Public offline-activation portal: relays canonical-CBOR activation requests to `/v1/offline/request` and renders `CLK1` armor as a QR code, client-side |

Known deviation: the portal does not yet render Base32-armored activation *requests* as QR codes
(only `CLK1` license bundles). Air-gapped customers move the request file by other means; see
[CLI Reference → Offline activation](/docs/reference/cli#offline-activation) for the file flow.

## Environment variables

| Variable | Where | Purpose |
|---|---|---|
| `ACCESS_ENFORCE` | `wrangler.jsonc` var | `"true"` requires the `Cf-Access-Jwt-Assertion` header on non-public routes; default `"false"` |
| `CF_ACCESS_TEAM_DOMAIN`, `CF_ACCESS_AUD` | console env | Inputs to the pending JWKS signature verification — set them before production |
| `API_UPSTREAM` | console env | Dev fallback upstream when no Service Binding is present |
| `PUBLIC_API_BASE` | console env | Dev override for the client API base; defaults to `/admin-api` |
| `TURNSTILE_SECRET_KEY` / `PUBLIC_TURNSTILE_SITE_KEY` | console env | Optional Turnstile challenge on the public offline portal; note it conflicts with a strict `script-src 'self'` CSP |

## The proxy routes

- `/admin-api/[...path]` — server-side proxy to the API Worker. Only `/v1/admin/*` paths pass;
  the Bearer token must match `clat_` + 43 base64url characters; bodies are capped at 4 MiB;
  `Idempotency-Key` and `Retry-After` are forwarded; the token is never logged.
- `/offline-api/request` — public proxy to `POST /v1/offline/request` with 16 KiB request /
  2 MiB response caps and the optional Turnstile check.
