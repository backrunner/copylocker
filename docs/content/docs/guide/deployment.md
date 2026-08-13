---
title: Deployment
navTitle: Deployment
order: 6
description: How a CopyLocker server is deployed and kept healthy on Cloudflare — bindings, migrations, secrets, Cron, queues, and gradual rollout.
---

# Deployment & Operations

How a CopyLocker server is deployed and kept healthy. Sources: `server-template/README.md`,
`server-template/wrangler.jsonc`, `scripts/check-server-template.sh`, and
`.agents/05-ops/security-operations.md`. Operational incidents are covered by the
[Runbook](/docs/operations/runbook).

## What you deploy

The server project rendered by `copylocker init` deploys the **versioned `copylocker-worker`
npm package** — it does not copy the Rust runtime. `wrangler.jsonc` binds:

- **D1** (`DB`) — the authoritative relational store; migrations in `migrations/`.
- **Durable Objects** — `LicenseDO`, `AccountDO`, `IssuerDO` (v1) and `AdminAuditDO` (v2) as
  SQLite classes. Issuance, seats, and audit ordering live here.
- **KV** (`CACHE`) — edge-cached public keysets and revocation data, so validation traffic does
  not hit Durable Objects (NFR-COST-002).
- **R2** (`ARCHIVE`, bucket `<project-name>-archive`) — immutable audit/event archive.
- **Secrets Store** — `EPOCH_SIGNING_KEY`, `EPOCH_FAST_SIGNING_KEY`, `SERVER_PEPPER`,
  `ADMIN_TOKEN_PEPPER`, `VARIANT_PARAMS_KEY`, `ASSET_KEK_KEY`, `BUILD_SIGNING_KEY`, and the
  payment webhook secrets
  (`STRIPE_WEBHOOK_SECRET`, `PADDLE_WEBHOOK_SECRET`, `LEMONSQUEEZY_WEBHOOK_SECRET`).
- **Queues** — `EVENTS` producer; a consumer on `<project-name>-events` with
  `max_concurrency: 1` and the `<project-name>-events-dlq` dead-letter queue.
- **Cron** — `* * * * *` (every minute; the recovery spine) and `15 0 * * *` (the daily
  analytics/telemetry rollup — see [Telemetry & DSR](/docs/operations/privacy)).

Worker environment variables (plain vars, not secrets):

- `ENVIRONMENT` — `"production"` in the template; `"test"` enables test-only seams and must
  never reach a production deployment.
- `INTEGRITY_OIDC_AUDIENCE` — required to enable GitHub Actions OIDC signing of integrity
  manifests (`/v1/admin/integrity/sign`); OIDC is disabled without it.
- `INTEGRITY_OIDC_ISSUER` (default `https://token.actions.githubusercontent.com`),
  `INTEGRITY_OIDC_REPOSITORIES` and `INTEGRITY_OIDC_REFS` (comma-separated allowlists),
  `INTEGRITY_OIDC_JWKS_URL` (default `{issuer}/.well-known/jwks`) — the rest of the OIDC
  configuration.

Observability is on by default: logs at 100% head sampling, traces at 1%.

## The deploy commands

```bash
copylocker deploy --project .            # local dry-run only; writes .copylocker/dry-run.js
copylocker deploy --project . --confirm  # applies remote D1 migrations, then deploys
copylocker doctor --project . --check-api
```

`bootstrap apply --confirm` already runs the remote migrations; the confirmed deploy repeats the
migration check first. Use `--skip-migrations` only when a separately controlled step has already
applied the exact migration set.

## Migration discipline (enforced, not aspirational)

The migration set is ten files, applied in order: `0001_initial`, `0002_release_feature_keks`,
`0003_admin_revocations`, `0004_admin_audit`, `0005_billing_webhooks`,
`0006_unified_admin_audit`, `0007_admin_operations`, `0008_epoch_approvals`,
`0009_integrity_signer_keys`, `0010_release_admin`.

- Worker and `server-template` migration files must be **byte-identical**.
  `scripts/check-server-template.sh` fails the build otherwise: it diffs every migration in both
  directions, rebuilds the Worker package, checks the template's `copylocker-worker` dependency
  matches the built version, runs the package content check, and renders the template with
  placeholder IDs to type-check it through Wrangler.
- Every migration must be registered in the CLI scaffold and its tests.
- Run the script from the repository root after any Worker or template change:

```bash
bash scripts/check-server-template.sh
```

## Secrets discipline

- Secret values are complete **versioned JSON objects**, uploaded on stdin via
  `wrangler secrets-store secret create <store-id> --name <NAME> --scopes workers --remote`.
  They never appear in `wrangler.jsonc`, argv, logs, fixtures, or commits.
- **Root keys never touch this project.** Root generation and signing happen on the offline
  ceremony host; only the Root-signed epoch certificate travels to the Admin API, and only the
  matching secret JSON to Secrets Store.
- The Admin token lives only in the environment variable named by `admin_token_env` in
  `copylocker.json` (default `COPYLOCKER_ADMIN_TOKEN`). The server stores its HMAC.
- Do not place Root keys, Epoch keys, webhook secrets, Admin tokens, or pepper values in the
  project directory. The full custody matrix is in
  [Runbook → Key and credential inventory](/docs/operations/runbook#key-and-credential-inventory).

## The minute Cron — leave it enabled

The `* * * * *` trigger is the recovery spine. Each tick advances, in fixed order and at most one
item per class per tick (failures are not skipped):

1. the oldest pending Admin side effect;
2. the oldest Admin audit operation whose side effect completed;
3. the single pending strict revocation;
4. due billing transitions.

Disabling the Cron strands pending revocations, audit publications, and subscription transitions
mid-flight.

## Queue discipline

The events consumer intentionally runs with `max_concurrency: 1` so billing events cannot race,
with `max_retries: 10` before the DLQ. Any DLQ message or sustained backlog growth is an alert
condition — see [SLOs & Alerting](/docs/operations/slo#alert-thresholds).

## Idempotency and dry-run culture

Every Admin mutation requires an explicit, stable, unique idempotency key
(`--idempotency-key`); retries reuse the same key. Destructive operations are dry-run by default
and need `--confirm`. Epoch revocation additionally needs two distinct Admin actors within
15 minutes. These are server-enforced contracts, not CLI politeness.

## The admin console

The console (`apps/console`) is a separate SvelteKit app deployed to Cloudflare
(`npm run build && wrangler deploy` in that directory). Its pages, environment variables, and
proxy routes are documented in [Admin Console](/docs/guide/console). It is an untrusted
frontend: real
authorization always happens in the API Worker (Bearer token + scope checks). The console's
own route guard relies on Cloudflare Access:

- **`ACCESS_ENFORCE=true` only checks the *presence* of the `Cf-Access-Jwt-Assertion`
  header.** Full JWKS signature verification against
  `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` (validating `exp`/`aud` with
  `CF_ACCESS_TEAM_DOMAIN` / `CF_ACCESS_AUD`) is deployment-time configuration — see the
  `TODO(deployment)` note in `apps/console/src/hooks.server.ts`. **Complete this before any
  production deployment**; presence checking alone is not an authorization boundary.
- `/offline` and `/offline-api` are public routes (the offline activation portal) and never
  share the admin authentication path. The Admin token lives only in `sessionStorage` and is
  proxied via `/admin-api`; it never enters URLs or logs.

## Gradual rollout

Worker deployments support percentage-based gradual rollout and fast rollback via Cloudflare
Versions & Gradual Deployments (NFR-REL-008). Pair them with the client-side staged rollout in
the [go-live checklist](/docs/guide/protection-levels#go-live-checklist).
