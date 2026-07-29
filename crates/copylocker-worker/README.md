# CopyLocker Worker

`copylocker-worker` is the Cloudflare adapter around `copylocker-server-core`. Durable Objects own
strongly consistent license state; D1 holds catalog/configuration data and recovery journals; KV is
cache and signed publication storage; R2 stores archives; Queues move projection, audit, analytics,
and webhook work off the request path.

## Local checks

```bash
cargo install --locked worker-build@0.8.5
npm install
npm run check
npm test
npm run build
npm run size
npm run startup
npx wrangler d1 migrations apply copylocker --local
npx wrangler dev
```

`npm run size` builds the `worker-release` artifact and gates `build/index_bg.wasm` after
deterministic gzip level 9 compression. NFR-PERF-003 is 1,500,000 compressed bytes; raw Wasm and
JavaScript shim bytes are diagnostic only.

`npm run startup` profiles 20 independent local module instantiations of the real release bundle
with `wrangler check startup`. Its P95 `< 50 ms` gate catches local regressions. A release check must
repeat the measurement on a Cloudflare preview because local CPU timings do not represent edge cold
starts.

The IDs in `wrangler.jsonc` are development placeholders. Bind production resources and Secrets
Store names at deployment time; secret values never belong in the config file. Create both the
event queue and its dead-letter queue before deployment. The consumer deliberately uses
`max_concurrency = 1` so subscription events cannot race.

## M1 Admin API

Every `/v1/admin/*` endpoint requires
`Authorization: Bearer clat_<32-byte-canonical-base64url>`. The server stores only
`HMAC(ADMIN_TOKEN_PEPPER, token)`, checks the token's time window and scope, applies vendor
ownership filtering, and returns `Cache-Control: no-store`.

The implemented surface is:

| Resource | Methods and paths | Scope |
|---|---|---|
| Catalog | `GET/POST/PATCH /v1/admin/catalog/{features,groups,tiers}` | `catalog:rw` |
| Catalog resolution | `POST /v1/admin/catalog/resolve` | `catalog:rw` |
| Policies | `GET/POST /v1/admin/policies`, `GET/PATCH /v1/admin/policies/:id` | `policies:rw` |
| Licenses | `GET/POST /v1/admin/licenses`, `GET/PATCH /v1/admin/licenses/:id` | `licenses:rw` |
| License actions | `POST .../:id/change-tier`, `GET .../:id/preview-fallback`, `GET .../:id/machines` | `licenses:rw` |
| License/machine revoke | `POST /v1/admin/{licenses,machines}/:id/revoke?dry_run=true|false` | `revoke` |
| Epochs | `GET/POST /v1/admin/epochs`, `GET /v1/admin/epochs/:id` | `epochs:rw` |
| Epoch revoke | `POST /v1/admin/epochs/:id/revoke?dry_run=true|false` | `epochs:rw`; confirmed requests also require `revoke` |

All confirmed mutations require an explicit `Idempotency-Key`. Reusing the key with the same
canonical request replays the stored result; using it for a different request returns
`idempotency_conflict`. Revoke dry-runs do not allocate a key or mutate state.

Epoch certificates are verified against the Root public key supplied in the upload body before
they are persisted. Confirmed epoch revocation also requires an active, unrevoked replacement.
The first actor creates a durable approval; a different actor must confirm within 15 minutes using
a different idempotency key. Only the second approval allocates and publishes the revocation.

Release, standalone machine administration, analytics, audit query/verify, DSR, telemetry purge,
and Admin token lifecycle endpoints are post-M1. Webhook routes are runtime integrations, not part
of `/v1/admin/*`.

## Mutation recovery

Normal resource mutations atomically commit their D1 business write, immutable
`admin_operations` row, and (for mutable entities) append-only `admin_entity_versions` row. The
remaining checkpoints are idempotent and ordered:

1. Apply the recorded Durable Object or KV side effect, if any.
2. Append the immutable event to `AdminAuditDO` and mirror it in `admin_audit_events`.
3. Send the event to `EVENTS` and persist the enqueue/completion checkpoints.
4. Let the queue consumer archive R2 content and update the D1 audit index.

Revocations separately reserve one monotonic `revocations.seq`, apply it to the target Durable
Object where applicable, and publish both the immutable KV batch and `rev:epoch` before marking the
row complete. A later revocation cannot pass a pending sequence.

Keep the `* * * * *` Cron trigger enabled. Each tick resumes one pending Admin side effect first,
then one journaled Admin audit operation, then one strict revocation, and finally elapsed billing
transitions. It always reuses the original operation/request ID, entity version, revocation sequence,
and idempotent side effect; operators must never delete a pending row or allocate a replacement
sequence manually.

## Runtime secrets and integrations

`IssuerDO` reads CL-STD-1 signing material from `EPOCH_SIGNING_KEY` and
`EPOCH_FAST_SIGNING_KEY`. `copylocker keygen epoch` emits both versioned mode-0600 JSON values. Put
those complete JSON objects into their matching Secrets Store entries; do not extract or transform
the byte arrays.

Payment providers post JSON to `/webhooks/stripe`, `/webhooks/paddle`, and
`/webhooks/lemonsqueezy`. Configure `STRIPE_WEBHOOK_SECRET`, `PADDLE_WEBHOOK_SECRET`, and
`LEMONSQUEEZY_WEBHOOK_SECRET` in Secrets Store. Stripe and Paddle signatures are accepted only
within five minutes of their signed timestamp; Lemon Squeezy uses its raw-body HMAC plus provider
event ID for replay protection.

The event queue's dead-letter queue must remain available for investigation and replay after
exhausted audit, projection, billing, or webhook retries.
