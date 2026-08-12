---
title: Runbook
navTitle: Runbook
order: 1
description: Incident response procedures for a CopyLocker deployment — activation spikes, epoch revocation drills, key compromise, queues, and periodic tasks.
---

# Operations Runbook

Incident response procedures for a CopyLocker deployment. Based on
`.agents/05-ops/security-operations.md` and `.agents/05-ops/testing-strategy.md`; every command
is from the shipped `copylocker` CLI. Capabilities marked "not yet implemented" there are marked
here too — do not write them into production automation.

## Key and credential inventory

| Key / credential | Location | Protection | Rotation | Blast radius if leaked |
|---|---|---|---|---|
| **Root Current** (CL-STD-1 hybrid) | Offline custody | CLI writes mode 0600; HSM/sharding/escrow is your external process | 10 years or on compromise | Catastrophic: can sign new Epochs |
| **Root Next** | Separate custody from Current | Same; pre-provisioned public key by `keygen root` | Replenish after Current activates | Same |
| **Epoch** (hybrid) | Secrets Store | RBAC, write-only deploy channel, audit | ~90 days, 14-day overlap | Credential forgery until revoked |
| **Epoch Fast** (Ed25519) | Secrets Store | Same | With Epoch | Can forge validation tickets, cannot create credentials |
| **Build Signing** | CI secret / Secrets Store | Dedicated key, least privilege | 180 days | Can sign fake build manifests |
| **Server Pepper** | Secrets Store | RBAC; never in D1/config/logs | Rotation requires re-HMACing all license keys | With D1, enables license-key enumeration |
| **Admin Token Pepper** | Secrets Store | Bootstrap uploads via stdin only | Rotation requires recomputing token HMACs | With D1, weakens token protection |
| **Admin Token** | Operator environment variable | Server stores HMAC; scope/time/actor constraints | Bootstrap default 90 days | Scoped resource administration |
| **Bootstrap bundle** | Short-lived offline file | Create-only, mode 0600, never committed; contains token + pepper | One-time | Equivalent to Admin token + pepper leak |
| **Vendor Fingerprint Salt** | Secrets Store | RBAC | Normally never | Offline fingerprint recomputation |

## Activation failure rate spike

Alert threshold: activation failure rate > 5% over 15 minutes (see
[SLOs & Alerting](/docs/operations/slo#alert-thresholds)).

1. **Scope it**: segment failures by app version, build fingerprint, OS, and error code.
2. **Classify**: signing/keyset problem, catalog/policy problem, release-compatibility problem,
   or client bug.
3. If a keyset problem, check the Epoch state: `copylocker epoch list` /
   `copylocker epoch show <id>` (confirms replacement readiness).
4. If you need to extend grace: M1 has **no** general `copylocker grace-extension` command. Use
   only an already-approved, signed, client-implemented configuration path.
5. If the spike is attack traffic, rate-limit and isolate first — **do not** reach for
   irreversible revocation as a first response.

## Epoch revocation drill

Run this quarterly as a drill (see the periodic-task table below) so the real thing is boring.

Preconditions: a valid **replacement Epoch** for the same product must already exist on the
server, and both actors' tokens must hold `epochs:rw` **and** `revoke` (dry-run needs only
`epochs:rw`). The two actors must be genuinely distinct people with distinct tokens.

**Actor A** (dry-run, then first confirmation):

```bash
copylocker epoch revoke 0011223344556677 \
  --admin-token-env COPYLOCKER_ADMIN_TOKEN_A

copylocker epoch revoke 0011223344556677 \
  --admin-token-env COPYLOCKER_ADMIN_TOKEN_A \
  --confirm \
  --confirm-epoch-id 0011223344556677 \
  --idempotency-key incident-2026-0042-epoch-a
```

**Actor B**, within **15 minutes**, with their own token and a different idempotency key:

```bash
copylocker epoch revoke 0011223344556677 \
  --admin-token-env COPYLOCKER_ADMIN_TOKEN_B \
  --confirm \
  --confirm-epoch-id 0011223344556677 \
  --idempotency-key incident-2026-0042-epoch-b
```

The CLI validates the typed ID before any network call; the server enforces the distinct actors,
the 15-minute window, the replacement, and journals everything. Only the second approval produces
the final `epoch` entity version and revocation sequence.

Before executing for real, confirm: the leak is genuine (not a false positive); the replacement
is uploaded and can issue; support and announcements are ready; the two actors are independent.

### Root key compromise

1. Freeze new Epoch uploads/rotations; preserve logs and the affected time window.
2. Sign a new Epoch with the pre-provisioned `root_next`; switch online issuance to it.
3. Two-actor-revoke every affected Epoch signed by Current (procedure above).
4. Ship a client update removing Current, promoting Next to Current, and pinning a fresh Next.
5. Clients too old to recognize Next will fail — announcements, upgrade paths, and support
   scripts must launch with the technical switch.
6. Rebuild the Root custody chain and complete an independent post-mortem.

## D1 / Durable Object failure

**D1.** The authoritative state for seats and issuance lives in Durable Objects; D1 holds the
projections and admin data, fed by an outbox with at-least-once delivery and idempotent consumers
(NFR-REL-004; convergence P95 < 5 s). DO SQLite has 30-day PITR; D1 exports to R2 periodically;
the audit log is immutable append-only (NFR-REL-005). Migrations must be reversible and dry-run
first (NFR-OPS-006) — `copylocker deploy --confirm` re-checks the migration set before deploying.

**DO hotspot** (one license shared across the internet, hammering a single `LicenseDO`; soft
limit ~1000 req/s, product target ≥ 200 req/s):

1. Locate the DO and request source in Cloudflare telemetry.
2. A single anomalous license: suspend it first (`copylocker license suspend <id>`), investigate,
   then revoke with dry-run confirmation if confirmed abusive.
3. A legitimate large customer: adjust seats or split the license. **Never** edit DO storage to
   bypass authoritative state.
4. Issuer shard-count changes are schema/routing migrations — never attempt them mid-incident.

## Queue backlog and DLQ

Alert on any sustained backlog growth and any DLQ message.

1. Inspect the `<project-name>-events` consumer; it runs with `max_concurrency: 1` by design, so
   backlog means failures, not parallelism limits.
2. Isolate the failing events from the DLQ; fix the cause; **replay idempotently** — consumers
   are idempotent, replay is safe.
3. Verify the minute Cron is running: it is what resumes pending Admin side effects, audit
   publication, revocation sequences, and billing transitions after interrupted requests.
4. Never lower `rev:epoch` or overwrite a published `rev:batch:<seq>` — they are monotonic,
   immutable security history.

## Credential compromise and recovery

| Compromised | Severity | Response |
|---|---|---|
| Admin token | Medium/High | Break-glass revocation; export operations by actor/request ID; audit all mutations |
| Bootstrap bundle | High | Treat as Admin token **and** pepper leak: revoke the token, assess D1 exposure, rebuild credentials |
| Build signing key | Medium | Revoke; re-sign live build manifests; investigate fake-manifest distribution |
| Epoch Fast | Medium | Generate a replacement and rotate; assess the forged-VT window |
| Epoch | High | Two-actor revocation (above), switch to replacement, announce |
| Root | Disaster | Root compromise procedure (above) |
| Server/Admin pepper | Low–High | Grade with D1 exposure; rotation requires data migration — isolate and preserve evidence first |

**Break-glass Admin token revocation (the single documented exception).** M1 has no Admin token
lifecycle API. In an emergency, minimally update `admin_tokens.revoked_at` through the Cloudflare
break-glass flow, and record command, approval, result, and timestamps in an external incident
log. This is the only sanctioned exception to "production D1 is touched only through the Admin
API" — it disappears when the token management API ships.

**Mass-revocation mistake.** There is no unrevoke in M1 (the schema keeps `undo_until`, but no
CLI/API contract exists):

1. Stop new confirmations immediately; keep the minute Cron running so already-allocated
   sequences complete without holes.
2. Preserve the dry-run output, idempotency keys, `revocations` rows, Admin journal, KV batches,
   and audit archive.
3. Re-issue new licenses to affected customers (`copylocker license issue …`) and deliver them
   through the approved secure channel.
4. Clients that received the revocation batch must re-activate; coordinate support scripts and
   the status page.
5. Post-mortem the approval, dry-run review, and batch input source.

**Everyday license revocation** (the safe path the mistake above bypassed):

```bash
copylocker license revoke 0123456789abcdef0123456789abcdef                 # dry-run
copylocker license revoke 0123456789abcdef0123456789abcdef \
  --confirm --idempotency-key incident-2026-0042-license-01
```

Check target, affected machines, already-revoked status, and reason in the dry-run before
confirming. A pending revocation sequence rejects later ones with `revocation_in_progress` —
retry with the **same** idempotency key; never allocate around or delete the pending row.

## Periodic security tasks

| Cadence | Task |
|---|---|
| Every PR | Rust fmt/check/test/clippy; Worker check/test/size/startup; dependency audit |
| Daily | Pending journals, queue/DLQ, Epoch expiry, Secrets Store access anomalies |
| Weekly | Sample-verify the Admin operation → AdminAuditDO → Queue → R2/index chain |
| Monthly | Admin token usage/expiry, Cloudflare RBAC, break-glass record review |
| Quarterly | Epoch rotation; random runbook drill; threat-model review |
| Annually | Root custody-chain verification, recovery drill, external security audit |

`copylocker audit verify` is **not yet implemented**; the weekly sample-verification above is
the manual stand-in until it ships.
