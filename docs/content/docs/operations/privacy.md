---
title: Telemetry & DSR
navTitle: Telemetry & DSR
order: 24
description: What telemetry CopyLocker collects, the consent and tier gates in front of it, retention and purge mechanics, and data-subject request handling — with the deviations written down.
---

# Telemetry & DSR

This page is the data-protection contract of a CopyLocker deployment: exactly what telemetry
exists, what gates it, how long it lives, and how export/delete requests behave — including the
parts that are deliberately *not* perfect. Client-side collection mechanics are in
[SDK Reference → `@copylocker/telemetry`](/docs/reference/sdks#copylockertelemetry).

## What is collected

Telemetry rides the validate path as an optional `TelemetryBlock` (max 512 bytes). The fields,
after client-side and server-side clipping (`clip.rs`):

| Field | Shape | Cap |
|---|---|---|
| `consent_version` | Privacy-notice version the user accepted; `0` = no consent | — |
| `window_start` | Server-supplied window marker, passed through | — |
| `session_count` | Sessions in the window | 10,000 |
| `session_duration_histogram` | Bucketed durations (default buckets 5 min / 30 min / 2 h) | exact durations never cross the wire |
| `feature_hits` | Hit counts for allow-listed feature ids | 64 features, 128-char ids, 10,000 hits |
| `days_active` | Active days in the window | 0–28 |

Two independent gates stand in front of every block: the **policy tier gate** (the tier must
permit telemetry) and the **consent gate** (consent version > 0). Blocks dropped at either gate
are counted as operational `t1.*` counters (`no_consent`, `tier_gate`) — the drop itself is
visible, the data is not collected. Clip events (`session_count_clipped`,
`feature_key_dropped`, …) are likewise counted as anomalies.

## Pseudonymity

Analytics rows are keyed by `HMAC(SERVER_PEPPER, "copylocker/analytics-pepper")`-derived
pseudonyms, domain-separated from the license-key HMACs used elsewhere. Raw IP addresses are not
part of the telemetry model.

## Pipeline and retention

1. One analytics detail event per successful activation/check-in goes to the `EVENTS` queue.
2. The consumer archives raw events to R2 under `analytics/raw/`; the bucket has a 90-day
   lifecycle rule.
3. A daily Cron (`15 0 * * *`) aggregates, idempotently, into `analytics_rollup` (exact),
   `analytics_hll` (HyperLogLog sketches), and `telemetry_rollup` (T1 aggregates).
4. T1 raw telemetry in D1 is retained for **30 days** (`TELEMETRY_RAW_RETENTION_DAYS`), enforced
   by `telemetry purge`.

Known deviation: the near-realtime Analytics Engine leg is pending — there is no
`analytics_engine` binding in the shipped `wrangler.jsonc` yet; dashboards read the rollup
tables and Workers Logs instead.

## Telemetry purge

`POST /v1/admin/telemetry/purge` (CLI: `copylocker telemetry purge`) enforces the raw-retention
horizon. Dry-run by default; `--confirm` applies and requires an idempotency key. With no
arguments it deletes T1 raw rows older than 30 days. Passing `--before <YYYY-MM-DD>` also
removes `telemetry_rollup` rows older than the date — rollups are otherwise kept, because they
are aggregates without subject identifiers.

## Data-subject requests

`POST /v1/admin/dsr/export` and `POST /v1/admin/dsr/delete` take exactly one subject — a machine
id or a license id (CLI: `copylocker dsr export|delete --machine … | --license …`).

- **Export** gathers everything held about the subject and returns it as one document. It is not
  journaled — the audit journal records before/after transitions, and an export has none.
- **Delete** is a cascade: Durable Object activation erasure, D1 projection delete, and a bounded
  scan of raw telemetry. Dry-run by default; confirming requires an idempotency key. Deleting a
  machine via `DELETE /v1/admin/machines/:id` runs the same cascade, authorized by `machines:rw`
  instead of `dsr:rw`.

Bounds (deliberate, to keep a DSR request from becoming a table scan):
`MAX_DSR_MACHINES = 500`, `MAX_SCAN_DATES = 400`, `MAX_SCAN_RECORDS = 50,000`,
`MAX_MATCHED_KEYS = 20,000`, `MAX_AUDIT_REFERENCES = 100`.

### What delete does not do — documented deviations

- **Audit entries are not tombstoned.** The audit chain is content-hashed; rewriting an entry
  would break the chain. Audit rows instead expire with audit retention, and the delete response
  states `audit_tombstone: false`. If your privacy policy promises erasure from audit logs, that
  promise is currently false — adjust the policy, not the code.
- **Aggregate tables are never touched.** `analytics_rollup`, `analytics_hll`, and
  `telemetry_rollup` contain no subject identifiers, so cascades skip them by design.

## Operating checklist

- Decide per tier whether telemetry is on, and surface the privacy notice version your consent
  flow records — the server will not accept T1 blocks without it.
- Watch the `t1.*` drop counters: a spike in `no_consent` after a release usually means the
  consent flow regressed, not that users changed their minds en masse.
- Schedule `telemetry purge` in the runbook cadence (or rely on the default horizon) and alert
  on purge dry-run failures — retention that silently stops being enforced is a compliance bug,
  not an ops metric.
