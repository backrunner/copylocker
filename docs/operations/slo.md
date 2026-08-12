# SLOs & Alerting

Service-level objectives for a CopyLocker deployment, derived from the NFR-REL/PERF requirements
in `.agents/01-requirements/non-functional-requirements.md` and the alert thresholds in
`.agents/05-ops/security-operations.md` §7.

::: info External dependency
The dashboards themselves are **external configuration** — Grafana, Cloudflare
Analytics/Workers Logs, or your APM of choice. This page defines the SLIs, the SLO targets, and
the wiring; it does not ship a dashboard. Metrics sources on Cloudflare: Workers Logs /
observability (enabled in `wrangler.jsonc` with logs at 100% head sampling and traces at 1%),
Workers Analytics Engine (NFR-OPS-002), and Queue/DO metrics in the Cloudflare dashboard.
:::

## SLIs

| SLI | Definition | Source |
|---|---|---|
| Availability | Share of validation/activation requests not returning 5xx, per month | Worker request metrics |
| Validation latency | End-to-end online validation latency (global, excluding client network degradation) | Worker timing / Analytics Engine |
| Cold start | Worker cold start including WASM instantiation | Cloudflare startup metrics / `scripts/check-worker-startup.mjs` in CI |
| Issuance success | Share of license-issuance operations completing without error | IssuerDO / Admin API logs |
| Activation success | Share of activation attempts succeeding | Protocol endpoint logs |
| Projection lag | DO → D1 outbox projection delay | Consumer instrumentation |
| Queue health | Events-queue backlog depth and DLQ message count | Cloudflare Queues metrics |
| Epoch freshness | Remaining validity of the current signing Epoch | `copylocker epoch show <id>` |
| Pending-operation age | Age of the oldest pending Admin operation / side effect / revocation | D1 admin tables via read-only API |

## SLOs

| SLO | Target | Origin |
|---|---|---|
| Monthly availability | **99.9%**; exhausting the error budget freezes feature releases | NFR-REL-001 |
| Validation latency | P50 < 60 ms, P95 < 120 ms | NFR-PERF-001 |
| Cold start | P95 < 50 ms | NFR-PERF-002 |
| Issuance signing CPU | < 3 ms per ML-DSA-65 + Ed25519 hybrid sign | NFR-PERF-009 |
| Projection lag | P95 < 5 s (at-least-once outbox, idempotent consumers) | NFR-REL-004 |
| Single-LicenseDO throughput | ≥ 200 req/s (well under the ~1000 req/s soft ceiling) | NFR-PERF-008 |
| Validation request size | < 8 KB up / < 12 KB down per background validation | NFR-PERF-010 |

Client-side budgets that shape your rollout monitoring: local credential verification < 5 ms
desktop / < 15 ms browser WASM (NFR-PERF-004); guard LCP impact < 20 ms (NFR-PERF-006); desktop
SDK memory delta < 8 MB (NFR-PERF-007). These are CI-gated product budgets (a > 15% regression
fails the gate), not server SLOs.

### Availability, defined honestly

A server outage is not automatically an SLO burn for your users: Mode O clients ride through it
inside their grace window, and Mode E clients inside `refresh + grace` (NFR-REL-002). Track both
*server* availability (the 99.9% SLO) and *user-visible lockouts* (should be zero absent client
bugs) — the gap between them is what grace is for.

## Alert thresholds

From the operations guide's alert table — wire these into your pager:

| Alert | Threshold | First response |
|---|---|---|
| Pending Admin operation/side effect age | > 2 minutes | Check Worker/Cron/DO/KV; retry with the original request ID |
| Pending revocation age | > 2 minutes | Block new sequences; inspect DO, KV, and Cron |
| Event queue backlog / DLQ | Any sustained growth / any DLQ message | Isolate failing events; replay idempotently |
| Epoch remaining validity | < 30 d / < 14 d / < 7 d | Schedule → escalate → execute rotation ([Runbook](./runbook#epoch-revocation-drill)) |
| Issuance failure rate | > 1% over 5 minutes | Check signing secrets, IssuerDO, Epoch state |
| Activation failure rate | > 5% over 15 minutes | Segment by release/client/keyset ([Runbook](./runbook#activation-failure-rate-spike)) |
| 5xx rate | > 0.5% over 5 minutes | Check dependencies; debit the error budget |

## Wiring notes

- **Metrics export**: NFR-OPS-002 requires activation/validation QPS, success rates, latency
  histograms, DO storage, and seat utilization to be exportable to Workers Analytics Engine. In
  Grafana, use the Cloudflare data source (or Logpush → your log backend) and build one panel
  per SLI above.
- **Logs**: NFR-OPS-001 requires structured JSON logs with automatic redaction of sensitive
  fields; Workers Logs is enabled in the template, and Logpush is the supported export path.
- **Error budget policy**: when the 99.9% monthly budget is exhausted, freeze feature releases
  (NFR-REL-001) until recovery — write this into your release checklist, not just the dashboard.
- **Epoch expiry alerts** are calendar-driven as much as metric-driven: the recommended cadence
  is D-30 scheduling, D-14 generation/upload into overlap, D0 issuance switch, D+14 end of old
  issuance — with windows sized to your product's longest refresh/grace, not mechanically 14
  days.
