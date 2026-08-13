---
title: Operations
navTitle: Operations
order: 20
description: Running a CopyLocker deployment in production — runbook, SLOs, cost model, and the telemetry/DSR data contract.
---

# Operations

Everything you need to run a self-hosted CopyLocker server in production.

- [Runbook](/docs/operations/runbook) — incident response: activation spikes, epoch revocation
  drills, key compromise, queue/DLQ handling, periodic tasks.
- [SLOs & Alerting](/docs/operations/slo) — the SLIs, SLO targets, and alert thresholds to wire
  into your pager.
- [Cost Estimation](/docs/operations/cost-estimation) — the Cloudflare usage model behind the
  $20/month at 100k devices design target.
- [Telemetry & DSR](/docs/operations/privacy) — what telemetry exists, the consent/tier gates,
  retention and purge, and data-subject requests with the deviations written down.
