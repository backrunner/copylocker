# Cost Estimation

A usage model for the Cloudflare bill of a self-hosted CopyLocker server. The design constraint
is NFR-COST-001: **100,000 active devices per month, each validating once per day, must cost
under $20/month**.

::: warning Prices move
All unit prices below are placeholders from public Cloudflare pricing at the time of writing —
**verify against Cloudflare's then-current pricing** before budgeting. The formulas are the
durable part; plug in current rates.
:::

## Scale assumptions

Following the roadmap-scale assumption behind NFR-COST-001:

| Variable | Symbol | Default |
|---|---|---|
| Active devices / month | `D` | 100,000 |
| Validations per device per day | `V` | 1 |
| Days / month | — | 30 |
| Activations per device per month | `A` | 0.05 (1 per 20 devices) |
| Validation payload | — | ≤ 8 KB up / ≤ 12 KB down (NFR-PERF-010) |
| Audit/telemetry events per validation | `E` | ~1 |

Derived monthly volumes:

```text
validations/month   = D × V × 30            = 3,000,000
activations/month   = D × A                 = 5,000
requests/month      ≈ validations + activations ≈ 3.0 M
queue ops/month     ≈ requests × E × 3      (produce + consume + retry headroom)
```

## Cost model by service

Formulas use placeholder unit prices (marked `~`). Paid-plan baselines (e.g. Workers Paid at
~$5/month) are excluded — this models usage charges only.

### Workers (requests)

Most validation traffic should resolve at the edge: public keysets and revocation data are
KV-cached, and Cache/KV short-circuits everything that does not need a Durable Object
(NFR-COST-002).

```text
worker_requests = requests/month
cost ≈ worker_requests × ~$0.30 / 1M        ≈ 3.0M × $0.30/1M ≈ $0.90
```

CPU time matters more than request count at this scale: signing is < 3 ms CPU (NFR-PERF-009)
and validation is signature verification plus KV reads, comfortably inside the included CPU
allowance of the paid plan at millions of requests.

### Durable Objects

Only stateful operations hit DOs: activations, seat changes, issuance, admin mutations.
Validations are designed to be served from KV.

```text
do_requests = activations + admin_ops + seat_events   ≈ 10⁴–10⁵ / month
cost ≈ do_requests × ~$0.15 / 1M  +  duration_gb_s × ~$12.50 / 1M GB-s
     ≈ cents
```

Duration stays negligible because DO requests are short (single-digit ms) and infrequent. Watch
this term if you enable heartbeats at short intervals — heartbeat traffic lands here unless
deliberately cached.

### D1

D1 is written through the outbox projection (batched by the queue consumer) and read by the
Admin API — not by validation traffic.

```text
d1_rows_read    ≈ admin reads + projection bookkeeping          ≈ 10⁶
d1_rows_written ≈ activations + license/admin mutations + projections ≈ 10⁵–10⁶
cost ≈ reads × ~$0.001 / 1M  +  writes × ~$1.00 / 1M            ≈ $1
```

### KV

```text
kv_reads  ≈ validations (keyset/revocation lookups)             ≈ 3.0 M
kv_writes ≈ epoch rotations + revocation batches + key rebuilds ≈ 10²–10³
cost ≈ kv_reads × ~$0.50 / 1M                                   ≈ $1.50
```

### Queues

Audit and telemetry events flow through the queue in batches to R2 (NFR-COST-003) — never as
high-frequency D1 writes.

```text
queue_ops ≈ events × ~3 (produce/consume/retry headroom)        ≈ 9 M
cost ≈ queue_ops × ~$0.40 / 1M                                  ≈ $3.60
```

### R2

Immutable audit/event archive. Storage is the dominant term; Class A/B operations are minor at
batch sizes.

```text
storage ≈ events/month × ~1 KB × retention_months
        ≈ 3M × 1KB × 12 ≈ 36 GB after a year
cost ≈ storage × ~$0.015 / GB-month + operations                ≈ $0.54
```

R2 has no egress fees, which is what makes long audit retention cheap.

### Secrets Store

Secrets Store is free at this scale; ignore it.

## Rollup (defaults above)

| Service | ≈ $/month |
|---|---|
| Workers | 0.90 |
| Durable Objects | < 0.10 |
| D1 | 1.00 |
| KV | 1.50 |
| Queues | 3.60 |
| R2 | 0.54 |
| **Total** | **≈ $7.6** |

Against the **$20** budget (NFR-COST-001) that leaves ~2.5× headroom for retries, admin traffic,
growth, and price drift. The sensitive terms, in order: **Queues** (event fan-out `E` — batch
aggressively), **KV reads** (scales with validations), **D1 writes** (keep projections batched).

## Keeping it true

- **Cache short-circuits are the design** (NFR-COST-002): if validation traffic starts hitting
  DOs or D1, cost and latency both degrade — treat that as a bug.
- **Batch through the Queue** (NFR-COST-003): audit/telemetry must never become per-request D1
  writes.
- The requirements call for a `copylocker-cli estimate --devices N --interval D` command
  (NFR-COST-004) — **not yet implemented**; until it ships, this page's formulas are the
  estimator.
