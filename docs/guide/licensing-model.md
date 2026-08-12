# The Licensing Model

CopyLocker policies are built from **five orthogonal axes** — commercial shapes are combinations,
not an enum (ADR-0009). This page follows `.agents/02-architecture/licensing-model.md`, with type
fields verified against `crates/copylocker-server-core/src/policy.rs`.

```text
Policy = Entitlement × Validity × VersionScope × Seats × Mode
```

```rust
pub struct Policy {
    pub id: String,
    pub product_id: String,
    pub name: String,
    pub entitlement: EntitlementSpec,   // axis 1
    pub validity: Validity,             // axis 2
    pub version_scope: VersionScope,    // axis 3
    pub seats: SeatSpec,                // axis 4
    pub mode: Mode,                     // axis 5
    pub runtime: RuntimeSpec,           // refresh_after / grace / fingerprint tolerance / …
}
```

## Axis 1: Entitlement

A four-level structure:

```text
Feature (atomic capability)
  ↑ included in
FeatureGroup (named set, may include other groups)
  ↑ included in
Tier (a bundle of groups + limits + display info + rank)
  ↑ added on top
Grant (add-on / individual grant, may carry its own validity window)
```

The server **resolves** a spec into a flat snapshot at issuance time and writes it into the
machine credential. Resolution is a deterministic pure function (property-tested): tier → groups
(recursive, cycle-detected, depth cap 8) → extra groups → currently-valid grants → minus excluded
features; limits merge `tier ← grant ← limit_overrides` with a declared `LimitMergePolicy`
(`max` / `sum` / `override`, default `max`). Output is ordered (`BTreeSet`/`BTreeMap`), so
encoding is deterministic and signatures are reproducible.

**The client never receives the catalog.** It only sees the resolved snapshot — smaller client,
smaller attack surface, and your pricing structure stays on the server.

### Feature IDs are immutable — hard constraint

Because `FeatureKey(f) = KDF(SessionRoot, … ‖ feature_id)`:

| Object | Mutability | If violated |
|---|---|---|
| `feature_id` | **Never mutable, never reused** | Every asset sealed under it becomes undecryptable |
| Group membership | Mutable | — |
| Tier → group membership | Mutable | — |
| Limit key | Immutable | Clients can't read that limit |
| Limit value | Mutable | — |

Features support a `deprecated_at` marker (still resolvable; new tiers should not reference
them). The CLI hard-blocks renaming or deleting a published feature
(`copylocker catalog feature deprecate` exists; there is no rename). Naming convention:
`<domain>.<capability>` — `export.pdf`, `ai.assist`, `render.4k`. Groups may reference globs
(`export.*`), which are expanded to concrete features at resolution time; wildcards are never
sent to clients.

### Limits: who enforces what

**CopyLocker only provides signed numbers; runtime enforcement is your application's job.**
`max_projects`-style quotas are business semantics, and enforcing them server-side would require
reporting counters — a privacy and availability problem we deliberately do not create. If you
need a quota that cannot be bypassed, seal the capability behind a feature key (L2/L3), not a
number.

## Axis 2: Validity

```rust
pub enum Validity {
    Perpetual,
    FixedTerm { duration_secs: i64 },
    Subscription {
        period_secs: i64,
        dunning_grace_secs: i64,          // default 7d
        fallback: Option<PerpetualFallback>,
    },
    Trial {
        duration_secs: i64,
        once_per: TrialScope,             // Fingerprint | Account | Email
        extendable_by_secs: Option<i64>,
    },
}
```

### The subscription self-harm constraint

```text
not_after      = current_period_end + dunning_grace     ← NOT current_period_end
refresh_after ≤ billing_period / 4                      ← cancellations propagate in time
```

Payment webhook lag, issuer processing, and expired cards all mean `current_period_end` passes
while the user has actually paid. Setting `not_after` directly to `current_period_end`
periodically locks out a cohort of legitimate paying users — the most common self-inflicted
wound of subscription software.

### Subscription state machine

```text
        ┌──────────── renew (webhook) ────────────┐
        ▼                                          │
  active ──payment_failed──▶ past_due ──dunning expires──▶ suspended
    │  │                        │                            │
    │  └──payment_ok────────────┘                            │
    │                                                        │
  cancel_at_period_end                        reactivate (webhook)
    │                                                        │
    ▼                                                        ▼
  canceling ──period_end──▶ ended ──(if earned)──▶ perpetual_fallback
                              └──(otherwise)──▶ expired
```

| State | Client availability |
|---|---|
| `active` | Normal |
| `past_due` | Normal during dunning; the ticket carries a hint so the app can show "update your payment method" |
| `canceling` | Normal until period end |
| `suspended` | Renewal refused; existing credentials lock at `not_after` |
| `ended` / `expired` | Same |
| `perpetual_fallback` | Converts to perpetual + version cap (below) |

All transitions are webhook-driven, **idempotent** (deduplicated by `(provider, event_id)` in
`billing_events`), and audited.

### Trial anti-abuse

`once_per: Fingerprint` (tolerance-matched, so swapping a NIC does not reset it),
`once_per: Email` (with disposable-domain blocklists), rate limits across IP / fingerprint /
email domain, optional Turnstile, and `extendable_by` for support-granted extensions (capped,
audited — safer than "issue another trial"). Honest note: trial anti-abuse is never watertight
(VM + fresh email). The goal is to raise the cost above "just buy it", not to reach zero.

## Axis 3: VersionScope

```rust
pub enum VersionScope {
    Unlimited,
    SemverRange(String),       // "^3", ">=2.0 <4.0"
    ReleasedBefore(i64),       // ★ recommended: releases.published_at <= cutoff
    Pinned(Vec<ReleaseId>),    // enterprise lock to specific releases
}
```

`ReleasedBefore` is recommended because it is exact and unambiguous — "was this release published
before T?" — where semver ranges invite endless edge-case arguments. It is also the standard
mechanics of "buy once, get one year of updates".

**The enforcement point is the server.** At issuance/renewal the server checks the client-reported
`release_id` against `releases.published_at` and withholds out-of-scope releases' `wrapped_keks`.
The client-side check is UX only. A client can lie about its `release_id` — and it does not
matter: lying about an old release gets it the old variant's keys, which cannot open the new
version's sealed assets. The variant mechanism carries the version-scope enforcement (ADR-0008 ×
ADR-0009 synergy).

Out-of-scope UX: the app enters a **limited mode** — "your license covers up to 3.8; keep using
3.8 or upgrade" — with a one-click downgrade link. Never a crash, never an accusation of piracy.

## Perpetual fallback

```rust
pub struct PerpetualFallback {
    pub after_months: u32,        // consecutive paid months required, default 12
    pub scope_at: FallbackScopeAt, // EarnedAt | SubscriptionStart
}
```

Each successful billing period accumulates `continuous_paid_months`; an interruption past dunning
resets it (and records the reset). Reaching the threshold writes `fallback_earned_at` once —
persisted, audited, never updated again (this is the idempotency key of the whole mechanism;
webhooks may replay). When the subscription ends, an earned fallback converts to
`Perpetual + ReleasedBefore(fallback_earned_at)`. Refunds/fraud revoke through the standard
revocation flow.

Preview before it matters — this is a real CLI command:

```bash
copylocker license preview-fallback <license-id>
```

The validation ticket also carries `fallback_progress` so your app can show "3 more months of
continuous subscription to earn a perpetual license" — a product capability, not a security
decision.

## Axes 4 & 5: Seats and Mode

`SeatSpec` carries `seats`, optional `max_transfers` / `transfer_window_secs`, and optional
`heartbeat_secs` (enables zombie-seat recovery). Mode is offline-tolerant (**O**) or
online-enforced (**E**). Interactions that bite:

| Interaction | Rule |
|---|---|
| Trial × Seats | Trials force `seats = 1`, no machine transfer (prevents rotation abuse) |
| Subscription × Seats | Seat reductions take effect at the next renewal, never mid-period |
| Perpetual × Mode E | Legal but warned: a perpetual license that requires your server to run forever |

### Mode O vs Mode E, honestly

Mode O clients keep working through a full server outage until grace ends (NFR-REL-002) — and a
fully offline attacker with a manipulated clock can stretch usage to `not_after`. Mode E trades
that residual risk for a hard `not_after` and a hard dependency on your server's availability.

## Propagation of entitlement changes

| Change | Path | Latency |
|---|---|---|
| Tier upgrade (paid) | webhook → license → next validation carries new entitlements + `wrapped_keks` | ≤ `refresh_after`; pushable |
| Tier downgrade | Same, but **scheduled to period end** (`scheduled_changes`) | Period end |
| Add-on grant | Same as upgrade | ≤ `refresh_after` |
| Catalog change | Only affects **newly issued** credentials; issued snapshots are frozen | Next renewal |
| Seat change | Written to the DO immediately; excess seats are not kicked, they age out | Immediate |

User-hostile changes (downgrade, seat reduction, scope tightening) land at the end of the billing
period by default; user-friendly ones (upgrade, add-on) apply immediately. With Mode E or
heartbeats, the server can push a `refresh_now` flag to compress propagation to minutes.

## Presets and the simulator

`copylocker policy presets` lists eleven starting points, and
`copylocker policy create --preset <name> --id <id> --product <p> --tier <t> --at <ts> --out
policy.json` generates one you can edit freely:

`trial-14d` · `perpetual` · `perpetual-major` · `perpetual-fallback` (mainstream buy-once) ·
`sub-monthly` · `sub-annual` · `sub-annual-fallback` (JetBrains-style) · `team-sub` ·
`enterprise-airgap` · `saas-client` (the one Mode E preset) · `edu-1y`

Five axes make a large combination space — **validate and simulate before pushing**:

```bash
copylocker policy validate --policy policy.json --catalog catalog.json --at 1767225600
copylocker policy simulate --policy policy.json --catalog catalog.json \
  --releases releases.json --scenario scenario.json
```

The simulator runs the same pure logic as the live server (NFR-LIC-004: preview output must match
production behavior — it is also the best regression-test carrier). Example timeline for a
`sub-annual-fallback` purchase cancelled after 18 months: activation → renewals accumulate
`continuous_paid_months` → month 12 records `fallback_earned_at` → cancellation → period end
converts to perpetual capped at releases published before the earned date → newer versions enter
limited mode with a downgrade path.

## Data model notes

- `catalog_versions` stores immutable snapshots; `licenses.catalog_version` reproduces exactly
  what any user was entitled to at issuance — dispute resolution is a replay, not an argument.
- `licenses.entitlement_override_json` covers per-license enterprise customization without
  polluting shared policies.
- `billing_events` deduplicates by `(provider, event_id)` — webhooks are safe to replay.

For the full schema see `.agents/02-architecture/data-model.md`.
