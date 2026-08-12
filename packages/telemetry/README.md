# @copylocker/telemetry

The SDK side of CopyLocker **T1 aggregate telemetry** (M6). It collects
consented, pre-aggregated usage counters on the device and encodes them as
the protocol `telemetry_block` that piggybacks on the existing
`/v1/validate` request (proto key 11) — **no new endpoint, no new request**.

Design sources: `.agents/03-modules/90-analytics-telemetry.md`,
`.agents/00-overview/decisions/ADR-0007-analytics-tiering.md`,
`.agents/06-legal/privacy-and-legal-pack.md`. Wire format authority:
`TelemetryBlock` in `crates/copylocker-proto/src/requests.rs`.

- Zero runtime dependencies. Node ≥ 20.
- Canonical CBOR encoder is a narrowed copy of `packages/web/src/cbor.ts`.

## Privacy position

T1 reports **aggregates only**:

| Field | Shape |
|---|---|
| `session_count` | one integer per window |
| `session_duration_histogram` | 4 bucket counters (`<5m / 5–30m / 30m–2h / >2h` by default) — never exact durations |
| `feature_hits` | per-feature counters, **whitelisted feature ids only** |
| `days_active` | integer 0–28 (distinct UTC days) |
| `consent_version` | the privacy-notice version the user agreed to |

It never contains: event timestamps, event order, user input, file names,
location, or any device identifier beyond what the validate request already
carries for licensing. The report is capped at **512 encoded bytes**; the
lowest-priority `feature_hits` entries are dropped first when the budget is
tight.

T1 is **off by default** and requires end-user consent (GDPR Art. 6(1)(a)).
The consent provider is consulted **before every report**; a withdrawal stops
the very next upload. `consent_version = 0` means *no block is produced at
all* — the SDK never emits a zero-consent block (the server counts those as
integration errors).

Everything the client reports is **untrusted**: the server clips again,
counts its own clipping, and displays T1 separately from the trusted
protocol-derived (T0) metrics.

## Usage

```ts
import { createTelemetryHook } from '@copylocker/telemetry'

const telemetry = createTelemetryHook({
  tier: 'T1',
  consent: () => consentStore.get('analytics'), // version number; 0 = no consent
  featureWhitelist: ['export', 'render'],
})

telemetry.track('export')        // whitelisted features only
telemetry.recordSession(420)     // session duration in seconds

// Wire into the web SDK — the block rides on /v1/validate:
const cl = await CopyLocker.create({
  /* … */,
  telemetry,                     // structurally matches CopyLockerOptions.telemetry
})
```

The hook's `buildBlock()` returns the encoded block **and resets the
aggregation window**. If the validate request then fails on the network, that
window's counters are lost — T1 data is low-value aggregate, and the
protocol deliberately trades exactly-once delivery for not adding a retry
queue or a second request.

## Fail-fast rules (FR-TLM-019)

Illegal combinations throw `TelemetryConfigError` at **initialization**, not
silently at runtime:

- `tier: 'T1'` without a `consent` provider → **error** (reporting without
  consent must be impossible).
- `consent` or a non-empty `featureWhitelist` under `tier: 'off' | 'T0'` →
  **error** (dead config = the integration is not doing what its author thinks).
- Empty/duplicate/over-64-char whitelist entries, or more than 64 features → error.
- Non-ascending or non-positive `sessionBuckets`; non-positive `windowSecs`;
  `maxBlockBytes` above 512 → error.

Runtime behavior:

- `track()` of a non-whitelisted feature: **throws in `devMode`**, silently
  dropped (and counted in `stats().droppedFeatureHits`) in production.
- A consent provider that throws or returns garbage (NaN, negative,
  non-integer) is treated as **no consent** — privacy failures always resolve
  toward not reporting.

## Anomaly clipping

`clipBlock` enforces the wire-side ceilings before encoding; the same
clipping runs again server-side before projection:

- `session_count`, histogram buckets, feature hits: clipped to 10 000 each.
- `days_active`: clipped to 28.
- Non-whitelisted feature ids: dropped.
- Encoded size > 512 bytes: lowest-priority `feature_hits` dropped until it fits.

Clipped/dropped counts are surfaced via `hook.stats()` (`clippedFields`,
`droppedFeatures`). The proto wire format has **no field** for these counts;
the server keeps its own clipped counters (`90-analytics-telemetry.md` §6).

## Relationship to legal-sync / data-inventory

The fields above are exactly the T1 section of the data inventory
(`06-legal/privacy-and-legal-pack.md` §3.2), whose field table is generated
from the protocol schema and checked in CI by the `legal-sync` gate. The
`consent_version` carried in every block is the vendor's compliance evidence
that reports match a presented privacy notice; consent withdrawal takes
effect on the next report, and previously reported data is purged server-side
(`POST /v1/admin/telemetry/purge`). If the block's shape ever changes, the
schema, this package, and the inventory must change together.

## API

- `createTelemetryHook(config)` → `TelemetryHook` (`track`, `recordSession`,
  `buildBlock`, `stats`) — mount on `CopyLockerOptions.telemetry`.
- `encodeTelemetryBlock(block)` — raw block encoder (proto-aligned).
- `clipBlock(block, options)` — standalone clipping (also used internally).
- `WindowCollector` — the windowed aggregator (used internally; exported for
  custom hosts).
- `resolveConfig`, `TelemetryConfigError`, `staticConsent`,
  `resolveConsentVersion` — config validation and consent plumbing.

## Development

```sh
npm install
npm run check   # tsc --noEmit
npm test        # vitest
npm run build   # tsc → dist/
```
