# @copylocker/admin-sdk

Typed TypeScript client for the CopyLocker **Admin API** (`/v1/admin/*` on
the CopyLocker Worker). It backs the management console (`apps/console`)
and any vendor-side automation that manages releases, licenses, accounts,
asset KEKs, integrity signer keys, offline license keys, the entitlement
catalog, policies, epochs, revocations, analytics, and DSR requests.

Wire format authority: `crates/copylocker-worker/src/admin.rs` and
`crates/copylocker-worker/src/admin_resources/`. The types in
`src/types.ts` are hand-mirrored from the Rust source; the subset that maps
1:1 onto shared Rust types is pinned by generated ts-rs bindings under
`bindings/` and a drift-check CI job (see the header comment in
`src/types.ts` for the exact boundary).

Covered endpoint groups (every admin route):

- `releases` — list/get/register, `deprecate`, `mark-compromised`
  (dry-run-first, `revoke` requires `acknowledge_revoke: true`)
- `licenses` — list/get/issue/update/change-tier, `preview-fallback`,
  `machines`
- `accounts` — list/create (Mode E)
- `assetKeks` — list/register/delete (dry-run-first)
- `integrity` — signer key list/register/revoke, remote manifest `sign`
- `offlineKey` — OLK issuance (`POST /v1/admin/licenses/:id/offline-key`)
- `catalog` — features/groups/tiers list/create/update, `resolve` preview
- `policies` — list/get/create/update with server-side guardrail warnings
- `epochs` — list/get/upload, two-actor `revoke` (dry-run-first)
- `revoke` — license/machine revocation (dry-run-first, `revoke` scope)
- `products` — anomaly `alert-webhook` get/update
- `analytics` — `definitions`, `metrics`, CSV/NDJSON `export`,
  `subscriptions` list/create (`analytics:r` scope)
- `dsr` — subject `export`, `delete` cascade (dry-run-first, `dsr:rw` scope)
- `telemetry` — retention `purge` (dry-run-first, `dsr:rw` scope)

```ts
import { createAdminClient } from '@copylocker/admin-sdk'

const admin = createAdminClient({
  baseUrl: 'https://licenses.example.com',
  token: process.env.COPYLOCKER_ADMIN_TOKEN!, // clat_… bearer token
})

const releases = await admin.releases.list('my-product')

// Confirmed mutations require an Idempotency-Key:
const issued = await admin.licenses.issue(
  { product_id: 'my-product', policy_id: 'default', count: 1 },
  { idempotencyKey: crypto.randomUUID() },
)

// Destructive transitions are dry runs by default; confirm explicitly:
const impact = await admin.releases.deprecate('rel_…', { productId: 'my-product' })
if (impact.dry_run) {
  await admin.releases.deprecate('rel_…', {
    productId: 'my-product',
    dryRun: false,
    idempotencyKey: crypto.randomUUID(),
  })
}
```

Non-2xx responses throw `AdminApiError` carrying the worker's error
envelope (`code`, `message`) and the HTTP `status`.

- Zero runtime dependencies. Node ≥ 20.
- Never put the Admin token in URLs, logs, fixtures, or commits.
