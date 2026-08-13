---
title: CLI Reference
navTitle: CLI Reference
order: 11
description: The complete copylocker CLI command surface — connection handling, guards, and every command with its flags.
---

# CLI Reference

The `copylocker` binary is built from `crates/copylocker-cli`:

```bash
cargo install --locked --path crates/copylocker-cli
```

Every fact on this page is taken from the clap definitions and command implementations in that
crate. When this page and `copylocker <cmd> --help` disagree, `--help` wins — file an issue.

## Global contract

- **`--json`** works on every command: stdout becomes a stable JSON envelope, and errors print as
  `{"ok":false,"error":{"code","message"}}`. Error codes are stable machine strings
  (`io_error`, `file_exists`, `invalid_policy_json`, `product_mismatch`, …); Admin API failures
  propagate the server's `error.code`.
- **Exit codes**: `0` success, `1` runtime error, `2` argument parse error (clap).
- **Create-only writes**: key generation, `init`, and file outputs never overwrite existing files
  (`file_exists`) unless a `--force` flag exists and is passed.

## Connection handling (all remote commands)

Remote commands share three flags, flattened into each command:

| Flag | Default | Purpose |
|---|---|---|
| `--project <dir>` | `.` | Any directory in or below an initialized project; the CLI walks ancestors for `copylocker.json` |
| `--api-url <url>` | — | Overrides env and config |
| `--admin-token-env <name>` | `COPYLOCKER_ADMIN_TOKEN` | Environment variable holding the Admin bearer token |

Resolution order: API URL = `--api-url` → `COPYLOCKER_API_URL` → `api_url` in `copylocker.json`.
Token env var name = `--admin-token-env` → `admin_token_env` in config → `COPYLOCKER_ADMIN_TOKEN`.
The token itself is **never** accepted on the command line; it must match `clat_` + 43 base64url
characters and is validated before any request. The HTTP client uses 10 s connect / 30 s total
timeouts, follows no redirects, caps responses at 4 MiB, and only calls `/v1/admin/*` paths.

`copylocker.json` (rendered by `init`, validated on every use):

```json
{
  "schema_version": 1,
  "project_name": "…",
  "product_id": "…",
  "secret_store_id": "…",
  "api_url": "https://… or null",
  "admin_token_env": "COPYLOCKER_ADMIN_TOKEN"
}
```

## Production-mutation guards

Three layers, all server- or CLI-enforced rather than conventional:

1. **Dry-run first.** `deploy`, `bootstrap apply`, `license revoke`, `asset-kek delete`,
   `release deprecate`, `release mark-compromised`, `epoch revoke`, `dsr delete`, and
   `telemetry purge` only plan until `--confirm` is passed. For Admin API commands the dry run is
   server-side (`?dry_run=true`), and `--confirm` makes `--idempotency-key` required.
2. **Idempotency keys.** Every Admin API mutation requires `--idempotency-key` (1–128 printable
   non-whitespace ASCII characters); retries reuse the same key.
3. **Typed acknowledgements.** `keygen root` requires `--offline-confirm`;
   `epoch revoke --confirm` additionally requires `--confirm-epoch-id` matching the positional id
   exactly (plus two distinct Admin actors server-side within 15 minutes);
   `release mark-compromised --action revoke --confirm` additionally requires `--ack-revoke`.

## Project lifecycle

### `init`

Render a deployable server project from the embedded `server-template/` into the positional
`<path>` (an empty or nonexistent directory). Local; create-only.

| Flag | Required | Notes |
|---|---|---|
| `--product <id>` | yes | 1–128 chars of `[A-Za-z0-9-_.]` |
| `--d1-database-id <uuid>` | yes | D1 database UUID |
| `--kv-namespace-id <hex32>` | yes | KV namespace id |
| `--secret-store-id <hex32>` | yes | Secrets Store id |
| `--name <name>` | no | Defaults to the directory name; Worker-name rules |
| `--api-url <url>` | no | Baked into `copylocker.json` |

Writes `package.json`, `wrangler.jsonc`, `copylocker.json`, `src/index.js`, migrations
`0001`–`0010`, and a starter `catalog.json`.

### `deploy`

Validate or deploy an initialized project. Shells out to the project's own Wrangler
(`npm install` first; `wrangler_missing` otherwise).

```bash
copylocker deploy --project .            # wrangler deploy --dry-run, writes .copylocker/dry-run.js
copylocker deploy --project . --confirm  # remote D1 migrations apply, then wrangler deploy
```

`--skip-migrations` (requires `--confirm`) skips the migration apply step — use it only when a
separately controlled step has already applied the exact migration set.

### `bootstrap`

Create the first vendor, product, and Admin credential safely.

- `bootstrap prepare --vendor <id> --actor <name> --out <file>` — local. Writes a mode-0600 JSON
  bundle containing a `clat_` Admin token and a 32-byte HMAC pepper. `--expires-at <unix>`
  defaults to now + 90 days. Token scopes are fixed:
  `products:rw, catalog:rw, policies:rw, licenses:rw, machines:rw, revoke, releases:rw, epochs:rw,
  audit:r, analytics:r, sign:manifest`.
- `bootstrap apply --bundle <file>` — dry-run prints the planned steps. With `--confirm`: uploads
  `ADMIN_TOKEN_PEPPER` to Secrets Store over stdin, applies remote D1 migrations, and seeds the
  vendor/product/admin-token rows (the server stores only `HMAC(pepper, token)`).
  `--skip-secret-upload` exists for split-duty ceremonies.

### `doctor`

Report local readiness. Offline by default; `--check-api` makes one authenticated read-only GET
(`/v1/admin/catalog/features`). `--vectors <path>` points at the KAT file (default
`vectors/CL-STD-1/kat.json`).

## Key ceremonies

### `keygen` (local, suite fixed to CL-STD-1)

- `keygen root --out-dir <dir> --offline-confirm` — generates the current **and** next hybrid
  root key pairs (`cl-root.*.json`, `cl-root-next.*.json`; secrets mode 0600, never overwritten).
- `keygen epoch --root-key <file> --product <id> --not-before <unix> --not-after <unix>
  --out-dir <dir>` — epoch hybrid + fast signing keys and a root-signed `EpochCert`
  (`epoch-<id>.cert.cbor` plus public/secret JSON). `--epoch-id <16 hex>` optional.
- `keygen build --out <prefix>` — build-manifest signing pair (`<prefix>.public.json`,
  `<prefix>.secret.json`).

Root keys are generated and kept on an offline ceremony host; only the Root-signed epoch
certificate travels to the Admin API. See
[Deployment → Secrets discipline](/docs/guide/deployment#secrets-discipline).

## Catalog

Local file operations against `--file` (default `catalog.json`), plus remote pull/push. Local
mutations validate evolution rules — feature identifiers are immutable — and bump `version` by 1.

- `catalog feature add --id <id> --label <label> [--description …]`
- `catalog feature list` / `catalog feature deprecate --id <id> --at <unix>`
- `catalog group add|edit --id … --label … [--include <group>]… [--feature <id|glob>]…` — feature
  ids accept a trailing `*` glob; `catalog group list`
- `catalog tier add|edit --id … --label … --rank <i32> [--group …]… [--feature …]…
  [--limit KEY=VALUE]…` — `-1` means unlimited; `catalog tier list`
- `catalog resolve --tier <id> [--at <unix>]` — print the deterministic feature/limit snapshot
- `catalog export --out <file> [--force]` / `catalog import --from <file>` — normalized snapshot
  out; evolution-validated replace in
- `catalog pull [--force]` — **network**; write the remote catalog into `--file`
- `catalog push --idempotency-key <key>` — **network, mutates**; diffs against remote, refuses to
  delete published identifiers, pushes features → groups → tiers in dependency order

## Policies

- `policy presets` — list the eleven presets: `trial-14d`, `perpetual`, `perpetual-major`,
  `perpetual-fallback`, `sub-monthly`, `sub-annual`, `sub-annual-fallback`, `team-sub`,
  `enterprise-airgap`, `saas-client`, `edu-1y`.
- `policy create --preset … --id … --product … --tier … --at <unix> --out <file>` — local.
- `policy validate --policy <file> --catalog <file> --at <unix>` — local.
- `policy simulate --policy … --catalog … --releases … --scenario …` — local; scenario steps must
  be in ascending `at` order.
- `policy list` / `policy show <id>` — **network**, read-only.
- `policy push --file <policy.json> --idempotency-key …` / `policy update` — **network, mutate**.

## Licenses (all network)

- `license issue --policy <id> [--count 1..100] [--account …] [--seats …] [--expires-at <unix>]
  [--metadata <json-file>] --idempotency-key …` — **plaintext license keys are returned only by
  this call.**
- `license list [--status active|suspended|expired|revoked] [--limit 1..100]`
- `license show <id>` — 32-hex license id.
- `license suspend|resume <id> --idempotency-key …`
- `license extend <id> --by-seconds <n> --idempotency-key …`
- `license change-tier <id> --to <tier-id> --idempotency-key …`
- `license preview-fallback <id>` — read-only preview of the fallback retained when a
  subscription ends.
- `license machines <id>`
- `license revoke <id> [--reason <u8>]` — dry-run by default; `--confirm` applies (and makes
  `--idempotency-key` required). There is no unrevoke; mistaken revocations are handled by
  re-issuing.

## Releases (all network)

- `release register --app-version … --build-fingerprint … [--channel stable]
  [--manifest-root-hex …] [--module-digest-hex …] [--variant-seed-hex …] --idempotency-key …` —
  the CI gate for published builds. The server assigns `release_id`/`variant_id`; an omitted
  variant seed is generated and shown exactly once.
- `release list` / `release show <release_id>`
- `release deprecate <release_id>` — dry-run prints impacted device counts; `--confirm` applies.
- `release mark-compromised <release_id> --action warn|force_upgrade|revoke
  [--bump-security-floor]` — dry-run by default; confirming `--action revoke` additionally
  requires `--ack-revoke`.

## Epochs (all network)

- `epoch list` / `epoch show <id>` — 16-hex epoch id; `show` reports replacement readiness.
- `epoch upload <cert.cbor> --root-public <file> --idempotency-key …` — upload a Root-signed
  epoch certificate (1 byte – 64 KiB).
- `epoch rotate <cert.cbor> …` — same arguments and code path as `upload`; the difference is
  semantic (this certificate is the replacement).
- `epoch revoke <id>` — dry-run by default. `--confirm` submits one approval and requires
  `--confirm-epoch-id <id>` to match exactly. The server requires **two distinct Admin actors
  within 15 minutes** and an active replacement before revocation takes effect.

## Asset KEKs (all network)

- `asset-kek register --release <id> --feature <id> [--kek-hex <64 hex>] --idempotency-key …` —
  an omitted KEK is generated from the CSPRNG and **shown exactly once**.
- `asset-kek list [--release <id>]` — returns fingerprints only.
- `asset-kek delete --release <id> --feature <id>` — dry-run by default; `--confirm` applies.

## DSR & telemetry (all network)

- `dsr export (--machine <32 hex> | --license <32 hex>) [--out <file> [--force]]` — exactly one
  subject; stdout without `--out`.
- `dsr delete (--machine … | --license …)` — dry-run by default; `--confirm` applies.
- `telemetry purge [--before <YYYY-MM-DD>]` — dry-run by default; the default horizon is the
  30-day T1 raw retention window, and `--before` also removes older `telemetry_rollup` rows.

## Offline activation

- `offline request --license-key … --release-id … --build-fingerprint … --app-version …
  --variant-id <u64> --fingerprint-hex <64 hex> --out <file> --keys-out <file> [--armor-out …]` —
  local; builds the air-gapped request CBOR and a mode-0600 device key file.
- `offline redeem --request <file> --out <file> --idempotency-key …` — **network,
  unauthenticated**; POSTs to `/v1/offline/request` (`Content-Type: application/cbor`,
  `X-CL-Proto: 1`). Accepts CBOR or `CLR1` armor.
- `offline import --response <file> --keys <file> --root-public <file> --out <file>` — local;
  verifies the epoch chain, nonce echo, `valid_until`, and fingerprint binding, then exports the
  machine credential.
- `offline qr --input <file> [--format ascii|svg] [--out <file>]` — render `CLK1`/`CLR1` armor or
  binary bundles as a QR code (`--out` required for SVG).
- `offline issue --license <32 hex> --release-id … [--bound-fingerprint-hex …] [--max-seats …]
  --out <file> [--armor-out …] --idempotency-key …` — **network (Admin API)**; mints an offline
  license key bundle. The bundle is a bearer credential.

## Utilities

- `kat generate --out <file> [--force]` / `kat verify --file …` / `kat check --file …` — known
  answer vectors; `check` regenerates deterministically and exits `1` with `kat_drift` on any
  difference. Never writes.
- `inspect <artifact> [--hex]` — decode a canonical-CBOR artifact or signed Envelope (≤ 2 MiB) to
  JSON. Always reports `"verified": false` / `"trusted": false` — it decodes, it does not
  establish signature trust.
- `request get <path>` — authenticated read-only GET against the Admin API for anything this
  reference does not cover. The path must normalize to under `/v1/admin/`; `..`, backslashes,
  fragments, and control characters are rejected.
