# CopyLocker CLI

`copylocker` combines offline protocol tooling with a narrow authenticated client for the M1 Admin
API. Credentials are not needed for local catalog, policy, key, artifact, or KAT operations.

## Install

```bash
cargo install --locked --path crates/copylocker-cli
copylocker doctor
```

`doctor` is offline by default. `doctor --check-api` opts into one authenticated, read-only Admin
request and never prints the token.

## Offline workflows

```bash
copylocker kat generate --out vectors/CL-STD-1/kat.json
copylocker kat verify --file vectors/CL-STD-1/kat.json
copylocker kat check --file vectors/CL-STD-1/kat.json

copylocker policy presets
copylocker policy create --preset perpetual --id policy_acme --product acme \
  --tier pro --at 1767225600 --out policy.json
copylocker policy validate --policy policy.json --catalog catalog.json --at 1767225600
copylocker policy simulate --policy policy.json --catalog catalog.json \
  --releases releases.json --scenario scenario.json
```

`kat generate` is create-only by default. Replacing a committed vector requires `--force`, because
a changed vector can indicate a protocol-breaking change. CI should use `kat check`; it never
writes.

Generate Root keys only on a physically offline host. The CLI writes current and next public files
plus mode-0600 secret files; external custody or secret-sharing remains the operator's
responsibility.

```bash
copylocker keygen root --out-dir /secure/root-ceremony --offline-confirm
copylocker keygen epoch \
  --root-key /secure/root-ceremony/cl-root.secret.json \
  --product acme \
  --not-before 1767225600 \
  --not-after 1775001600 \
  --out-dir /secure/epoch-2026q1
```

## Initialize and bootstrap a server

`init` creates a new directory from the embedded deployment template. It requires existing
Cloudflare resource IDs and refuses a non-empty destination.

```bash
copylocker init server \
  --product acme \
  --d1-database-id 00000000-0000-0000-0000-000000000000 \
  --kv-namespace-id 00000000000000000000000000000000 \
  --secret-store-id 00000000000000000000000000000000 \
  --api-url https://licenses.example.com
```

After `npm install`, `copylocker deploy --project server` builds a local Wrangler dry-run. Only
`copylocker deploy --project server --confirm` applies remote D1 migrations and deploys the Worker;
`--skip-migrations` is available only for a separately controlled migration workflow.

A migrated database has no initial vendor, product, or Admin credential. Bootstrap them with a
recoverable credential bundle:

```bash
copylocker bootstrap prepare \
  --project server \
  --vendor vendor-acme \
  --actor owner \
  --out /secure/copylocker-bootstrap.json

# Preview only.
copylocker bootstrap apply \
  --project server \
  --bundle /secure/copylocker-bootstrap.json

# Upload ADMIN_TOKEN_PEPPER through Wrangler stdin, migrate, and seed D1.
copylocker bootstrap apply \
  --project server \
  --bundle /secure/copylocker-bootstrap.json \
  --confirm
```

`prepare` creates a new mode-0600 file and never overwrites one. The bundle is bound to the
project name, product, and Secrets Store ID, expires with its Admin token, and contains the only
plaintext copy of that token plus the pepper. `apply` stores only `HMAC(pepper, token)` in D1. If
the secret upload succeeded but a later step failed, retry the same bundle with `--confirm
--skip-secret-upload`.

Move `admin_token` from the bundle into the environment variable configured in
`copylocker.json` (default `COPYLOCKER_ADMIN_TOKEN`), then destroy the bundle or escrow it under
production credential controls. Never commit it or relax its permissions.

## Remote Admin CLI

The API origin is resolved from `--api-url`, `COPYLOCKER_API_URL`, or `copylocker.json`, in that
order. The token is read only from `--admin-token-env` or the configured environment-variable name;
there is deliberately no token command-line option.

Implemented M1 commands are:

```text
init | deploy | bootstrap | doctor
keygen | inspect | kat
catalog pull | push
policy list | show | push | update
license issue | list | show | suspend | resume | extend
license change-tier | preview-fallback | machines | revoke
epoch list | show | upload | rotate | revoke
request get
doctor --check-api
```

Typical mutations require an explicit idempotency key:

```bash
copylocker catalog push --project server \
  --file server/catalog.json \
  --idempotency-key catalog-2026q1

copylocker policy push --project server \
  --file policy.json \
  --idempotency-key policy-acme-v1

copylocker license issue --project server \
  --policy policy_acme \
  --count 1 \
  --idempotency-key order-18432

copylocker epoch upload --project server \
  /secure/epoch-2026q1/epoch-0011223344556677.cert.cbor \
  --root-public /secure/root-ceremony/cl-root.public.json \
  --idempotency-key epoch-0011223344556677-upload
```

Plaintext license keys are returned only by the successful `license issue` call. Capture its
output into the intended secret delivery path; subsequent list/show calls cannot recover keys.

License and epoch revocation default to a server-side dry-run. A confirmed license revocation adds
an idempotency key. Epoch revocation additionally requires the exact epoch ID locally and a second
approval by a different Admin actor within 15 minutes:

```bash
copylocker license revoke 0123456789abcdef0123456789abcdef
copylocker license revoke 0123456789abcdef0123456789abcdef \
  --confirm --idempotency-key revoke-order-18432

copylocker epoch revoke 0011223344556677
copylocker epoch revoke 0011223344556677 \
  --confirm \
  --confirm-epoch-id 0011223344556677 \
  --idempotency-key epoch-revoke-0011223344556677-actor-a
```

The second actor repeats the confirmed epoch command with their own token and a different
idempotency key. The server rejects the same actor, an expired approval window, or an epoch with no
active replacement.

`catalog push` reads all three remote collections consistently, validates the complete evolution
before its first write, never deletes remote identifiers, orders feature groups by their include
dependencies, and pushes tiers last. A temporary tier bridge prevents a limit key moving between
tiers from violating the server's no-delete evolution guard.

The HTTP client accepts only `/v1/admin/*`, refuses credentials embedded in origins, does not
follow redirects, limits responses to 4 MiB, and preserves the Worker's machine-readable
`error.code`. `request get` is intentionally read-only and cannot be used to bypass the typed
mutation commands.

## JSON contract

Pass global `--json` before or after the subcommand. JSON mode writes exactly one object to stdout.
Success has a stable envelope:

```json
{"ok":true,"command":"kat.verify","suite_id":"0x01000001","vectors":40,"path":"vectors/CL-STD-1/kat.json"}
```

Failure exits non-zero and returns a machine-readable error without secrets:

```json
{"ok":false,"error":{"code":"kat_failed","message":"..."}}
```

Local validation errors use stable CLI codes. Admin API errors retain the server's dynamic
`error.code`, which lets automation distinguish conflicts, missing scopes, and invalid requests
without parsing text.

Release administration, machine mutation commands, analytics, audit verification, DSR, and Admin
token lifecycle commands are post-M1 and are not exposed by this binary yet.
