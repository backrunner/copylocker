# CopyLocker

CopyLocker is a Rust licensing protocol, policy engine, administration CLI, and Cloudflare Worker
runtime. This workspace currently implements the M1 server administration surface: entitlement
catalogs, policies, licenses, signing epochs, authenticated Admin API access, and recoverable
mutation journals.

## Workspace

- `crates/copylocker-cli`: offline tooling, project scaffolding, bootstrap, and the remote Admin CLI.
- `crates/copylocker-worker`: the Cloudflare Worker, Durable Objects, D1 migrations, KV/R2/Queue
  adapters, and Admin API.
- `crates/copylocker-server-core`: storage-independent catalog, policy, and entitlement logic.
- `crates/copylocker-proto`, `copylocker-suite*`, and `copylocker-types`: protocol and cryptography.
- `server-template`: the deployable project embedded by `copylocker init`.

## M1 quick start

Install the CLI from this checkout:

```bash
cargo install --locked --path crates/copylocker-cli
```

Provision a D1 database, KV namespace, R2 bucket, Secrets Store, event queue, and dead-letter queue
in Cloudflare. Then generate a server project with the real resource IDs:

This path assumes the matching `copylocker-worker` version in `server-template/package.json` is
already published to npm. Before publication, validate the exact local tarball and template with
`bash scripts/check-server-template.sh`; do not commit a local-path dependency as a substitute.

```bash
copylocker init server \
  --product acme-desktop \
  --d1-database-id 00000000-0000-0000-0000-000000000000 \
  --kv-namespace-id 00000000000000000000000000000000 \
  --secret-store-id 00000000000000000000000000000000 \
  --api-url https://licenses.example.com

cd server
npm install
copylocker deploy
```

Create the first vendor, product, Admin token, and token HMAC pepper. `apply` is a dry-run unless
`--confirm` is present:

```bash
copylocker bootstrap prepare \
  --project . \
  --vendor vendor-acme \
  --actor owner \
  --out /secure/copylocker-bootstrap.json

copylocker bootstrap apply --project . --bundle /secure/copylocker-bootstrap.json
copylocker bootstrap apply --project . --bundle /secure/copylocker-bootstrap.json --confirm
```

Move `admin_token` from the mode-0600 bundle into the environment variable named by
`copylocker.json` (default `COPYLOCKER_ADMIN_TOKEN`). Do not commit, print, or pass the token as a
command-line argument. Destroy the bundle after verified recovery storage is in place, or escrow it
under the same controls as a production credential.

Deploy and probe the read-only Admin endpoint:

```bash
copylocker deploy --confirm
copylocker doctor --project . --check-api
```

The bootstrap step only creates `ADMIN_TOKEN_PEPPER`. Provision all other bound secrets, including
the server pepper, signing keys, variant/asset keys, and configured webhook secrets, before using
the corresponding runtime paths. See [the generated-server guide](server-template/README.md) and
[the CLI guide](crates/copylocker-cli/README.md).

## Safety contracts

- Every remote mutation requires an explicit `Idempotency-Key`; catalog push derives stable child
  keys from its required prefix.
- License and epoch revocation are dry-run by default.
- Epoch revocation requires an existing replacement plus approvals by two distinct Admin actors
  within 15 minutes. Each approval uses a different idempotency key.
- Admin credentials are accepted only from an environment variable. The CLI refuses redirects and
  arbitrary non-`/v1/admin/*` paths.
- Keep the minute Cron enabled. It resumes side effects, audit publication, strict revocation
  sequencing, and billing transitions after interrupted requests.

## Verification

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

for parameter_set in 44 65 87; do
  cargo test -p copylocker-suite-std --no-default-features \
    --features std,pq-ml-dsa-${parameter_set}
done

cd crates/copylocker-worker
npm run check
npm test
npm run size
npm run startup
```

Release, machine mutation CLI commands, analytics/audit/DSR APIs, Admin token lifecycle APIs, and a
web console remain post-M1 work. They are not part of the current operational contract.
