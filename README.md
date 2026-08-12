# CopyLocker

CopyLocker is a Rust licensing protocol, policy engine, administration CLI, Cloudflare Worker
runtime, and client SDK family. The workspace covers the protocol and cryptography, the server
core, the desktop SDKs, the Web SDK (WASM core, `@copylocker/web`, framework bindings, browser
E2E), the build toolchain (`@copylocker/unplugin`, `@copylocker/guard`, `@copylocker/seal`), the
release registry and offline activation loop, Mode E accounts, privacy-preserving telemetry and
analytics with DSR surfaces, the admin SDK, and the SvelteKit admin console. See `agent.md` for
the current milestone state and evidence.

## Documentation

The documentation site source lives in [`docs/`](docs/) (VitePress; `npm install && npm run dev`
in that directory). It covers the five-minute quickstart, protection-level guide, licensing
model, Web SDK, deployment, operations runbook, SLOs, and cost estimation. The security policy
and residual-risk statement are in [SECURITY.md](SECURITY.md).

## Workspace

- `crates/copylocker-cli`: offline tooling, project scaffolding, bootstrap, and the remote Admin CLI.
- `crates/copylocker-worker`: the Cloudflare Worker, Durable Objects, D1 migrations, KV/R2/Queue
  adapters, and Admin API.
- `crates/copylocker-server-core`: storage-independent catalog, policy, and entitlement logic.
- `crates/copylocker-proto`, `copylocker-suite*`, and `copylocker-types`: protocol and cryptography.
- `crates/copylocker-core`, `copylocker-store`, `copylocker-fingerprint`, `copylocker-client`:
  the desktop client core, protected storage, device fingerprinting, and async facade.
- `crates/copylocker-tauri`, `copylocker-node`, `copylocker-ffi`: native SDK surfaces.
- `crates/copylocker-wasm`: the browser WASM core with the opaque `step()` interface.
- `packages/`: TypeScript packages — `web`, `react`, `vue`, `svelte`, `tauri`, `electron`,
  `guard`, `seal`, `unplugin`, `telemetry`, and `web-e2e`.
- `apps/console`: the SvelteKit admin console.
- `server-template`: the deployable project embedded by `copylocker init`.

## Repository model and licensing

This public repository is licensed under `GPL-3.0-only`; see [LICENSE](LICENSE) and
[LICENSING.md](LICENSING.md). Third-party dependencies retain their own licenses.

The proprietary `copylocker-suite-priv` implementation belongs in the private
[`BackRunner/copylocker-suite-priv`](https://github.com/BackRunner/copylocker-suite-priv)
repository. Authorized checkouts mount it as the optional `private/copylocker-suite-priv`
submodule. The public workspace and public CI must remain fully functional without that
submodule.

A submodule does not create a GPL linking exception. Distributing a combined binary containing
proprietary code requires a separate commercial license, process/service isolation, or legal
review confirming compliance with the GPL. See
[the open/closed boundary](.agents/00-overview/open-closed-boundary.md) for the engineering rules.

## Quick start

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

The release registry, machine mutation CLI commands, analytics/audit/DSR APIs, Admin token
lifecycle APIs, and the web console are part of the current operational contract; the release
lifecycle, analytics, audit, and DSR guides in [`docs/`](docs/) describe them.
