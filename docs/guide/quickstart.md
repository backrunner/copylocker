# 5-Minute Quickstart

The shortest honest path: provision a Cloudflare backend, initialize it with the CLI, issue one
license, and unseal one asset from a web app. Every command below is taken from the actual CLI
surface (`copylocker <cmd> --help`) and `server-template/README.md`.

::: warning Before you start
Nothing is on a public registry yet. The CLI is built from this repository, and the SDK packages
are consumed from the workspace or local tarballs. See
[repository state](https://github.com/backrunner/copylocker) — no npm package has been published
and no hosted CopyLocker service exists.
:::

## 0. Prerequisites

- Rust toolchain (pinned by `rust-toolchain.toml`) and Node.js ≥ 20.
- A Cloudflare account with `wrangler` authenticated (`npx wrangler login`).
- Provisioned Cloudflare resources — the IDs are inputs to `copylocker init`:
  - one **D1 database** and one **KV namespace**,
  - one **Secrets Store** (its 32-character ID),
  - one **R2 bucket** named `<project-name>-archive`,
  - two **Queues**: `<project-name>-events` and `<project-name>-events-dlq`.

Build the CLI from the repository root:

```bash
cargo install --locked --path crates/copylocker-cli
copylocker --help
```

## 1. Initialize the server project (1 min)

```bash
copylocker init server \
  --product my-app \
  --d1-database-id <D1_DATABASE_UUID> \
  --kv-namespace-id <KV_NAMESPACE_ID> \
  --secret-store-id <SECRETS_STORE_ID>
```

This renders the embedded `server-template/` into `server/` with your resource IDs wired into
`wrangler.jsonc` and `copylocker.json`. The template deploys the versioned `copylocker-worker`
package — it does not copy the Rust runtime.

```bash
cd server
npm install
copylocker deploy --project .        # local dry-run only; writes .copylocker/dry-run.js
```

## 2. Bootstrap the first Admin credential (1 min)

Migrations intentionally do not invent a vendor, product, or Admin token. Create the bootstrap
bundle **outside** the project directory, preview, then confirm:

```bash
copylocker bootstrap prepare \
  --project . \
  --vendor vendor-acme \
  --actor owner \
  --out /secure/copylocker-bootstrap.json

copylocker bootstrap apply --project . --bundle /secure/copylocker-bootstrap.json            # dry-run
copylocker bootstrap apply --project . --bundle /secure/copylocker-bootstrap.json --confirm  # executes
```

The confirmed apply uploads `ADMIN_TOKEN_PEPPER` through Wrangler stdin, applies all remote D1
migrations, and conflict-checks the initial vendor/product/token rows. Then:

1. Move `admin_token` from the bundle into the environment variable named by `admin_token_env` in
   `copylocker.json` (default `COPYLOCKER_ADMIN_TOKEN`).
2. **Destroy the bundle** (mode-0600 file containing the plaintext token and pepper) or escrow it
   in protected recovery storage. Never commit it, log it, or pass it on a command line.

Provision the remaining bound secrets — each value is a complete versioned JSON object, sent on
stdin, never in `wrangler.jsonc`:

```bash
# One per secret: SERVER_PEPPER, VARIANT_PARAMS_KEY, ASSET_KEK_KEY,
# plus EPOCH_SIGNING_KEY / EPOCH_FAST_SIGNING_KEY from step 3.
npx wrangler secrets-store secret create <SECRETS_STORE_ID> \
  --name SERVER_PEPPER --scopes workers --remote < server-pepper.secret.json
```

## 3. Generate keys and publish the first Epoch (1 min)

On a trusted, ideally offline host, generate the Root pair (current + next) and the first Epoch:

```bash
copylocker keygen root --out-dir /secure/root-ceremony --offline-confirm

copylocker keygen epoch \
  --root-key /secure/root-ceremony/cl-root.secret.json \
  --product my-app \
  --not-before 1767225600 \
  --not-after 1775001600 \
  --out-dir /secure/epoch-q1
```

Upload the two epoch secret JSON files to Secrets Store (same `wrangler secrets-store secret
create` pattern as above, names `EPOCH_SIGNING_KEY` and `EPOCH_FAST_SIGNING_KEY`), then publish
the Root-signed certificate through the Admin API:

```bash
copylocker epoch upload /secure/epoch-q1/epoch-<id>.cert.cbor \
  --root-public /secure/root-ceremony/cl-root.public.json \
  --idempotency-key epoch-<id>-upload
```

Only Root **public** JSON ever leaves the offline host. The Root secret never touches an online
machine, Secrets Store, CI, or the Admin API.

## 4. Deploy, define entitlements, issue a license (1 min)

```bash
copylocker deploy --project . --confirm
copylocker doctor --project . --check-api
```

Create the entitlement catalog (immutable feature IDs — choose names you can live with forever),
a policy from a preset, and push both:

```bash
copylocker catalog feature add --id export.pdf --label "PDF export"
copylocker catalog tier add --id pro --label "Pro" --rank 10 --feature export.pdf
copylocker catalog push --project . --idempotency-key catalog-2026q1

copylocker policy create --preset sub-annual --id policy-pro --product my-app \
  --tier pro --at 1767225600 --out policy.json        # 11 presets: policy presets
copylocker policy push --project . --file policy.json --idempotency-key policy-v1
```

Issue the first license. **The plaintext key exists only in this output** — deliver it through a
secure channel:

```bash
copylocker license issue --policy <POLICY_ID> --idempotency-key issue-0001
```

## 5. Activate and unseal from a web app (1 min)

```ts
import { CopyLocker } from '@copylocker/web'

const cl = await CopyLocker.create({
  serverUrl: 'https://license.example.com',
  productId: 'my-app',
  rootPins: ['<hex of the pinned root verifying key>'], // from cl-root.public.json
  onStateChange: (s) => renderBadge(s),                 // advisory UI only — never gate on it
})

await cl.activate('CL-XXXX-…')   // the plaintext key from step 4

// The only "use the license" entry points: they return plaintext or throw.
// loadSealed fetches an asset sealed by @copylocker/seal under the per-feature
// asset KEK and unwraps that KEK from the credential inside the core:
const bytes = await cl.loadSealed('/assets/pro.clx', 'export.pdf')
// unseal opens bytes sealed against the session FinalKey:
// const bytes = await cl.unseal('export.pdf', sealedAssetBytes)
```

There is deliberately **no** `isLicensed()`. `unseal()` / `loadSealed()` either succeed or throw
`NotEntitledError` / `UnsealError` — that throw is the enforcement. A runnable reference
integration lives in `examples/vite-spa/`.

## Local development without deploying

The full loop runs locally: `wrangler dev` on the server project plus the same CLI chain
(keygen → bootstrap → catalog/policy/epoch → license issue) against `http://localhost:8787`.
`packages/web-e2e/scripts/backend-up.mjs` is the executable reference for this flow, and
`examples/vite-spa` points at the local Worker by default.

## Where to go next

- [Protection Levels](./protection-levels) — what to seal, and the go-live checklist.
- [The Licensing Model](./licensing-model) — trials, subscriptions, dunning, perpetual fallback.
- [Deployment](./deployment) — migrations discipline, secrets, Cron, and queues.
- [Runbook](../operations/runbook) — when something goes wrong.
