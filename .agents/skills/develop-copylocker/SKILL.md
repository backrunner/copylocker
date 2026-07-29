---
name: develop-copylocker
description: "Develop, review, validate, license, and commit changes in the CopyLocker public repository and its optional private-suite submodule. Use for any CopyLocker code, documentation, schema, dependency, release, Git history, repository split, or contribution task; enforce security architecture, GPL and proprietary boundaries, release gates, and English type(scope): description commits."
---

# Develop CopyLocker

Apply the repository's engineering contract from discovery through commit. Keep the public GPL
workspace independently buildable and keep proprietary implementation details in the private
repository.

## Establish Context

1. Read `AGENTS.md` and `agent.md` from the public repository root.
2. Read only the `.agents/` documents relevant to the affected behavior.
3. Treat executable migrations and tested implementation as authority when roadmap text is stale.
4. Inspect the worktree before editing. Preserve user-owned and unrelated changes.
5. In the Orchiliao environment, read `/Users/orchiliao/.codex/RTK.md`, use the fixed toolchain
   `PATH`, and prefix every shell command with `rtk`.
6. Use `rg` or `rg --files` for discovery and `apply_patch` for manual edits.

## Select the Repository

Use the public repository for protocol contracts, standard suites, clients, Worker, CLI, SDKs,
tests, public vectors, documentation, and public CI.

Use the private `copylocker-suite-priv` repository for proprietary suite code, vendor parameters,
private vectors, internal design notes, and authorized integration pipelines.

Reserve `private/copylocker-suite-priv` as the public checkout's optional submodule mount point.
Do not invent a submodule URL. Add the gitlink only after the real access-controlled remote exists.
The public build and CI must pass with the submodule absent and uninitialized.

Never place these in the public repository:

- private suite source or generated constants;
- vendor seeds, customer parameters, private KATs, or private audit reports;
- private registry credentials, deploy keys, secret bundles, or production identifiers;
- a public manifest or lockfile dependency on the private crate.

## Implement Changes

1. Identify the smallest owning module and its public contract.
2. Follow existing crate, package, error, serialization, and test patterns.
3. Keep canonical CBOR, domain separation, secret zeroization, bounded parsing, and no-panic
   behavior intact.
4. Use structured parsers and serializers for structured data.
5. Add abstractions only when they remove real duplication or enforce an existing boundary.
6. Update documentation when behavior, schema, repository state, accepted risk, or roadmap status
   changes.
7. Update `agent.md` when the durable handoff state changes.

## Preserve Security Contracts

- Accept Admin tokens only through the configured environment variable. Never place secrets in
  argv, URLs, redirects, logs, fixtures, generated projects, or commits.
- Require explicit idempotency keys for confirmed mutations and preserve Worker error codes.
- Keep license and Epoch revocation dry-run by default.
- Require a valid replacement Epoch and two distinct actors within 15 minutes.
- Preserve immutable operation journals, monotonic revocation data, audit ordering, and recovery
  checkpoints.
- Keep Worker and `server-template` migrations byte-identical. Register every migration in the CLI
  scaffold and its tests.
- Keep public security independent of proprietary implementation secrecy.
- Do not deploy, publish, confirm bootstrap, or mutate production without explicit authorization.

## Enforce Licensing and Submodule Boundaries

- License original public repository code and documentation as `GPL-3.0-only` unless a file has an
  explicit, approved exception.
- Preserve third-party notices and dependency licenses; do not rewrite lockfile dependency
  licenses as GPL.
- Run `cargo-deny` after changing Rust dependencies or license policy.
- Treat the private repository as proprietary and commercially licensed.
- Do not assume that repository separation, a submodule, dynamic loading, or one-way dependency
  direction creates a GPL linking exception.
- Require a commercial license, reviewed process/service isolation, or GPL-compliant source
  distribution before shipping a combined proprietary binary.
- Escalate licensing ambiguity for qualified legal review; do not present engineering policy as
  legal advice.

When updating the private submodule:

1. Commit and validate the change in the private repository.
2. Push the private commit to an accessible private remote.
3. Update only the submodule gitlink in the public repository.
4. Commit the gitlink as `chore(private): update private suite submodule` or a more specific valid
   subject.
5. Verify a fresh authorized clone can initialize the pinned commit and a public clone can still
   build without it.

## Validate in Proportion to Risk

Run focused tests while iterating, then run the affected release gates. For broad or release-bound
changes, use the complete matrix below.

```bash
rtk cargo fmt --all -- --check
rtk cargo check --workspace
rtk cargo clippy --workspace --all-targets -- -D warnings
rtk cargo test --workspace
rtk cargo test -p copylocker-suite-std --no-default-features --features std,pq-ml-dsa-44
rtk cargo test -p copylocker-suite-std --no-default-features --features std,pq-ml-dsa-65
rtk cargo test -p copylocker-suite-std --no-default-features --features std,pq-ml-dsa-87
rtk cargo deny --locked check advisories bans licenses sources
rtk cargo audit --deny warnings
```

Do not use workspace `--all-features`; the ML-DSA parameter-set features are mutually exclusive.

For Worker or generated-template changes, run from `crates/copylocker-worker`:

```bash
rtk npm run check
rtk npm test
rtk npm run size
rtk npm run startup
rtk npm run package:check
```

Then run `rtk bash scripts/check-server-template.sh` from the public repository root. Run package
and template checks after startup because Wrangler custom builds can regenerate metadata.

For native changes, validate the affected Rust crate, npm package, tarball, example build, security
tests, and the three-platform CI definition. Never commit a locally built `.node`, `target/`,
`dist/`, `build/`, `release/`, Playwright session, or QA screenshot directory.

## Create Commits

Write every commit subject in English using exactly:

```text
type(scope): description
```

Accept these types:

- `feat`: user-visible capability;
- `fix`: defect or security correction;
- `docs`: documentation or agent guidance only;
- `refactor`: behavior-preserving code restructuring;
- `perf`: measured performance or size improvement;
- `test`: tests, fuzz targets, fixtures, or validation tooling;
- `build`: build system or package assembly;
- `ci`: continuous integration or release automation;
- `chore`: repository, dependency, licensing, or maintenance work;
- `revert`: explicit reversal of an earlier commit.

Use a concise lowercase scope such as `repo`, `architecture`, `crypto`, `proto`, `client`, `store`,
`server`, `worker`, `cli`, `ffi`, `node`, `tauri`, `electron`, `native`, `web`, `template`, `fuzz`,
`release`, `deps`, `license`, `agent`, `skill`, or `private`.

Follow these subject rules:

- use an imperative English description;
- keep the subject at 72 characters or fewer when practical;
- omit the trailing period;
- never omit the scope;
- do not use vague subjects such as `update files`, `fix stuff`, or `wip`;
- use `BREAKING CHANGE:` in the body or footer for incompatible contracts;
- explain security, migration, licensing, or operational consequences in the body when relevant.

Valid examples:

```text
feat(worker): add recoverable epoch revocation
fix(node): redact initialization diagnostics
docs(agent): capture repository release state
chore(license): adopt GPL public repository policy
ci(native): add three-platform SDK matrix
```

Split commits by one reviewable concern. Keep generated updates with the source change that requires
them. Keep tests with the behavior they prove unless the test framework itself is the change. Never
mix public and private source in one commit or use a public commit to smuggle private content.

Before each commit:

1. Inspect `git status` and the staged diff.
2. Confirm generated and secret files are excluded.
3. Run the affected checks.
4. Verify author and committer identity requested by the repository owner.
5. Commit without rewriting unrelated user history unless explicitly authorized.

## Hand Off

Report the behavior and repository boundary changed, tests and release metrics, commit hashes,
accepted risks, and any external action not performed. Distinguish local artifacts from published
packages and deployed infrastructure.
