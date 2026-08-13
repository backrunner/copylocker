---
title: Migration
navTitle: Migration
order: 8
description: Moving to CopyLocker from another licensing system, and moving between CopyLocker versions — what exists today and what is only planned.
---

# Migration Guide

This page covers moving **to** CopyLocker from another licensing system, and moving **between**
CopyLocker versions. It is deliberately short: it documents what exists today and what is only
planned. Where no tooling exists yet, we say so instead of inventing a path.

## From keygen.sh and other licensing systems

**Status: not yet implemented.** A keygen.sh migration tool is on the v1.1+ backlog
(`.agents/04-roadmap/roadmap.md`) alongside iOS/Android SDKs, floating licenses, and metered
billing. There is no importer in the CLI today — `copylocker --help` is the ground truth.

What you can do today, by hand:

1. **Model your products** as CopyLocker catalogs. Map each old "feature flag" to an immutable
   `feature_id` (choose these names carefully — they can never change, see
   [Licensing Model](/docs/guide/licensing-model#feature-ids-are-immutable--hard-constraint)), group them,
   and define tiers. `copylocker catalog import` enforces identifier immutability when evolving
   an existing catalog file.
2. **Model your license shapes** as policies from the eleven presets
   (`copylocker policy presets`) — perpetual, subscription, and JetBrains-style fallback all have
   direct equivalents.
3. **Re-issue licenses** with `copylocker license issue --count N --idempotency-key …` and
   deliver the new keys through your existing customer portal. CopyLocker plaintext license keys
   are returned only at issuance; there is no way (and no need) to import old plaintext keys.

What a future migration tool would need to preserve — and what you must preserve in any manual
migration:

- **No forced re-entry of keys** for existing installs (NFR-VER-001's spirit applied to
  migrations): run both systems in parallel during a transition window, activate CopyLocker
  silently against the old proof of purchase, then sunset the old verifier.
- **Grandfathered version scope**: model "bought before date T" as
  `VersionScope::ReleasedBefore(T)` rather than trying to encode it in semver.

## Between CopyLocker versions

The protocol compatibility promise is **N and N−1** and takes effect at GA; see
`.agents/02-architecture/versioning-and-variants.md`. Until v1.0, only the latest commit on the
default branch receives fixes (see [SECURITY.md](https://github.com/backrunner/copylocker/blob/main/SECURITY.md)).

Designed-in guarantees you can rely on when upgrading:

- **Client upgrades never invalidate existing credentials** (NFR-REL-007): credential formats are
  backward-compatible and version-negotiated.
- **Variant rotation is transparent**: every release gets its own derivation variant, and offline
  clients follow the policy's `offline_upgrade_policy` (e.g. `preload_n` preloads the next N
  variants' keys at renewal).
- **Downgrade attacks are blocked, not migrations**: `security_floor` is monotonic — clients
  persist the maximum seen and reject older-floor credentials. Legitimate upgrades are unaffected;
  revoked-version credentials die on schedule.
- **Server migrations are dry-run-first**: `copylocker deploy --confirm` re-checks the migration
  set before deploying, `bootstrap apply` is rerunnable with the same bundle, and
  `scripts/check-server-template.sh` keeps template and Worker migrations byte-identical (see
  [Deployment](/docs/guide/deployment)).

## What does not exist yet (do not plan around it)

- A `keygen.sh` (or any third-party) importer.
- A `copylocker license unrevoke` command — the schema keeps `undo_until`, but M1 has no
  unrevoke contract; mistaken revocations are handled by re-issuing (see the
  [Runbook](/docs/operations/runbook#credential-compromise-and-recovery)).
- A `copylocker-cli dev-license` helper and `copylocker-cli estimate` cost command — both are
  requirements (NFR-DX-004 / NFR-COST-004) not yet surfaced in the CLI.
- A `copylocker audit verify` CLI command — the server endpoint (`/v1/admin/audit/verify`) and
  the console's one-click verification exist; the gap is CLI-side only.
- An Admin token lifecycle API; emergency token revocation is a documented break-glass procedure
  (see [Runbook](/docs/operations/runbook#credential-compromise-and-recovery)).
