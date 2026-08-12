#!/usr/bin/env bash
# Regenerate the admin-sdk ts-rs bindings (packages/admin-sdk/bindings/) from
# the Rust wire types and fail on any drift. Mirrors scripts/check-legal-sync.mjs:
# the bindings are generated code checked into the repository, so a Rust wire
# change without a regeneration is a CI failure.
#
# The hand-written side of the contract (src/types.ts) is pinned against these
# bindings by `npm run check:bindings` in packages/admin-sdk.
set -euo pipefail

cd "$(dirname "$0")/.."

# ts-rs maps i64/u64 to `bigint` by default; the Admin API wire is JSON, where
# every integer is a number, so generation must run with the number mapping.
export TS_RS_LARGE_INT=number

cargo test --locked -p copylocker-types --features ts-rs export_bindings
cargo test --locked -p copylocker-server-core --features ts-rs export_bindings

if [ -n "$(git status --porcelain -- packages/admin-sdk/bindings)" ]; then
  echo "error: packages/admin-sdk/bindings drifted from the Rust wire types" >&2
  echo "run this script and commit the regenerated bindings with the Rust change" >&2
  git status --porcelain -- packages/admin-sdk/bindings >&2
  exit 1
fi
