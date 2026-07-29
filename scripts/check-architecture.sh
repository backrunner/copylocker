#!/usr/bin/env bash
set -euo pipefail

metadata_file="$(mktemp)"
trap 'rm -f "$metadata_file"' EXIT
cargo metadata --locked --no-deps --format-version 1 >"$metadata_file"

if ! jq -e '
  def deps_of($package):
    [.packages[] | select(.name == $package) | .dependencies[].name];

  (deps_of("copylocker-suite")
    | map(select(startswith("copylocker-suite-") and . != "copylocker-suite"))
    | length == 0)
  and
  ([deps_of("copylocker-core")[], deps_of("copylocker-server-core")[]]
    | map(select(
        startswith("worker") or
        startswith("tauri") or
        startswith("napi") or
        startswith("wasm-bindgen")
      ))
    | length == 0)
' "$metadata_file" >/dev/null; then
  echo "forbidden Cargo dependency direction detected" >&2
  exit 1
fi

if rg -n "copylocker-suite-priv" Cargo.toml crates packages apps server-template 2>/dev/null; then
  echo "public workspace references copylocker-suite-priv" >&2
  exit 1
fi
