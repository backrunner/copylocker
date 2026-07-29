#!/usr/bin/env bash
set -euo pipefail

readonly target="wasm32-unknown-unknown"
readonly package="copylocker-wasm-verifier-size"
readonly wasm="target/${target}/release/copylocker_wasm_verifier_size.wasm"
readonly max_gzip_bytes="${COPYLOCKER_WASM_GZIP_MAX_BYTES:-307200}"

cargo build --locked --release --target "${target}" -p "${package}"

gzip_file="$(mktemp)"
trap 'rm -f "${gzip_file}"' EXIT
gzip -9 -c "${wasm}" >"${gzip_file}"

raw_bytes="$(wc -c <"${wasm}" | tr -d ' ')"
gzip_bytes="$(wc -c <"${gzip_file}" | tr -d ' ')"
echo "CL-STD-1 verification WASM: ${raw_bytes} raw bytes, ${gzip_bytes} gzip bytes (limit ${max_gzip_bytes})"

if (( gzip_bytes > max_gzip_bytes )); then
  echo "WASM verification path exceeds the ${max_gzip_bytes}-byte gzip limit" >&2
  exit 1
fi
