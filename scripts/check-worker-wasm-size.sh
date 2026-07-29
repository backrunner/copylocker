#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly worker_dir="${repo_root}/crates/copylocker-worker"
readonly wasm="${worker_dir}/build/index_bg.wasm"
readonly max_gzip_bytes="${COPYLOCKER_WORKER_WASM_GZIP_MAX_BYTES:-1500000}"

(
  cd "${worker_dir}"
  npm run build
)

gzip_file="$(mktemp)"
trap 'rm -f "${gzip_file}"' EXIT
gzip -9 -n -c "${wasm}" >"${gzip_file}"

raw_bytes="$(wc -c <"${wasm}" | tr -d ' ')"
gzip_bytes="$(wc -c <"${gzip_file}" | tr -d ' ')"
echo "Worker release WASM: ${raw_bytes} raw bytes, ${gzip_bytes} gzip bytes (limit ${max_gzip_bytes})"

if (( gzip_bytes > max_gzip_bytes )); then
  echo "Worker release WASM exceeds the ${max_gzip_bytes}-byte gzip limit" >&2
  exit 1
fi
