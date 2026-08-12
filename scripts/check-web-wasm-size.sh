#!/usr/bin/env bash
# Size gate for the browser WASM core (NFR-PERF-005, 40-web-sdk-wasm-ts.md §7).
#
# Builds crates/copylocker-wasm for wasm32-unknown-unknown in release mode, runs
# `wasm-opt -Oz` when available (warning only when not), and fails when the gzip
# payload exceeds 350 KiB.
set -euo pipefail

readonly target="wasm32-unknown-unknown"
readonly package="copylocker-wasm"
readonly wasm="target/${target}/release/copylocker_wasm.wasm"
readonly max_gzip_bytes="${COPYLOCKER_WEB_WASM_GZIP_MAX_BYTES:-358400}" # 350 * 1024

cargo_bin="${CARGO:-cargo}"
rustc_bin="${RUSTC:-rustc}"

# The build needs a toolchain whose rustlib includes the wasm target. When the
# default cargo/rustc pair lacks it (e.g. a Homebrew install), fall back to the
# rustup toolchain selected by rust-toolchain.toml.
if ! libdir="$("${rustc_bin}" --print target-libdir --target "${target}" 2>/dev/null)" \
  || [[ ! -d "${libdir}" ]]; then
  if command -v rustup >/dev/null 2>&1; then
    cargo_bin="$(rustup which cargo)"
    rustc_bin="$(rustup which rustc)"
  fi
fi

RUSTC="${rustc_bin}" "${cargo_bin}" build --locked --release --target "${target}" -p "${package}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT
cp "${wasm}" "${workdir}/core.wasm"

raw_bytes="$(wc -c <"${workdir}/core.wasm" | tr -d ' ')"
if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -Oz --enable-bulk-memory "${workdir}/core.wasm" -o "${workdir}/core.opt.wasm"
  mv "${workdir}/core.opt.wasm" "${workdir}/core.wasm"
  opt_note="wasm-opt -Oz"
  opt_bytes="$(wc -c <"${workdir}/core.wasm" | tr -d ' ')"
else
  opt_note="wasm-opt not found; measuring the raw build"
  opt_bytes="${raw_bytes}"
  echo "warning: wasm-opt not found; gating on the unoptimized wasm" >&2
fi

gzip -9 -c "${workdir}/core.wasm" >"${workdir}/core.wasm.gz"
gzip_bytes="$(wc -c <"${workdir}/core.wasm.gz" | tr -d ' ')"

echo "copylocker-wasm (web SDK core): ${raw_bytes} raw bytes, ${opt_bytes} after ${opt_note}, ${gzip_bytes} gzip bytes (limit ${max_gzip_bytes})"

if (( gzip_bytes > max_gzip_bytes )); then
  echo "copylocker-wasm exceeds the ${max_gzip_bytes}-byte gzip limit (NFR-PERF-005)" >&2
  exit 1
fi
