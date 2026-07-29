#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly worker_dir="${repo_root}/crates/copylocker-worker"
readonly template_dir="${repo_root}/server-template"

for migration in "${worker_dir}"/migrations/*.sql; do
  name="$(basename "${migration}")"
  if ! cmp -s "${migration}" "${template_dir}/migrations/${name}"; then
    echo "server-template migration ${name} differs from copylocker-worker" >&2
    exit 1
  fi
done

for migration in "${template_dir}"/migrations/*.sql; do
  name="$(basename "${migration}")"
  if [[ ! -f "${worker_dir}/migrations/${name}" ]]; then
    echo "server-template has an unknown migration: ${name}" >&2
    exit 1
  fi
done

(
  cd "${worker_dir}"
  npm run build
)

node -e '
  const fs = require("node:fs");
  const template = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const runtime = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  if (template.dependencies["copylocker-worker"] !== runtime.version) {
    throw new Error(`template expects copylocker-worker ${template.dependencies["copylocker-worker"]}, built ${runtime.version}`);
  }
' "${template_dir}/package.json" "${worker_dir}/build/package.json"

node "${repo_root}/scripts/check-worker-package.mjs"

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
cp -R "${template_dir}" "${work_dir}/server"

rendered_config="${work_dir}/server/wrangler.rendered.jsonc"
sed \
  -e 's/__COPYLOCKER_PROJECT_NAME__/copylocker-template-check/g' \
  -e 's/__COPYLOCKER_D1_DATABASE_ID__/00000000-0000-0000-0000-000000000001/g' \
  -e 's/__COPYLOCKER_KV_NAMESPACE_ID__/00000000000000000000000000000002/g' \
  -e 's/__COPYLOCKER_SECRET_STORE_ID__/00000000000000000000000000000003/g' \
  "${template_dir}/wrangler.jsonc" >"${rendered_config}"

mkdir -p "${work_dir}/server/node_modules"
ln -s "${worker_dir}/build" "${work_dir}/server/node_modules/copylocker-worker"
ln -s "${worker_dir}/node_modules/wrangler" "${work_dir}/server/node_modules/wrangler"

mkdir -p "${work_dir}/server/.copylocker"
"${worker_dir}/node_modules/.bin/wrangler" types \
  "${work_dir}/server/.copylocker/worker-configuration.d.ts" \
  --config "${rendered_config}" \
  >/dev/null

"${worker_dir}/node_modules/.bin/esbuild" \
  "${work_dir}/server/src/index.js" \
  --bundle \
  --conditions=workerd,worker,browser \
  "--external:cloudflare:*" \
  --format=esm \
  --loader:.wasm=file \
  --log-level=warning \
  --outfile="${work_dir}/server/.copylocker/template-bundle.js"

echo "server-template migrations, configuration, and bundle are current"
