#!/usr/bin/env node

import {
  existsSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const buildDir = join(repoRoot, "crates", "copylocker-worker", "build");
const manifestPath = join(buildDir, "package.json");
const runtimeFiles = ["index_bg.wasm", "index.js"];
const npmRepositoryUrl = "git+https://github.com/backrunner/copylocker.git";

if (!existsSync(manifestPath)) {
  throw new Error(`Worker package manifest is missing at ${manifestPath}`);
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
if (
  manifest.name !== "copylocker-worker" ||
  typeof manifest.version !== "string" ||
  manifest.version.length === 0
) {
  throw new Error("Worker build produced invalid npm package identity");
}
if (
  typeof manifest.repository !== "object" ||
  manifest.repository === null ||
  manifest.repository.type !== "git"
) {
  throw new Error("Worker build produced invalid npm repository metadata");
}

for (const relative of runtimeFiles) {
  const path = join(buildDir, relative);
  if (!existsSync(path) || !statSync(path).isFile()) {
    throw new Error(`Worker package runtime file is missing: ${relative}`);
  }
}

// worker-build 0.8.5 disables declaration generation but still lists index.d.ts.
// Normalize the generated manifest so npm never advertises a file it cannot ship.
manifest.files = runtimeFiles;
manifest.main = "index.js";
manifest.repository.url = npmRepositoryUrl;
manifest.sideEffects = ["./index.js"];
delete manifest.types;
delete manifest.typings;

writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
