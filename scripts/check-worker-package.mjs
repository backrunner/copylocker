#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const buildDir = join(repoRoot, "crates", "copylocker-worker", "build");
const manifestPath = join(buildDir, "package.json");
const templatePath = join(repoRoot, "server-template", "package.json");
const expectedRuntimeFiles = ["index.js", "index_bg.wasm"];
const expectedRepositoryUrl = "git+https://github.com/backrunner/copylocker.git";

const manifest = readJson(manifestPath);
const template = readJson(templatePath);
if (template.dependencies?.[manifest.name] !== manifest.version) {
  throw new Error(
    `Template expects ${manifest.name} ${template.dependencies?.[manifest.name]}, ` +
      `but the Worker package is ${manifest.version}`,
  );
}
if (
  manifest.repository?.type !== "git" ||
  manifest.repository.url !== expectedRepositoryUrl
) {
  throw new Error(
    `Worker package repository must be ${expectedRepositoryUrl}`,
  );
}

const declared = [...(manifest.files ?? [])].sort();
assertSameFiles("Worker package manifest", declared, expectedRuntimeFiles);
for (const relative of declared) {
  const path = join(buildDir, relative);
  if (!existsSync(path) || !statSync(path).isFile()) {
    throw new Error(`Worker package declares a missing file: ${relative}`);
  }
}

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const packed = spawnSync(npm, ["pack", "--dry-run", "--json"], {
  cwd: buildDir,
  encoding: "utf8",
  env: process.env,
});
if (packed.error) throw packed.error;
if (packed.status !== 0) {
  process.stdout.write(packed.stdout ?? "");
  process.stderr.write(packed.stderr ?? "");
  throw new Error(`npm pack exited with status ${packed.status}`);
}

const report = JSON.parse(packed.stdout);
if (!Array.isArray(report) || report.length !== 1) {
  throw new Error("npm pack returned an unexpected report");
}
const packedFiles = report[0].files.map((file) => file.path).sort();
assertSameFiles("Worker npm tarball", packedFiles, [
  "index.js",
  "index_bg.wasm",
  "package.json",
]);

console.log(
  `Worker npm package ${manifest.name}@${manifest.version}: ` +
    `${report[0].size} packed bytes, ${report[0].unpackedSize} unpacked bytes; ` +
    "tarball contents accepted",
);

function readJson(path) {
  if (!existsSync(path)) throw new Error(`Required JSON file is missing: ${path}`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function assertSameFiles(label, actual, expected) {
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((file, index) => file !== sortedExpected[index])
  ) {
    throw new Error(
      `${label} contains [${actual.join(", ")}], expected ` +
        `[${sortedExpected.join(", ")}]`,
    );
  }
}
