#!/usr/bin/env node

// legal-sync CI gate (M6): every collected field referenced in code must stay
// in sync with the machine-readable `data-inventory` YAML block at the end of
// .agents/06-legal/templates/data-inventory.md. Drift fails the build.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const inventoryPath = join(
  repoRoot,
  ".agents",
  "06-legal",
  "templates",
  "data-inventory.md",
);
const protoPath = join(repoRoot, "crates", "copylocker-proto", "src", "requests.rs");
const catalogPath = join(
  repoRoot,
  "crates",
  "copylocker-server-core",
  "src",
  "analytics",
  "catalog.rs",
);
const migrationPath = join(
  repoRoot,
  "crates",
  "copylocker-worker",
  "migrations",
  "0001_initial.sql",
);

const inventory = readFileSync(inventoryPath, "utf8");
const proto = readFileSync(protoPath, "utf8");
const catalog = readFileSync(catalogPath, "utf8");
const migration = readFileSync(migrationPath, "utf8");

// --- Parse the machine-readable YAML block (one-line flow maps, line parsing) ---

const yamlBlock = inventory.match(/```yaml\n([\s\S]*?)```/);
if (!yamlBlock || !yamlBlock[1].includes("data-inventory:")) {
  throw new Error(`No data-inventory YAML block found in ${inventoryPath}`);
}
const fieldNames = new Set();
const storageTokens = new Set();
for (const line of yamlBlock[1].split("\n")) {
  if (!/^\s*- \{/.test(line)) continue;
  const name = line.match(/\bname:\s*([A-Za-z0-9_]+)/);
  if (name) fieldNames.add(name[1]);
  const storage = line.match(/\bstorage:\s*\[([^\]]*)\]/);
  if (storage) {
    for (const token of storage[1].split(",")) {
      const trimmed = token.trim();
      if (trimmed) storageTokens.add(trimmed);
    }
  }
}
if (fieldNames.size === 0) {
  throw new Error("The data-inventory YAML block contains no field entries");
}

// --- Parse the code sources of truth ---

const structStart = proto.indexOf("pub struct TelemetryBlock {");
if (structStart === -1) {
  throw new Error("TelemetryBlock struct not found in requests.rs");
}
const structBody = proto.slice(structStart, proto.indexOf("\n}", structStart));
const telemetryFields = [...structBody.matchAll(/^\s*pub ([a-z0-9_]+):/gm)].map(
  (m) => m[1],
);
if (telemetryFields.length === 0) {
  throw new Error("No fields parsed from the TelemetryBlock struct");
}

const t0MetricIds = [];
const t1MetricIds = [];
for (const m of catalog.matchAll(/MetricDefinition::t([01])\(\s*"([^"]+)"/g)) {
  (m[1] === "0" ? t0MetricIds : t1MetricIds).push(m[2]);
}
if (t1MetricIds.length === 0) {
  throw new Error("No T1 metric ids parsed from the analytics catalog");
}

const rollupTables = [...migration.matchAll(/CREATE TABLE (\w*(?:rollup|hll)\w*)/g)].map(
  (m) => m[1],
);
if (rollupTables.length === 0) {
  throw new Error("No rollup tables parsed from 0001_initial.sql");
}

// --- Hard-fail drift checks ---

const drift = [];
for (const field of telemetryFields) {
  if (!fieldNames.has(field)) {
    drift.push(
      `TelemetryBlock field \`${field}\` (${protoPath}) is missing from the data-inventory YAML block`,
    );
  }
}
for (const id of t1MetricIds) {
  const field = id.replace(/^use\./, "");
  const covered = [...fieldNames].some(
    (name) => name === field || name.startsWith(`${field}_`),
  );
  if (!covered) {
    drift.push(
      `T1 metric \`${id}\` (${catalogPath}) has no matching field in the data-inventory YAML block`,
    );
  }
}
for (const table of rollupTables) {
  const covered = [...storageTokens].some(
    (token) => token === table || token.endsWith(`.${table}`),
  );
  if (!covered) {
    drift.push(
      `rollup table \`${table}\` (${migrationPath}) is missing from the data-inventory YAML storage entries`,
    );
  }
}

if (drift.length > 0) {
  console.error("legal-sync check FAILED: code drifted from the data inventory.");
  console.error("Update .agents/06-legal/templates/data-inventory.md:");
  for (const item of drift) console.error(`  - ${item}`);
  process.exit(1);
}

// --- Warn-only: T0 metric ids are aggregates, not fields; they should at least
// be mentioned somewhere in the document. ---

const unmentioned = t0MetricIds.filter((id) => !inventory.includes(id));
if (unmentioned.length > 0) {
  console.warn(
    `legal-sync warning: T0 metric ids not mentioned in data-inventory.md: ${unmentioned.join(", ")}`,
  );
}

console.log(
  `legal-sync OK: ${telemetryFields.length} telemetry fields, ${t1MetricIds.length} T1 metrics, ` +
    `${rollupTables.length} rollup tables covered by the data inventory`,
);
