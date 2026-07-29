#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const workerDir = join(repoRoot, "crates", "copylocker-worker");
const wrangler = join(
  workerDir,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "wrangler.cmd" : "wrangler",
);
const samples = positiveInteger(
  "COPYLOCKER_WORKER_STARTUP_SAMPLES",
  process.env.COPYLOCKER_WORKER_STARTUP_SAMPLES ?? "20",
);
const maxP95Ms = positiveNumber(
  "COPYLOCKER_WORKER_STARTUP_P95_MAX_MS",
  process.env.COPYLOCKER_WORKER_STARTUP_P95_MAX_MS ?? "50",
);

if (!existsSync(wrangler)) {
  throw new Error(`Wrangler is not installed at ${wrangler}; run npm ci first`);
}

const workDir = mkdtempSync(join(tmpdir(), "copylocker-worker-startup-"));
try {
  const bundle = join(workDir, "worker.bundle");
  await writeWorkerBundle(bundle);

  const durations = [];
  for (let index = 0; index < samples; index += 1) {
    const profilePath = join(workDir, `startup-${index}.cpuprofile`);
    runWrangler(
      ["check", "startup", "--worker", bundle, "--outfile", profilePath],
      false,
    );
    const profile = JSON.parse(readFileSync(profilePath, "utf8"));
    if (
      !Number.isFinite(profile.startTime) ||
      !Number.isFinite(profile.endTime) ||
      profile.endTime < profile.startTime
    ) {
      throw new Error(`Wrangler produced an invalid CPU profile at sample ${index}`);
    }
    durations.push((profile.endTime - profile.startTime) / 1000);
  }

  durations.sort((left, right) => left - right);
  const p50 = percentile(durations, 0.5);
  const p95 = percentile(durations, 0.95);
  const maximum = durations[durations.length - 1];
  console.log(
    `Worker local startup: ${samples} samples, p50 ${p50.toFixed(3)} ms, ` +
      `p95 ${p95.toFixed(3)} ms, max ${maximum.toFixed(3)} ms ` +
      `(limit p95 < ${maxP95Ms} ms)`,
  );
  if (p95 >= maxP95Ms) {
    throw new Error(
      `Worker local startup p95 ${p95.toFixed(3)} ms exceeds the ${maxP95Ms} ms limit`,
    );
  }
} finally {
  rmSync(workDir, { force: true, recursive: true });
}

function runWrangler(args, showOutput) {
  const result = spawnSync(wrangler, args, {
    cwd: workerDir,
    encoding: "utf8",
    env: process.env,
    stdio: showOutput ? "inherit" : "pipe",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    if (!showOutput) {
      process.stdout.write(result.stdout ?? "");
      process.stderr.write(result.stderr ?? "");
    }
    throw new Error(`Wrangler exited with status ${result.status}`);
  }
}

async function writeWorkerBundle(path) {
  const config = JSON.parse(
    readFileSync(join(workerDir, "wrangler.jsonc"), "utf8"),
  );
  if (
    typeof config.compatibility_date !== "string" ||
    !Array.isArray(config.compatibility_flags)
  ) {
    throw new Error("Worker compatibility configuration is invalid");
  }

  const modules = [
    {
      name: "index.js",
      path: join(workerDir, "build", "index.js"),
      type: "application/javascript+module",
    },
    {
      name: "index_bg.wasm",
      path: join(workerDir, "build", "index_bg.wasm"),
      type: "application/wasm",
    },
  ];
  const form = new FormData();
  form.set(
    "metadata",
    JSON.stringify({
      main_module: "index.js",
      compatibility_date: config.compatibility_date,
      compatibility_flags: config.compatibility_flags,
    }),
  );
  for (const module of modules) {
    if (!existsSync(module.path)) {
      throw new Error(`Worker startup module is missing: ${module.path}`);
    }
    form.set(
      module.name,
      new Blob([readFileSync(module.path)], { type: module.type }),
      module.name,
    );
  }
  writeFileSync(path, Buffer.from(await new Response(form).arrayBuffer()));
}

function percentile(sorted, fraction) {
  return sorted[Math.ceil(sorted.length * fraction) - 1];
}

function positiveInteger(name, value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function positiveNumber(name, value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive number`);
  }
  return parsed;
}
