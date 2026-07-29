import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";

const wasmPath =
  process.argv[2] ??
  "target/wasm32-unknown-unknown/release/copylocker_wasm_verifier_size.wasm";
const maxP95Ms = Number(process.env.COPYLOCKER_WASM_VERIFY_P95_MS ?? "15");
const bytes = await readFile(wasmPath);
const { instance } = await WebAssembly.instantiate(bytes);
const verify = instance.exports.copylocker_verify_embedded_chain;

if (typeof verify !== "function") {
  throw new Error("verification export is missing from the WASM size harness");
}

for (let index = 0; index < 10; index += 1) {
  if (verify() !== 1) {
    throw new Error("embedded certificate chain failed during WASM warmup");
  }
}

const durations = [];
for (let index = 0; index < 100; index += 1) {
  const started = performance.now();
  const result = verify();
  durations.push(performance.now() - started);
  if (result !== 1) {
    throw new Error("embedded certificate chain failed during WASM benchmark");
  }
}

durations.sort((left, right) => left - right);
const p95 = durations[Math.ceil(durations.length * 0.95) - 1];
const average = durations.reduce((total, value) => total + value, 0) / durations.length;
console.log(
  `CL-STD-1 WASM chain verification: average ${average.toFixed(3)} ms, p95 ${p95.toFixed(3)} ms (limit ${maxP95Ms} ms)`,
);

if (p95 > maxP95Ms) {
  throw new Error(`WASM verification p95 ${p95.toFixed(3)} ms exceeds ${maxP95Ms} ms`);
}
