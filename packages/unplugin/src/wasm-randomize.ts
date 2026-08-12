/**
 * WASM export-name randomization (`40-web-sdk-wasm-ts.md §5`).
 *
 * Build-time post-processing of `wasm-bindgen` output: new export names are
 * derived from the per-build seed, the WASM binary's export section is
 * rewritten, and every covered JS chunk that references those exports (the
 * generated glue) is rewritten to match. Same seed → same names; different
 * seed → different names.
 *
 * This is **obfuscation / diversification, not cryptographic protection**
 * (design §5): it raises the cost of name-based generic patch scripts; it
 * does not change what a determined attacker can do by hand.
 *
 * Scope limits (kept deliberately conservative so the textual glue rewrite
 * can never corrupt unrelated code):
 *
 * - The `memory` export keeps its name. It is generic (`.memory` property
 *   accesses appear in non-glue code) and carries no CopyLocker semantics.
 * - Exports whose names are not plain JS identifiers (glue would need
 *   bracket access to reach them) or shorter than 4 characters keep their
 *   names — a textual rewrite cannot target them unambiguously.
 * - Glue references are rewritten in the forms wasm-bindgen actually emits:
 *   `wasm.<name>`, `<anything>.<name>` (the minifier may rename the `wasm`
 *   variable, but never property names) and `["<name>"]` / `['<name>']`
 *   bracket access. Property names survive minification verbatim, so a
 *   dot-access rewrite on the final bytes is reliable.
 * - A covered `.wasm` asset whose exports are not referenced by ANY covered
 *   chunk is left untouched (with a warning): renaming without rewriting
 *   the glue would break the runtime.
 *
 * The binary rewriter is a minimal section-level re-encoder (LEB128, export
 * section re-serialization). The custom `name` section is dropped while
 * rewriting: it duplicates exactly the symbol names this pass exists to
 * hide (plus internal Rust symbols), and nothing at runtime reads it.
 */

import { createHash } from 'node:crypto'
import { ConfigError } from './config.js'

const WASM_MAGIC = 0x6d736100 // '\0asm' little-endian
const WASM_VERSION = 1
const SECTION_CUSTOM = 0
const SECTION_EXPORT = 7

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

/** Names that are never renamed (see the module comment). */
const STABLE_NAMES = new Set(['memory'])

const JS_IDENTIFIER = /^[A-Za-z_$][\w$]*$/

/** An export entry decoded from the export section. */
export interface WasmExportEntry {
  name: string
  kind: number
  index: number
}

function fail(message: string): never {
  throw new ConfigError(`CopyLocker unplugin: ${message}`)
}

/** Read one unsigned LEB128 value; returns [value, nextOffset]. */
function readLeb128(bytes: Uint8Array, offset: number): [number, number] {
  let result = 0
  let shift = 0
  let cursor = offset
  for (;;) {
    if (cursor >= bytes.byteLength) fail('malformed WASM binary: truncated LEB128')
    const byte = bytes[cursor] as number
    cursor += 1
    result += (byte & 0x7f) * 2 ** shift
    if ((byte & 0x80) === 0) break
    shift += 7
    if (shift > 35) fail('malformed WASM binary: LEB128 value too large')
  }
  return [result, cursor]
}

/** Encode one unsigned LEB128 value. */
function writeLeb128(value: number): number[] {
  const out: number[] = []
  let remaining = value
  do {
    let byte = remaining % 128
    remaining = Math.floor(remaining / 128)
    if (remaining > 0) byte |= 0x80
    out.push(byte)
  } while (remaining > 0)
  return out
}

interface Section {
  id: number
  /** Payload range [start, end) inside the module bytes. */
  start: number
  end: number
}

function parseSections(bytes: Uint8Array): Section[] {
  if (bytes.byteLength < 8) fail('malformed WASM binary: shorter than the header')
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  if (view.getUint32(0, true) !== WASM_MAGIC || view.getUint32(4, true) !== WASM_VERSION) {
    fail('malformed WASM binary: bad magic or version')
  }
  const sections: Section[] = []
  let cursor = 8
  while (cursor < bytes.byteLength) {
    const id = bytes[cursor] as number
    const [size, start] = readLeb128(bytes, cursor + 1)
    const end = start + size
    if (end > bytes.byteLength) fail('malformed WASM binary: section extends past EOF')
    sections.push({ id, start, end })
    cursor = end
  }
  return sections
}

function readName(bytes: Uint8Array, offset: number): [string, number] {
  const [length, start] = readLeb128(bytes, offset)
  const end = start + length
  if (end > bytes.byteLength) fail('malformed WASM binary: truncated name')
  return [textDecoder.decode(bytes.subarray(start, end)), end]
}

/** Decode the export section; returns [] when the module has none. */
export function listWasmExports(bytes: Uint8Array): WasmExportEntry[] {
  const section = parseSections(bytes).find((candidate) => candidate.id === SECTION_EXPORT)
  if (!section) return []
  const entries: WasmExportEntry[] = []
  let cursor = section.start
  const [count, after] = readLeb128(bytes, cursor)
  cursor = after
  for (let i = 0; i < count; i += 1) {
    const [name, nameEnd] = readName(bytes, cursor)
    if (nameEnd >= section.end) fail('malformed WASM binary: truncated export entry')
    const kind = bytes[nameEnd] as number
    const [index, next] = readLeb128(bytes, nameEnd + 1)
    entries.push({ name, kind, index })
    cursor = next
  }
  return entries
}

/** True when an export name may be renamed (see the module comment). */
export function isRenameableExport(name: string): boolean {
  return !STABLE_NAMES.has(name) && name.length >= 4 && JS_IDENTIFIER.test(name)
}

/**
 * Derive the randomized name for one export: `__cl_<16 hex of
 * SHA-256('copylocker/wasm-export/v1' ‖ seed ‖ name)>`. Deterministic in
 * (seed, name); the result is always a valid JS identifier and WASM name.
 * `salt` disambiguates the (astronomically unlikely) collision case.
 */
export function deriveExportName(seed: string, name: string, salt = 0): string {
  const digest = createHash('sha256')
    .update(`copylocker/wasm-export/v1:${seed}:${name}:${salt}`)
    .digest('hex')
  return `__cl_${digest.slice(0, 16)}`
}

/** Build the old → new name map for a module's exports. */
export function deriveExportRenames(seed: string, names: string[]): Map<string, string> {
  const used = new Set(names)
  const renames = new Map<string, string>()
  for (const name of names) {
    if (!isRenameableExport(name)) continue
    let salt = 0
    let candidate = deriveExportName(seed, name, salt)
    while (used.has(candidate)) {
      salt += 1
      candidate = deriveExportName(seed, name, salt)
    }
    used.add(candidate)
    renames.set(name, candidate)
  }
  return renames
}

export interface WasmRandomization {
  /** The rewritten module (export section re-encoded, `name` section dropped). */
  bytes: Uint8Array
  renames: Map<string, string>
}

/**
 * Rewrite a module's export section with seed-derived names and drop the
 * custom `name` section. Sections are otherwise copied verbatim; only the
 * export section's payload (and therefore its LEB128 size) changes.
 */
export function randomizeExports(bytes: Uint8Array, seed: string): WasmRandomization {
  const sections = parseSections(bytes)
  const exports = listWasmExports(bytes)
  const renames = deriveExportRenames(
    seed,
    exports.map((entry) => entry.name),
  )
  if (renames.size === 0) return { bytes, renames }

  const out: number[] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
  for (const section of sections) {
    if (section.id === SECTION_CUSTOM) {
      const [name] = readName(bytes, section.start)
      if (name === 'name') continue // debug symbols — leak the original names
    }
    if (section.id === SECTION_EXPORT) {
      const payload: number[] = [...writeLeb128(exports.length)]
      for (const entry of exports) {
        const nameBytes = textEncoder.encode(renames.get(entry.name) ?? entry.name)
        payload.push(...writeLeb128(nameBytes.byteLength), ...nameBytes, entry.kind)
        payload.push(...writeLeb128(entry.index))
      }
      out.push(SECTION_EXPORT, ...writeLeb128(payload.length), ...payload)
      continue
    }
    out.push(section.id, ...writeLeb128(section.end - section.start))
    for (let i = section.start; i < section.end; i += 1) out.push(bytes[i] as number)
  }
  return { bytes: new Uint8Array(out), renames }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function referencePatterns(name: string): RegExp[] {
  const escaped = escapeRegExp(name)
  return [
    new RegExp(`\\.${escaped}(?![\\w$])`, 'g'), // .name property access
    new RegExp(`\\["${escaped}"\\]`, 'g'), // ["name"]
    new RegExp(`\\['${escaped}'\\]`, 'g'), // ['name']
  ]
}

/** Count how many DISTINCT `names` a chunk references in glue-access forms. */
export function countGlueReferences(text: string, names: Iterable<string>): number {
  let distinct = 0
  for (const name of names) {
    if (referencePatterns(name).some((pattern) => pattern.test(text))) distinct += 1
  }
  return distinct
}

/**
 * Rewrite every glue reference to the renamed exports in one chunk. Only
 * property-access POSITIONS (`.name`, `["name"]`, `['name']`) are targeted,
 * but the replacement is a plain textual one — a string literal whose
 * CONTENT contains e.g. `"wasm.copylocker_init"` is rewritten too. That is
 * acceptable here (the copylocker-prefixed export names are unlikely to
 * appear in prose) and keeps the rewriter parser-free.
 */
export function rewriteGlueReferences(text: string, renames: Map<string, string>): string {
  let out = text
  for (const [oldName, newName] of renames) {
    const escaped = escapeRegExp(oldName)
    out = out
      .replace(new RegExp(`\\.${escaped}(?![\\w$])`, 'g'), `.${newName}`)
      .replace(new RegExp(`\\["${escaped}"\\]`, 'g'), `["${newName}"]`)
      .replace(new RegExp(`\\['${escaped}'\\]`, 'g'), `['${newName}']`)
  }
  return out
}
