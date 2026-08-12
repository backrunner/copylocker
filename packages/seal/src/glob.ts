/**
 * Minimal dependency-free glob for build-time asset selection.
 *
 * Supported syntax (deliberately small — this is not fast-glob):
 * - literal path segments
 * - `*`  — any run of characters within one path segment
 * - `**` — any number of path segments (including zero)
 *
 * Paths are matched as POSIX-style relative paths from `cwd`.
 * `node_modules` and `.git` directories are never descended into, and neither
 * is `.copylocker` — the package's own key-material directory must never end
 * up inside a shippable sealed artifact.
 */

import { readdir, stat } from 'node:fs/promises'
import { isAbsolute, join, relative, resolve } from 'node:path'
import { configError } from './errors.js'
import { DEFAULT_REGISTRY_DIR } from './keystore.js'

const SKIP_DIRS = new Set(['node_modules', '.git', DEFAULT_REGISTRY_DIR])

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** Compile a glob pattern to an anchored RegExp over POSIX relative paths. */
export function globToRegExp(pattern: string): RegExp {
  const segments = pattern.split('/')
  let source = '^'
  let needSeparator = false
  segments.forEach((segment, i) => {
    const last = i === segments.length - 1
    if (segment === '**') {
      // `**/` matches zero or more leading segments (separator included);
      // a trailing `**` matches everything below, including nothing.
      if (last) {
        source += needSeparator ? '(?:/.*)?' : '.*'
      } else {
        // A non-trailing `**` still needs the separator from the preceding segment:
        // `static/**/*.js` must compile to `^static/(?:[^/]+/)*[^/]*\.js$`.
        if (needSeparator) source += '/'
        source += '(?:[^/]+/)*'
      }
      needSeparator = false
      return
    }
    if (needSeparator) source += '/'
    source += segment.split('*').map(escapeRegExp).join('[^/]*')
    needSeparator = true
  })
  source += '$'
  return new RegExp(source)
}

/** True when the pattern contains glob magic. */
export function isGlob(pattern: string): boolean {
  return pattern.includes('*')
}

async function walk(dir: string, prefix: string, out: string[]): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true })
  for (const entry of entries) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) await walk(join(dir, entry.name), rel, out)
    } else if (entry.isFile()) {
      out.push(rel)
    }
  }
}

/**
 * Expand patterns against the filesystem under `cwd`. Returns a sorted,
 * de-duplicated list of POSIX relative file paths. Literal patterns (no
 * magic) name a file when it exists and are skipped when it does not; glob
 * patterns may match zero files. Literals that resolve outside `cwd` (`..`
 * traversal) are rejected — sealing must never read outside the project.
 */
export async function expandGlobs(cwd: string, patterns: string[]): Promise<string[]> {
  const matched = new Set<string>()
  const globbed: { pattern: string; regex: RegExp }[] = []
  const root = resolve(cwd)
  for (const pattern of patterns) {
    const normalized = pattern.replace(/\\/g, '/').replace(/^\.\//, '')
    if (isGlob(normalized)) {
      globbed.push({ pattern: normalized, regex: globToRegExp(normalized) })
    } else {
      const rel = relative(root, resolve(root, normalized))
      if (rel.startsWith('..') || isAbsolute(rel)) {
        throw configError(`CopyLocker seal: pattern escapes the working directory: '${pattern}'`)
      }
      const info = await stat(join(cwd, normalized)).catch(() => undefined)
      if (info?.isFile()) matched.add(normalized)
    }
  }
  if (globbed.length > 0) {
    const files: string[] = []
    await walk(cwd, '', files)
    for (const file of files) {
      if (globbed.some(({ regex }) => regex.test(file))) matched.add(file)
    }
  }
  return [...matched].sort()
}
