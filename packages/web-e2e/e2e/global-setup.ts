/**
 * Playwright global setup: wipe the per-browser R-consistency artifacts so a
 * run never compares against stale values from a previous build.
 */
import { rmSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../../..')

export const rConsistencyArtifactDir = path.join(repoRoot, 'output', 'playwright', 'r-consistency')

export default function globalSetup(): void {
  rmSync(rConsistencyArtifactDir, { recursive: true, force: true })
}
