#!/usr/bin/env node
/**
 * Dev-harness projection flush for the console E2E.
 *
 * The web-e2e local backend's machine projection (`LicenseDO outbox → EVENTS
 * queue → consumer → D1 machines/licenses`) does not land under `wrangler dev`:
 * the DO alarm that runs `flush_outbox` does not fire promptly, and queue
 * payloads carrying byte arrays are discarded by the local consumer (both are
 * pre-existing harness gaps — the vitest suite covers the consumer logic via
 * direct dispatch, not the live queue round-trip).
 *
 * This script performs the flush the pipeline would have done: it reads every
 * pending `outbox` payload from the LicenseDO's persisted sqlite state and
 * applies the exact D1 writes of `projection::apply` (machines upsert +
 * license row update, both proj_version-guarded) through `wrangler d1 execute
 * --local`. The writes are idempotent, so a later real flush is a no-op.
 *
 * Usage: node scripts/flush-projection.mjs   (exit 0; prints applied count)
 */

import { readdirSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../../..')
const STATE_DIR = path.join(repoRoot, 'target', 'tmp', 'web-e2e', 'state')
const WRANGLER_CONFIG = path.join(repoRoot, 'target', 'tmp', 'web-e2e', 'work', 'wrangler.jsonc')
const WRANGLER = path.join(
  repoRoot,
  'crates',
  'copylocker-worker',
  'node_modules',
  '.bin',
  'wrangler',
)
const LICENSE_DO_DIR = path.join(STATE_DIR, 'v3', 'do', 'copylocker-LicenseDO')

const quote = (value) => `'${String(value).replaceAll("'", "''")}'`
const hex = (bytes) => `X'${Buffer.from(bytes).toString('hex')}'`
const optText = (value) => (value === null || value === undefined ? 'NULL' : quote(value))
const optInt = (value) => (value === null || value === undefined ? 'NULL' : String(value))

function sqliteJson(db, sql) {
  const result = spawnSync('sqlite3', ['-json', db, sql], { encoding: 'utf8' })
  if (result.status !== 0) return []
  try {
    return JSON.parse(result.stdout || '[]')
  } catch {
    return []
  }
}

/** The exact statements of crates/copylocker-worker/src/projection.rs. */
function projectionStatements(event) {
  const statements = []
  const machine = event.machine
  if (machine) {
    statements.push(
      `INSERT INTO machines(
         id, license_id, fingerprint, status, activation_path, first_seen_at,
         last_seen_at, os, arch, app_version, sdk_version, release_id, variant_id,
         build_fp, geo_country, suspicion, proj_version
       ) VALUES (
         ${hex(machine.machine_id)}, ${hex(event.license_id)}, ${hex(machine.fingerprint)},
         ${quote(machine.status)}, ${quote(machine.activation_path)}, ${machine.first_seen_at},
         ${optInt(machine.last_seen_at)}, ${optText(machine.os)}, ${optText(machine.arch)},
         ${optText(machine.app_version)}, ${optText(machine.sdk_version)},
         ${optText(machine.release_id)}, ${optInt(machine.variant_id)},
         ${optText(machine.build_fp)}, ${optText(machine.geo_country)},
         ${machine.suspicion}, ${event.proj_version}
       )
       ON CONFLICT(id) DO UPDATE SET
         license_id = excluded.license_id, fingerprint = excluded.fingerprint,
         status = excluded.status, activation_path = excluded.activation_path,
         first_seen_at = excluded.first_seen_at, last_seen_at = excluded.last_seen_at,
         os = excluded.os, arch = excluded.arch, app_version = excluded.app_version,
         sdk_version = excluded.sdk_version, release_id = excluded.release_id,
         variant_id = excluded.variant_id, build_fp = excluded.build_fp,
         geo_country = excluded.geo_country, suspicion = excluded.suspicion,
         proj_version = excluded.proj_version
         WHERE machines.proj_version < excluded.proj_version`,
    )
  }
  statements.push(
    `UPDATE licenses SET
       status = ${quote(event.license_status)}, seats_used = ${event.seats_used},
       last_seen_at = ${optInt(event.last_seen_at)}, updated_at = ${event.occurred_at},
       proj_version = ${event.proj_version}
     WHERE id = ${hex(event.license_id)} AND proj_version < ${event.proj_version}`,
  )
  return statements
}

function main() {
  const doFiles = readdirSync(LICENSE_DO_DIR).filter(
    (name) => name.endsWith('.sqlite') && name !== 'metadata.sqlite',
  )
  const events = []
  for (const file of doFiles) {
    const db = path.join(LICENSE_DO_DIR, file)
    for (const row of sqliteJson(db, 'SELECT payload FROM outbox WHERE sent_at IS NULL ORDER BY id')) {
      try {
        events.push(JSON.parse(row.payload))
      } catch {
        /* skip an unreadable payload */
      }
    }
  }
  if (events.length === 0) {
    console.log('[flush-projection] no pending projection events')
    return
  }
  const sql = events.flatMap(projectionStatements).join(';\n')
  const result = spawnSync(
    WRANGLER,
    [
      'd1',
      'execute',
      'copylocker',
      '--local',
      '--config',
      WRANGLER_CONFIG,
      '--persist-to',
      STATE_DIR,
      '--yes',
      '--command',
      sql,
    ],
    { encoding: 'utf8', env: { ...process.env, CI: '1', NO_UPDATE_NOTIFIER: '1' } },
  )
  if (result.status !== 0) {
    console.error(result.stdout)
    console.error(result.stderr)
    throw new Error('wrangler d1 execute failed')
  }
  console.log(`[flush-projection] applied ${events.length} projection event(s)`)
}

main()
