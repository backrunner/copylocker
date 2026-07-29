PRAGMA foreign_keys = ON;

-- The v1 table coupled the Admin chain sequence to revocations.seq. Preserve
-- every archived event while allowing AdminAuditDO to allocate one sequence
-- space for all mutation kinds.
CREATE TABLE admin_audit_events_v2 (
  seq           INTEGER PRIMARY KEY CHECK (seq > 0),
  operation_id  TEXT NOT NULL UNIQUE,
  source_kind   TEXT NOT NULL,
  source_id     TEXT NOT NULL,
  event_json    TEXT NOT NULL,
  prev_hash     BLOB NOT NULL,
  hash          BLOB NOT NULL,
  r2_key        TEXT NOT NULL UNIQUE,
  enqueued_at   INTEGER,
  archived_at   INTEGER,
  created_at    INTEGER NOT NULL
);

INSERT INTO admin_audit_events_v2(
  seq, operation_id, source_kind, source_id, event_json, prev_hash, hash,
  r2_key, enqueued_at, archived_at, created_at
)
SELECT
  audit.seq,
  json_extract(audit.event_json, '$.vendor_id') || '/' || revocation.request_id,
  'revocation',
  CAST(revocation.seq AS TEXT),
  audit.event_json,
  audit.prev_hash,
  audit.hash,
  audit.r2_key,
  audit.enqueued_at,
  audit.archived_at,
  audit.created_at
FROM admin_audit_events AS audit
JOIN revocations AS revocation ON revocation.seq = audit.seq;

DROP TABLE admin_audit_events;
ALTER TABLE admin_audit_events_v2 RENAME TO admin_audit_events;

CREATE INDEX idx_admin_audit_enqueue
ON admin_audit_events(seq) WHERE enqueued_at IS NULL;
CREATE INDEX idx_admin_audit_archive
ON admin_audit_events(seq) WHERE archived_at IS NULL;
CREATE INDEX idx_admin_audit_source
ON admin_audit_events(source_kind, source_id);
