PRAGMA foreign_keys = ON;

-- Admin mutations use the revocation epoch as their chain sequence. The exact
-- event is persisted before any Durable Object mutation so recovery cannot
-- reconstruct a different before snapshot.
CREATE TABLE admin_audit_events (
  seq          INTEGER PRIMARY KEY REFERENCES revocations(seq) ON DELETE CASCADE,
  event_json   TEXT NOT NULL,
  prev_hash    BLOB NOT NULL,
  hash         BLOB NOT NULL,
  r2_key       TEXT NOT NULL UNIQUE,
  enqueued_at  INTEGER,
  archived_at  INTEGER,
  created_at   INTEGER NOT NULL
);
CREATE INDEX idx_admin_audit_enqueue
ON admin_audit_events(seq) WHERE enqueued_at IS NULL;
CREATE INDEX idx_admin_audit_archive
ON admin_audit_events(seq) WHERE archived_at IS NULL;
