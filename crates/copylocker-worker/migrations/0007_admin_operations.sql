PRAGMA foreign_keys = ON;

-- Every non-revocation Admin mutation first commits its business writes and an
-- immutable recovery record in the same D1 batch. The remaining checkpoints
-- are advanced only after AdminAuditDO and Queue have accepted the event.
CREATE TABLE admin_operations (
  operation_id   TEXT PRIMARY KEY,
  vendor_id      TEXT NOT NULL,
  request_id     TEXT NOT NULL,
  actor          TEXT NOT NULL,
  required_scope TEXT NOT NULL,
  action         TEXT NOT NULL,
  target         TEXT NOT NULL,
  source_kind    TEXT NOT NULL,
  source_id      TEXT NOT NULL,
  request_hash   BLOB NOT NULL,
  before_json    TEXT NOT NULL,
  after_json     TEXT NOT NULL,
  result_json    TEXT NOT NULL,
  response_status INTEGER NOT NULL CHECK (response_status BETWEEN 200 AND 299),
  side_effect_json TEXT,
  created_at     INTEGER NOT NULL,
  applied_at     INTEGER NOT NULL,
  side_effect_at INTEGER,
  audit_seq      INTEGER,
  enqueued_at    INTEGER,
  completed_at   INTEGER,
  UNIQUE (vendor_id, request_id)
);
CREATE INDEX idx_admin_operations_pending
ON admin_operations(created_at, operation_id) WHERE completed_at IS NULL;
CREATE INDEX idx_admin_operations_source
ON admin_operations(source_kind, source_id);

-- This append-only history is an optimistic lock for mutable entities whose
-- primary table does not already expose an immutable version sequence.
CREATE TABLE admin_entity_versions (
  entity_kind TEXT NOT NULL,
  entity_id   TEXT NOT NULL,
  version     INTEGER NOT NULL CHECK (version > 0),
  operation_id TEXT NOT NULL REFERENCES admin_operations(operation_id),
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (entity_kind, entity_id, version),
  UNIQUE (operation_id)
);

CREATE TRIGGER admin_operations_immutable_fields
BEFORE UPDATE OF
  operation_id, vendor_id, request_id, actor, required_scope, action, target,
  source_kind, source_id, request_hash, before_json, after_json, result_json,
  response_status, side_effect_json, created_at, applied_at
ON admin_operations
BEGIN
  SELECT RAISE(ABORT, 'admin operation payload is immutable');
END;

CREATE TRIGGER admin_operations_no_delete
BEFORE DELETE ON admin_operations
BEGIN
  SELECT RAISE(ABORT, 'admin operations are immutable');
END;

CREATE TRIGGER admin_entity_versions_no_update
BEFORE UPDATE ON admin_entity_versions
BEGIN
  SELECT RAISE(ABORT, 'admin entity versions are immutable');
END;

CREATE TRIGGER admin_entity_versions_no_delete
BEFORE DELETE ON admin_entity_versions
BEGIN
  SELECT RAISE(ABORT, 'admin entity versions are immutable');
END;
