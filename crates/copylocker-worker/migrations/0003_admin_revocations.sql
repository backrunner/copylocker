PRAGMA foreign_keys = ON;

-- Bearer tokens are shown once; only their keyed digest is retained.
CREATE TABLE admin_tokens (
  id          TEXT PRIMARY KEY,
  vendor_id   TEXT NOT NULL REFERENCES vendors(id),
  token_hmac  BLOB NOT NULL UNIQUE,
  actor       TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  not_before  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  revoked_at  INTEGER,
  created_at  INTEGER NOT NULL
);
CREATE INDEX idx_admin_tokens_vendor ON admin_tokens(vendor_id);
CREATE INDEX idx_admin_tokens_expiry ON admin_tokens(expires_at);

-- Cross-service revocations are resumable. `applied_at` means LicenseDO accepted
-- the epoch; `published_at` means the signed batch and epoch pointer reached KV.
ALTER TABLE revocations ADD COLUMN request_id TEXT;
ALTER TABLE revocations ADD COLUMN applied_at INTEGER;
ALTER TABLE revocations ADD COLUMN published_at INTEGER;

-- Rows created before this migration predate resumable Admin operations.
UPDATE revocations
SET applied_at = created_at, published_at = created_at
WHERE request_id IS NULL;

CREATE UNIQUE INDEX idx_revocations_request_id
ON revocations(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX idx_revocations_pending
ON revocations(seq) WHERE published_at IS NULL;
