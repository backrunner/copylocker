PRAGMA foreign_keys = ON;

-- Epoch revocation is a two-person operation. The first approval is durable and
-- audited; a distinct actor must complete it before the short approval window
-- expires. The final revocation sequence is recorded for deterministic replay.
CREATE TABLE epoch_revocation_approvals (
  epoch_id            BLOB PRIMARY KEY REFERENCES epochs(id),
  vendor_id           TEXT NOT NULL REFERENCES vendors(id),
  first_actor         TEXT NOT NULL,
  first_request_id    TEXT NOT NULL,
  first_approved_at   INTEGER NOT NULL,
  expires_at          INTEGER NOT NULL,
  second_actor        TEXT,
  second_request_id   TEXT,
  second_approved_at  INTEGER,
  revocation_seq      INTEGER,
  CHECK (expires_at > first_approved_at),
  CHECK (
    (second_actor IS NULL AND second_request_id IS NULL AND
     second_approved_at IS NULL AND revocation_seq IS NULL) OR
    (second_actor IS NOT NULL AND second_request_id IS NOT NULL AND
     second_approved_at IS NOT NULL AND revocation_seq IS NOT NULL)
  )
);
CREATE UNIQUE INDEX idx_epoch_approval_first_request
ON epoch_revocation_approvals(vendor_id, first_request_id);
CREATE UNIQUE INDEX idx_epoch_approval_second_request
ON epoch_revocation_approvals(vendor_id, second_request_id)
WHERE second_request_id IS NOT NULL;
CREATE INDEX idx_epoch_approval_expiry
ON epoch_revocation_approvals(expires_at)
WHERE second_actor IS NULL;
