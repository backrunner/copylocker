-- Build-manifest signing keys registered per product (M4-B remote signer).
-- Only Ed25519 public keys live in D1; the signing seed stays in the
-- BUILD_SIGNING_KEY secret binding and never reaches the database.
CREATE TABLE integrity_signer_keys (
  product_id  TEXT NOT NULL REFERENCES products(id),
  vendor_id   TEXT NOT NULL REFERENCES vendors(id),
  fingerprint TEXT NOT NULL,
  public_key  BLOB NOT NULL,
  status      TEXT NOT NULL DEFAULT 'active',
  created_by  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  revoked_at  INTEGER,
  PRIMARY KEY (product_id, fingerprint)
);

CREATE INDEX idx_integrity_signer_keys_vendor
  ON integrity_signer_keys(vendor_id, product_id);
