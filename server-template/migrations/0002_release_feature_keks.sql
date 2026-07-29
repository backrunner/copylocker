-- Per-release asset KEKs uploaded by the sealing build step (ADR-0013).
-- Values are encrypted with ASSET_KEK_KEY before they reach D1.
CREATE TABLE release_feature_keks (
  release_id    TEXT NOT NULL REFERENCES releases(id),
  product_id    TEXT NOT NULL REFERENCES products(id),
  feature_id    TEXT NOT NULL,
  key_version   INTEGER NOT NULL DEFAULT 1,
  encrypted_kek BLOB NOT NULL,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  PRIMARY KEY (release_id, feature_id),
  FOREIGN KEY (product_id, feature_id) REFERENCES features(product_id, id)
);

CREATE INDEX idx_release_feature_keks_product
  ON release_feature_keks(product_id, release_id);
