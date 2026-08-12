PRAGMA foreign_keys = ON;

-- Release registration and version-level revocation (M5-A).
--
-- `variant_stable` products deliberately register several releases on one
-- variant, so (product_id, variant_id) is no longer unique. The index is kept
-- as a plain lookup index; variant allocation is guarded by the register
-- transaction instead.
DROP INDEX idx_releases_variant;
CREATE INDEX idx_releases_variant ON releases(product_id, variant_id);

-- Vendor-configured anomaly alerting. A NULL URL means "record only": the
-- worker logs a crossed suspicion threshold without delivering a webhook.
ALTER TABLE products ADD COLUMN alert_webhook_url TEXT;
ALTER TABLE products ADD COLUMN alert_suspicion_threshold INTEGER;
