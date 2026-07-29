PRAGMA foreign_keys = ON;

-- Catalog and configuration.
CREATE TABLE vendors (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  fpr_salt_ref  TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);

CREATE TABLE products (
  id              TEXT PRIMARY KEY,
  vendor_id       TEXT NOT NULL REFERENCES vendors(id),
  name            TEXT NOT NULL,
  min_suite_id    BLOB NOT NULL,
  min_proto_ver   INTEGER NOT NULL DEFAULT 1,
  min_sdk_version TEXT NOT NULL DEFAULT '0.0.0',
  created_at      INTEGER NOT NULL,
  archived_at     INTEGER
);
CREATE INDEX idx_products_vendor ON products(vendor_id);

-- Entitlement catalog. Published feature IDs are immutable.
CREATE TABLE features (
  product_id    TEXT NOT NULL REFERENCES products(id),
  id            TEXT NOT NULL,
  label         TEXT NOT NULL,
  description   TEXT,
  deprecated_at INTEGER,
  created_at    INTEGER NOT NULL,
  PRIMARY KEY (product_id, id)
);

CREATE TABLE feature_groups (
  product_id   TEXT NOT NULL,
  id           TEXT NOT NULL,
  label        TEXT NOT NULL,
  members_json TEXT NOT NULL,
  updated_at   INTEGER NOT NULL,
  PRIMARY KEY (product_id, id)
);

CREATE TABLE tiers (
  product_id    TEXT NOT NULL,
  id            TEXT NOT NULL,
  label         TEXT NOT NULL,
  rank          INTEGER NOT NULL,
  groups_json   TEXT NOT NULL,
  features_json TEXT,
  limits_json   TEXT NOT NULL,
  archived_at   INTEGER,
  PRIMARY KEY (product_id, id)
);

CREATE TABLE catalog_versions (
  product_id TEXT NOT NULL,
  version    INTEGER NOT NULL,
  snapshot   BLOB NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (product_id, version)
);

-- Five-axis policies.
CREATE TABLE policies (
  id                     TEXT PRIMARY KEY,
  product_id             TEXT NOT NULL REFERENCES products(id),
  name                   TEXT NOT NULL,
  preset                 TEXT,
  entitlement_json       TEXT NOT NULL,
  validity_json          TEXT NOT NULL,
  version_scope_json     TEXT NOT NULL,
  seats                  INTEGER NOT NULL,
  max_transfers          INTEGER,
  transfer_window_s      INTEGER,
  heartbeat_sec          INTEGER,
  mode                   INTEGER NOT NULL,
  refresh_after_sec      INTEGER NOT NULL,
  grace_seconds          INTEGER NOT NULL,
  fpr_tolerance          INTEGER NOT NULL DEFAULT 70,
  allow_vm               INTEGER NOT NULL DEFAULT 1,
  allow_olk              INTEGER NOT NULL DEFAULT 0,
  allow_unbound_olk      INTEGER NOT NULL DEFAULT 0,
  vt_signature           TEXT NOT NULL DEFAULT 'fast',
  offline_upgrade_policy TEXT NOT NULL DEFAULT 'require_online',
  preload_variants_n     INTEGER NOT NULL DEFAULT 3,
  report_attrs           INTEGER NOT NULL DEFAULT 0,
  telemetry_tier         TEXT NOT NULL DEFAULT 'T0',
  created_at             INTEGER NOT NULL,
  updated_at             INTEGER NOT NULL
);
CREATE INDEX idx_policies_product ON policies(product_id);

-- License and device rows are asynchronous projections of LicenseDO state.
CREATE TABLE licenses (
  id                           BLOB PRIMARY KEY,
  product_id                   TEXT NOT NULL REFERENCES products(id),
  policy_id                    TEXT NOT NULL REFERENCES policies(id),
  key_hmac                     BLOB NOT NULL UNIQUE,
  account_id                   TEXT,
  status                       TEXT NOT NULL,
  seats_override               INTEGER,
  entitlement_override_json    TEXT,
  version_scope_override_json  TEXT,
  expires_at                   INTEGER,
  catalog_version              INTEGER NOT NULL,
  metadata_json                TEXT,
  created_at                   INTEGER NOT NULL,
  updated_at                   INTEGER NOT NULL,
  seats_used                   INTEGER NOT NULL DEFAULT 0,
  last_seen_at                 INTEGER,
  proj_version                 INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_licenses_product_status ON licenses(product_id, status);
CREATE INDEX idx_licenses_account ON licenses(account_id);
CREATE INDEX idx_licenses_expires ON licenses(expires_at);

CREATE TABLE machines (
  id              BLOB PRIMARY KEY,
  license_id      BLOB NOT NULL,
  fingerprint     BLOB NOT NULL,
  status          TEXT NOT NULL,
  activation_path TEXT NOT NULL,
  first_seen_at   INTEGER NOT NULL,
  last_seen_at    INTEGER,
  os              TEXT,
  arch            TEXT,
  app_version     TEXT,
  sdk_version     TEXT,
  release_id      TEXT,
  variant_id      INTEGER,
  build_fp        TEXT,
  geo_country     TEXT,
  suspicion       INTEGER NOT NULL DEFAULT 0,
  proj_version    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_machines_license ON machines(license_id);
CREATE INDEX idx_machines_fpr ON machines(fingerprint);
CREATE INDEX idx_machines_lastseen ON machines(last_seen_at);
CREATE INDEX idx_machines_release ON machines(release_id);

CREATE TABLE accounts (
  id            TEXT PRIMARY KEY,
  product_id    TEXT NOT NULL,
  email         TEXT NOT NULL,
  pwd_hash      TEXT,
  oauth_subject TEXT,
  status        TEXT NOT NULL,
  max_devices   INTEGER,
  created_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_accounts_product_email ON accounts(product_id, email);

-- Subscriptions, scheduled changes, and billing webhook idempotency.
CREATE TABLE subscriptions (
  license_id             BLOB PRIMARY KEY,
  provider               TEXT NOT NULL,
  external_id            TEXT NOT NULL,
  state                  TEXT NOT NULL,
  billing_period         TEXT NOT NULL,
  current_period_start   INTEGER NOT NULL,
  current_period_end     INTEGER NOT NULL,
  dunning_until          INTEGER,
  continuous_paid_months INTEGER NOT NULL DEFAULT 0,
  fallback_earned_at     INTEGER,
  canceled_at            INTEGER,
  updated_at             INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_subs_external ON subscriptions(provider, external_id);
CREATE INDEX idx_subs_state_period ON subscriptions(state, current_period_end);

CREATE TABLE scheduled_changes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id   BLOB NOT NULL,
  effective_at INTEGER NOT NULL,
  change_json  TEXT NOT NULL,
  status       TEXT NOT NULL,
  created_by   TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);
CREATE INDEX idx_sched_pending ON scheduled_changes(effective_at) WHERE status = 'pending';

CREATE TABLE billing_events (
  provider     TEXT NOT NULL,
  event_id     TEXT NOT NULL,
  event_ts     INTEGER NOT NULL,
  processed_at INTEGER NOT NULL,
  PRIMARY KEY (provider, event_id)
);

-- Releases, variants, and the global security floor.
CREATE TABLE releases (
  id                 TEXT PRIMARY KEY,
  product_id         TEXT NOT NULL REFERENCES products(id),
  app_version        TEXT NOT NULL,
  variant_id         INTEGER NOT NULL,
  variant_params     BLOB NOT NULL,
  build_fingerprint  TEXT NOT NULL UNIQUE,
  manifest_root      BLOB,
  channel            TEXT NOT NULL,
  status             TEXT NOT NULL,
  compromised_action TEXT,
  min_sdk_version    TEXT NOT NULL,
  proto_ver          INTEGER NOT NULL,
  suite_id           BLOB NOT NULL,
  published_at       INTEGER NOT NULL,
  deprecated_at      INTEGER,
  created_at         INTEGER NOT NULL
);
CREATE INDEX idx_releases_product_status ON releases(product_id, status);
CREATE INDEX idx_releases_published ON releases(product_id, published_at);
CREATE UNIQUE INDEX idx_releases_variant ON releases(product_id, variant_id);

CREATE TABLE security_floor_log (
  floor      INTEGER PRIMARY KEY,
  reason     TEXT NOT NULL,
  release_id TEXT,
  actor      TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Epochs, revocations, audit index, and request idempotency.
CREATE TABLE epochs (
  id            BLOB PRIMARY KEY,
  product_scope TEXT,
  suite_id      BLOB NOT NULL,
  vk_pq         BLOB NOT NULL,
  vk_trad       BLOB NOT NULL,
  vk_fast       BLOB NOT NULL,
  cert          BLOB NOT NULL,
  not_before    INTEGER NOT NULL,
  not_after     INTEGER NOT NULL,
  revoked_at    INTEGER,
  created_at    INTEGER NOT NULL
);

CREATE TABLE revocations (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT NOT NULL,
  target     BLOB NOT NULL,
  reason     INTEGER NOT NULL,
  actor      TEXT NOT NULL,
  undo_until INTEGER,
  undone_at  INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_revocations_target ON revocations(kind, target);

CREATE TABLE audit_index (
  seq       INTEGER PRIMARY KEY,
  ts        INTEGER NOT NULL,
  actor     TEXT NOT NULL,
  action    TEXT NOT NULL,
  target    TEXT,
  prev_hash BLOB NOT NULL,
  hash      BLOB NOT NULL,
  r2_key    TEXT NOT NULL
);
CREATE INDEX idx_audit_ts ON audit_index(ts);
CREATE INDEX idx_audit_target ON audit_index(target);

CREATE TABLE idempotency (
  key           TEXT PRIMARY KEY,
  endpoint      TEXT NOT NULL,
  response_hash BLOB NOT NULL,
  r2_key        TEXT,
  created_at    INTEGER NOT NULL
);

-- Daily analytics and telemetry aggregates. Raw events stay in R2.
CREATE TABLE analytics_rollup (
  product_id TEXT NOT NULL,
  date       TEXT NOT NULL,
  metric_id  TEXT NOT NULL,
  dims_json  TEXT NOT NULL,
  value      INTEGER NOT NULL,
  PRIMARY KEY (product_id, date, metric_id, dims_json)
);
CREATE INDEX idx_rollup_metric ON analytics_rollup(product_id, metric_id, date);

CREATE TABLE analytics_hll (
  product_id TEXT NOT NULL,
  date       TEXT NOT NULL,
  cube_key   TEXT NOT NULL,
  sketch     BLOB NOT NULL,
  PRIMARY KEY (product_id, date, cube_key)
);
CREATE INDEX idx_hll_cube ON analytics_hll(product_id, cube_key, date);

CREATE TABLE telemetry_rollup (
  product_id TEXT NOT NULL,
  date       TEXT NOT NULL,
  metric_id  TEXT NOT NULL,
  dims_json  TEXT NOT NULL,
  value      INTEGER NOT NULL,
  sample_n   INTEGER NOT NULL,
  PRIMARY KEY (product_id, date, metric_id, dims_json)
);
