# 数据模型

> **本文是全项目所有 schema 的唯一事实源（single source of truth）。**
> 其他文档只描述语义，不重复 DDL。改 schema 只改这里，并同步 `migrations/`。

存储拓扑决策见 [ADR-0003](../00-overview/decisions/ADR-0003-cloudflare-storage-topology.md)。

## 1. 责任划分速查

| 数据 | 权威存储 | 投影/缓存 |
|---|---|---|
| 席位占用、Activation 状态 | `LicenseDO` | D1（异步投影，供报表） |
| nonce 防重放 | `LicenseDO` | — |
| 权益目录、Policy、Release、订阅 | D1 | KV（快照，供边缘快读） |
| License 元数据 | D1 | KV（policy 快照） |
| 账号与会话 | `AccountDO` | D1（账号档案） |
| Epoch 公钥集、revocation_epoch、security_floor | D1 | KV + Cache API |
| 签发序号与审计链 | `IssuerDO` | R2（归档） |
| Admin mutation 恢复 journal / entity version | D1 | `AdminAuditDO` + Queue |
| Epoch 吊销双人批准 | D1 | — |
| 审计事件 | Queue → R2 | D1（索引） |
| 分析明细 | R2 (raw) | — |
| 分析聚合 | D1（rollup + HLL 草图） | Analytics Engine（近实时） |

## 2. D1：目录与配置

```sql
CREATE TABLE vendors (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  fpr_salt_ref  TEXT NOT NULL,          -- 指向 Secrets Store 的键名，不存明文
  created_at    INTEGER NOT NULL
);

CREATE TABLE products (
  id            TEXT PRIMARY KEY,       -- 人类可读 slug
  vendor_id     TEXT NOT NULL REFERENCES vendors(id),
  name          TEXT NOT NULL,
  min_suite_id  BLOB NOT NULL,
  min_proto_ver INTEGER NOT NULL DEFAULT 1,
  min_sdk_version TEXT NOT NULL DEFAULT '0.0.0',
  created_at    INTEGER NOT NULL,
  archived_at   INTEGER
);
CREATE INDEX idx_products_vendor ON products(vendor_id);
```

## 3. D1：权益目录（ADR-0009）

```sql
-- feature_id 一旦发布即不可变、不可复用（FeatureKey 派生依赖它）
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
  members_json TEXT NOT NULL,      -- { includes: [groupId], features: [featureId|glob] }
  updated_at   INTEGER NOT NULL,
  PRIMARY KEY (product_id, id)
);

CREATE TABLE tiers (
  product_id    TEXT NOT NULL,
  id            TEXT NOT NULL,
  label         TEXT NOT NULL,
  rank          INTEGER NOT NULL,  -- 用于比较升降级方向
  groups_json   TEXT NOT NULL,
  features_json TEXT,              -- tier 直接包含的 feature（不经 group）
  limits_json   TEXT NOT NULL,     -- { key: value }，-1 = 无限制
  archived_at   INTEGER,
  PRIMARY KEY (product_id, id)
);

-- 目录的不可变快照；用于复现"当时为什么解析成这样"
CREATE TABLE catalog_versions (
  product_id TEXT NOT NULL,
  version    INTEGER NOT NULL,
  snapshot   BLOB NOT NULL,        -- 整个目录的 canonical CBOR
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (product_id, version)
);
```

## 4. D1：Policy（五个正交轴）

```sql
CREATE TABLE policies (
  id                    TEXT PRIMARY KEY,
  product_id            TEXT NOT NULL REFERENCES products(id),
  name                  TEXT NOT NULL,
  preset                TEXT,                -- 由哪个预设生成（UI 显示用）

  -- 轴一：Entitlement
  entitlement_json      TEXT NOT NULL,       -- { tier, extra_groups, grants, excluded_features, limit_overrides }
  -- 轴二：Validity
  validity_json         TEXT NOT NULL,       -- Perpetual | FixedTerm | Subscription | Trial
  -- 轴三：VersionScope
  version_scope_json    TEXT NOT NULL,       -- Unlimited | SemverRange | ReleasedBefore | Pinned
  -- 轴四：Seats
  seats                 INTEGER NOT NULL,
  max_transfers         INTEGER,
  transfer_window_s     INTEGER,
  heartbeat_sec         INTEGER,             -- NULL = 不启用僵尸回收
  -- 轴五：Mode
  mode                  INTEGER NOT NULL,    -- 0=offline_hybrid 1=enforced_online

  -- 运行时参数
  refresh_after_sec     INTEGER NOT NULL,
  grace_seconds         INTEGER NOT NULL,
  fpr_tolerance         INTEGER NOT NULL DEFAULT 70,
  allow_vm              INTEGER NOT NULL DEFAULT 1,
  allow_olk             INTEGER NOT NULL DEFAULT 0,
  allow_unbound_olk     INTEGER NOT NULL DEFAULT 0,
  vt_signature          TEXT NOT NULL DEFAULT 'fast',   -- 'fast' | 'pq'
  offline_upgrade_policy TEXT NOT NULL DEFAULT 'require_online',
                                             -- require_online | preload_n | variant_stable
  preload_variants_n    INTEGER NOT NULL DEFAULT 3,
  report_attrs          INTEGER NOT NULL DEFAULT 0,     -- 是否允许上报原始属性
  telemetry_tier        TEXT NOT NULL DEFAULT 'T0',     -- T0 | T1 | Off

  created_at            INTEGER NOT NULL,
  updated_at            INTEGER NOT NULL
);
CREATE INDEX idx_policies_product ON policies(product_id);
```

## 5. D1：授权与设备

```sql
-- 席位的权威状态在 LicenseDO；此表为索引 + 投影
CREATE TABLE licenses (
  id             BLOB PRIMARY KEY,          -- 16 bytes
  product_id     TEXT NOT NULL REFERENCES products(id),
  policy_id      TEXT NOT NULL REFERENCES policies(id),
  key_hmac       BLOB NOT NULL UNIQUE,      -- HMAC(server_pepper, lk_bytes)，不存明文
  account_id     TEXT,                      -- Mode E
  status         TEXT NOT NULL,             -- active|suspended|expired|revoked
  seats_override INTEGER,
  entitlement_override_json TEXT,           -- 单个 License 的权益覆盖（企业定制）
  version_scope_override_json TEXT,
  expires_at     INTEGER,                   -- NULL = 永久
  catalog_version INTEGER NOT NULL,         -- 签发时的目录版本
  metadata_json  TEXT,                      -- 订单号、邮箱、渠道
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  -- 投影字段（DO outbox 异步同步）
  seats_used     INTEGER NOT NULL DEFAULT 0,
  last_seen_at   INTEGER,
  proj_version   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_licenses_product_status ON licenses(product_id, status);
CREATE INDEX idx_licenses_account ON licenses(account_id);
CREATE INDEX idx_licenses_expires ON licenses(expires_at);

CREATE TABLE machines (
  id             BLOB PRIMARY KEY,          -- 16 bytes
  license_id     BLOB NOT NULL,
  fingerprint    BLOB NOT NULL,
  status         TEXT NOT NULL,             -- active|released|revoked
  activation_path TEXT NOT NULL,            -- online|offline_ar|olk|account
  first_seen_at  INTEGER NOT NULL,
  last_seen_at   INTEGER,
  os TEXT, arch TEXT,
  app_version TEXT, sdk_version TEXT,
  release_id     TEXT,
  variant_id     INTEGER,
  build_fp       TEXT,
  geo_country    TEXT,                      -- 国家级；不存 IP
  suspicion      INTEGER NOT NULL DEFAULT 0,
  proj_version   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_machines_license ON machines(license_id);
CREATE INDEX idx_machines_fpr ON machines(fingerprint);
CREATE INDEX idx_machines_lastseen ON machines(last_seen_at);
CREATE INDEX idx_machines_release ON machines(release_id);

CREATE TABLE accounts (
  id            TEXT PRIMARY KEY,
  product_id    TEXT NOT NULL,
  email         TEXT NOT NULL,
  pwd_hash      TEXT,                       -- Argon2id；NULL = 仅 OAuth/passkey
  oauth_subject TEXT,
  status        TEXT NOT NULL,
  max_devices   INTEGER,
  created_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_accounts_product_email ON accounts(product_id, email);
```

## 6. D1：订阅与计划变更（ADR-0009 §5）

```sql
CREATE TABLE subscriptions (
  license_id             BLOB PRIMARY KEY,
  provider               TEXT NOT NULL,     -- stripe|paddle|lemonsqueezy|manual
  external_id            TEXT NOT NULL,
  state                  TEXT NOT NULL,     -- active|past_due|canceling|suspended|ended
  billing_period         TEXT NOT NULL,     -- monthly|annual|custom:<days>
  current_period_start   INTEGER NOT NULL,
  current_period_end     INTEGER NOT NULL,
  dunning_until          INTEGER,
  continuous_paid_months INTEGER NOT NULL DEFAULT 0,
  fallback_earned_at     INTEGER,           -- 一旦写入不再更新（幂等）
  canceled_at            INTEGER,
  refund_observe_until   INTEGER,           -- 退款观察期截止；期间 suspended，届满走标准吊销链
  updated_at             INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_subs_external ON subscriptions(provider, external_id);
CREATE INDEX idx_subs_state_period ON subscriptions(state, current_period_end);
CREATE INDEX idx_subscriptions_refund_review ON subscriptions(refund_observe_until)
  WHERE refund_observe_until IS NOT NULL;

CREATE TABLE scheduled_changes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id   BLOB NOT NULL,
  effective_at INTEGER NOT NULL,
  change_json  TEXT NOT NULL,               -- { tier, seats, version_scope, ... }
  status       TEXT NOT NULL,               -- pending|applied|canceled
  created_by   TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);
CREATE INDEX idx_sched_pending ON scheduled_changes(effective_at) WHERE status = 'pending';

-- 支付 webhook 幂等
CREATE TABLE billing_events (
  provider   TEXT NOT NULL,
  event_id   TEXT NOT NULL,
  event_ts   INTEGER NOT NULL,
  processed_at INTEGER NOT NULL,
  PRIMARY KEY (provider, event_id)
);
```

## 7. D1：发布与变体（ADR-0008）

```sql
CREATE TABLE releases (
  id                 TEXT PRIMARY KEY,      -- rel_xxx (ULID)
  product_id         TEXT NOT NULL REFERENCES products(id),
  app_version        TEXT NOT NULL,         -- semver
  variant_id         INTEGER NOT NULL,
  variant_params     BLOB NOT NULL,         -- VARIANT_PARAMS_KEY AEAD 密文（ADR-0013）
  build_fingerprint  TEXT NOT NULL UNIQUE,
  manifest_root      BLOB,                  -- Web 端 IntegrityManifest 根
  channel            TEXT NOT NULL,         -- stable|beta|canary
  status             TEXT NOT NULL,         -- active|deprecated|compromised
  compromised_action TEXT,                  -- warn|force_upgrade|revoke
  min_sdk_version    TEXT NOT NULL,
  proto_ver          INTEGER NOT NULL,
  suite_id           BLOB NOT NULL,
  published_at       INTEGER NOT NULL,      -- ★ VersionScope::ReleasedBefore 的判定依据
  deprecated_at      INTEGER,
  created_at         INTEGER NOT NULL
);
CREATE INDEX idx_releases_product_status ON releases(product_id, status);
CREATE INDEX idx_releases_published ON releases(product_id, published_at);
CREATE UNIQUE INDEX idx_releases_variant ON releases(product_id, variant_id);

-- 构建上传的 32B 资产 KEK；只为实际有 sealed asset 的 feature 建行。
-- encrypted_kek = nonce || ciphertext || tag，由 ASSET_KEK_KEY 加密（ADR-0013）。
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
CREATE INDEX idx_release_feature_keks_product ON release_feature_keks(product_id, release_id);

-- 全局单调递增的安全基线；客户端拒绝低于已见最大值的凭证
CREATE TABLE security_floor_log (
  floor      INTEGER PRIMARY KEY,
  reason     TEXT NOT NULL,
  release_id TEXT,
  actor      TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
```

## 8. D1：密钥、吊销、审计

```sql
CREATE TABLE epochs (
  id            BLOB PRIMARY KEY,           -- 8 bytes
  product_scope TEXT,                       -- NULL = 全局
  suite_id      BLOB NOT NULL,
  vk_pq         BLOB NOT NULL,
  vk_trad       BLOB NOT NULL,
  vk_fast       BLOB NOT NULL,              -- 每请求快签的 Ed25519 公钥
  cert          BLOB NOT NULL,              -- envelope(EpochCert)，Root 签发
  not_before    INTEGER NOT NULL,
  not_after     INTEGER NOT NULL,
  revoked_at    INTEGER,
  created_at    INTEGER NOT NULL
);

CREATE TABLE revocations (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT, -- 即 revocation_epoch
  kind         TEXT NOT NULL,                     -- license|machine|epoch|release
  target       BLOB NOT NULL,
  reason       INTEGER NOT NULL,
  actor        TEXT NOT NULL,
  undo_until   INTEGER,                           -- 24h 可撤销窗口
  undone_at    INTEGER,
  created_at   INTEGER NOT NULL,
  request_id   TEXT,                              -- Admin Idempotency-Key；旧记录为 NULL
  applied_at   INTEGER,                           -- LicenseDO 已接受该 epoch
  published_at INTEGER                             -- RB + rev:epoch 已写入 KV
);
CREATE INDEX idx_revocations_target ON revocations(kind, target);
CREATE UNIQUE INDEX idx_revocations_request_id
ON revocations(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX idx_revocations_pending
ON revocations(seq) WHERE published_at IS NULL;
```

吊销发布按 `seq` 严格串行：条件 `INSERT` 只在不存在
`published_at IS NULL` 的记录时分配下一个 epoch。`LicenseDO` 接受后写
`applied_at`，不可变 `RevocationBatch` 与单调 `rev:epoch` 都写入 KV 后才写
`published_at`。Worker 的每分钟 Cron 从 D1 primary 恢复唯一 pending 记录，且必须复用
原 `request_id`、`seq`、DO 操作与 IssuerDO 幂等响应；不得删除 pending 行或另分配 epoch，
否则会制造客户端无法跨越的吊销序列空洞。

```sql
-- Epoch 吊销的第一名 actor 批准会跨请求持久化；第二名 actor 必须不同且在 15 分钟内完成。
-- 最终 revocation_seq 让 replay/Cron 始终复用原吊销序号。
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

-- 每个非普通吊销 Admin mutation 先把业务写和不可变恢复记录放在同一 D1 batch。
-- side effect、AdminAuditDO 和 Queue checkpoint 只能在该 batch 成功后推进。
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

-- 对主表没有不可变 version sequence 的可变实体提供 append-only optimistic lock。
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

CREATE TABLE admin_audit_events (
  seq          INTEGER PRIMARY KEY CHECK (seq > 0), -- AdminAuditDO 全局序列
  operation_id TEXT NOT NULL UNIQUE,                -- vendor/idempotency-key
  source_kind  TEXT NOT NULL,                       -- revocation|catalog|policy|...
  source_id    TEXT NOT NULL,
  event_json   TEXT NOT NULL,                       -- 已固化的 before/after 与链字段
  prev_hash    BLOB NOT NULL,
  hash         BLOB NOT NULL,
  r2_key       TEXT NOT NULL UNIQUE,
  enqueued_at  INTEGER,                             -- Queue 已接受
  archived_at  INTEGER,                             -- R2 + audit_index 已完成
  created_at   INTEGER NOT NULL
);
CREATE INDEX idx_admin_audit_enqueue
ON admin_audit_events(seq) WHERE enqueued_at IS NULL;
CREATE INDEX idx_admin_audit_archive
ON admin_audit_events(seq) WHERE archived_at IS NULL;
CREATE INDEX idx_admin_audit_source
ON admin_audit_events(source_kind, source_id);
```

Admin 审计链格式、R2 key 与恢复顺序见 ADR-0014。`audit_index` 的正数键保留给
ADR-0011 的 Issuer 分片；Admin 事件使用 `audit_index.seq = -admin_audit_events.seq`。

```sql
CREATE TABLE admin_tokens (
  id          TEXT PRIMARY KEY,
  vendor_id   TEXT NOT NULL REFERENCES vendors(id),
  token_hmac  BLOB NOT NULL UNIQUE,               -- HMAC(admin_token_pepper, token)
  actor       TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  not_before  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  revoked_at  INTEGER,
  created_at  INTEGER NOT NULL
);
CREATE INDEX idx_admin_tokens_vendor ON admin_tokens(vendor_id);
CREATE INDEX idx_admin_tokens_expiry ON admin_tokens(expires_at);

CREATE TABLE audit_index (
  seq        INTEGER PRIMARY KEY,           -- 正数=Issuer(ADR-0011)，负数=Admin(ADR-0014)
  ts         INTEGER NOT NULL,
  actor      TEXT NOT NULL,
  action     TEXT NOT NULL,
  target     TEXT,
  prev_hash  BLOB NOT NULL,
  hash       BLOB NOT NULL,
  r2_key     TEXT NOT NULL                  -- 全文在 R2
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
```

## 9. D1：分析聚合（ADR-0007）

```sql
-- 精确计数 rollup（每日 Cron 产出）
CREATE TABLE analytics_rollup (
  product_id TEXT NOT NULL,
  date       TEXT NOT NULL,               -- YYYY-MM-DD (UTC)
  metric_id  TEXT NOT NULL,               -- act.new / act.by_path / seat.exhausted ...
  dims_json  TEXT NOT NULL,               -- { app_version, os, country, ... }，规范化有序
  value      INTEGER NOT NULL,
  PRIMARY KEY (product_id, date, metric_id, dims_json)
);
CREATE INDEX idx_rollup_metric ON analytics_rollup(product_id, metric_id, date);

-- 唯一设备数的 HLL 草图（可合并 → 任意时间窗口；不含个人数据 → 可长期保留）
CREATE TABLE analytics_hll (
  product_id TEXT NOT NULL,
  date       TEXT NOT NULL,
  cube_key   TEXT NOT NULL,               -- cube_0..cube_8 + 维度取值
  sketch     BLOB NOT NULL,               -- HLL p=14，~16KB
  PRIMARY KEY (product_id, date, cube_key)
);
CREATE INDEX idx_hll_cube ON analytics_hll(product_id, cube_key, date);

-- T1 遥测的聚合结果（原始上报 30 天后清理，只留这里）
CREATE TABLE telemetry_rollup (
  product_id TEXT NOT NULL,
  date       TEXT NOT NULL,
  metric_id  TEXT NOT NULL,               -- use.session_count / use.feature_hits ...
  dims_json  TEXT NOT NULL,
  value      INTEGER NOT NULL,
  sample_n   INTEGER NOT NULL,            -- 上报设备数（用于 k-匿名抑制判定）
  PRIMARY KEY (product_id, date, metric_id, dims_json)
);
```

## 10. Durable Object：`LicenseDO`（一个 License 一个实例）

```sql
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB);
-- keys: license_id, product_id, policy_snapshot(CBOR), entitlement_snapshot(CBOR),
--       status, seats, expires_at, revocation_epoch_seen, security_floor, proj_version

CREATE TABLE IF NOT EXISTS activations (
  machine_id     BLOB PRIMARY KEY,
  fingerprint    BLOB NOT NULL,
  attrs          BLOB,                    -- 规范化属性（容差匹配用；受 report_attrs 控制）
  device_kem_ek  BLOB NOT NULL,
  device_sig_vk  BLOB NOT NULL,           -- 校验 validate 请求的 proof
  status         INTEGER NOT NULL,        -- 0=active 1=released 2=revoked 3=pending
  activation_path TEXT NOT NULL,
  release_id     TEXT,
  variant_id     INTEGER,
  created_at     INTEGER NOT NULL,
  last_seen_at   INTEGER,
  last_hb_at     INTEGER,
  refresh_after  INTEGER,
  not_after      INTEGER,
  build_fp       TEXT,
  app_version    TEXT,
  geo            TEXT,
  transfer_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_act_fpr ON activations(fingerprint);
CREATE INDEX IF NOT EXISTS idx_act_status ON activations(status);
CREATE INDEX IF NOT EXISTS idx_act_hb ON activations(last_hb_at);

CREATE TABLE IF NOT EXISTS nonces (nonce BLOB PRIMARY KEY, seen_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_nonce_ts ON nonces(seen_at);

CREATE TABLE IF NOT EXISTS transfers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  machine_id BLOB NOT NULL, action INTEGER NOT NULL, at INTEGER NOT NULL
);

-- outbox 模式：与业务写同事务，由 alarm/请求尾部推 Queue
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                     -- projection|audit|analytics|webhook
  payload BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  sent_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(sent_at) WHERE sent_at IS NULL;

CREATE TABLE IF NOT EXISTS idem (
  key TEXT PRIMARY KEY, resp BLOB NOT NULL, created_at INTEGER NOT NULL
);
```

### 10.1 席位分配：两阶段预留

避免"占了席位但签发失败"的悬挂状态：

```
Phase 1 (LicenseDO): 插入 activation, status = PENDING, alarm(now+60s) 回收
Phase 2 (Worker):    IssuerDO 签发 MC
Phase 3 (LicenseDO): commit → status = ACTIVE
失败 → 不 commit，60s 后 alarm 自动回收
```

**实现纪律**：`activate`/`validate` 的事务段内**禁止 `await`**（DO 的原子性依赖无 I/O 的连续写）。
签名调用必须在事务提交后进行。

### 10.2 Alarm 职责

| 周期 | 动作 |
|---|---|
| `min(heartbeat_sec, 1h)` | 回收超时僵尸、清理过期 nonce、刷 outbox |
| `expires_at` | 标记过期，推送投影 |
| PENDING 超时 | 回收未提交的席位预留 |

## 11. Durable Object：`AccountDO` / `IssuerDO` / `AdminAuditDO`

```sql
-- AccountDO
CREATE TABLE sessions (
  token_hash BLOB PRIMARY KEY, machine_id BLOB,
  issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE TABLE login_attempts (at INTEGER NOT NULL, ok INTEGER NOT NULL, ip_hash BLOB);

-- IssuerDO（按 FNV-1a-64(routing_key) % 8 分片；对象名 issuer-{shard}，见 ADR-0011）
CREATE TABLE issuance_log (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,   -- 单调
  ts        INTEGER NOT NULL,
  kind      INTEGER NOT NULL,                    -- artifact_kind
  subject   BLOB NOT NULL,
  epoch_id  BLOB NOT NULL,
  digest    BLOB NOT NULL,
  prev_hash BLOB NOT NULL,
  hash      BLOB NOT NULL
);

-- 单例 AdminAuditDO（对象名 global；统一 Admin mutation 强一致序列）
CREATE TABLE chain_base (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  seq INTEGER NOT NULL,
  hash BLOB NOT NULL
);
CREATE TABLE events (
  seq INTEGER PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  request_hash BLOB NOT NULL,
  event_json TEXT NOT NULL,
  hash BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
```

## 12. KV 命名空间

| Key | Value | TTL |
|---|---|---|
| `keys:current` | CBOR{ epoch_certs[], revocation_epoch, security_floor } | 300s |
| `policy:<product>:<policy>` | CBOR(PolicySnapshot)（含解析后的权益） | 600s |
| `release:<product>:<release_id>` | CBOR(ReleaseSnapshot)（variant 参数、published_at、status） | 600s |
| `rev:epoch` | uint | 60s |
| `rev:batch:<n>` | envelope(RevocationBatch) | 永久（不可变） |
| `flag:<product>` | CBOR(FeatureFlags)（**被签名**，如临时放宽 grace、关闭 guard 影响） | 300s |

**规则**：KV 只承载性能优化。任何来自 KV 的数据必须**被签名**，或**即使过期也不影响正确性**。

## 13. R2 布局

```
audit/<yyyy>/<mm>/<dd>/<shard>/<seq>.cbor      审计事件全文
audit/anchors/<yyyy-mm-dd>.sig                 哈希链每日签名锚点
analytics/raw/<yyyy-mm-dd>/<shard>.ndjson.gz   分析明细（90 天）
offline/<license_id>/<nonce>.aresp             离线激活响应（7 天）
manifests/<product>/<build_fp>.cbor            IntegrityManifest 归档
exports/d1/<timestamp>.sql.gz                  D1 定期导出
```

## 14. 保留与删除

| 数据 | 保留 | 方式 |
|---|---|---|
| nonce | 2 × max_skew（48h） | DO alarm |
| 已释放 activation | 90 天 | DO alarm + 投影同步 |
| 分析 raw（R2） | 90 天 | R2 lifecycle |
| `analytics_rollup` / `analytics_hll` | 3 年 | 不含个人数据 |
| T1 原始上报 | 30 天（之后只留 `telemetry_rollup`） | Cron |
| 审计事件 | 3 年（可配置） | R2 lifecycle |
| 账号 | 注销后 30 天 | Admin API 级联删除 |
| 幂等记录 | 24h | alarm |

**GDPR 删除**：DO 删 activation → D1 删 machines 行 → R2 raw 清理 →
审计日志 PII 替换为 tombstone（保留哈希链）。
**HLL 草图与 rollup 计数不回溯修改** —— 不含个人数据，且回溯会破坏历史可比性。
此边界必须写入隐私政策（见 [`06-legal`](../06-legal/privacy-and-legal-pack.md)）。

## 15. 一致性契约

1. **DO 是权威**。任何安全判定（席位、吊销、状态）只读 DO。
2. **D1 是投影**，可滞后（P95 < 5s），只用于展示与报表。**禁止在校验路径读 D1 做判定**。
3. **投影用 outbox**：DO 写 outbox（同事务）→ 推 Queue → 消费者幂等 upsert（`WHERE proj_version < ?`）。
4. **KV 可能过期 60s**：内容必须自带签名或不影响安全。
5. **跨 DO 无事务**。批量操作设计为逐个幂等 + 可重入。
6. **schema 迁移**必须可回滚且有 dry-run；D1 只做向后兼容变更（新增可空列，不删列）。
   **DO 类的存储格式迁移不可回滚** → 用 DO 内版本化 schema，或新增 DO 类。
