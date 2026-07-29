# 模块：License Server（Cloudflare Workers）

Crate：`copylocker-server-core`（纯逻辑）+ `copylocker-worker`（CF 适配层）
需求：FR-SRV-*、NFR-PERF-001/002/003、NFR-REL-*

## 1. 分层

```
copylocker-worker  (workers-rs)
├── router.rs          路由（手写 match，避免引入重路由框架增大体积）
├── middleware/
│   ├── ratelimit.rs   三维限流（IP / license / fingerprint）
│   ├── body.rs        大小 + 深度 + Content-Encoding 限制
│   ├── idem.rs        Idempotency-Key
│   └── audit.rs       请求尾部推 Queue
├── bindings/
│   ├── storage_d1.rs      impl Storage（D1 部分）
│   ├── storage_do.rs      impl LicenseStore（DO stub 调用）
│   ├── kv_cache.rs        Policy/keys 缓存读取
│   └── issuer.rs          impl Issuer（调 IssuerDO）
├── durable/
│   ├── license_do.rs
│   ├── account_do.rs
│   └── issuer_do.rs
├── admin/             Admin REST（JSON）
└── queue/             Queue 消费者（投影/审计/webhook）

copylocker-server-core   ← 无 CF 依赖，可 native 测试
├── activate.rs   validate.rs   deactivate.rs   heartbeat.rs
├── offline.rs    auth.rs       revoke.rs       issue.rs
├── entitlement/  ← ★ 权益引擎：catalog、resolve()、limits 合并（ADR-0009）
├── validity/     ← ★ 订阅状态机、dunning、永久回退、scheduled_changes
├── version/      ← ★ Release 注册表、变体参数、版本范围判定、security_floor
├── analytics/    ← ★ 指标口径、rollup、HLL（委托 copylocker-analytics）
├── policy.rs     simulator.rs   fingerprint_match.rs   anomaly.rs
└── error.rs      （ClientFault / ServerFault 严格分离）
```

## 2. 关键路径实现要点

### 2.1 `POST /v1/validate`（最热）

```rust
async fn validate(req: Request, env: Env) -> Result<Response> {
    // ① 限流（Cloudflare Rate Limiting binding + DO 兜底）
    guard_rate(&req, &env).await?;

    // ② 解析（先长度检查，再 CBOR，深度 ≤16）
    let vr: ValidateRequest = decode_limited(req.body_bytes().await?, 16 * 1024, 16)?;
    if vr.proto_ver != 1 { return err(1004); }

    // ③ Policy 快照走 KV（命中率 >99%），未命中回 D1 并回填
    let policy = kv_cache::policy(&env, &vr).await?;

    // ④ 按 proof 覆盖的 license_id 路由；D1 machines 投影不得参与
    //    LicenseDO 核对对象身份、machine 归属、设备 proof 与 nonce 后才写状态
    let stub = env.durable_object("LICENSE")?
        .id_from_name(&hex(vr.license_id))?.get_stub()?;
    let verdict: Verdict = do_call(&stub, "/validate", &vr).await?;

    // ⑤ 签发（IssuerDO 分片；fast 签名在 Worker 内直接做以省一次 RPC —— 见 §2.2）
    let env_out = match verdict {
        Verdict::Ok(tbs)   => issuer::sign_fast(&env, ArtifactKind::ValidationTicket, tbs).await?,
        Verdict::Kill(tbs) => issuer::sign_fast(&env, ArtifactKind::KillOrder, tbs).await?,
    };

    // ⑥ 审计走 Queue，不阻塞响应（用 ctx.wait_until）
    ctx.wait_until(audit::emit(&env, ...));
    Ok(cbor_response(env_out))
}
```

**性能预算（P95 < 120ms 全球）**

| 段 | 预算 |
|---|---|
| 边缘 → Worker 冷/热启动 | 0–50ms |
| KV 读 Policy（缓存命中） | < 5ms |
| DO 调用（同 colo 或跨 colo） | 10–60ms ← **主要变量** |
| 签名（Ed25519 fast） | < 1ms |
| CBOR 编解码 | < 1ms |

> DO 位置是延迟主因。缓解：`locationHint` 按首次激活地域设置；
> 对纯读的心跳路径可用 KV/Cache 短路（不进 DO）。

### 2.2 签名策略与 IssuerDO

- **fast 签名（Ed25519）**：私钥可直接从 Secrets Store 读入 Worker，
  在 Worker 内签名，省掉一次 DO 往返。审计通过 Queue 异步记录。
- **PQ 签名（MC、EpochCert、RevocationBatch、`vt_signature=pq`）**：
  必须经 `IssuerDO`，因为需要单调序号 + 哈希链审计。
- `IssuerDO` 分片：`shard = FNV-1a-64(routing_key) % 8`，对象名、哈希链和归档线格式见
  [ADR-0011](../00-overview/decisions/ADR-0011-issuer-sharding-and-audit-chain.md)。

**为什么 fast 私钥可以进 Worker 内存**：它与 Epoch PQ 私钥同级保护（Secrets Store + RBAC），
且泄露的最大危害是"伪造 VT 延长已有凭证"，无法凭空创造 MC（需 PQ 私钥 + KEM 密封）。
Policy 可设 `vt_signature = "pq"` 关闭此优化。

### 2.3 两阶段席位预留

避免"占了席位但签发失败"：

```
Phase 1 (LicenseDO): 插入 activation, status = PENDING, alarm(now + 60s) 回收 PENDING
Phase 2 (Worker):    IssuerDO 签发 MC
Phase 3 (LicenseDO): commit(machine_id) → status = ACTIVE
失败 → 不 commit，60s 后 alarm 自动回收 PENDING
```

### 2.4 指纹容差匹配

在 `copylocker-server-core::fingerprint_match`：

```rust
pub fn similarity(a: &DeviceAttrs, b: &DeviceAttrs) -> u8 {
    // 加权：稳定属性权重高
    // machine_guid 40 / cpu_id 15 / board_serial 15 / disk_serial 10
    // os_install_id 10 / mac_addrs(集合 Jaccard) 5 / hostname 5
    ...
}
```

- `similarity >= policy.fpr_tolerance`（默认 70）→ 视为同一设备，复用 activation，不占新席位。
- 匹配成功后**更新**存储的 attrs（渐进适应硬件变化）。
- 匹配成功但指纹字节不同 → 重新签发 MC（绑定新指纹），记录 `transfer` 但不计入换机限额。
- **注意**：容差匹配需要客户端上报 attrs（而非只有摘要）。隐私配置为 `off` 时退化为精确匹配，
  文档需说明取舍。

### 2.5 异常检测（`anomaly.rs`）

在 DO 内低成本计算，不引入外部依赖：

| 信号 | 计算 | 权重 |
|---|---|---|
| 短窗口多指纹 | 24h 内 distinct fingerprint 数 / seats | 40 |
| 地理跳变 | 相邻两次校验的国家不同且时间差 < 2h | 25 |
| 指纹漂移过快 | 同 machine_id 的 attrs 变更频率 | 15 |
| 校验频率异常 | 远超 `refresh_after` 的高频校验 | 10 |
| 客户端版本混杂 | 同 license 下 app_version 种类数 | 10 |

`suspicion_score` 写入 VT 返回客户端（客户端可选择降级体验），并触发 Policy 配置的动作
（告警 / 强制重新校验 / 自动挂起）。

## 3. Admin API

端点清单、scope 定义与 CLI 见 [`70-admin-cli-console.md`](70-admin-cli-console.md)。
控制台经 **Service Binding** 调用本 Worker（无需长期 token），
且**控制台的判断不作数** —— 每个变更在此重新做 scope 校验与审计（FR-CON-004）。

本 Worker 侧的硬性纪律：

- **吊销类操作的 dry-run 是硬性要求**（防自伤 DoS）：先返回受影响设备数与列表，二次确认才执行。
  适用于 `licenses/:id/revoke`、`releases/:id/compromise`、`epochs/:id/revoke`。
- `epochs/:id/revoke` 额外要求双人确认（影响面是全部用户）。
- 批量签发返回的明文 LK **仅此一次**，服务端只存 `HMAC(pepper, lk)`。
- 支付 webhook 按 `(provider, event_id)` 幂等；乱序按事件时间戳判定；
  退款先 `suspended` + 观察期，不立即 `revoked`。

## 4. 错误处理纪律

```rust
// server-core/error.rs
pub enum ClientFault {   // → 4xx，客户端 fail-closed
    InvalidCredential, SeatExhausted, NeedsReactivation,
    NeedsLogin, UnsupportedProto, RateLimited, FingerprintMismatch,
    ReleaseNotRegistered, ReleaseCompromised,
}
pub enum ServerFault {   // → 5xx，客户端 fail-open（进 Grace）
    Storage(..), Issuer(..), Internal(..),
}
```

- 对外**只暴露** `protocol-spec.md §10.3` 的数值码，不暴露内部细节。
- `InvalidCredential` 涵盖"key 不存在""key 已吊销""license 过期"等，防枚举（FR-SRV-026）。
- 内部细分写审计日志。
- **绝不 panic**：`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`；
  DO 内 panic 会导致对象重启并可能丢失内存状态。

## 5. 限流设计

三维令牌桶，用 Cloudflare Rate Limiting binding（边缘、便宜）+ DO 内计数（精确）：

| 维度 | 限额（默认，可配） | 位置 |
|---|---|---|
| IP | 60 req/min（全部端点合计） | 边缘 binding |
| license_id | activate 10/h，validate 120/h | LicenseDO |
| fingerprint | activate 5/h | LicenseDO |
| account | login 10/15min（指数退避） | AccountDO |

超限返回 `1005` + `retry_after`；客户端必须实现指数退避 + 抖动（FR-CLI-005）。

## 6. 可观测性

- **日志**：`worker::console_log!` → Workers Logs；结构化 JSON；
  自动脱敏字段：`license_key`、`fingerprint`（只留前 8 hex）、`email`。
- **指标**：Analytics Engine `writeDataPoint`，维度 `{endpoint, verdict, suite_id, country}`，
  指标 `{latency_ms, do_latency_ms}`。
- **Trace**：请求 ID 贯穿 Worker → DO → Queue，写入日志。
- **告警**：Epoch 剩余有效期 < 14 天、签发失败率 > 1%、异常激活突增（见 `05-ops`）。

## 7. 部署与灰度

```jsonc
// wrangler.jsonc（模板节选）
{
  "name": "copylocker",
  "main": "build/worker/shim.mjs",
  "compatibility_date": "2026-07-01",
  "build": { "command": "cargo install -q worker-build && worker-build --release" },
  "durable_objects": { "bindings": [
    { "name": "LICENSE", "class_name": "LicenseDO" },
    { "name": "ACCOUNT", "class_name": "AccountDO" },
    { "name": "ISSUER",  "class_name": "IssuerDO"  }
  ]},
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["LicenseDO","AccountDO","IssuerDO"] }],
  "d1_databases": [{ "binding": "DB", "database_name": "copylocker" }],
  "kv_namespaces": [{ "binding": "CACHE" }],
  "r2_buckets":    [{ "binding": "ARCHIVE", "bucket_name": "copylocker-archive" }],
  "queues": { "producers": [{ "binding": "EVENTS", "queue": "copylocker-events" }],
              "consumers": [{ "queue": "copylocker-events", "max_batch_size": 100 }] },
  "observability": { "enabled": true }
}
```

- 用 Cloudflare **Versions & Gradual Deployments** 做 1% → 10% → 100% 灰度。
- 回滚：`wrangler rollback`；D1 迁移必须向后兼容（新增列可空，不删列）。
- **DO 类迁移不可回滚** → 新增 DO 类而非改现有类的存储格式；格式变更走 DO 内的版本化 schema 迁移。

## 8. 测试

| 层 | 方式 |
|---|---|
| `server-core` 单元/属性测试 | native，内存 Storage 实现，`proptest` |
| 席位并发 | `server-core` 层模拟 + 真实 DO 的 100 并发压测 |
| 端到端 | `wrangler dev` + Vitest（`@cloudflare/vitest-pool-workers`） |
| Fuzz | `cargo-fuzz` 对所有 CBOR 解析入口 |
| 契约测试 | 用 `vectors/` 中的 KAT 验证签发的凭证可被客户端验证，反之亦然 |
| 混沌 | 注入 D1/DO/KV 失败，验证客户端进入 Grace 而非失效 |
