# ADR-0003：Cloudflare 存储拓扑（DO + D1 + KV + R2 + Queues）

- **状态**：Accepted
- **日期**：2026-07-26
- **相关**：`02-architecture/data-model.md`、`03-modules/10-server-worker.md`

## 背景

License Server 有三类差异极大的访问模式：

1. **强一致的席位竞争**：同一 License 的并发激活必须原子地判断「还有没有位」。D1 上做需要
   乐观并发 + 重试；D1 客户端对写不做自动重试（写不可安全重放）。
2. **跨实体的关系型查询**：管理后台「列出某产品所有过期 License」「某账号的所有设备」。
3. **超高频只读**：客户端校验时要读公钥集、吊销 epoch、Policy 快照 —— 每次校验都要读，必须极快。

## 决策

| 存储 | 用途 | 理由 |
|---|---|---|
| **Durable Object（SQLite 后端）`LicenseDO`** | 每个 License 一个 DO：席位表、Activation 表、nonce 防重放缓存、心跳、alarm 驱动的租约回收 | 单线程串行化 → 席位计数天然原子，无需分布式锁/重试；每 DO 独立 SQLite，读写本地零延迟；alarm 替代 cron 做过期回收；PITR 30 天便于授权纠纷取证 |
| **Durable Object `AccountDO`** | Mode E 的账号会话、并发设备数、登录节流 | 同上 |
| **Durable Object `IssuerDO`** | 签名操作序列化 + 签发序号单调递增 + 签名审计链 | 保证签发序号无重复；集中签名便于限流与审计；配合 Secrets Store 绑定收敛密钥暴露面 |
| **D1** | 全局目录：`vendors` `products` `policies` `licenses`（索引行）`accounts` `orders` `revocations` `audit_index` | 关系型查询、管理后台、报表；写入频率低 |
| **KV** | 公钥集（`pubkeys/<epoch>`）、当前 `revocation_epoch` 指针、Policy 快照、产品级开关 | 边缘读极快、全球复制；容忍最终一致（≤60s 传播）—— 见下方一致性设计 |
| **R2** | 离线激活包、IntegrityManifest 归档、审计日志冷存储、SDK 分发 | 便宜、无出口费 |
| **Queues** | 审计事件、异常检测、Webhook 外发、批量签发 | 把非关键路径移出请求周期 |
| **Secrets Store** | Epoch 私钥（RBAC + 审计日志，优于普通 Worker Secret） | — |

### 一致性设计要点

- **权威数据在 DO**，D1 中的 License 行是**投影（projection）**，由 DO 在状态变更后经 Queue 异步同步。
  管理后台读 D1（可能滞后数秒），关键判定读 DO。
- **KV 的最终一致性不能承担安全语义**：吊销的**权威**判定发生在 DO（在线校验时）；
  KV 上的 `revocation_epoch` 只用于让客户端知道「我该刷新了」，且 epoch 单调递增、被签名。
  即使 KV 滞后 60s，攻击窗口也受限于客户端本来就有的校验周期。
- **DO 单对象 ~1000 req/s 软上限**：按 License 分片天然分散；
  仅 `IssuerDO` 是潜在热点 → version 1 按 `FNV-1a-64(routing_key) % 8` 分片，线格式与迁移约束见
  [ADR-0011](ADR-0011-issuer-sharding-and-audit-chain.md)。

## 备选方案与否决理由

| 方案 | 否决 |
|---|---|
| 纯 D1 | 席位竞争需要乐观并发 + 应用层重试与幂等；高冲突场景吞吐差；D1 写不自动重试 |
| 纯 DO | 跨 License 的管理查询无法做（要扫全部 DO）；报表不可行 |
| 外部数据库（Postgres/Neon） | 引入非 Cloudflare 依赖、冷启动与连接开销、违背 Serverless 自持定位 |
| KV 作为主存储 | 最终一致 + 无事务，不能承担席位语义 |

## 后果

- 复杂度：需要维护 DO ↔ D1 的投影同步（幂等、可重放、带版本号）。
  → 用 `LicenseDO` 内 `outbox` 表 + Queue 消费者实现 outbox 模式，保证至少一次投递 + 幂等 upsert。
- 迁移/备份：DO 数据的导出需要专门的 `admin/export` 路径（遍历 D1 索引 → 逐个 DO 拉取）。
- 本地开发：`wrangler dev` 支持 DO/D1/KV/R2/Queues 本地模拟，可全链路离线开发。
- 成本：以 10 万活跃设备、每设备每日 1 次校验计 ≈ 300 万请求/月 + DO 时长，估算 < $20/月。

## 未决

- SQLite-in-DO 的存储计费自 2026-01 起生效，需在成本文档中按实际字节量重新核算。
- 若单 Vendor 的 License 数量极大（百万级），D1 的行数与查询性能需再评估，可能需要按 product 分库。
