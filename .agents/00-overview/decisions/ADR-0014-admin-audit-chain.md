# ADR-0014：Admin 变更审计链与恢复协议

- **状态**：Accepted
- **日期**：2026-07-28
- **修订**：2026-07-28（统一 `AdminAuditDO` 与 v2 事件）
- **相关**：ADR-0003、ADR-0011、`02-architecture/data-model.md`、FR-ADM-006

## 背景

Issuer 审计链记录签发工件，但不能表达 Admin 变更的 `before` / `after` 快照。ADR-0011
又把 D1 `audit_index` 的正数空间固定为 8 个 Issuer 分片的交错映射，Admin 事件不能占用同一
编号空间。吊销还跨越 D1、LicenseDO、IssuerDO、KV 与 Queue；若审计只在请求末尾临时生成，
故障恢复可能生成不同的 before 快照，或出现“吊销已生效但无审计事件”。

## 决策

### 1. 独立 Admin 链

Admin 链与 8 条 Issuer 链相互独立。`0004_admin_audit.sql` 创建的 v1 事件仅覆盖吊销，
其 `seq` 复用 `revocation_epoch`。这些事件与归档字节永久保持可验证，不重写、不回造。

`0006_unified_admin_audit.sql` 起，所有新事件由对象名固定为 `global` 的单例
`AdminAuditDO` 分配 `seq`。DO 的 SQLite 存储持有 `chain_base` 与不可变 `events`：第一次追加
以 D1 primary 中最后一条 v1/v2 事件的 `(seq, hash)` 为 base；没有旧事件时使用
`(0, zero32)`。后续每次追加都要求调用者看到的 D1 链头与 DO 当前链头逐字节相同，否则返回
`stale_chain_head`，必须先恢复缺失的 D1 镜像。这样 DO 已分配但尚未镜像的事件不能被下一次
变更跨过。

DO 以 `vendor_id + "/" + Idempotency-Key` 作为全局 operation id，并另存不含 bootstrap
字段的 request hash。同一 operation 的相同正文返回原事件；正文不同返回
`idempotency_conflict`。第一条链事件的 `prev_hash` 为 32 个零字节，或迁移时最后一条 v1
事件的 hash。

#### v1（仅兼容旧吊销）

哈希使用 `SHA-256(LP(part_0) || ... || LP(part_11))`，其中
`LP(x) = u64_be(byte_length(x)) || x`：

| 顺序 | 字段 | 编码 |
|---:|---|---|
| 0 | domain | ASCII `copylocker/admin-audit/v1` |
| 1 | `seq` | 正数 `i64` 大端补码 |
| 2 | `occurred_at` | Unix 秒 `i64` 大端补码 |
| 3 | `vendor_id` | UTF-8 |
| 4 | `actor` | UTF-8 |
| 5 | `action` | UTF-8；当前为 `revoke:license\|machine` |
| 6 | `target` | 32 字符小写十六进制 UTF-8 |
| 7 | `reason` | 单个 `u8` |
| 8 | `request_id` | Admin `Idempotency-Key` UTF-8 |
| 9 | canonical `before` snapshot | CBOR bytes |
| 10 | canonical `after` snapshot | CBOR bytes |
| 11 | `prev_hash` | 32 bytes |

snapshot 是 canonical CBOR map：`0 kind`、`1 target`、`2 license_id`、`3 product_id`、
`4 status`、`5 seats`、`6 heartbeat_sec?`、`7 expires_at?`、`8 affected_machines`、
`9 revocation_epoch`。after 必须保持同一实体和策略字段，状态为 `revoked`，受影响机器数为 0，
epoch 恰好比 before 大 1。

#### v2（统一 Admin 事件）

v2 使用同样的长度前缀哈希结构，但 domain 改为
`copylocker/admin-audit/v2`。字段顺序仍为 `seq`、`occurred_at`、`vendor_id`、`actor`、
`action`、`target`、`reason?`、`request_id`、canonical `before`、canonical `after`、
`prev_hash`；无 `reason` 时该 part 是零长度字节串，有值时是单个 `u8`。

v2 snapshot 来自 JSON 的严格子集：`null`、布尔、JavaScript safe integer、UTF-8 字符串、
数组和字符串键 map；禁止浮点数，最大深度 16，单个 snapshot canonical CBOR 不超过 64 KiB。
map 按 RFC 8949 canonical key bytes 排序，因此事件 JSON 的属性顺序不影响哈希。创建、删除可用
`null` 表达一侧空快照；普通更新要求 before 与 after 不同。

### 2. 持久化与恢复顺序

确认吊销按以下顺序执行：

1. D1 条件插入 `revocations`，分配唯一 revocation epoch。
2. 以原 `request_id` 查找已有审计镜像；没有时从 D1 primary 读取链头并调用
   `AdminAuditDO /append`。
3. 将 DO 返回的不可变 v2 事件插入 `admin_audit_events`，同时记录 `operation_id`、
   `source_kind=revocation` 与 revocation source id。
4. LicenseDO 接受 revocation epoch，写 `applied_at`。
5. IssuerDO 签发 RB，写不可变 `rev:batch:<epoch-1>`，单调推进 `rev:epoch`。
6. 将已持久化的 Admin 事件发送到 Queue，写 `enqueued_at`。
7. 最后写 `revocations.published_at`。

任一步失败都保留唯一 pending 吊销；每分钟 Cron 使用原 `request_id`、epoch 和审计正文恢复。
Queue 可能重复投递，但消费者必须先确认消息与 D1 `event_json`、哈希和 R2 key 完全相同；
v2 还必须向 `AdminAuditDO /verify` 确认正文一致。v1 因在 DO 上线前生成，只验证 D1 固化来源。

### 3. R2 与 D1 索引

R2 key 固定为：

```text
audit-admin/<yyyy>/<mm>/<dd>/<seq>.cbor
```

R2 对象使用 canonical CBOR map：`0 schema_version`、`1 seq`、`2 occurred_at`、
`3 vendor_id`、`4 actor`、`5 action`、`6 target`、`7 reason?`、`8 request_id`、
`9 before`、`10 after`、`11 prev_hash`、`12 hash`。写入使用
`etagDoesNotMatch: "*"`；已存在时仅逐字节相同才算幂等成功。

`audit_index` 的正数空间保持 ADR-0011 不变。Admin 映射为：

```text
audit_index.seq = -admin_event.seq
```

因此两类链永不碰撞。验证器按 `seq < 0` 识别 Admin 链，取绝对值恢复本地序号；不能把正负
相邻行视为同一条哈希链。

## 后果

- 吊销成功响应意味着审计消息已经由 Queue 接受；归档可异步完成并重放。
- D1 投影随后变成 `revoked` 也不会改变已固化的 before 快照。
- `admin_audit_events.seq` 与 `revocations.seq` 自 v2 起是两个独立序列；任何代码都不得再假设二者
  相等。D1 表解除 revocation 外键，但保留 `source_kind/source_id` 关联。
- 其他 Admin mutation 必须先固化可恢复的操作意图与 before/after，再走同一
  `AdminAuditDO`；不得用到达 D1/Queue 的偶然顺序分配链序号。
- 每日链头签名和 CLI `audit verify` 仍是后续交付物。
