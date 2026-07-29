# ADR-0011：Issuer 分片与审计链线格式

- **状态**：Accepted
- **日期**：2026-07-27
- **相关**：ADR-0003、`02-architecture/data-model.md`、`03-modules/10-server-worker.md`、FR-SRV-024

## 背景

`IssuerDO` 需要并行承担 PQ 工件签发，因此不能只有一个全局实例。每个分片独立维护本地单调序号和
哈希链，而 D1 的 `audit_index` 只有一个整数主键，R2 还要提供可由 CLI 长期验证的 canonical
归档。若不固定分片算法、序号映射和哈希输入，Worker、Queue 消费者与未来的
`copylocker audit verify` 会各自推断出不兼容的格式。

ADR-0003 只确定了需要分片，`data-model.md` 也只给出了路径轮廓；它们没有定义可重放的字节级契约。

## 决策

以下规则组成审计 schema version 1。任何会改变既有输出的修改都必须提升 schema version，并提供
双读或迁移方案。

### 1. Issuer 路由

- version 1 固定使用 `8` 个分片，编号为 `0..7`。
- 内部签发请求必须携带 16 字节 `routing_key`。License 归属的工件使用 `license_id`；其他工件由调用方
  选择稳定的 16 字节归属键，并在幂等重试时保持不变。
- `shard = FNV-1a-64(routing_key) mod 8`。FNV offset basis 为
  `0xcbf29ce484222325`，prime 为 `0x00000100000001b3`；每个字节先 XOR，再乘 prime，乘法按
  `mod 2^64` 回绕。
- Durable Object 名称固定为 `issuer-{shard}`，例如 `issuer-3`。`IssuerDO` 必须同时验证请求中的
  `shard` 与 `routing_key` 相符，并验证当前对象 ID 等于命名空间对该名称计算出的确定性 ID。

分片数量不是可热改的吞吐参数。增加分片数会改变所有路由，必须作为新的路由版本和新的 DO 命名空间
迁移，不能直接把 `8` 改成其他值。

### 2. 逐分片签发链

每个 `issuer-{shard}` 独立维护 `local_seq`，从 `1` 开始逐条加一。第一条记录的 `prev_hash` 是
32 个零字节；之后的 `prev_hash` 必须等于同一分片上一条记录的 `hash`。

`digest = SHA-256(envelope)`。链哈希按以下方式计算：

```text
LP(x) = u64_be(byte_length(x)) || x
hash  = SHA-256(LP(part_0) || LP(part_1) || ... || LP(part_9))
```

| 顺序 | 字段 | 字节编码 |
|---:|---|---|
| 0 | domain label | ASCII `copylocker/issuer-audit/v1` |
| 1 | `shard` | 单个 `u8` |
| 2 | `local_seq` | 正数 `i64` 的 8 字节大端补码 |
| 3 | `occurred_at` | Unix UTC 秒，`i64` 的 8 字节大端补码 |
| 4 | `artifact_kind` | 单个 `u8` |
| 5 | `product_id` | ASCII 子集 `[A-Za-z0-9._-]` |
| 6 | `subject` | 原始字节 |
| 7 | `epoch_id` | 8 个原始字节 |
| 8 | `digest` | 32 个原始字节 |
| 9 | `prev_hash` | 32 个原始字节 |

每一项都包含自己的 8 字节长度前缀，包括固定宽度整数和单字节字段。这样可避免不同字段拼接产生歧义。

### 3. Queue 与 R2 归档

签发记录、outbox 事件和幂等响应必须在同一段无 `await` 的 Durable Object SQLite 写入中产生。
Queue 使用 at-least-once 投递；消费者必须允许完全相同的事件重放，但不得覆盖不同内容。
处理持续失败的消息在 10 次重试后进入 `copylocker-events-dlq`，不得直接丢弃；运维工具从 DLQ
修复并重放时仍遵守同一幂等规则。

R2 key 由事件时间的 UTC 日期、分片和本地序号确定：

```text
audit/<yyyy>/<mm>/<dd>/<shard>/<local_seq>.cbor
```

R2 对象是 canonical CBOR map，整数 key 与值固定如下：

| CBOR key | 值 |
|---:|---|
| 0 | `schema_version` (`uint`，version 1 为 `1`) |
| 1 | `shard` (`uint`) |
| 2 | `local_seq` (`uint`) |
| 3 | `occurred_at` (`uint`) |
| 4 | `artifact_kind` (`uint`) |
| 5 | `product_id` (`text`) |
| 6 | `subject` (`bytes`) |
| 7 | `epoch_id` (`bytes`) |
| 8 | `digest` (`bytes`) |
| 9 | `prev_hash` (`bytes`) |
| 10 | `hash` (`bytes`) |
| 11 | `envelope` (`bytes`) |

Queue 的事件类型和派生出的 `r2_key` 不写入 canonical 对象。消费者以
`etagDoesNotMatch: "*"` 条件写 R2；若对象已存在，只有逐字节相同时才视为幂等成功。

### 4. D1 全局索引序号

D1 `audit_index.seq` 是跨分片唯一的索引序号，不是某条全局哈希链的序号：

```text
global_seq = (local_seq - 1) * 8 + shard + 1
```

例如 `(shard=0, local_seq=1) -> 1`、`(7, 1) -> 8`、`(0, 2) -> 9`。反向映射为：

```text
shard    = (global_seq - 1) mod 8
local_seq = floor((global_seq - 1) / 8) + 1
```

Queue 可乱序到达，因此 `global_seq` 允许存在暂时或永久空洞，也不表示跨分片的时间顺序。
`prev_hash` 和 `hash` 始终只连接同一分片。验证器必须先按 `shard` 分组，再按 `local_seq` 验证连续性；
不能把 D1 的相邻行当作同一条链。

D1 索引行使用 `actor = "issuer:<shard>"`、`action = "issue:<artifact-context>"`，并把
`subject` 编码为小写十六进制 `target`。相同 `global_seq` 的重放只有在所有索引字段一致时才可接受。

## 备选方案与否决理由

| 方案 | 否决理由 |
|---|---|
| 单个全局 IssuerDO 与全局序号 | PQ 签发会集中到一个热点，限制吞吐和故障隔离 |
| 以到达 D1 的顺序分配全局自增序号 | Queue 可重放、乱序，D1 写失败后的恢复无法保持确定映射 |
| 直接拼接字段后哈希 | 可变长字段之间存在边界歧义，跨语言实现容易不一致 |
| 允许覆盖同名 R2 对象 | 重放或攻击可静默改写审计证据 |

## 后果

- Worker、Queue 消费者、R2 归档和 CLI 有了同一个可跨语言复现的字节级契约。
- 八条分片链可独立验证，但没有一个天然的全局时间顺序；每日签名锚点必须覆盖每个分片的链头。
- 分片数、哈希字段顺序、CBOR key 或序号映射一旦发布都不能原地修改。
- `audit_index.seq` 的含义从“IssuerDO 本地序号”澄清为“由本地序号与分片确定映射的全局索引序号”。
