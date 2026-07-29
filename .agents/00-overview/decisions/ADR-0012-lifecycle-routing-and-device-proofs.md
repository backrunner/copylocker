# ADR-0012：生命周期请求路由与设备证明

- **状态**：Accepted
- **日期**：2026-07-27
- **相关**：ADR-0003、`02-architecture/protocol-spec.md`、`02-architecture/data-model.md`、FR-SRV-005、FR-SRV-021

## 背景

`LicenseDO` 以“一 License 一个实例”提供席位、激活、nonce 与吊销状态的强一致判定，因此
`validate`、`heartbeat` 和 `deactivate` 必须在进入安全路径前就能确定 `license_id`。原
`ValidateRequest` 只有 `machine_id`；若用 D1 的 `machines` 投影反查 License，会违反
`data-model.md §15` 的一致性契约，并在投影延迟或缺失时产生错误路由。

同时，原 `ActivationRequest` 的文字说明要求设备自签，但 wire map 没有签名字段；
`HeartbeatRequest` 与 `DeactivateRequest` 也只有端点名称，没有正式编码或独立签名域。
仅凭公开的 `machine_id` 就允许心跳或释放席位，会让攻击者替其他设备续活、消耗限流或释放席位。

## 决策

### 1. 强一致路由

- 所有激活后的生命周期请求必须携带 16 字节 `license_id`。
- `ValidateRequest` 使用 CBOR key `12`；key `11` 已保留给可选 telemetry，不得重编号。
- `HeartbeatRequest` 与 `DeactivateRequest` 均使用 key `2` 表示 `license_id`。
- Worker 以小写十六进制 `license_id` 调用 `LICENSE.idFromName()`；D1 投影不得参与路由或授权。
- `license_id` 只是未验证的路由提示。LicenseDO 必须核对自身 `meta.license_id`、请求
  `license_id` 与 `machine_id` 所属 activation 三者一致，才可继续。

### 2. 设备证明

设备证明统一使用该 activation 的 Ed25519 设备签名密钥。验证 key 在激活时写入 LicenseDO，
私钥只留在设备安全存储中。

| 请求 | wire kind | 域名 | proof key |
|---|---:|---|---:|
| ActivationRequest | 8 | `ar` | 12 |
| ValidateRequest | 10 | `validate-request` | 8 |
| HeartbeatRequest | 11 | `heartbeat-request` | 6 |
| DeactivateRequest | 12 | `deactivate-request` | 6 |

`proof_input` 固定为：删除本请求的 `proof` key 后，把剩余完整 map 重新编码成 RFC 8949
deterministic CBOR。不存在的可选字段保持不存在，不编码为空值。签名消息仍使用通用
`DomainCtx = "copylocker/v1/" || kind_name || 0x00 || suite_id || product_id`。

ActivationRequest 的 proof 用请求内 `device_sig_vk` 验证，并覆盖 credential、两个设备公钥、
fingerprint、nonce、attestation 与 client_info。它不是授权信任锚，只证明转发途中这些字段没有
被换掉。其余三个请求使用 LicenseDO 中已登记的 `device_sig_vk`，并把 `license_id`、`machine_id`
与 nonce 全部纳入 proof。

### 3. 验证与写入顺序

激活后的请求按以下顺序处理：

1. 有界 canonical CBOR 解码与基础长度检查。
2. 按 `license_id` 路由，并在 LicenseDO 内核对对象身份和 activation 归属。
3. 用已登记的 `device_sig_vk` 与该请求的独立域验证 proof。
4. 在同一个 LicenseDO SQLite 写入批次中插入 nonce 并执行状态变更；nonce 已存在则拒绝重放。
5. 只有以上步骤都成功，才更新 `last_seen`、`last_hb_at` 或 activation 状态。

无效 proof 不得预先写入 nonce 表，否则攻击者可以用伪造请求抢占合法设备稍后会使用的 nonce。
Deactivate 的 HTTP `Idempotency-Key` 响应缓存与 nonce 去重并存：完全相同的已完成重试返回缓存响应，
未命中缓存的 nonce 重放仍被拒绝。

## 备选方案与否决理由

| 方案 | 否决理由 |
|---|---|
| 用 D1 `machines` 反查 `license_id` | D1 是异步投影，不能参与安全路由或判定 |
| 建一个全局 MachineDO 做索引 | 新增全局协调热点，且仍需处理跨 DO 非事务一致性 |
| 把 `license_id` 放 URL/Header | 更容易在代理日志泄露，也不会自然被请求 proof 覆盖 |
| heartbeat/deactivate 复用 `validate-request` 域 | 已签名消息可跨用途重放，违反域分隔规则 |
| deactivate 只依赖 Idempotency-Key | 幂等 key 不证明设备身份，知道 ID 的攻击者仍可释放别人的席位 |

## 后果

- 激活后的所有安全路径可以直接、确定地进入权威 LicenseDO，不依赖最终一致投影。
- v1 请求格式新增必填字段和两个 artifact kind；尚未发布的 KAT 随本 ADR 一次更新。
- Worker 必须在公开 heartbeat/deactivate 前实现设备 proof 验证和原子 nonce 写入，不能直接暴露现有
  只收 `machine_id` 的内部 DO 端点。
