# 安全运营（bootstrap、密钥仪式、轮换、吊销、事件响应）

需求：NFR-SEC-003、NFR-OPS-003/004/005、FR-ADM-007

本文以 M1 已实现 CLI/API 为准。标成“后续”的能力不得写入生产自动化。

## 1. 密钥与凭据清单

| 密钥/凭据 | 位置 | M1 保护要求 | 轮换 | 泄露影响 |
|---|---|---|---|---|
| **Root Current**（CL-STD-1 hybrid） | 离线托管 | CLI 输出 mode 0600；组织在外部执行 HSM/分片/异地保管 | 10 年或泄露时 | 灾难级：可签新 Epoch |
| **Root Next** | 与 Current 分离托管 | 同上；由 `keygen root` 同时生成并预置公钥 | Current 启用后补充新 Next | 同上 |
| **Epoch**（hybrid） | Secrets Store | RBAC、只写部署通道、审计 | 通常 90 天，重叠 14 天 | 可伪造凭证直至吊销 |
| **Epoch Fast**（Ed25519） | Secrets Store | 同 Epoch | 随 Epoch | 可伪造 VT，不能创造 MC |
| **Build Signing** | CI secret / Secrets Store | 单独 key、最小权限 | 180 天 | 可签假构建清单 |
| **Server Pepper** | Secrets Store | RBAC；不进入 D1/配置/日志 | 轮换需迁移所有 LK HMAC | 与 D1 同时泄露时可枚举 LK |
| **Admin Token Pepper** | Secrets Store | bootstrap 只经 stdin 上传；不进入 argv | 轮换需重算 token HMAC | 与 D1 同时泄露时削弱 token 保护 |
| **Admin Token** | 操作端环境变量 | 服务端只存 HMAC；scope/时间窗/actor 约束 | bootstrap 默认 90 天 | 可按 scope 管理资源 |
| **Bootstrap bundle** | 短期离线文件 | create-only、mode 0600、禁止入库；含 token 与 pepper | 单次初始化 | 等同完整 Admin token + pepper 泄露 |
| **Vendor Fingerprint Salt** | Secrets Store | RBAC | 通常不轮换 | 可离线复算指纹 |

## 2. 首次 bootstrap

新项目迁移后没有 vendor、product 或 Admin token。先在可信操作机生成恢复包：

```bash
copylocker bootstrap prepare \
  --project server \
  --vendor vendor-acme \
  --actor owner \
  --out /secure/copylocker-bootstrap.json
```

先审阅 dry-run，再执行：

```bash
copylocker bootstrap apply --project server --bundle /secure/copylocker-bootstrap.json
copylocker bootstrap apply --project server --bundle /secure/copylocker-bootstrap.json --confirm
```

`apply --confirm` 的固定顺序是：通过 Wrangler stdin 上传 `ADMIN_TOKEN_PEPPER` → 应用 remote
D1 migrations → conflict-checking seed。若第一步成功、D1 步骤失败，使用同一 bundle 执行：

```bash
copylocker bootstrap apply \
  --project server \
  --bundle /secure/copylocker-bootstrap.json \
  --confirm \
  --skip-secret-upload
```

完成后：

1. 从 bundle 把 `admin_token` 转移到 `copylocker.json` 指定的环境变量。
2. 运行 `copylocker doctor --project server --check-api` 验证只读认证。
3. 记录 token ID、actor、expiry 和托管人，但不得记录明文 token/pepper。
4. 销毁 bundle；若保留灾难恢复副本，必须加密并与操作端、D1 备份分离托管。

恢复包绑定 project name、product 和 Secrets Store ID。禁止为了“复用”而编辑 JSON；权限过宽、
过期、畸形或绑定不符时 CLI 必须拒绝。

M1 尚无 Admin token lifecycle API。紧急撤销 bootstrap token 时使用 Cloudflare break-glass
流程对 `admin_tokens.revoked_at` 做最小条件更新，保留命令、审批、结果和时间戳到外部事件记录；
这是“生产 D1 只经 Admin API”规则的唯一临时例外。token 管理 API 发布后删除该例外。

## 3. Root 密钥仪式

### 3.1 前置条件

- [ ] 专用机器物理断网；`--offline-confirm` 只是人工声明，不会替代网络检查
- [ ] 至少两名见证人和一名操作人；记录 CLI hash/version、OS、机器序列号和 UTC 时间
- [ ] 已定义 Current/Next 分离保管、恢复审批和销毁流程
- [ ] 已准备只读或单向介质，用于带出 public JSON 与 Epoch certificate
- [ ] 已在相同 CLI build 上通过 `copylocker kat check`

### 3.2 生成与托管

```bash
copylocker keygen root \
  --out-dir /secure/root-ceremony-2026 \
  --offline-confirm
```

命令 create-only 地生成：

```text
cl-root.public.json
cl-root.secret.json
cl-root-next.public.json
cl-root-next.secret.json
```

两个 secret 文件为 mode 0600，但 CLI **不实现** Shamir、HSM 写入或硬件 token。需要 3-of-5、
HSM 或纸质分片时，由获批的外部工具在离线仪式中处理；不得声称 CLI 已生成分片。Current 与
Next 的恢复材料不得由同一人、同一设备或同一地点单独控制。

记录两个 public 文件的 fingerprint。只有 public JSON 可进入源码/客户端 pinned 配置；Root
secret 永远不进入在线主机、Secrets Store、CI 或 Admin API。

## 4. Epoch 轮换

### 4.1 离线签发

在 Root 可用的离线环境生成新 Epoch。`not_before`/`not_after` 是 Unix 秒，必须先由两人复核：

```bash
copylocker keygen epoch \
  --root-key /secure/root-ceremony-2026/cl-root.secret.json \
  --product my-app \
  --not-before 1767225600 \
  --not-after 1775001600 \
  --out-dir /secure/epoch-2026q1
```

输出包括 Root-signed `epoch-<id>.cert.cbor`、public metadata、
`epoch-<id>.signing.secret.json` 和 `epoch-<id>.fast-signing.secret.json`。后两者都是完整、
versioned、mode-0600 Worker secret JSON。

### 4.2 上线顺序

1. 通过受审计的 Secrets Store 写入流程，把两个完整 secret JSON 分别设置为
   `EPOCH_SIGNING_KEY` 与 `EPOCH_FAST_SIGNING_KEY`；不要只复制 `signing_key` 数组。
2. 在在线操作机用 Root public JSON 上传证书：

```bash
copylocker epoch rotate /secure/epoch-2026q1/epoch-0011223344556677.cert.cbor \
  --root-public /secure/root-ceremony-2026/cl-root.public.json \
  --idempotency-key epoch-0011223344556677-rotate
```

3. Worker 会重新验证 Root 签名、suite、product scope、时间窗和 key shape，再持久化并重建
   `keys:current`。用 `copylocker epoch show 0011223344556677` 核对。
4. 在重叠窗口内观察签发和验证；确认客户端 refresh window 可跨越旧 Epoch 的 `not_after`。
5. 旧 Epoch 停止签发后仍保留验证，直到其凭证完成续期；不要把正常过期误当紧急吊销。

建议节奏：D-30 告警和排期，D-14 生成/上传并进入重叠，D0 切换签发，D+14 结束旧 Epoch
签发。具体窗口必须覆盖产品最长 refresh/grace，而不是机械套用 14 天。

## 5. 吊销操作

### 5.1 License（日常）

先运行服务端 dry-run：

```bash
copylocker license revoke 0123456789abcdef0123456789abcdef
```

核对 target、affected machines、already-revoked 和 reason 后确认：

```bash
copylocker license revoke 0123456789abcdef0123456789abcdef \
  --confirm \
  --idempotency-key incident-2026-0042-license-01
```

确认后严格分配单调 `revocations.seq`，应用目标状态，再发布不可变 `rev:batch:<seq>` 与
`rev:epoch`。前一序号 pending 时后一吊销返回 `revocation_in_progress`；保留同一 idempotency key
重试，不得另分配或删除 pending 行。

schema 保留 `undo_until`，但 M1 CLI/API **没有** unrevoke 契约。不得使用旧文档中的
`copylocker license unrevoke`。误吊销按 §6.2 处理。

### 5.2 Epoch（紧急、双人）

影响面是该 Epoch 的全部凭证。服务端要求先存在同 product 的有效 replacement。第一名 actor：

```bash
copylocker epoch revoke 0011223344556677 \
  --admin-token-env COPYLOCKER_ADMIN_TOKEN_A

copylocker epoch revoke 0011223344556677 \
  --admin-token-env COPYLOCKER_ADMIN_TOKEN_A \
  --confirm \
  --confirm-epoch-id 0011223344556677 \
  --idempotency-key incident-2026-0042-epoch-a
```

15 分钟内，第二名不同 actor 使用自己的 token 和不同 key：

```bash
copylocker epoch revoke 0011223344556677 \
  --admin-token-env COPYLOCKER_ADMIN_TOKEN_B \
  --confirm \
  --confirm-epoch-id 0011223344556677 \
  --idempotency-key incident-2026-0042-epoch-b
```

执行前必须确认：确为泄露而非误报；replacement 已上传并可签发；支持/公告准备完成；两名
actor 的身份与职责独立。CLI 在任何网络连接前检查 typed ID；服务端检查 actor、15 分钟窗口、
replacement 和 journal。只有第二次批准产生最终 `epoch` entity version 与 revocation sequence。
两名 actor 的 token 都必须同时具有 `epochs:rw` 与 `revoke`；dry-run 只要求 `epochs:rw`。

### 5.3 Root 泄露

1. 冻结新的 Epoch upload/rotation，保存日志和受影响时间窗。
2. 用预置 `root_next` 签新 Epoch，并把在线签发切到新 Epoch。
3. 按 §5.2 对 Current 签发的每个受影响 Epoch 执行双人吊销。
4. 发布客户端更新，移除 Current、把原 Next 提升为 Current，并预置全新的 Next public key。
5. 无法识别 Next 的旧客户端会失效；公告、升级和客服路径必须与技术切换同时启动。
6. 重建 Root 保管链并完成独立事后审计。

## 6. 事件响应

### 6.1 `key-compromise`

| 对象 | 严重度 | 动作 |
|---|---|---|
| Admin token | 中/高 | break-glass 撤销；按 actor/request ID 导出操作；核对所有 mutation；生成替代 token 的 M1 外流程 |
| Bootstrap bundle | 高 | 同时视为 Admin token 与 pepper 泄露；撤销 token；评估 D1 是否泄露；重建凭据 |
| Build signing | 中 | 撤销 key；重签在线构建清单；调查假清单分发 |
| Epoch Fast | 中 | 生成 replacement 并轮换；评估伪造 VT 时间窗 |
| Epoch | 高 | §5.2 双人吊销、切换 replacement、公告 |
| Root | 灾难 | §5.3 |
| Server/Admin pepper | 低至高 | 结合 D1 是否泄露定级；轮换需要数据迁移，先隔离和取证 |

### 6.2 `mass-revoke-mistake`

1. 立即停止新的确认操作；保持 minute Cron 运行，让已经分配的序号完成，避免序列空洞。
2. 保存 dry-run、idempotency key、`revocations`、Admin journal、KV batch 和审计归档。
3. M1 不支持 unrevoke。为受影响客户重新签发新 license，并走已批准的安全交付渠道。
4. 已接收 KillOrder/吊销 batch 的客户端必须重新激活；同步客服脚本与状态页。
5. 不得降低 `rev:epoch` 或覆盖既有 `rev:batch:<seq>`；它们是单调、不可变的安全历史。
6. 复盘审批、dry-run 核对和批量输入来源。

### 6.3 `client-mass-failure`

1. 按 app version、build fingerprint、OS 和错误码定位范围。
2. 判断是签名/keyset、catalog/policy、release 兼容还是客户端 bug。
3. 若需延长 grace，使用已批准、带签名且客户端实现的配置路径；M1 没有通用
   `copylocker grace-extension` 命令。
4. 若是攻击流量，先限流和隔离上报，不要用不可逆吊销作为第一反应。

### 6.4 `do-hotspot`

1. 从 Cloudflare telemetry 定位 Durable Object 和请求来源。
2. 单 License 异常共享先挂起并调查；确认后再走带 dry-run 的吊销。
3. 合法大客户应调整席位/拆分 License；不要修改 DO storage 绕过权威状态。
4. Issuer 分片数变化是 schema/routing migration，不得在事件中临时修改。

## 7. Cron、监控与告警

minute Cron 的固定恢复顺序：

1. 最老的 pending Admin side effect；
2. 最老的、side effect 已完成的 Admin audit operation；
3. 唯一 pending strict revocation；
4. 到期 billing transition。

每类每 tick 最多推进一条，失败不跳过。告警必须覆盖：

| 告警 | 建议阈值 | 动作 |
|---|---|---|
| pending Admin operation/side effect 年龄 | > 2 分钟 | 查 Worker/Cron/DO/KV；用原 request ID 重试 |
| pending revocation 年龄 | > 2 分钟 | 禁止新序号；检查 DO、KV 和 Cron |
| event queue backlog / DLQ | 任意持续增长 / 任意 DLQ | 隔离失败事件并幂等 replay |
| Epoch 剩余有效期 | < 30d / 14d / 7d | 排期、升级严重度、执行 §4 |
| 签发失败率 | > 1%（5 分钟） | 检查 signing secret、IssuerDO、Epoch 状态 |
| 激活失败率 | > 5%（15 分钟） | 分析 release/client/keyset |
| 5xx | > 0.5%（5 分钟） | 检查依赖与错误预算 |

## 8. 定期安全作业

| 频率 | 作业 |
|---|---|
| 每次 PR | Rust fmt/check/test/clippy；Worker check/test/size/startup；依赖审计 |
| 每日 | pending journal、queue/DLQ、Epoch expiry 与 Secrets Store 访问异常 |
| 每周 | 抽样核对 Admin operation → AdminAuditDO → Queue → R2/index 完整链路 |
| 每月 | Admin token 使用/expiry、Cloudflare RBAC、break-glass 记录复核 |
| 每季度 | Epoch 轮换；随机 Runbook 演练；威胁模型复审 |
| 每年 | Root 保管链核验、恢复演练、外部安全审计 |

`copylocker audit verify` 尚未在 M1 实现，不能作为当前门禁命令。整链验证 CLI 发布后再替换
上述抽样流程。

## 9. 访问控制

| 资源 | 谁能访问 |
|---|---|
| Cloudflare account | 至少两名管理员，强制 MFA，日常最小权限 |
| Secrets Store Epoch key | 密钥管理员 + 只写部署身份 |
| Root Current / Next custody | 分离的保管人与审批人；任何单人不能恢复两者 |
| Bootstrap bundle | 初始化操作人短期持有；验证后销毁或独立加密 escrow |
| 生产 D1 | 正常操作只经 Admin API；bootstrap 和 token 紧急撤销为记录完整的 break-glass 例外 |
| Admin token | 每个 actor 独立 token；禁止共享 actor，尤其是 Epoch 双人审批 |
| CI credentials | 短期、最小 scope；不得使用 bootstrap 全 scope token |

离职/换人：撤销 Cloudflare 身份 → break-glass 撤销其 Admin token → 轮换其接触过的在线 secret
→ 若接触 Root custody，按组织策略重新分片/托管。

## 10. 合规支撑材料

- PQC/hybrid 算法与迁移说明
- 数据流图、保留和删除边界
- Root/Epoch/Admin credential 仪式记录与保管链
- Admin journal、双人审批和 break-glass 记录
- 第三方审计摘要、SBOM 与依赖许可
- DPA 与隐私政策模板
