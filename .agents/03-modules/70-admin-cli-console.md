# 模块：CLI 与 Admin API

Crate：`copylocker-cli`  
需求：FR-ADM-*、NFR-OPS-*

> 管理控制台（Web UI）见 [`95-admin-console.md`](95-admin-console.md)。本文只定义可以独立用于
> CI、脚本和无 UI 部署的 CLI 与 Admin REST API，并明确区分 M1 已实现能力和后续规划。

## 1. M1 已实现的 CLI

`copylocker` 是单一跨平台二进制。`--json` 可置于子命令前后；成功时 stdout 只有一个
稳定 JSON 对象，失败时非零退出并返回 `error.code`。远端 API 的动态错误码保持原样。

```text
copylocker
├── init                              从内嵌模板创建可部署项目
├── deploy                            默认 Wrangler dry-run；--confirm 才远端迁移/部署
├── bootstrap prepare | apply         首个 vendor/product/Admin credential
├── doctor [--check-api]              默认离线；显式选择只读 API 探测
├── keygen root | epoch | build       Root、Epoch、构建签名密钥
├── inspect                           解码协议工件
├── kat generate | verify | check     KAT 生成、验证与漂移门禁
├── catalog
│   ├── feature | group | tier        本地目录演进
│   ├── resolve | export | import     本地解析、导出、导入
│   └── pull | push                   远端目录同步
├── policy
│   ├── presets | create              本地预设与生成
│   ├── validate | simulate           本地验证与时间轴模拟
│   └── list | show | push | update   远端策略管理
├── license
│   ├── issue | list | show
│   ├── suspend | resume | extend
│   ├── change-tier | preview-fallback | machines
│   └── revoke                        默认服务端 dry-run
├── epoch
│   ├── list | show
│   ├── upload | rotate               上传真实 Root 签名证书
│   └── revoke                        默认 dry-run；双人审批
└── request get                       仅允许 /v1/admin/* 的只读逃生口
```

### 1.1 连接与凭据

API origin 按 `--api-url`、`COPYLOCKER_API_URL`、`copylocker.json` 顺序解析。Admin token
只从 `--admin-token-env` 指定的环境变量，或项目配置的 `admin_token_env`（默认
`COPYLOCKER_ADMIN_TOKEN`）读取。CLI 不提供明文 token 参数。

客户端拒绝带用户名/密码或路径的 origin、禁止跟随 redirect、只允许
`/v1/admin/*`、把响应限制为 4 MiB，并验证 `clat_` 后 32 byte canonical base64url 格式。
这些约束用于避免 Bearer token 被 redirect 或任意路径转发到其他服务。

### 1.2 首次 bootstrap

迁移后的新 D1 没有 vendor、product 或 Admin token；部署成功本身不等于 Admin API 可用。

```bash
copylocker bootstrap prepare \
  --project server \
  --vendor vendor-acme \
  --actor owner \
  --out /secure/copylocker-bootstrap.json

copylocker bootstrap apply --project server --bundle /secure/copylocker-bootstrap.json
copylocker bootstrap apply --project server --bundle /secure/copylocker-bootstrap.json --confirm
```

- `prepare` 是 create-only，输出 mode `0600` 恢复包；stdout/JSON 不含明文 token 或 pepper。
- 恢复包绑定 project、product、Secrets Store ID，并随 token 到期；权限过宽、过期、畸形或
  属于另一项目时拒绝。
- `apply` 默认 dry-run。`--confirm` 后通过 Wrangler stdin 上传 `ADMIN_TOKEN_PEPPER`，执行
  D1 migrations，并用 conflict-checking SQL 写首个 vendor/product/token。
- D1 只存 `HMAC(pepper, token)`。若 secret 已上传但后续 D1 步骤失败，用同一恢复包加
  `--confirm --skip-secret-upload` 重试。
- 将恢复包中的 `admin_token` 转移到项目配置指定的环境变量后，销毁恢复包；需要灾难恢复
  时则按生产凭据等级加密托管，禁止入库或进入日志。

### 1.3 幂等与危险操作

所有远端 mutation 都要求显式 `Idempotency-Key`。同 key + 同 canonical request 重放原结果；
同 key + 不同请求返回 `idempotency_conflict`。`catalog push` 接受一个稳定前缀，为每个实际
变化的 item 派生独立 key。

`catalog push` 在第一次写请求前完成全量演进验证，禁止删除远端 ID；按 feature、group 的
include 拓扑序、tier 顺序更新。把 limit key 从一个 tier 移到另一个 tier 时先提交并集桥接，
再收敛为目标定义，避免瞬时违反不可删除护栏。

License 与 Epoch 吊销默认调用 `dry_run=true`。确认 License 吊销必须增加 `--confirm` 和
idempotency key。Epoch 还要求：

1. CLI 在建连前校验 `--confirm-epoch-id` 与目标完全一致；不匹配时绝不发请求。
2. 服务端已有覆盖该 product/time window 的有效 replacement Epoch。
3. 第一名 actor 的批准写入 D1，第二名不同 actor 在 15 分钟内用另一个 idempotency key 批准。
4. 只有第二次批准分配 revocation sequence 并发布；同 actor、过期窗口或重复完成均拒绝。

### 1.4 Root 与 Epoch 工件

当前 CLI 直接生成 mode-0600 Root secret 文件，不实现 Shamir 或硬件 token 集成。组织若要求
3-of-5/HSM，必须在 CLI 之外执行托管和恢复仪式。

```bash
copylocker keygen root --out-dir /secure/root --offline-confirm
copylocker keygen epoch \
  --root-key /secure/root/cl-root.secret.json \
  --product my-app \
  --not-before 1767225600 \
  --not-after 1775001600 \
  --out-dir /secure/epoch

copylocker epoch upload /secure/epoch/epoch-0011223344556677.cert.cbor \
  --root-public /secure/root/cl-root.public.json \
  --idempotency-key epoch-0011223344556677-upload
```

Worker signing secret 与 fast-signing secret 只进 Secrets Store；Admin API 只接收证书和 Root
公钥并重新验证真实签名，不信任客户端自报的 Epoch 元数据。

## 2. M1 Admin REST API

路径前缀为 `/v1/admin/*`，JSON，Bearer token，建议再置于 Cloudflare Access 之后。所有响应
均 `Cache-Control: no-store`，认证后按 token 的 vendor 做资源归属过滤。

| 分组 | 已实现端点 | scope |
|---|---|---|
| 目录 | `GET/POST/PATCH /catalog/{features,groups,tiers}`、`POST /catalog/resolve` | `catalog:rw` |
| 策略 | `GET/POST /policies`、`GET/PATCH /policies/:id` | `policies:rw` |
| 授权 | `GET/POST /licenses`、`GET/PATCH /licenses/:id`、`POST /licenses/:id/change-tier`、`GET /licenses/:id/preview-fallback`、`GET /licenses/:id/machines` | `licenses:rw` |
| 日常吊销 | `POST /{licenses,machines}/:id/revoke?dry_run=true\|false` | `revoke` |
| Epoch | `GET/POST /epochs`、`GET /epochs/:id` | `epochs:rw` |
| Epoch 吊销 | `POST /epochs/:id/revoke?dry_run=true\|false` | `epochs:rw`；确认请求另需 `revoke` |

Admin token wire format：

```text
Authorization: Bearer clat_<32 bytes canonical base64url without padding>
```

服务端只存 `HMAC(ADMIN_TOKEN_PEPPER, token)`，并校验 `not_before`、`expires_at`、
`revoked_at` 与 scope。M1 的 bootstrap token 具有完整已知 scope；token 创建、缩权、轮换、
撤销 API 属于后续范围。

### 2.1 Journal、审计与恢复

非普通吊销的 mutation 在一个 D1 batch 中写业务状态、不可变 `admin_operations` journal，
以及需要 optimistic lock 的 `admin_entity_versions`。后续 checkpoint 顺序固定：

1. 执行 journal 中记录的 DO/KV side effect，并写 `side_effect_at`。
2. 用 `operation_id` 幂等追加到 `AdminAuditDO`，镜像到 `admin_audit_events`。
3. Queue 接受事件后写 `enqueued_at` 与 `completed_at`。
4. Consumer 把 canonical 全文归档 R2，并写 D1 `audit_index`。

每分钟 Cron 严格按“未完成 side effect → 未完成 Admin operation → 未完成 revocation → 到期
billing transition”恢复，每类每 tick 至多推进一条。恢复必须复用原 operation/request ID、entity
version、revocation seq 和 side-effect payload；禁止删 pending 行或另分配序号。

普通 License/Machine/Epoch 最终吊销使用严格单调的 `revocations.seq`。前一条未完成 KV batch
与 `rev:epoch` 发布前，后一条不能分配序号，从而避免客户端永远无法跨越的空洞。

## 3. M1 之后

以下仍是路线图，不得在 M1 runbook 或集成中当成已发布契约：

- release 注册、deprecate、compromise 与 manifest sign/verify；
- standalone machine release/revoke CLI；
- analytics 查询/导出与 subscriptions；
- audit 查询/整链 verify、每日 anchor；
- DSR export/delete、telemetry purge；
- Admin token lifecycle、OIDC token exchange、Service Binding console auth；
- Web 管理控制台、Admin SDK、offline/OLK、diagnose、estimate、runbook 子命令。

支付 webhook 已作为运行时集成存在，但不是 `/v1/admin/*` 资源管理 API。事件仍必须按 provider
event ID 幂等，并处理签名时间窗、重放与乱序。

## 4. 测试门禁

| 类型 | M1 覆盖 |
|---|---|
| CLI 工作流 | token/header/idempotency、redirect、raw path、dry-run、typed confirmation |
| Catalog | create/update/skip、依赖拓扑、limit-key bridge、不可删除演进 |
| Epoch | 真实 Root 签名、replacement、双 actor/15 分钟审批、KV keyset/revocation batch |
| Journal | D1 原子提交、DO/KV side effect、AdminAuditDO/Queue 中断恢复、Cron 顺序 |
| 权限 | canonical token、时间窗、vendor ownership、scope matrix |
| 发布门禁 | Rust fmt/check/test/clippy；Worker check/test/size/startup |
