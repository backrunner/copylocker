# 系统架构

## 1. 全局视图

```
┌───────────────────────────────── Vendor 侧 ─────────────────────────────────┐
│                                                                             │
│  离线签名机（air-gapped）                    CI / 发布流水线                 │
│  ┌──────────────────────┐                  ┌─────────────────────────────┐  │
│  │ Root Key (PQ hybrid) │  签发 Epoch 证书  │ @copylocker/unplugin        │  │
│  │ HSM / YubiKey / 纸备 │ ───────────────▶ │ copylocker-seal             │  │
│  └──────────────────────┘                  │ 产出：IntegrityManifest+签名 │  │
│            │ pin 到客户端                   └─────────────┬───────────────┘  │
└────────────┼──────────────────────────────────────────────┼─────────────────┘
             │                                              │
             ▼                                              ▼
┌──────────────────── Cloudflare（Vendor 自己的账号）────────────────────────┐
│                                                                            │
│   ┌────────────────────────┐  Service Binding                              │
│   │ copylocker-admin       │ ─────(内部,不出网)────┐                        │
│   │ SvelteKit SSR Worker   │                       │                        │
│   │ · 目录/Policy 编辑器    │  ← Cloudflare Access  │                        │
│   │ · 配置预览器            │     或 Passkey 会话   │                        │
│   │ · Release/分析看板      │                       │                        │
│   │ · 离线激活门户（公开）   │  ✗ 无密钥绑定         │                        │
│   └────────────────────────┘  ✗ 无 D1/DO 直连      ▼                        │
│                                                                            │
│   Workers（Rust / workers-rs · copylocker-worker）                         │
│   ┌──────────────────────────────────────────────────────────────────┐     │
│   │ 路由 · 限流 · CBOR 编解码 · 适配层                                 │     │
│   │        └── copylocker-server-core（纯 Rust 领域逻辑）             │     │
│   └───┬────────────┬─────────────┬──────────────┬──────────────┬─────┘     │
│       │            │             │              │              │           │
│   ┌───▼────┐  ┌────▼─────┐  ┌────▼────┐   ┌─────▼────┐   ┌─────▼─────┐     │
│   │LicenseDO│ │AccountDO │  │IssuerDO │   │   D1     │   │    KV     │     │
│   │(SQLite) │ │(SQLite)  │  │(签名序列)│   │ 目录/报表 │   │公钥/epoch │     │
│   │席位/激活 │ │会话/并发 │  │审计哈希链│   │          │   │Policy快照 │     │
│   │nonce/alarm            │  └────┬────┘   └──────────┘   └───────────┘     │
│   └────┬────┘  └──────────┘       │                                        │
│        │                    ┌─────▼────────┐   ┌────────────┐              │
│        └───outbox──────────▶│   Queues     │──▶│     R2     │              │
│                             │审计/分析/回调 │   │冷存/离线包 │              │
│                             └──────┬───────┘   │  /分析明细  │              │
│                                    │           └──────┬─────┘              │
│                          Cron 每日 │                  │                    │
│                                    ▼                  ▼                    │
│                          ┌──────────────────────────────────┐              │
│                          │ D1: analytics_rollup + HLL 草图  │              │
│                          │ Analytics Engine（近实时,含采样） │              │
│                          └──────────────────────────────────┘              │
│                                    ▲                                       │
│                             ┌──────┴────────┐                              │
│                             │ Secrets Store │ Epoch 私钥（RBAC+审计）      │
│                             └───────────────┘                              │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     │ HTTPS + 应用层签名（TLS 之上再签一层）
        ┌────────────────────────────┼────────────────────────────┐
        ▼                            ▼                            ▼
┌───────────────┐          ┌──────────────────┐         ┌──────────────────┐
│  Tauri App    │          │  Electron App    │         │   Web App        │
│               │          │                  │         │                  │
│ tauri-plugin- │          │ copylocker-node  │         │ copylocker-wasm  │
│ copylocker    │          │ (napi-rs .node)  │         │       ╱╲         │
│   (静态链接)   │          │  主进程 + 桥      │         │  @copylocker/web │
│      │        │          │       │          │         │  (TS 触发+二段变换)│
│      ▼        │          │       ▼          │         │       │          │
│ copylocker-core          │ copylocker-core  │         │ @copylocker/guard│
│ + copylocker-store       │ + store          │         │ (完整性 runtime) │
│ + fingerprint            │ + fingerprint    │         │ IndexedDB+WebCrypto│
└───────────────┘          └──────────────────┘         └──────────────────┘
```

## 2. 分层模型

| 层 | 职责 | 代码位置 | 平台无关？ |
|---|---|---|---|
| **L5 宿主集成层** | Tauri command / Electron IPC / TS API / 构建插件 | `copylocker-tauri`、`copylocker-node`、`packages/*` | ❌ |
| **L4 客户端外壳** | 触发调度、传输、存储、指纹 | `copylocker-client`、`-store`、`-fingerprint` | 部分 |
| **L3 领域核心** | 状态机、策略判定、时钟守卫、密钥派生 | `copylocker-core`、`copylocker-server-core` | ✅ 纯函数 |
| **L2 协议层** | 凭证编解码、信封、版本协商 | `copylocker-proto` | ✅ |
| **L1 密码学槽位** | trait 契约 + Suite 实现 | `copylocker-suite`、`-suite-std`、`-suite-priv` | ✅ |
| **L0 原语** | ml-dsa / ml-kem / dalek / chacha / hkdf / blake3 | 外部 crate | ✅ |

**核心不变式**：L1–L3 完全平台无关、无 I/O、纯 Rust、可在 native 上跑完整测试与 fuzz。
所有平台差异（Cloudflare 绑定、OS keychain、浏览器 API）都被推到 L4/L5，通过 trait 注入。

```rust
// L3 的形状：所有外部世界通过 trait 注入
pub struct Core<S: CryptoSuite, T: Transport, K: KeyStore, C: Clock, F: Fingerprinter> { ... }
```

## 3. 数据流：在线校验（最热路径）

```
客户端                          Worker                       LicenseDO
  │                               │                              │
  │ 1. 生成 nonce_c、读本地 MC     │                              │
  │ 2. POST /v1/validate          │                              │
  │    { suite_id, license_id,    │                              │
  │      machine_id,              │                              │
  │      fingerprint, nonce_c,    │                              │
  │      client_sig }  ───────────▶ 3. 限流 / 大小校验            │
  │                               │ 4. KV 读 policy 快照(缓存)    │
  │                               │ 5. 路由到 idFromName(license) │
  │                               │ ────────────────────────────▶ 6. 事务内：
  │                               │                              │   - nonce 去重
  │                               │                              │   - 查 activation
  │                               │                              │   - 查吊销
  │                               │                              │   - 更新 last_seen
  │                               │                              │   - 计算 next refresh
  │                               │ ◀──────────────────────────── 7. 判定结果
  │                               │ 8. 调 IssuerDO 签 VT / KillOrder
  │ ◀─────────────────────────────  9. 返回 CBOR(VT | KillOrder)  │
  │ 10. 验签（Root→Epoch→VT 链）   │                              │
  │ 11. 校验 nonce 回显、时间窗    │                              │
  │ 12. 更新本地状态与时钟高水位   │                              │
  │ 13. 重新派生 SessionRoot/FK   │                              │
  │ 14. （若 KillOrder）擦除凭证   │                              │
```

**关键点**
- 第 8 步的签名可被优化：VT 的多数字段可预签或用轻量 MAC（对称、Epoch 派生）+ 周期性完整签名，
  以规避每请求 PQ 签名的 CPU 成本。**决策见 `protocol-spec.md` §VT 的双层设计**。
- 第 10 步客户端必须验证完整链，不能只验 VT。
- 第 13 步：Feature Key 随每次成功校验刷新 → 旧的被截获的响应无法长期复用。

## 4. 数据流：激活

```
客户端                                  Worker / LicenseDO
  │ 1. 采集指纹 fp = HMAC(vendor_salt, attrs)
  │ 2. 生成设备长期 KEM 密钥对（存 keychain）
  │ 3. AR = { license_key | account_token, fp, device_kem_pk,
  │           device_sig_vk, nonce, client_info, proof }
  │ 4. POST /v1/activate（含 Idempotency-Key）───────▶
  │                                        5. 验证设备自签 proof；解析 LK → license_id
  │                                        6. DO：席位事务
  │                                           - 已有同 fp 的 activation? → 复用
  │                                           - 有空席位? → 占位
  │                                           - 否则 → SEAT_EXHAUSTED
  │                                        7. IssuerDO 签发 MC：
  │                                           - CredentialSecret ← 随机
  │                                           - kem_ct ← Encap(device_kem_pk)
  │                                           - 签名 payload（含 fp、entitlements、
  │                                             not_after、refresh_after、
  │                                             revocation_epoch、build_fingerprint）
  │ ◀──────────────── 8. CBOR(MC) + epoch 证书链
  │ 9. 验签链 → Decap 得 CredentialSecret
  │ 10. 用 fp 派生 + OS keychain 双重保护落盘
  │ 11. 派生 SessionRoot → FeatureKey → 解封 Sealed Assets
```

## 5. 数据流：离线（air-gapped）激活

```
[离线设备]                    [任意联网设备/手机]                [Worker]
 AR 文件 / QR  ──── 人工搬运 ───▶ 上传门户 / 扫码  ──── HTTPS ────▶ /v1/offline/request
                                                                       │
 导入 AResp ◀──── 人工搬运 ───── 下载 AResp / 显示 QR ◀────────────────┘
 验签 → Decap → 落地
```

- AR 中的 `nonce` 与 `device_kem_pk` 保证 AResp 无法被复用到别的设备。
- AResp 有 `valid_until`（默认 7 天），过期则需重新生成 AR。
- 离线设备的 `refresh_after` 由 Policy 指定为 `never`（纯离线）或长周期 + 手动续期文件。

## 6. 客户端状态机

```
                    ┌───────────────────────────────────────────┐
                    │                                           │
  Unlicensed ──activate──▶ Activating ──ok──▶ Active            │
      ▲                        │                │               │
      │                       err               │ past refresh_after
      │                        ▼                ▼               │
      │                    Unlicensed    NeedsRevalidation       │
      │                                        │                │
      │                          online ok ────┘                │
      │                          net fail ─▶ Grace ──deadline──▶ Locked
      │                                        │                  │
      │                          online ok ────┘        online ok │
      │                                                           │
      └──── KillOrder / 吊销命中 ──▶ Revoked ──user re-activate───┘
                                        ▲
      Tampered ◀── 完整性校验失败 ───────┘（Tampered 也可直接转 Locked，按 Policy）
```

**迁移规则（必须严格实现，见 `copylocker-core::state`）**

| 事件 | Active | NeedsRevalidation | Grace | Locked |
|---|---|---|---|---|
| 在线校验成功 | → Active（刷新期限） | → Active | → Active | → Active |
| 在线校验返回 KillOrder | → Revoked（**立即擦除**） | → Revoked | → Revoked | → Revoked |
| 在线校验签名不合法 | → Tampered | → Tampered | → Tampered | → Tampered |
| 网络不可达 | 无变化 | 无变化 | 无变化 | 无变化 |
| 时钟到达 `refresh_after` | → NeedsRevalidation | — | — | — |
| 首次网络失败于 NeedsRevalidation | — | → Grace | — | — |
| 时钟到达 `grace_deadline` 或 `not_after` | → Locked | → Locked | → Locked | — |
| 检测到时钟回拨 > 阈值 | → NeedsRevalidation + 强制立即校验 | — | — | — |

> **fail-open vs fail-closed 的分界线**：网络类失败 fail-open（进入 Grace）；
> 密码学/协议/吊销类失败 fail-closed（立即失效）。这两类在代码中用**不同的 error enum**，
> 禁止用一个 `Error` 类型混合，并有 lint 保证不会误处理。

## 7. 部署形态

| 形态 | 说明 |
|---|---|
| **单 Vendor 单环境** | 一个 Cloudflare 账号，`dev` / `staging` / `prod` 三套 Worker + 三套 D1/DO namespace |
| **多产品** | 同一部署内多 `product_id`，Policy 隔离，Admin token 可按 product scope |
| **多区域数据本地化** | 用 Cloudflare Jurisdictional Restrictions 约束 DO 落地区域（EU / FedRAMP） |
| **未来：托管 SaaS** | 多租户 Worker + 每租户独立 Root Key，v1 不做 |

## 8. 版本与兼容策略

六个独立的版本轴（`proto_ver` / `suite_id` / `variant_id` / `sdk_version` / `app_version` /
`security_floor`）、发布变体、版本级吊销与兼容矩阵，见
[`versioning-and-variants.md`](versioning-and-variants.md)。

## 9. 与需求的追溯

| 架构元素 | 满足的需求 |
|---|---|
| L1–L3 平台无关分层 | FR-CRY-001、NFR-PORT-001/004、NFR-DX-004 |
| DO 席位事务 | FR-SRV-005、AC-10、NFR-PERF-008 |
| 双 KEM 密封 + 指纹绑定 | FR-CLI-003、AC-6、NFR-SEC-008 |
| Root→Epoch 链 + pin | FR-CRY-011/012、NFR-SEC-003 |
| 状态机的 fail-open/closed 分界 | FR-CLI-006、AC-2、AC-4 |
| 机会性触发器 | FR-CLI-005、AC-3、PRD §5.1 |
| Feature Key 刷新 | ADR-0004、AC-8 |
| 权益服务端解析 + 快照 | FR-LIC-002/007、ADR-0009 |
| Release 注册表 + 变体 | FR-VER-002/004、ADR-0008 |
| `security_floor` 防降级 | FR-VER-012、RT-9 |
| 控制台与 API 分离 + Service Binding | FR-CON-002/004、ADR-0010 |
| 分析双管线 + HLL | FR-TLM-010/014、ADR-0007 |
