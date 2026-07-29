# 功能需求清单（Functional Requirements）

编号规则：`FR-<域>-<序号>`。域：`SRV` 服务端 / `CLI` 客户端核心 / `NAT` 原生 SDK /
`WEB` Web SDK / `BLD` 构建工具 / `ADM` CLI 与 Admin API / `CRY` 密码学 /
`LIC` 授权模型 / `VER` 版本与变体 / `TLM` 分析与遥测 / `CON` 管理控制台。

优先级：P0 = v1.0 必须；P1 = v1.0 应该；P2 = v1.1；P3 = backlog。

---

## CRY — 密码学基座

| ID | 需求 | 优先级 |
|---|---|---|
| FR-CRY-001 | 定义 `CryptoSuite` trait 族（Sig/Kem/Aead/Kdf/Hash/Fpr/Codec/Binder），所有密码学调用经由槽位 | P0 |
| FR-CRY-002 | 实现开源参考套件 `CL-STD-1`（Ed25519+ML-DSA-65 混合签名、X-Wing KEM、XChaCha20-Poly1305、HKDF-SHA512） | P0 |
| FR-CRY-003 | 所有凭证头部携带 4 字节 `suite_id`，且该字段被签名/AEAD AAD 覆盖 | P0 |
| FR-CRY-004 | 混合签名必须两个分量都验证通过才算成功；单分量通过视为攻击并记录 | P0 |
| FR-CRY-005 | 提供 `copylocker-suite-testkit`：trait 一致性测试、属性测试、KAT 加载器 | P0 |
| FR-CRY-006 | 支持多套件并存与按 `suite_id` 分派（服务端），用于灰度迁移 | P1 |
| FR-CRY-007 | 实现紧凑套件 `CL-CMP-1`（FN-DSA-512 + Ed25519），仅用于 OLK | P1 |
| FR-CRY-008 | 实现私有套件 `CL-PRIV-1`（闭源仓库），含厂商参数派生器 | P1 |
| FR-CRY-009 | 所有密钥材料类型实现 `Zeroize`/`ZeroizeOnDrop`；禁止 `Debug` 泄露密钥 | P0 |
| FR-CRY-010 | 提供确定性测试 RNG 注入点（仅 `#[cfg(test)]` 与 CLI 的 `--deterministic` 下可用） | P0 |
| FR-CRY-011 | 密钥层级：离线 Root → Epoch（90d）→ 凭证；客户端 pin Root 公钥，验证 Epoch 证书链 | P0 |
| FR-CRY-012 | 支持 Root 公钥的多值 pin（主 + 备），用于根密钥轮换而不砖化客户端 | P0 |

## SRV — License Server

### 生命周期与实体

| ID | 需求 | 优先级 |
|---|---|---|
| FR-SRV-001 | 产品（Product）CRUD，含 `product_id`、名称、版本范围 | P0 |
| FR-SRV-002 | 策略（Policy）CRUD：mode、seats、duration、refresh_after、grace、max_transfers、指纹容差、是否允许 OLK | P0 |
| FR-SRV-003 | License 签发：批量生成 LK、绑定 Policy、可附元数据（订单号、邮箱） | P0 |
| FR-SRV-004 | License 状态：`active` / `suspended` / `expired` / `revoked`，状态迁移有审计 | P0 |
| FR-SRV-005 | Seat 管理：占用、释放、上限判定必须原子（Durable Object 单线程保证） | P0 |
| FR-SRV-006 | Machine/Activation 记录：指纹、首次激活时间、最近心跳、客户端版本、地理粗粒度 | P0 |
| FR-SRV-007 | 心跳与僵尸回收：超时未心跳的 Activation 由 DO alarm 自动释放席位 | P1 |
| FR-SRV-008 | 换机限额：按 Policy 限制周期内 deactivate/activate 次数 | P1 |

### 端点（客户端面）

| ID | 端点 | 说明 | 优先级 |
|---|---|---|---|
| FR-SRV-010 | `POST /v1/activate` | LK/账号 + AR → MachineCredential | P0 |
| FR-SRV-011 | `POST /v1/validate` | MC + nonce → ValidationTicket 或 KillOrder | P0 |
| FR-SRV-012 | `POST /v1/heartbeat` | 轻量存活上报（可与 validate 合并） | P1 |
| FR-SRV-013 | `POST /v1/deactivate` | 释放席位 + 服务端标记 | P0 |
| FR-SRV-014 | `GET  /v1/keys` | 当前 Epoch 公钥集 + 链 + `revocation_epoch`（可缓存，带签名） | P0 |
| FR-SRV-015 | `GET  /v1/revocations?since=<epoch>` | 吊销增量（签名） | P0 |
| FR-SRV-016 | `POST /v1/offline/request` | 上传 AR，返回 AResp（供联网中转设备使用） | P1 |
| FR-SRV-017 | `POST /v1/auth/login` `refresh` `logout` | Mode E 账号会话 | P1 |
| FR-SRV-018 | `POST /v1/integrity/report` | 客户端完整性异常上报（可选、限流、不可信） | P2 |

### 安全与健壮性

| ID | 需求 | 优先级 |
|---|---|---|
| FR-SRV-020 | 所有客户端端点做速率限制：按 IP、按 license_id、按指纹三个维度 | P0 |
| FR-SRV-021 | nonce 防重放：DO 内维护 nonce 缓存（TTL = 时钟容差 ×2），重复 nonce 拒绝 | P0 |
| FR-SRV-022 | 请求体大小限制、CBOR 深度限制、解析前长度校验（防解析型 DoS） | P0 |
| FR-SRV-023 | 服务端**从不信任**客户端上报的时间；所有时间戳以服务端为准 | P0 |
| FR-SRV-024 | 签发操作序列化于 `IssuerDO`，签发序号单调递增，写入哈希链审计日志 | P1 |
| FR-SRV-025 | 常数时间比较用于所有 MAC/token 校验 | P0 |
| FR-SRV-026 | 错误响应不泄露区分信息（"key 不存在" vs "key 已用尽"统一为通用错误 + 内部审计细分） | P1 |
| FR-SRV-027 | 支持 Turnstile 挡在激活端点前（可选），抵御自动化撞库 | P2 |
| FR-SRV-028 | 幂等性：`activate` 支持 `Idempotency-Key`，重试不重复占席位 | P0 |

### 异常检测

| ID | 需求 | 优先级 |
|---|---|---|
| FR-SRV-030 | 检测同一 license 短窗口内的多指纹/多地理激活，产生 `suspicion_score` | P2 |
| FR-SRV-031 | 检测指纹"漂移过快"（同一 machine_id 指纹属性频繁变化） | P2 |
| FR-SRV-032 | 可配置自动动作：仅告警 / 要求重新校验 / 自动挂起 | P2 |
| FR-SRV-033 | Webhook 外发（签名的 HMAC 头），事件：activated、revoked、suspicious、seat_exhausted | P1 |

## CLI — 客户端核心（`copylocker-core` / `copylocker-client`）

| ID | 需求 | 优先级 |
|---|---|---|
| FR-CLI-001 | 实现 §glossary 定义的状态机，状态迁移纯函数化、可完全单元测试 | P0 |
| FR-CLI-002 | 本地凭证存储：OS Keychain（macOS）/ DPAPI+Credential Manager（Windows）/ Secret Service（Linux），失败回退到 AEAD 文件 | P0 |
| FR-CLI-003 | 凭证在磁盘上始终以 AEAD 密文存在，密钥由指纹派生材料 + OS 保护结合 | P0 |
| FR-CLI-004 | 时钟守卫：维护单调高水位（last_seen_max），检测回拨；回拨超阈值 → 强制在线校验 | P0 |
| FR-CLI-005 | 机会性在线校验触发器（启动/网络恢复/唤醒/周期/插桩点/随机抖动） | P0 |
| FR-CLI-006 | 网络失败与密码学失败严格区分：前者进宽限，后者立即失效 | P0 |
| FR-CLI-007 | 收到 KillOrder → 立即擦除本地凭证与派生密钥并进入 `Revoked` | P0 |
| FR-CLI-008 | Feature Key 派生 API：`derive_feature_key(feature_id) -> SecretKey`（无 bool 返回值） | P0 |
| FR-CLI-009 | 传输层抽象 `trait Transport`，默认 HTTPS 实现，允许自定义（代理/内网中转） | P0 |
| FR-CLI-010 | 证书 pinning（可选）与 TLS 之上的应用层签名双保险 | P1 |
| FR-CLI-011 | 离线激活：生成 AR、导入 AResp（文件与 QR 两种编码） | P1 |
| FR-CLI-012 | OLK 导入与离线验证 | P1 |
| FR-CLI-013 | 设备指纹采集，可插拔 `FingerprintProvider`，默认提供 win/mac/linux 实现 | P0 |
| FR-CLI-014 | 指纹容差：多属性加权，允许 N 个属性变化仍视为同一设备（避免换网卡即失效） | P1 |
| FR-CLI-015 | 所有网络调用异步、非阻塞，绝不阻塞 UI 线程 | P0 |
| FR-CLI-016 | 结构化日志与诊断导出（`copylocker diagnose` 生成脱敏报告供支持使用） | P1 |

## NAT — 原生 SDK

| ID | 需求 | 优先级 |
|---|---|---|
| FR-NAT-001 | `tauri-plugin-copylocker`：Tauri v2 插件，静态链接，提供 command + event | P0 |
| FR-NAT-002 | Tauri 侧提供 `@copylocker/tauri` TS 绑定（类型安全，与 Rust 类型由 `specta`/`ts-rs` 同源生成） | P0 |
| FR-NAT-003 | `copylocker-node`：napi-rs 原生模块，跨平台预编译（darwin-arm64/x64, win32-x64/arm64, linux-x64/arm64-gnu/musl） | P0 |
| FR-NAT-004 | Electron 集成包 `@copylocker/electron`：主进程 API + contextBridge 安全桥 + 渲染进程客户端 | P0 |
| FR-NAT-005 | Electron 场景下把 `.node` 与 `app.asar` 的摘要纳入 Feature Key 派生输入 | P1 |
| FR-NAT-006 | `copylocker-ffi`：稳定 C ABI（`cbindgen` 生成头文件），供 Qt/Flutter/C++ 宿主 | P1 |
| FR-NAT-007 | 原生模块暴露给 JS 的接口为 challenge/response 与 seal/unseal，不暴露布尔判定 | P0 |
| FR-NAT-008 | 提供 `verify_self()`：校验自身二进制/模块摘要（原生侧），结果参与密钥派生而非返回 bool | P1 |

## WEB — Web SDK

| ID | 需求 | 优先级 |
|---|---|---|
| FR-WEB-001 | Rust → WASM 核心（`copylocker-wasm`），`wasm-bindgen`，导出面为不透明 CBOR challenge/response | P0 |
| FR-WEB-002 | TS 层 `@copylocker/web`：触发调度、传输、状态订阅、二段变换 | P0 |
| FR-WEB-003 | **拆分密钥派生**：最终 Feature Key = f(WASM 输出, TS 侧构建期注入常量, 运行时环境摘要)；单边替换必失败 | P0 |
| FR-WEB-004 | 导出符号名每次构建随机化（由 build seed 派生），并在 TS 侧由构建插件回填 | P1 |
| FR-WEB-005 | WASM 二进制摘要参与密钥派生（自校验） | P0 |
| FR-WEB-006 | 浏览器指纹提供者：稳定属性优先（storage 中的持久设备 ID + UA-CH + 硬件并发度等），标注为低强度 | P0 |
| FR-WEB-007 | 凭证存储：IndexedDB + 非可提取 `CryptoKey`（WebCrypto `extractable:false`）包裹 | P0 |
| FR-WEB-008 | 支持 Web Worker / SharedWorker 中运行核心，减少主线程 hook 面 | P1 |
| FR-WEB-009 | 支持 SSR/同构框架（Next/Nuxt/SvelteKit）：服务端渲染阶段跳过、客户端 hydrate 后初始化 | P1 |
| FR-WEB-010 | 提供 React / Vue / Svelte 的轻量绑定（hook / composable / store） | P2 |
| FR-WEB-011 | 支持 COOP/COEP、CSP 严格模式（不使用 `eval`、不使用内联 script，除非显式配置 nonce） | P0 |

## BLD — 构建期工具链

| ID | 需求 | 优先级 |
|---|---|---|
| FR-BLD-001 | `@copylocker/unplugin`：支持 Vite/Rollup/Webpack/Rspack/esbuild/Farm | P0 |
| FR-BLD-002 | 构建后遍历所有产物 chunk，按可配置 `hasher` 计算摘要，产出 `IntegrityManifest` | P0 |
| FR-BLD-003 | 用可配置 `signer` 对清单签名（默认本地开发密钥；生产建议远程签名服务/CI OIDC） | P0 |
| FR-BLD-004 | 将清单与验证 runtime 注入产物；支持 CDN、hash 文件名、动态 import、多入口 | P0 |
| FR-BLD-005 | `@guarded` decorator + 构建期函数体摘要采集（TS transformer / babel plugin / SWC plugin） | P0 |
| FR-BLD-006 | 运行时校验对页面性能影响可控：默认异步 + 分片 + 空闲期执行 + 采样率可配 | P0 |
| FR-BLD-007 | `copylocker-seal`：按 glob 选中资产/chunk，用 Feature Key 加密，运行时解密加载 | P0 |
| FR-BLD-008 | Build fingerprint 生成与注入（参与 Feature Key 派生，防跨版本凭证重放） | P0 |
| FR-BLD-009 | 支持 sourcemap（生产建议不发布；若发布则清单覆盖 map 文件） | P1 |
| FR-BLD-010 | 提供 `--verify` 模式：CI 中校验产物与清单一致，防发布事故 | P1 |
| FR-BLD-011 | 与常见混淆器（javascript-obfuscator 等）的执行顺序有明确文档与集成测试 | P2 |

## ADM — 管理面

| ID | 需求 | 优先级 |
|---|---|---|
| FR-ADM-001 | `copylocker-cli`：keygen（root/epoch）、issue、revoke、inspect、sign-manifest、dev-license、diagnose | P0 |
| FR-ADM-002 | Admin REST API（Bearer token + 细粒度 scope），全部操作写审计 | P0 |
| FR-ADM-003 | Admin API 的类型化客户端 `@copylocker/admin-sdk`（类型由 `ts-rs` 从 Rust 生成） | P1 |
| FR-ADM-004 | `policy simulate` CLI：给定 Policy + 场景，输出用户会经历的时间轴 | P0 |
| FR-ADM-005 | 支付 Webhook 入口（Stripe/Paddle/Lemon Squeezy 适配示例），验签后自动签发 License | P1 |
| FR-ADM-006 | 审计日志导出（R2 + 哈希链，可验证未被篡改） | P1 |
| FR-ADM-007 | 密钥轮换流程的引导式 CLI（含双密钥并行期、客户端兼容窗口检查） | P1 |
| FR-ADM-008 | 从 Keygen.sh / 自研方案导入 License 的迁移工具 | P3 |

## LIC — 授权模型（ADR-0009 / `02-architecture/licensing-model.md`）

| ID | 需求 | 优先级 |
|---|---|---|
| FR-LIC-001 | 权益目录：Feature / FeatureGroup（可嵌套）/ Tier（含 limits、rank）的 CRUD | P0 |
| FR-LIC-002 | `resolve()` 纯函数：目录 + EntitlementSpec + now → 确定性的扁平权益快照 | P0 |
| FR-LIC-003 | group 的 glob 引用（`export.*`）在解析时展开，**不下发通配** | P0 |
| FR-LIC-004 | 循环引用检测（深度上限 8），检出即报错不栈溢出 | P0 |
| FR-LIC-005 | `limits` 合并策略 `max` / `sum` / `override`，默认 `max` | P1 |
| FR-LIC-006 | **`feature_id` 不可变、不可复用**；重命名/删除在 CLI 与 API 层硬拦截 | P0 |
| FR-LIC-007 | 权益快照写入 MC；客户端不需要也拿不到目录 | P0 |
| FR-LIC-008 | `catalog_versions` 不可变快照，可复现历史解析结果 | P1 |
| FR-LIC-009 | 五轴 Policy：Entitlement × Validity × VersionScope × Seats × Mode | P0 |
| FR-LIC-010 | Validity：`Perpetual` / `FixedTerm` / `Subscription` / `Trial` | P0 |
| FR-LIC-011 | 订阅状态机：`active`/`past_due`/`canceling`/`suspended`/`ended`，webhook 驱动且幂等 | P0 |
| FR-LIC-012 | **dunning 宽限**：`not_after = current_period_end + dunning_grace`（默认 7d） | P0 |
| FR-LIC-013 | `refresh_after ≤ billing_period / 4`，保证取消能及时传播（配置时校验并警告） | P1 |
| FR-LIC-014 | **永久回退**：连续付费达阈值后记录 `fallback_earned_at`；取消时转永久 + 版本封顶 | P1 |
| FR-LIC-015 | 永久回退幂等（`fallback_earned_at` 一旦写入不更新）、可 dry-run、可因退款撤销 | P1 |
| FR-LIC-016 | Trial：`once_per` ∈ {fingerprint, account, email}；强制 `seats=1` 且不可换机 | P0 |
| FR-LIC-017 | Trial 防滥用：指纹容差去重、速率限制、可选 Turnstile、可人工延长（有上限+审计） | P1 |
| FR-LIC-018 | VersionScope：`Unlimited` / `SemverRange` / **`ReleasedBefore`** / `Pinned` | P0 |
| FR-LIC-019 | **版本范围由服务端强制**：超范围则不下发该 release 的 `wrapped_keks` | P0 |
| FR-LIC-020 | 超范围时客户端进入**受限模式**，提示可用最高版本 + 升级入口，**不得表现为盗版警告** | P0 |
| FR-LIC-021 | Grant（加购）：可带独立有效期，叠加于 tier 之上 | P1 |
| FR-LIC-022 | `licenses.entitlement_override_json`：单 License 权益覆盖（企业定制） | P1 |
| FR-LIC-023 | `scheduled_changes`：改 tier/席位/版本范围可排到周期结束生效 | P1 |
| FR-LIC-024 | 权益变更传播：VT 携带新 `entitlements` + `refreshed wrapped_keks` + `refresh_now` | P0 |
| FR-LIC-025 | 11 个预设（trial-14d / perpetual-fallback / sub-annual-fallback / enterprise-airgap …） | P1 |
| FR-LIC-026 | **配置预览器**：给定 Policy + 场景，输出用户经历的时间轴（CLI P0，控制台 P1） | P0 |
| FR-LIC-027 | `subscription_hint` 下发：支付失败提示、永久回退进度 | P2 |
| FR-LIC-028 | `limits` 的运行时强制由 Vendor 应用负责；文档必须明确此边界 | P0 |

## VER — 版本兼容与发布变体（ADR-0008 / `02-architecture/versioning-and-variants.md`）

| ID | 需求 | 优先级 |
|---|---|---|
| FR-VER-001 | 六个独立版本轴：`proto_ver` / `suite_id` / `variant_id` / `sdk_version` / `app_version` / `security_floor` | P0 |
| FR-VER-002 | Release 注册：`copylocker release register` 写入 `releases` 表并产出 `variant.lock` | P0 |
| FR-VER-003 | 未注册的 `release_id` → 激活返回 `1007`，错误详情含注册命令 | P0 |
| FR-VER-004 | `variant_seed` 派生：codec 掩码/置换、FK info、binder 调度、WASM 符号名、常量布局、guard 盐、**离线验证路径参数** | P0 |
| FR-VER-005 | **变体只改形态不改语义**：不影响签名算法、`tbs` 内容、KEM、证书链验证 | P0 |
| FR-VER-006 | **本地存储的最外层封装必须 variant 无关**（升级不得导致重新激活） | P0 |
| FR-VER-007 | 客户端内置 `variant_current` + `variant_accept[]`（默认最近 3 个） | P0 |
| FR-VER-008 | 在线升级无感：检测 variant 不匹配 → 触发 validate → 拿新 `wrapped_keks` | P0 |
| FR-VER-009 | 离线升级策略：`require_online`（默认）/ `preload_n` / `variant_stable` | P1 |
| FR-VER-010 | `variant_stable` 在 CLI 与控制台显示明确安全警告 | P1 |
| FR-VER-011 | 版本级吊销：`mark-compromised` × {`warn`, `force_upgrade`, `revoke`}，默认 dry-run | P0 |
| FR-VER-012 | `security_floor` 单调递增，写入 MC/VT；客户端持久化最大值并拒绝更低凭证 | P0 |
| FR-VER-013 | `security_floor` 与 `clock.last_seen_max` 一样多处冗余 + AEAD 保护 | P0 |
| FR-VER-014 | 合法回滚支持：未标记 compromised 的旧版本可正常签发；Admin 可临时豁免 | P1 |
| FR-VER-015 | 兼容承诺：服务端支持 proto N 与 N-1；客户端支持 N 与 N-1 | P0 |
| FR-VER-016 | 旧套件的验证能力保留至该套件签发的凭证自然过期 | P0 |
| FR-VER-017 | 弃用流程：占比 < 1% → 公告 → 观察 ≥2 个 Epoch → 提升 `min_*` | P1 |
| FR-VER-018 | 历史版本 KAT 向量**永久保留**于 `vectors/history/<version>/` | P0 |
| FR-VER-019 | `compat-matrix` CI：最近 4 个版本客户端 × 当前服务端交叉测试 | P0 |

## TLM — 分析与遥测（ADR-0007 / `03-modules/90-analytics-telemetry.md`）

| ID | 需求 | 优先级 |
|---|---|---|
| FR-TLM-001 | 三层模型：T0 协议派生（默认开）/ T1 聚合遥测（默认关+同意）/ T2 事件（钩子，不自建） | P0 |
| FR-TLM-002 | **T0 零额外采集**：字段边界见 ADR-0007，不得扩充 | P0 |
| FR-TLM-003 | 指标目录：激活 / 活跃 / 版本 / 商业 / 健康 五类，**每个指标有唯一 ID 与精确定义** | P0 |
| FR-TLM-004 | `act.by_path`：在线 / 离线 AR / OLK / 账号 四种激活路径的分布 | P0 |
| FR-TLM-005 | `dev.checked_in_7d` / `_28d`：签到设备数（**不提供名为 DAU 的指标**） | P0 |
| FR-TLM-006 | **分辨率提示**：`refresh_after` 大于查询粒度时，API 与 UI 必须返回警告 | P0 |
| FR-TLM-007 | 版本类指标：app / release / variant / sdk / os-arch / proto-suite 分布 + 采纳曲线 + 升级滞后 | P0 |
| FR-TLM-008 | 商业类：席位利用率、**席位耗尽事件（加购线索）**、流失、续期、试用转化、地理分布 | P1 |
| FR-TLM-009 | 健康类：校验成功率、宽限期占比、**完整性失败（按 release 分组）**、时钟回拨、suspicion | P0 |
| FR-TLM-010 | HLL 草图（p=14）做唯一数排重；cube 为**固定集合**，新增需评审 | P0 |
| FR-TLM-011 | 草图可合并 → 任意窗口；不含个人数据 → 可长期保留且不受 DSR 删除影响 | P0 |
| FR-TLM-012 | 小规模同时提供 D1 精确路径；响应标注 `source` 与 `error_pct` | P1 |
| FR-TLM-013 | **k-匿名抑制**：桶内唯一设备数 < 5 显示为 `<5` | P0 |
| FR-TLM-014 | 双管线：Analytics Engine（近实时含采样）+ Queue→R2→Cron→D1（精确 T+1） | P1 |
| FR-TLM-015 | T1 搭车 `validate` 请求上报，**不新增端点/请求**；上限 512 字节 | P1 |
| FR-TLM-016 | T1 只上报**预聚合计数与分桶**，不含时间戳序列、不含顺序 | P0 |
| FR-TLM-017 | T1 的 feature 必须在 SDK 配置白名单内；未声明的静默丢弃（开发模式抛错） | P1 |
| FR-TLM-018 | T1 每次上报前调用 `consent()`；`consent_version = 0` 服务端丢弃并计数 | P0 |
| FR-TLM-019 | `tier: 'T1'` 未提供 `consent` → SDK 初始化**报错**（非警告） | P0 |
| FR-TLM-020 | 遥测标记为 `untrusted`，与 T0 分表存储、UI 分区展示 | P0 |
| FR-TLM-021 | 异常值裁剪（如 `session_count` 上限）并计入异常计数 | P1 |
| FR-TLM-022 | Admin API：`metrics` / `definitions` / `export` / `subscriptions`；`analytics:r` 独立 scope | P1 |
| FR-TLM-023 | 盲区标记：离线设备不可观测、OLK 安装数不可观测，API 与 UI 显式声明 | P0 |
| FR-TLM-024 | 可选「离线使用回执」：设备偶尔联网时上传签名的计数摘要（需 Policy 开启） | P3 |
| FR-TLM-025 | `dsr export|delete`、`telemetry purge`；HLL 与 rollup 不回溯修改（须写入隐私政策） | P0 |
| FR-TLM-026 | `legal-sync` CI 门禁：采集字段 schema 单一来源 → 自动生成数据清单 → 不一致即失败 | P0 |
| FR-TLM-027 | 新增采集字段的 PR 必须打 `needs-legal-review` 标签并在 CHANGELOG 说明隐私影响 | P0 |

## CON — 管理控制台（ADR-0010 / `03-modules/95-admin-console.md`）

| ID | 需求 | 优先级 |
|---|---|---|
| FR-CON-001 | SvelteKit + shadcn-svelte/bits-ui + Tailwind，`adapter-cloudflare` 部署为独立 Worker | P1 |
| FR-CON-002 | 经 **Service Binding** 调 API Worker；控制台**不绑定**签名密钥、不直连 D1/DO | P0 |
| FR-CON-003 | 认证：Cloudflare Access（默认）或内置 Passkey/WebAuthn 会话 | P1 |
| FR-CON-004 | 控制台是**不可信前端**：所有变更在 API Worker 侧重新做 scope 校验与审计 | P0 |
| FR-CON-005 | 权益目录编辑器：拖拽、实时解析预览、循环引用即时检出、glob 展开预览 | P1 |
| FR-CON-006 | **不可变性护栏**：已发布 feature 的重命名/删除按钮禁用并说明原因 | P0 |
| FR-CON-007 | Policy 编辑器：五轴分区 + 预设选择器 + **危险配置即时警告**（6 类） | P1 |
| FR-CON-008 | **配置预览器**：时间轴可视化 + 内置场景库 + 可拖动时间游标 | P1 |
| FR-CON-009 | Releases 页：注册状态、采纳曲线、完整性失败率、**破解疑似信号**、compromised 两步确认 | P1 |
| FR-CON-010 | 分析看板：口径 `ⓘ`、数据来源标注、分辨率警告、T1 独立分区标注"不可信" | P1 |
| FR-CON-011 | 离线激活门户（公开路由，不共享 admin 认证代码路径）+ QR 扫描 + 限流 + Turnstile | P1 |
| FR-CON-012 | 高危操作两步确认（dry-run 影响面 → 输入目标 ID），与 CLI 行为一致 | P0 |
| FR-CON-013 | 明文 License Key 仅签发响应中出现一次，强制下载 CSV 后从内存清除 | P0 |
| FR-CON-014 | 不写 localStorage / IndexedDB；CSP `script-src 'self'` 无 `unsafe-inline` | P0 |
| FR-CON-015 | 可访问性：axe 无 critical/serious，键盘全流程可操作 | P1 |
| FR-CON-016 | i18n（Paraglide，编译期抽取）；暗色模式 | P2 |
| FR-CON-017 | shadcn-svelte 源码在仓库内 → 建立季度性上游同步流程 | P2 |
