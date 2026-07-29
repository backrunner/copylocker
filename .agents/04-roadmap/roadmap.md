# 路线图

假设：3 名工程师全职（A：Rust/密码学；B：全栈/前端工具链/控制台；C：服务端/DX）。
总计约 **44 周到 v1.0 GA**。

```
M0 密码学与协议基座    ████                                  W1–W4
M1 服务端核心 + 授权模型    ███████                          W5–W11
M2 桌面 SDK                       █████                      W12–W16
M3 Web SDK                             █████                 W17–W21
M4 构建工具链                               ████             W22–W25
M5 变体 · 私有套件 · 强制在线 · 离线              ███████     W26–W32
M6 分析与遥测                                        ████    W33–W36
M7 管理控制台                                            ████ W37–W41
M8 GA 准备                                                ███ W42–W44
```

---

## M0 — 密码学与协议基座（W1–W4）

**目标**：把最难改的东西先定死 —— 算法、协议格式、trait 契约。

| 交付物 |
|---|
| `copylocker-types` / `-suite` / `-suite-testkit` |
| `copylocker-suite-std`（CL-STD-1：混合签名、X-Wing、AEAD、KDF、指纹） |
| `copylocker-proto`（全部工件编解码 + 信封 + 证书链） |
| `vectors/` 初版 KAT（正向 + 负向） |
| **PQ 库尽调报告**：ml-dsa / ml-kem / fn-dsa 的审计状态、no_std、wasm32 体积与性能 → 回填 ADR-0002 |
| CI 骨架：check(native+wasm32) / test / clippy / deny / size / 依赖方向 lint |

**验收**
- [x] CL-STD-1 通过 testkit 全部一致性测试（含跨域重放必失败）
- [ ] 所有工件编解码往返；畸形输入不 panic（fuzz 4h 无崩溃）
- [x] wasm32 上验证路径 ≤ 300KB gzip
- [x] ADR-0002 库选型定稿

---

## M1 — 服务端核心与授权模型（W5–W11）

**目标**：能签发、能激活、能校验、能吊销，且授权模型是最终态的五轴结构。

| 交付物 |
|---|
| `copylocker-server-core`：activate / validate / deactivate / heartbeat / revoke |
| **权益引擎**：`resolve()` 纯函数、目录（features/groups/tiers）、五轴 Policy、预设 |
| **`policy simulate` CLI**（配置预览器的文本版；控制台版排 M7） |
| **订阅状态机**：dunning、永久回退、`scheduled_changes` |
| `copylocker-worker`：路由、限流、CBOR、Service Binding 预留 |
| `LicenseDO` / `IssuerDO`：席位两阶段预留、nonce、alarm、outbox、哈希链 |
| D1 schema + migrations（[`data-model.md`](../02-architecture/data-model.md) 全量） |
| KV 缓存层、Queue 消费者（投影 + 审计） |
| `copylocker-cli`：keygen、catalog、policy、license、epoch、inspect、deploy |
| 支付 webhook 适配（Stripe / Paddle / LemonSqueezy） |
| `server-template` 脚手架 |

**验收**
- [x] 100 并发激活 3 席位 → 恰好 3 成功
- [x] 吊销后下次 validate 返回 KillOrder
- [x] 权益解析确定性：同输入 → 字节级相同快照；循环引用被检出
- [x] 订阅状态机全部转换 × webhook 重放 3 次幂等
- [x] 永久回退：到阈值 earned、中断清零、退款可撤销
- [x] `policy simulate` 的 11 个预设场景输出正确
- [ ] Worker WASM ≤ 1.5MB，冷启动 P95 < 50ms
- [ ] 全端点 fuzz 无 panic/500；审计哈希链可验证

---

## M2 — 桌面 SDK（W12–W16）

| 交付物 |
|---|
| `copylocker-core`：状态机、时钟守卫、`security_floor` 防降级、Feature Key 派生 |
| `copylocker-store`：keychain/DPAPI/secret-service + AEAD 文件双写（**variant 无关封装**） |
| `copylocker-fingerprint`：win/mac/linux + 容差 |
| `copylocker-client`：facade + 传输 + 触发调度 |
| `copylocker-tauri` + `@copylocker/tauri` |
| `copylocker-node` + `@copylocker/electron`（跨平台预编译） |
| `examples/tauri-app`、`examples/electron-app` |

**验收**
- [ ] 30 分钟内从零部署 + 激活（录屏计时）
- [ ] 断网可用 ≥ grace；恢复网络 60s 内自动校验
- [x] 复制 store 到另一台机器 → 失败
- [x] 时钟回拨 1 年 → 检出且不延长期限
- [x] `security_floor` 回滚的凭证被拒
- [x] evidence 采集：同机 10 次结果一致（防 FK 抖动）
- [ ] macOS/Windows/Linux CI 矩阵全绿；内存增量 < 8MB

---

## M3 — Web SDK（W17–W21）

| 交付物 |
|---|
| `copylocker-wasm`：不透明 `step()` 导出面、验签、KEM、状态机 |
| `@copylocker/web`：TS 层、二段变换、Worker 隔离、IndexedDB 存储 |
| 浏览器指纹提供者（默认不含 canvas） |
| React / Vue / Svelte 绑定 |
| `examples/vite-spa`、`examples/nextjs-app`（含 SSR） |

**验收**
- [ ] WASM ≤ 350KB gzip；本地校验 < 15ms
- [ ] Playwright 端到端：激活 → unseal → 断网 → 恢复
- [ ] CSP 严格模式下可运行

---

## M4 — 构建工具链（W22–W25）

| 交付物 |
|---|
| `@copylocker/unplugin`：6 个打包器、清单生成与签名、常量注入、自引用两轮方案 |
| `@copylocker/guard`：启动自校验、`@guarded` decorator、`R` 的产出 |
| `@copylocker/seal`：资产封印 + 服务端 KEK 包装 + 运行时解封 |
| 远程 signer 端点 + CI OIDC；`unplugin --verify` |

**验收**
- [ ] 6 个打包器各跑通完整构建 + 运行时校验
- [ ] 篡改任意 chunk 一字节 → `R` 变化 → unseal 失败
- [ ] 删除 guard → unseal 失败；替换 WASM stub → unseal 失败
- [ ] **多浏览器 `R` 一致（无误报）** ← 最高风险项
- [ ] LCP 影响 < 20ms

---

## M5 — 变体、私有套件、强制在线、离线（W26–W32）

| 交付物 |
|---|
| **Release 注册表与变体系统**（ADR-0008）：`release register` CI 门禁、variant 派生、`variant_accept[]` |
| **版本级吊销**：`mark-compromised` × {warn, force_upgrade, revoke} + 影响面 dry-run |
| **版本范围强制**：`ReleasedBefore` 的服务端判定 + 受限模式 UX |
| **离线升级策略**：`require_online` / `preload_n` / `variant_stable` |
| `copylocker-suite-priv`（私有仓库）CL-PRIV-1 + 厂商参数生成器 |
| `copylocker-suite-compact` CL-CMP-1（FN-DSA-512；**若 M0 尽调通过**，否则 OLK 降级为文件形态） |
| Mode E：账号体系、`AccountDO`、会话、并发设备限制 |
| 离线激活：AR/AResp 挑战响应、QR 编码；OLK 签发与导入 |
| 多套件并存与迁移；WASM 导出符号随机化、常量拆分 |
| 异常检测：suspicion score + Webhook |
| **`data-inventory.md`**（法律包的事实基础，`legal-sync` CI 门禁的输入） |

**验收**
- [ ] Mode E：断网超 refresh+grace → Locked；联网自动恢复
- [ ] air-gapped 全流程在完全断网的 VM 上跑通
- [ ] CL-STD-1 → CL-PRIV-1 只改一行类型别名
- [ ] CL-PRIV-1 通过公开 testkit 全绿 + 红线检查表签字
- [ ] **跨版本兼容矩阵**：4 个历史版本 × 当前服务端全绿；跨 variant 存储可读
- [ ] 谎报旧 `release_id` → 拿到旧 variant 的 keks → 新版本解不开 Sealed Asset
- [ ] 未注册 release → 激活失败且错误含注册命令

---

## M6 — 分析与遥测（W33–W36）

| 交付物 |
|---|
| **T0 协议派生分析**：指标目录、rollup Cron、HLL 草图、k-匿名抑制 |
| Analytics Engine 近实时写入 + R2 明细 + D1 rollup 双路径 |
| `/v1/admin/analytics/*`：metrics / definitions / export / subscriptions |
| **T1 聚合遥测**：搭车 validate 的 `telemetry_block`、同意机制、异常裁剪 |
| `@copylocker/telemetry` + SDK 配置与防呆 |
| `dsr export|delete`、`telemetry purge` |

**验收**
- [ ] 精确路径与 HLL 路径的口径误差 ≤ ±1%
- [ ] Rollup 幂等：重跑某日 Cron 结果不变
- [ ] k-匿名：< 5 的桶被抑制
- [ ] 遥测投毒（`session_count = 10^9`）被裁剪并计数
- [ ] `consent_version = 0` → 遥测被丢弃
- [ ] `refresh_after = 7d` 时日粒度查询返回分辨率警告
- [ ] `legal-sync` CI 门禁生效：新增采集字段必须同步数据清单

---

## M7 — 管理控制台（W37–W41）

| 交付物 |
|---|
| `apps/console`：SvelteKit + shadcn-svelte + Service Binding + Cloudflare Access |
| 页面：Overview / Licenses / Machines / Catalog / Policies / **Simulator** / Releases / Analytics / Keys / Audit / Settings |
| **权益目录编辑器**（拖拽 + 实时解析预览 + 不可变性护栏） |
| **Policy 编辑器**（五轴 + 预设 + 危险配置警告） |
| **配置预览器**（时间轴可视化 + 场景库） |
| **离线激活门户**（公开路由 + QR 扫描 + 限流 + Turnstile） |
| `@copylocker/admin-sdk`（类型由 `ts-rs` 生成） |

**验收**
- [ ] E2E：签发 → 激活 → 查看设备 → 吊销 → 验证生效
- [ ] Simulator 输出与 CLI、与服务端实际行为三方一致
- [ ] 尝试重命名已发布 feature → UI 禁用并给出原因
- [ ] 高危操作两步确认与 CLI 行为一致
- [ ] axe 无 critical/serious；键盘全流程可操作
- [ ] CSP `script-src 'self'` 无 `unsafe-inline`

---

## M8 — GA 准备（W42–W44）

| 交付物 |
|---|
| **外部安全审计**（密码学与协议）+ 修复 |
| **红队演练** RT-1 ~ RT-10 全部通过 |
| 文档站（VitePress）：5 分钟上手、强度分级指南、授权模型指南、迁移指南、FAQ |
| **法律配套包**：隐私政策章节、同意文案、DPA 附件、ROPA、DPIA、DSR 手册、EULA 条款（4 语） |
| 运维：Runbook、告警、SLO 仪表盘、成本估算 |
| 发布工程：可复现构建、Sigstore、SBOM、npm provenance |

**GA 门禁**
- [ ] 全部 P0 需求实现并有测试覆盖
- [ ] 外部审计无 High/Critical 未修复
- [ ] RT-1 ~ RT-10 通过
- [ ] 4 个示例应用可运行且有文档
- [ ] 公开仓库不接触私有仓库即可 CI 全绿
- [ ] 法律包经律师审阅
- [ ] SLO 仪表盘上线，错误预算机制生效
- [ ] `SECURITY.md` 含诚实的残余风险声明

---

## 依赖与并行

```
M0 ──▶ M1 ──┬──▶ M2 ──┐
            └──▶ M3 ──┴──▶ M4 ──▶ M5 ──▶ M6 ──▶ M7 ──▶ M8
```

M2/M3 可并行（不同人）。M6 依赖 M5 的 Release 注册表（版本维度分析）。
M7 依赖 M5（Release 管理 UI）与 M6（分析看板）。

| 周 | A（Rust/密码学） | B（前端/工具链/控制台） | C（服务端/DX） |
|---|---|---|---|
| W1–4 | suite + proto + KAT | CI + 构建配置 + PQ 尽调 | server-core 骨架 + 数据模型 |
| W5–11 | 权益引擎 + Issuer | CLI + 脚手架 + simulate | worker + DO + D1 + webhook |
| W12–16 | core + fingerprint + store | tauri 插件 + TS 绑定 | node 模块 + 跨平台 CI |
| W17–21 | wasm 核心 | @copylocker/web + 示例 | Admin API 完善 |
| W22–25 | seal 的密码学部分 | unplugin + guard | 远程 signer + OIDC |
| W26–32 | 私有套件（隔离环境） | 变体注入 + 符号随机化 | Release 注册表 + Mode E + 离线 |
| W33–36 | HLL + 指标口径 | 遥测 SDK | 分析管线 + Cron + Admin API |
| W37–41 | 审计配合 | **控制台全栈** | 控制台 API 支撑 + 离线门户 |
| W42–44 | 审计修复 | 文档站 | 运维 + 发布工程 |

## v1.1+ Backlog

iOS / Android SDK · 托管 SaaS 多租户 · TPM/Secure Enclave 凭证保护 ·
App Attest / Play Integrity · 从 Keygen.sh 迁移工具 · 浮动/并发许可 ·
用量计费（metered）· 离线 Relay · Turbopack / Bun bundler · 每用户资产水印
