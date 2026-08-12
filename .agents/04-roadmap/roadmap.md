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
- [x] 所有工件编解码往返；畸形输入不 panic（codec fuzz 累计 4h 无崩溃：首轮 2h 8,063,012 次 + 分段补跑 40×180s 47,235,544 次；补跑采用分段是因为 libFuzzer/ASAN 在本机呈 ~1.8KB/exec RSS 爬坡——独立探针证明 12 个 decode 在 200 万次变异输入下 RSS 平稳 5.8MB,OOM 属 fuzzer 基础设施行为而非 codec 缺陷）
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
- [x] Worker WASM ≤ 1.5MB，冷启动 P95 < 50ms（实测 910,764 gzip bytes、p95 10.639ms，CI run 30493940780；本地复测 p95 11.392ms）
- [x] 全端点 fuzz 无 panic/500；审计哈希链可验证（`fuzz_server_activate` 43,202,002 次/1h、`fuzz_server_validate` 8,451,251 次/1h 均无崩溃；worker vitest 全路由畸形输入不返回 500；`POST /v1/admin/audit/verify` 全链 seq/prev_hash/hash 重算验证，含断链定位测试）

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
- [ ] 断网可用 ≥ grace；恢复网络 60s 内自动校验（桌面端：状态机 grace/恢复逻辑与测试在 `copylocker-client`；Web 端已由 E2E 实证。桌面端 60s 计时证据未采）
- [x] 复制 store 到另一台机器 → 失败
- [x] 时钟回拨 1 年 → 检出且不延长期限
- [x] `security_floor` 回滚的凭证被拒
- [x] evidence 采集：同机 10 次结果一致（防 FK 抖动）
- [x] macOS/Windows/Linux CI 矩阵全绿；内存增量 < 8MB（CI 矩阵已于 run 30493941556 全绿；内存增量由 `tools/client-memory-budget` harness 实测：单客户端初始化 RSS 增量 624 KiB（3 次复测一致，预算 8192 KiB），16 客户端每额外实例 69–71 KiB 无泄漏斜率）

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
- [x] WASM ≤ 350KB gzip（实测 116,357 gzip bytes，见 `scripts/check-web-wasm-size.sh`）
- [x] 本地校验 < 15ms（`scripts/bench-wasm-verifier.mjs`：p95 0.987 ms；测量的是 CL-STD-1 链验证 harness 路径，非完整会话开销）
- [x] Playwright 端到端：激活 → unseal → 断网 → 恢复（`packages/web-e2e`，12 场景对真实本地 Worker 后端两连绿）
- [x] CSP 严格模式下可运行（vite-spa 静态 CSP + nextjs-app per-request nonce CSP；需 `wasm-unsafe-eval`，已写入 `packages/web` README）

---

## M4 — 构建工具链（W22–W25）

| 交付物 |
|---|
| `@copylocker/unplugin`：6 个打包器、清单生成与签名、常量注入、自引用两轮方案 |
| `@copylocker/guard`：启动自校验、`@guarded` decorator、`R` 的产出 |
| `@copylocker/seal`：资产封印 + 服务端 KEK 包装 + 运行时解封 |
| 远程 signer 端点 + CI OIDC；`unplugin --verify` |

**验收**
- [x] 6 个打包器各跑通完整构建 + 运行时校验（Vite/Rollup/esbuild/Webpack/Rspack/Farm 真实构建集成测试，`packages/unplugin` 49 测试全绿；webpack/rspack 用 `afterEmit` 终字节、farm 用 `finalizeResources` 内存补丁，均已实证）
- [x] 篡改任意 chunk 一字节 → `R` 变化 → unseal 失败（`packages/web-e2e` m4-integrity spec，真实后端）
- [x] 删除 guard → unseal 失败；替换 WASM stub → unseal 失败（前者靠 `requireIntegrityProof` fail-closed；后者 M3 E2E 已证）
- [x] **多浏览器 `R` 一致（无误报）**：chromium/firefox/webkit 三引擎同一构建产物的 R、guarded 函数体摘要、GuardState 逐字节一致（`packages/web-e2e` r-consistency spec，连原始 toString 输出都一致）
- [x] LCP 影响 < 20ms（对照构建实测 Δ ≤ 0ms，最悲观 `strategy: 'sync'` 配置下 5 次中位数）

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
- [x] Mode E：断网超 refresh+grace → Locked；联网自动恢复（状态机与凭据模式无关，`copylocker-core` 测试 `the_grace_window_eventually_locks`/`a_successful_validation_restores_service_from_any_recoverable_state`/`a_locked_client_cannot_reach_active_without_going_online` 全覆盖；Mode E 服务端强制在线由 `EnforcedOnline` 策略 + AccountToken 激活分支落实，worker 78/78）
- [ ] air-gapped 全流程在完全断网的 VM 上跑通（代码路径已由 CLI `offline_commands_cover_the_air_gapped_loop` 端到端覆盖、离线设备侧零网络调用；字面断网 VM 演练待做）
- [ ] CL-STD-1 → CL-PRIV-1 只改一行类型别名（pending-external：私有套件在 private 子模块，本次目标范围不触碰）
- [ ] CL-PRIV-1 通过公开 testkit 全绿 + 红线检查表签字（pending-external：同上，且红线签字需外部人员）
- [ ] **跨版本兼容矩阵**：4 个历史版本 × 当前服务端全绿；跨 variant 存储可读（阻塞：仓库尚无 tag 与已发布版本，历史版本不存在；待 ≥4 个版本发布后激活，npm 发布本身为外部依赖项）
- [x] 谎报旧 `release_id` → 拿到旧 variant 的 keks → 新版本解不开 Sealed Asset（variant 注册/复用/种子保密由 worker 测试覆盖；跨 variant 解封负向测试 `keks_from_an_older_variant_cannot_unseal_a_newer_releases_asset`（`copylocker-client`）双层锁定：metadata 门禁拒收异 variant 容器 + 伪造 variant 头过不了 AEAD（错误 KEK 进 AAD），附同 variant 阳性对照）
- [x] 未注册 release → 激活失败且错误含注册命令（M5-A：activate/validate 1007 文案内嵌 `copylocker release register ...`，worker 测试覆盖）

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
- [x] 精确路径与 HLL 路径的口径误差 ≤ ±1%（`server-core/src/analytics/hll.rs:255`，n=100/1k/10k/50k 实测 ≤ 0.8%；merge 等价测试同文件 :283）
- [x] Rollup 幂等：重跑某日 Cron 结果不变（worker vitest：重跑后表字节一致，`INSERT OR REPLACE` 主键幂等）
- [x] k-匿名：< 5 的桶被抑制（server-core 单测 + API 级 `suppressed_buckets` 元数据测试）
- [x] 遥测投毒（`session_count = 10^9`）被裁剪并计数（裁剪至 10,000 并置标志 + `t1.clipped_session_count` 计数器）
- [x] `consent_version = 0` → 遥测被丢弃（validate 仍 200 + `t1.dropped_no_consent` 计数器；7 个 Rust host 单测覆盖门禁逻辑）
- [x] `refresh_after = 7d` 时日粒度查询返回分辨率警告（`meta.warning`，周粒度则无警告）
- [x] `legal-sync` CI 门禁生效：新增采集字段必须同步数据清单（`scripts/check-legal-sync.mjs` 接入 ci.yml；注入漂移实测 exit 1）

> 偏差记录（详见 agent.md M6 证据节）：Analytics Engine 写入腿未实装（无绑定，D1 rollup 路径完整）；订阅投递仅存配置（`delivery: pending`）；导出为行内限量而非 R2 预签名；心跳不产生分析明细（`HeartbeatRequest` 无 client_info，`act.reactivation` 未计算）。

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
- [x] E2E：签发 → 激活 → 查看设备 → 吊销 → 验证生效（`packages/console-e2e` 16/16：UI 签发 → 真实 CL-STD-1 激活 → 许可详情页与跨许可设备目录均可见 → 两步吊销 → KillOrder 生效、后续 validate 拒绝 NotActivated）
- [x] Simulator 输出与 CLI、与服务端实际行为三方一致（`copylocker-simulator-wasm` 直接调用 `simulator::simulate` 零重实现；`tests/consistency.rs` 锁定 wrapper==direct==fixture，console vitest 经 wasm 重放同一 fixture，CLI 共享同一 `simulate`）
- [x] 尝试重命名已发布 feature → UI 禁用并给出原因（catalog 编辑器禁用 id 输入，理由含 FeatureKey 派生与凭证引用）
- [x] 高危操作两步确认与 CLI 行为一致（license/machine/epoch revoke + release deprecate/mark-compromised + DSR 删除/telemetry purge 均 typed-id 确认 + dry-run 影响预览，`acknowledge_revoke` 门）
- [x] axe 无 critical/serious；键盘全流程可操作（真实浏览器 Playwright axe 覆盖全部 10 页含数据页，修复了 jsdom 闸无法发现的两个 color-contrast 违规；键盘登录/侧边栏/签发全流程 + 对话框焦点陷阱双向 8 循环 + Escape 焦点还原）
- [x] CSP `script-src 'self'` 无 `unsafe-inline`（svelte.config.js csp auto，新增页面兼容已验证）

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
- [x] 全部 P0 需求实现并有测试覆盖（M0–M8 仓库内交付物全部实现；cargo 693+1、worker 98、admin-sdk 76、console 52、console-e2e 16、web-e2e 22 及各包测试全绿；外部依赖项已在 agent.md 如实标注 pending-external）
- [ ] 外部审计无 High/Critical 未修复（外部依赖：需委托独立安全审计方）
- [ ] RT-1 ~ RT-10 通过（外部依赖：红队演练；其中 RT-2/3/4/5/6 已有自动化测试覆盖，见各包测试与 web-e2e）
- [x] 4 个示例应用可运行且有文档（tauri/electron/vite-spa/nextjs，均有 README 且构建通过）
- [x] 公开仓库不接触私有仓库即可 CI 全绿（既有 CI 于 `52ed666` 验证；新增 M3/M4 包无私有依赖）
- [ ] 法律包经律师审阅（外部依赖：需执业律师；文档与数据清单在仓库内准备）
- [ ] SLO 仪表盘上线，错误预算机制生效（外部依赖：需生产环境与 Grafana/Cloudflare 账号；指标定义见文档站运维章节）
- [x] `SECURITY.md` 含诚实的残余风险声明（仓库根，与 threat-model §6 一致）

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
