# CopyLocker 文档中心

> CopyLocker 是一套面向 Web App / Tauri App / Electron App 的 License 解决方案。
> License Server 运行在 Cloudflare Serverless（Workers + Durable Objects + D1 + KV + R2 + Queues）之上，
> 核心以 Rust 编写，采用**后量子密码**与**可插拔算法套件**设计，
> 开源解决方案主体 + 闭源私有算法套件的半开源模式。

## 阅读顺序

1. [`00-overview/vision-and-scope.md`](00-overview/vision-and-scope.md) — 我们在做什么、不做什么
2. [`01-requirements/prd.md`](01-requirements/prd.md) — 产品需求
3. [`02-architecture/system-architecture.md`](02-architecture/system-architecture.md) — 系统总体架构
4. [`02-architecture/threat-model.md`](02-architecture/threat-model.md) — 威胁模型（**先读这个再写任何代码**）
5. [`02-architecture/licensing-model.md`](02-architecture/licensing-model.md) — 授权模型（五个正交轴）
6. [`02-architecture/crypto-architecture.md`](02-architecture/crypto-architecture.md) — 密码学架构与套件槽位
7. [`02-architecture/protocol-spec.md`](02-architecture/protocol-spec.md) — 协议与凭证格式
8. [`03-modules/`](03-modules/) — 各模块设计
9. [`04-roadmap/roadmap.md`](04-roadmap/roadmap.md) — 路线图
10. [`skills/develop-copylocker/SKILL.md`](skills/develop-copylocker/SKILL.md) — 开发、验证、许可与提交规范

## 目录索引

### 00-overview 总览

| 文档 | 内容 |
|---|---|
| [vision-and-scope.md](00-overview/vision-and-scope.md) | 愿景、范围、非目标、成功标准、诚实声明 |
| [glossary.md](00-overview/glossary.md) | 术语表（中英对照，全项目统一命名） |
| [open-closed-boundary.md](00-overview/open-closed-boundary.md) | 开源/闭源边界、仓库拆分、License 策略 |

### 架构决策记录（ADR）

| ADR | 决策 |
|---|---|
| [0001](00-overview/decisions/ADR-0001-crypto-agility-suite-slots.md) | 以「算法套件槽位」实现密码学敏捷 |
| [0002](00-overview/decisions/ADR-0002-pq-algorithm-selection.md) | 后量子算法选型（混合 Ed25519+ML-DSA / X-Wing / FN-DSA） |
| [0003](00-overview/decisions/ADR-0003-cloudflare-storage-topology.md) | Cloudflare 存储拓扑（DO + D1 + KV + R2 + Queues） |
| [0004](00-overview/decisions/ADR-0004-verification-must-be-productive.md) | **验证必须是「生产性」的,而非「判定性」的** |
| [0005](00-overview/decisions/ADR-0005-license-key-vs-license-file.md) | License Key 是标识符，签名凭证走文件/凭证 |
| [0006](00-overview/decisions/ADR-0006-rust-first-worker-with-ts-fallback.md) | 服务端以 Rust（workers-rs）为主 |
| [0007](00-overview/decisions/ADR-0007-analytics-tiering.md) | 分析数据分三层，默认层零额外采集 |
| [0008](00-overview/decisions/ADR-0008-per-release-variants.md) | **每发布版本一个变体，支持版本级吊销** |
| [0009](00-overview/decisions/ADR-0009-composable-license-model.md) | **可组合的授权模型（而非类型枚举）** |
| [0010](00-overview/decisions/ADR-0010-console-sveltekit.md) | 管理控制台采用 SvelteKit + shadcn-svelte |
| [0011](00-overview/decisions/ADR-0011-issuer-sharding-and-audit-chain.md) | Issuer 分片、审计哈希链与归档线格式 |
| [0012](00-overview/decisions/ADR-0012-lifecycle-routing-and-device-proofs.md) | 生命周期请求的 LicenseDO 强一致路由与独立设备证明域 |
| [0013](00-overview/decisions/ADR-0013-credential-sealing-and-kek-wrapping.md) | CredentialSecret、variant FeatureKey 与资产 KEK 的字节级包装契约 |
| [0014](00-overview/decisions/ADR-0014-admin-audit-chain.md) | Admin before/after 审计链、不可变归档与吊销恢复协议 |

### 01-requirements 需求

| 文档 | 内容 |
|---|---|
| [prd.md](01-requirements/prd.md) | 产品需求文档 |
| [functional-requirements.md](01-requirements/functional-requirements.md) | 功能需求清单（FR-xxx，可追溯） |
| [non-functional-requirements.md](01-requirements/non-functional-requirements.md) | 非功能需求（NFR-xxx） |

### 02-architecture 技术方案

| 文档 | 内容 |
|---|---|
| [system-architecture.md](02-architecture/system-architecture.md) | 总体架构、组件拓扑、数据流、客户端状态机 |
| [threat-model.md](02-architecture/threat-model.md) | STRIDE + 攻击树 + 缓解矩阵 + 残余风险 |
| [licensing-model.md](02-architecture/licensing-model.md) | 授权模型：权益 × 有效期 × 版本范围 × 席位 × 模式 |
| [versioning-and-variants.md](02-architecture/versioning-and-variants.md) | 六个版本轴、发布变体、版本级吊销、兼容矩阵 |
| [crypto-architecture.md](02-architecture/crypto-architecture.md) | PQ 算法选型、Suite 槽位、密钥层级、Feature Key 派生 |
| [protocol-spec.md](02-architecture/protocol-spec.md) | 凭证格式、线协议、时钟守卫、版本协商 |
| [data-model.md](02-architecture/data-model.md) | **全项目 schema 的唯一事实源**（D1 / DO / KV / R2） |

### 03-modules 模块设计

| 文档 | 内容 |
|---|---|
| [00-crate-layout.md](03-modules/00-crate-layout.md) | 仓库布局、依赖图、feature flags、CI 矩阵 |
| [10-server-worker.md](03-modules/10-server-worker.md) | License Server（Cloudflare Workers） |
| [20-client-core.md](03-modules/20-client-core.md) | 客户端核心状态机、存储、指纹 |
| [30-native-sdk-tauri-electron.md](03-modules/30-native-sdk-tauri-electron.md) | Tauri 插件 / Electron NAPI / C ABI |
| [40-web-sdk-wasm-ts.md](03-modules/40-web-sdk-wasm-ts.md) | Web SDK（Rust+WASM / TS 拆分） |
| [50-unplugin-integrity.md](03-modules/50-unplugin-integrity.md) | 构建期签名 + 运行时完整性 + 资产封印 |
| [60-instrumentation-guard.md](03-modules/60-instrumentation-guard.md) | 插桩范式、强度分级、Feature Key 使用指南 |
| [70-admin-cli-console.md](03-modules/70-admin-cli-console.md) | CLI 与 Admin API |
| [80-private-suite.md](03-modules/80-private-suite.md) | 闭源私有算法套件（接口契约 + 设计纲要） |
| [90-analytics-telemetry.md](03-modules/90-analytics-telemetry.md) | 授权分析与遥测（指标目录、HLL、隐私分层） |
| [95-admin-console.md](03-modules/95-admin-console.md) | 管理控制台（SvelteKit + shadcn-svelte） |

### 04-roadmap 路线图

| 文档 | 内容 |
|---|---|
| [roadmap.md](04-roadmap/roadmap.md) | M0–M8 里程碑、交付物、验收标准、并行安排 |
| [risks.md](04-roadmap/risks.md) | 风险登记册 |

### 05-ops 运维与安全运营

| 文档 | 内容 |
|---|---|
| [security-operations.md](05-ops/security-operations.md) | 密钥仪式、轮换、吊销、事件响应 Runbook |
| [testing-strategy.md](05-ops/testing-strategy.md) | 测试策略（KAT、fuzz、兼容矩阵、红队） |

### 06-legal 隐私与法律

| 文档 | 内容 |
|---|---|
| [privacy-and-legal-pack.md](06-legal/privacy-and-legal-pack.md) | 数据清单、法律基础、同意管理、DSR、模板清单 |

### Repository skill

| Skill | 内容 |
|---|---|
| [develop-copylocker](skills/develop-copylocker/SKILL.md) | 公开/私有仓库边界、开发流程、安全护栏、发布门禁、英文提交规范 |

## 核心设计要点速查

如果只读五条，读这五条：

1. **验证是生产性的**（[ADR-0004](00-overview/decisions/ADR-0004-verification-must-be-productive.md)）—— API 里没有返回 `bool` 的函数。校验产物是 Feature Key，用来解密应用真正需要的资产。`if (!valid) exit()` 无论用什么算法都是一条指令的事。
2. **授权模型是五个正交轴，不是类型枚举**（[ADR-0009](00-overview/decisions/ADR-0009-composable-license-model.md)）—— trial / 永久 / 订阅 / 版本封顶是组合，不是互斥类型。
3. **每个发布版本一个变体，且可被单独吊销**（[ADR-0008](00-overview/decisions/ADR-0008-per-release-variants.md)）—— 把破解的爆炸半径关进单个版本。
4. **私有算法套件不承担机密性**（[open-closed-boundary](00-overview/open-closed-boundary.md)）—— 红线：源码全公开后系统仍不可伪造凭证。它买的是成本不对称，不是保密性。
5. **分析的默认层零额外采集**（[ADR-0007](00-overview/decisions/ADR-0007-analytics-tiering.md)）—— 激活数、活跃设备、离线比例、版本分布全都已在协议里。

## 文档约定

- 需求 ID：`FR-<域>-<序号>` / `NFR-<域>-<序号>`，模块文档需反向引用。
- **schema 只在 [`data-model.md`](02-architecture/data-model.md) 定义**，其他文档只描述语义，不重复 DDL。
- **`entitlements` 只在 [`licensing-model.md §9`](02-architecture/licensing-model.md) 定义。**
- 任何影响跨模块契约的选择必须写 ADR，编号递增，状态 `Proposed | Accepted | Superseded`。
- 密码学改动必须同步更新 `crypto-architecture.md` + `protocol-spec.md`，并补 KAT 向量。
- 本目录是**给人和 AI agent 共同阅读的规格来源**；规范性设计与实现不得漂移。若路线图状态落后于已测试实现，以根目录 `agent.md` 记录当前事实，并在同一变更中同步相关文档。
