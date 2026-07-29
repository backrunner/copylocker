# CopyLocker 产品需求文档（PRD）

版本 v1.0 · 2026-07-26

## 1. 产品概述

CopyLocker 为 Web / Tauri / Electron 应用提供一套可自部署在 Cloudflare Serverless 之上的
授权（License）解决方案，包含 **License Server** 与 **客户端验证模块** 两大部分，
支持 **离线优先混合模式（Mode O）** 与 **强制在线模式（Mode E）**。

## 2. 用户角色

| 角色 | 描述 | 主要诉求 |
|---|---|---|
| **Vendor Admin** | 使用 CopyLocker 的软件开发者/运营 | 快速部署、签发/吊销 License、看到盗版异常 |
| **Vendor Developer** | 负责接入 SDK 的工程师 | 接入简单、类型安全、本地可调试、不污染业务代码 |
| **End User** | 购买软件的最终用户 | 激活简单、离线可用、换机方便、隐私可控 |
| **Attacker** | 破解者 | （反向角色，见威胁模型） |

## 3. 核心用户旅程

### 3.1 Vendor 首次部署（目标 ≤ 30 分钟）

```
npx create-copylocker my-license-server
  → 交互式向导：Cloudflare 账号、产品名、模式选择
  → copylocker-cli keygen root       # 生成离线根密钥（引导写入硬件密钥/纸质备份）
  → copylocker-cli keygen epoch      # 签发首个 90 天纪元密钥
  → wrangler deploy                  # 部署 Worker + D1 迁移 + DO + KV
  → 输出：server_url、root_pubkey（供客户端 pin）、admin_token
```

### 3.2 End User 激活（Mode O）

```
用户购买 → 收到 CL1-XXXXX-XXXXX-XXXXX-XXXXX
打开 App → 输入 Key → App 采集指纹 → POST /v1/activate
服务端：校验 Key、检查席位、占位、签发 MachineCredential（密封给该设备）
App：验签 → 解封 → 落地 keychain → 派生 Feature Key → 解密受保护资产 → 进入可用状态
```

之后：App 在后台按 `refresh_after` 周期尝试在线校验；无网则进入宽限期继续可用。

### 3.3 End User 激活（Mode E）

```
打开 App → 登录（邮箱+密码 / OAuth / SSO）→ 服务端下发在线数字凭证
→ 与设备指纹绑定签发 MachineCredential（含较短的 refresh_after 与硬 not_after）
→ 若超过 refresh_after + grace 仍未成功在线校验 → 锁定，提示"请联网"
```

### 3.4 盗版发现与回收

```
异常检测（同一 license 短时间内多地指纹）→ 告警到 Vendor Admin
Admin 在控制台点击 "Revoke Activation" / "Revoke License"
→ 写入 RevocationBatch，revocation_epoch++
→ 客户端下一次在线校验收到 KillOrder → 立即擦除本地凭证 → Unlicensed
```

### 3.5 Air-gapped 激活

见 [ADR-0005 §5.3](../00-overview/decisions/ADR-0005-license-key-vs-license-file.md)。

### 3.6 换机 / 席位释放

- 用户在 App 内「停用本设备」→ 释放席位（在线）。
- 设备损坏无法操作 → Admin 在控制台强制释放，或等待心跳超时被 alarm 回收（僵尸设备回收）。
- 每个 License 有「换机次数/周期」限额，防止把席位当共享池轮转。

## 4. 功能范围（Epic 级）

| Epic | 说明 | 优先级 |
|---|---|---|
| E1 密码学基座 | Suite 槽位、CL-STD-1、凭证编解码、KAT | P0 |
| E2 License Server 核心 | 产品/策略/License/席位/激活/校验 API | P0 |
| E3 客户端核心状态机 | 状态机、本地存储、时钟守卫、宽限期 | P0 |
| E4 桌面 SDK | Tauri 插件、Electron NAPI、C ABI | P0 |
| E5 Web SDK | WASM 核心 + TS 触发/二段变换层 | P0 |
| E6 构建期完整性 | unplugin 清单签名 + guard 运行时校验 + decorator | P0 |
| E7 Feature Key & Seal | 派生密钥、资产封印工具 | P0 |
| E8 管理面 | Admin API、CLI、最小控制台 | P1 |
| E9 强制在线与账号 | 账号体系、会话、并发设备限制 | P1 |
| E10 Air-gapped | AR/AResp 挑战响应、OLK | P1 |
| E11 异常检测与告警 | 指纹/地理/频率异常、Webhook | P2 |
| E12 私有套件 | CL-PRIV-1、厂商参数生成 | P1 |
| E13 可观测性 | 审计日志、指标、Trace | P2 |
| E14 迁移工具 | 从 Keygen / 自研方案导入 | P3 |
| **E15 授权模型** | 权益目录、五轴 Policy、订阅状态机、永久回退、版本范围、预设、配置预览器 | **P0** |
| **E16 发布变体与版本治理** | Release 注册表、变体派生、版本级吊销、`security_floor`、兼容矩阵 | **P0** |
| **E17 授权分析** | T0 指标目录、HLL 排重、rollup 管线、k-匿名、Admin API | **P1** |
| **E18 可选遥测** | T1 聚合上报、同意机制、异常裁剪、`legal-sync` 门禁 | P1 |
| **E19 管理控制台** | SvelteKit + shadcn-svelte，目录/Policy 编辑器、预览器、Release、分析看板、离线门户 | P1 |
| **E20 法律配套包** | 数据清单、隐私政策章节、同意文案、DPA/ROPA/DPIA/DSR/EULA 模板（4 语） | P1 |

## 5. 授权模式详细定义

### 5.1 Mode O — 离线优先混合模式

| 属性 | 默认值 | 可配置 |
|---|---|---|
| 首次激活 | 允许离线（AR/AResp 或 OLK），也允许在线 | ✅ |
| `refresh_after` | 7 天 | ✅ |
| `grace_window` | 30 天 | ✅ |
| `not_after` | 无（买断制）或订阅到期日 | ✅ |
| 联网时行为 | **只要检测到网络可达就尝试校验**（机会性），不等到 `refresh_after` | ✅ |
| 校验判非法 | **立即 deactivate**：擦除本地 MC、清除 Feature Key、状态转 `Revoked` | ❌（需求硬性） |
| 校验网络失败 | 不影响状态，记录尝试；超 `refresh_after` 转 `NeedsRevalidation`，超 `+grace` 转 `Locked` | — |

**"机会性在线校验"触发点**（需求"在任何用户可能恢复在线的情况进行在线的验证"）：

- 应用启动
- 网络状态从离线变为在线（`online` 事件 / OS 网络变更通知）
- 系统从睡眠唤醒
- 距上次成功校验超过 `min_check_interval`（默认 6 小时）且有任意网络请求成功
- 用户触发关键操作（插桩点）且距上次校验 > 阈值
- 随机抖动，避免全网同一时刻打服务端

### 5.2 Mode E — 强制在线模式

| 属性 | 默认值 |
|---|---|
| 首次激活 | **必须在线**，必须有账号凭据（不接受 LK/OLK） |
| `refresh_after` | 24 小时 |
| `grace_window` | 72 小时 |
| `not_after` | 订阅周期结束 + 缓冲 |
| 最长离线时长 | `refresh_after + grace_window` 硬上限，超出即 `Locked` |
| 并发设备 | 由 Seat 控制；可选"同时在线设备数"更严格限制（心跳） |

Mode E 相当于 Mode O + `require_online_activation=true` + 更短的窗口 + 硬上限。
**实现上是同一状态机的参数化**，不是两套代码。

## 6. 客户端接入形态需求

### 6.1 原生（Tauri / Electron）

- 以 Rust crate 形式与宿主一起编译，**不作为可替换的动态库单独分发**（避免整体替换 .dll/.node）。
  - Tauri：`tauri-plugin-copylocker`，静态链接进主二进制。
  - Electron：napi-rs 生成的 `.node` 原生模块。**必须**配合 `asar` 完整性 + 代码签名，
    且 `.node` 的摘要参与 Feature Key 派生（自校验）。
- 通过宿主接出到前端：Tauri command / Electron IPC（contextBridge）。
- **接出的接口不是 `isValid()`**：接出的是 challenge/response 与 Feature Key 使用能力（见 ADR-0004）。

### 6.2 Web（Rust+WASM + TS 混合）

- WASM 承担：验签、KEM 解封、密钥派生、状态机、凭证编解码。
- TS 承担：触发调度、传输、环境探针、**二段变换**（build 期注入的常量参与最终密钥派生）。
- 关键安全属性：**替换 WASM 或替换 TS 任意单边都无法得到正确的 Feature Key**。
- WASM 导出面必须是不透明的 challenge/response，且导出符号名每次构建随机化。

## 7. 构建期插件需求（Web）

- 基于 **unplugin**，一次实现支持 Vite / Rollup / Webpack / Rspack / esbuild / Farm。
- 构建后对所有 JS/CSS/WASM chunk 计算摘要，生成 `IntegrityManifest` 并签名。
- 运行时 `@copylocker/guard` 自校验：拉取自身 chunk → 计算摘要 → 与清单比对。
- 提供 `@guarded` decorator：构建期记录函数体摘要，调用时（可采样）校验函数未被替换。
- **签名算法可自定义**：插件暴露 `hasher` / `signer` / `verifierRuntime` 三个可替换点。
- 与 sourcemap、code splitting、动态 import、CDN 部署兼容。

## 8. 验收标准（摘要）

| 编号 | 验收 |
|---|---|
| AC-1 | 全新项目 30 分钟内完成部署 + 首次激活（录屏计时） |
| AC-2 | 断网状态下，Mode O 已激活客户端可连续正常使用 ≥ grace 配置值 |
| AC-3 | 恢复网络后 60 秒内自动完成一次在线校验（无需重启） |
| AC-4 | Admin 吊销后，目标客户端在下一次在线校验时立即失效并擦除凭证 |
| AC-5 | Mode E 客户端断网超过 `refresh+grace` 后锁定，联网后可自动恢复 |
| AC-6 | 把 MachineCredential 复制到另一台设备无法使用（指纹绑定 + KEM 密封） |
| AC-7 | 篡改 Web 构建产物任意 chunk 一个字节，guard 能检出并使 Feature Key 失效 |
| AC-8 | 替换 WASM 模块为返回"成功"的 stub，受保护资产仍无法解密 |
| AC-9 | 系统时间回拨 1 年，客户端检测到并拒绝延长有效期 |
| AC-10 | 同一 License 超席位激活被拒绝；并发 100 请求下席位数不超卖（DO 原子性验证） |
| AC-11 | 公开仓库在不接触私有仓库的情况下 CI 全绿、示例可运行 |
| AC-12 | 切换 CL-STD-1 → CL-PRIV-1 只需改一行类型别名 + 重新签发凭证 |
| AC-13 | 权益解析确定性：同一目录+规格+时间 → 字节级相同的快照；循环引用被检出且不栈溢出 |
| AC-14 | 尝试重命名/删除已发布的 `feature_id` → CLI 与控制台均硬拦截并说明原因 |
| AC-15 | 订阅状态机：同一 webhook 重放 3 次、乱序到达，结果一致（幂等） |
| AC-16 | `current_period_end` 到点但在 dunning 宽限内 → 用户仍可正常使用 |
| AC-17 | 永久回退：连续付费达阈值后取消 → 自动获得永久授权 + 版本封顶到 earned 时点 |
| AC-18 | 版本超出授权范围 → 客户端进入受限模式并提示可用最高版本，**不显示盗版警告** |
| AC-19 | 谎报旧 `release_id` 绕过版本封顶 → 拿到旧 variant 的 keks，新版本仍解不开 Sealed Asset |
| AC-20 | 未注册 Release 的客户端激活失败，错误信息含 `copylocker release register` 命令 |
| AC-21 | 跨 4 个版本连续升级，每一步都无需用户重新输入 Key（存储封装 variant 无关） |
| AC-22 | 标记某 Release 为 compromised + `force_upgrade` → 仅该版本受影响，其他版本用户无感 |
| AC-23 | 喂入 `security_floor` 低于已见最大值的凭证 → 被拒（`SecurityFloorRollback`） |
| AC-24 | 在**零额外采集**（T0）下能得出：激活数、签到设备数、离线/在线激活比例、版本分布 |
| AC-25 | HLL 路径与 D1 精确路径的口径误差 ≤ ±1%；重跑 rollup Cron 结果不变 |
| AC-26 | 桶内唯一设备数 < 5 时显示 `<5`；`refresh_after=7d` 时日粒度查询返回分辨率警告 |
| AC-27 | `tier: 'T1'` 未提供 `consent` → SDK 初始化报错；`consent_version=0` → 服务端丢弃遥测 |
| AC-28 | 遥测投毒（`session_count = 10^9`）被裁剪并计入异常；只影响该设备自身数据 |
| AC-29 | 新增任一采集字段而未同步数据清单 → `legal-sync` CI 门禁失败 |
| AC-30 | 控制台 Policy Simulator 的输出与 CLI、与服务端实际行为三方一致 |
| AC-31 | 控制台 axe 无 critical/serious 违规，键盘可完成全部关键流程 |

## 9. 度量与埋点（Vendor 侧可见）

- 激活成功率 / 失败原因分布
- 在线校验成功率、P50/P95 延迟
- 处于 Grace / Locked 状态的设备占比
- 指纹异常告警数
- 完整性校验失败上报数（可选上报，需隐私声明）

## 10. 隐私与合规

- 设备指纹**只上报 HMAC 摘要**，不上报原始硬件标识。
- 指纹使用的属性集合必须在客户端文档中公开列出，供 Vendor 写进自己的隐私政策。
- 提供 `telemetry: off` 配置；关闭后只发送校验必需的最小字段。
- 支持 GDPR 删除请求：`DELETE /v1/admin/machines/:id`（同时清 DO + D1 投影 + 审计脱敏）。
- EU/中国部署可通过 Cloudflare Data Localization 约束数据落地区域（文档给出配置指引）。
