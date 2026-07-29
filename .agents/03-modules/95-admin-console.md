# 模块：管理控制台（SvelteKit + shadcn-svelte）

Package：`apps/console`（`copylocker-admin` Worker）
需求：FR-CON-*、ADR-0010

## 1. 定位

控制台是 **API Worker 的一个不可信前端**。它自己不做任何授权判定、不持有签名密钥、
不直接访问 D1/DO。所有变更经 Service Binding 调 API Worker，在那里重新做 scope 校验与审计。

## 2. 技术栈

| 层 | 选型 |
|---|---|
| 框架 | SvelteKit + `@sveltejs/adapter-cloudflare` |
| 组件 | shadcn-svelte（源码复制式）+ bits-ui（无头原语） |
| 样式 | TailwindCSS + `mode-watcher` |
| 图标 | `lucide-svelte` |
| 表单 | `sveltekit-superforms` + `zod`（schema 由 Rust 类型生成后包一层） |
| 表格 | TanStack Table (Svelte) — 排序/筛选/虚拟滚动/分页 |
| 图表 | LayerChart（shadcn-svelte chart 底座） |
| API 客户端 | `@copylocker/admin-sdk`（类型由 `ts-rs` 从 Rust 生成） |
| i18n | Paraglide (inlang) — 编译期抽取，无运行时开销 |
| 测试 | Vitest（单元）+ Playwright（E2E）+ axe（可访问性） |

## 3. 部署拓扑

```
┌──────────────────────┐  Service Binding  ┌──────────────────────┐
│ copylocker-admin     │ ────(内部,不出网)───▶ │ copylocker (API)     │
│ SvelteKit SSR Worker │                    │ Rust Worker          │
│ admin.<domain>       │                    │ api.<domain>         │
│                      │                    │  · Epoch 私钥绑定     │
│ ✗ 无签名密钥绑定      │                    │  · D1 / DO / KV / R2 │
│ ✗ 无 D1/DO 直连      │                    │  · scope 校验 + 审计  │
└──────────────────────┘                    └──────────────────────┘
         ▲                                           ▲
 Cloudflare Access（默认）                    SDK（Bearer/CBOR）
 或内置 Passkey 会话
```

```jsonc
// apps/console/wrangler.jsonc
{
  "name": "copylocker-admin",
  "compatibility_date": "2026-07-01",
  "main": ".svelte-kit/cloudflare/_worker.js",
  "assets": { "directory": ".svelte-kit/cloudflare" },
  "services": [{ "binding": "API", "service": "copylocker" }],
  "observability": { "enabled": true }
}
```

## 4. 认证与授权

| 方案 | 定位 |
|---|---|
| **Cloudflare Access**（默认推荐） | 校验 `Cf-Access-Jwt-Assertion`；SSO / MFA / 审计由 CF 承担 |
| **内置 Passkey 会话**（回退） | WebAuthn 优先，无密码；给没有 Access 的小团队 |

- 会话仅存 HttpOnly + Secure + SameSite=Strict cookie；**不写 localStorage/IndexedDB**。
- 控制台把身份映射为 Admin scope，随每次 Service Binding 调用传给 API Worker，
  **由 API Worker 再次校验**（控制台的判断不作数）。
- scope：`products:rw` `catalog:rw` `policies:rw` `licenses:rw` `machines:rw`
  `revoke` `releases:rw` `epochs:rw` `audit:r` `analytics:r` `sign:manifest`

`analytics:r` 是独立 scope —— 市场同事可以只看分析，拿不到授权管理权限。

## 5. 页面结构

```
/                          Overview
/licenses                  授权列表（TanStack Table，服务端分页/筛选）
/licenses/[id]             详情：设备、激活历史、订阅状态、权益、吊销、延期、备注
/licenses/new              批量签发（明文 Key 仅此一次可见，强制下载 CSV）
/machines                  全局设备视图（按 suspicion 排序）
/catalog                   ★ 权益目录：Features / Groups / Tiers 编辑器
/policies                  Policy 列表
/policies/[id]             Policy 编辑器（五轴表单）
/policies/[id]/simulate    ★ 配置预览器（时间轴可视化）
/releases                  ★ 发布与变体：注册、状态、采纳曲线
/releases/[id]             详情：设备分布、完整性失败率、标记 compromised
/analytics                 分析看板（Overview / Activations / Versions / Retention / Seats / Health）
/keys                      Epoch 列表、剩余有效期、轮换引导
/audit                     审计流 + 哈希链验证状态
/settings                  Webhook、限流、隐私开关、Token、成员
/offline                   ★ 公开路由：离线激活门户（无 admin 认证）
```

### 5.1 权益目录编辑器（`/catalog`）

ADR-0009 的核心 UI。要点：

- 三栏：Features / Groups / Tiers，拖拽把 feature 加进 group、group 加进 tier。
- **实时解析预览**：选中一个 tier，右侧即时显示 `resolve()` 后的扁平 feature 集合与 limits。
- **不可变性护栏**：已发布的 `feature_id` 的重命名/删除按钮**禁用**，
  悬停显示原因（"已被 N 个已签发凭证引用，且 FeatureKey 派生依赖它"）。
- 循环引用在编辑时即时检出并高亮。
- glob（`export.*`）输入时实时展开预览。
- 变更保存 = 新建 `catalog_version` 快照（不可变），显示"影响：新签发的凭证；已有凭证在续期时生效"。

### 5.2 Policy 编辑器（`/policies/[id]`）

五个轴分成五个 Tab/Section，顶部是**预设选择器**（新建时先选预设，再微调）。

危险配置的即时警告：

| 配置 | 警告 |
|---|---|
| `Perpetual` + `Unlimited` version scope | "用户将永久获得所有未来版本" |
| `not_after = current_period_end`（无 dunning） | "支付延迟会锁死正常付费用户，建议 ≥7 天" |
| `refresh_after > billing_period / 4` | "取消订阅的传播延迟可能超过一个计费周期" |
| `grace < 7d` | "网络不稳定的用户会被频繁锁定" |
| `variant_stable` | "放弃版本隔离，破解可跨版本复用" |
| Mode E + Perpetual | "永久授权 + 强制在线意味着服务端必须永久运行" |

### 5.3 配置预览器（`/policies/[id]/simulate`）

`licensing-model.md §11` 的可视化版本。横向时间轴，可拖动"当前时间"游标：

```
2026-01-01 ●─激活────────────────────────────────────────────────▶
              tier=pro  features=[export.*, ai.assist, render.4k]
2027-01-01     ★ fallback earned (连续付费 12 月)
2027-06-01     ▼ 用户取消 → canceling
2027-12-31     ▼ 周期结束 → 永久授权，版本封顶 2027-01-01
                 可用最高版本：3.9（2026-12-20 发布）
                 ⚠️ 当前最新 4.2 超出范围 → 客户端进入受限模式
```

内置场景库（正常续订 / 中途取消 / 支付失败 / 退款 / 换机 / 断网 / 升降级），
一键切换查看用户会经历什么。**这是最有价值的一个页面** —— 它把 ADR-0009 的组合复杂度变得可理解。

### 5.4 Releases（`/releases`）

- 注册状态一览（哪些版本未注册 → CI 会失败）
- 采纳曲线（来自 `ver.adoption_curve`）
- 每个 release 的完整性失败率（来自 `health.integrity_fail`）→ 异常时高亮"考虑回滚"
- **破解疑似信号**：某 release 的活跃设备数显著高于其对应的销量/席位总数 → 醒目标记
- 标记 compromised 走两步确认（dry-run 影响面 → 输入 release_id）

### 5.5 分析看板（`/analytics`）

对应 `90-analytics-telemetry.md §9`。UI 纪律：

- 每个图表旁 `ⓘ` 显示精确口径定义（从 `/analytics/definitions` 拉取，不硬编码）。
- 标注数据来源：`精确` / `约 (HLL ±0.8%)` / `近实时（含采样）`。
- **分辨率提示**：`refresh_after = 7d` 时，日粒度图表上方显示黄条警告。
- T1 遥测的图表放在**独立分区**，标注"客户端自报，不可信"，与 T0 视觉区分。
- k-匿名抑制的桶显示为 `<5`，不显示精确值。

### 5.6 离线激活门户（`/offline`，公开路由）

- **不共享任何 admin 认证/会话代码路径**（独立 layout、独立 hooks 分支）。
- 上传 `.clar` 文件 或 摄像头扫 QR（`@zxing/browser`）。
- 严格限流 + Turnstile（可选）—— 防止被当作探测 License 有效性的 oracle。
- 输出 AResp 文件下载 + QR 显示。

## 6. 安全要求

| 项 | 要求 |
|---|---|
| CSP | `script-src 'self'`，无 `unsafe-inline`；SvelteKit CSP nonce 配置开启 |
| CSRF | 所有变更走 form action（SvelteKit 默认 origin 校验）+ 显式 token |
| 高危操作 | dry-run 影响面预览 → 输入目标 ID 确认（与 CLI 行为一致） |
| 密钥材料 | 控制台**不接触**任何私钥；明文 License Key 仅在签发响应中出现一次，强制下载后即从内存清除 |
| 客户端存储 | 不写 localStorage / IndexedDB |
| 依赖 | npm `--ignore-scripts` + lockfile 审查 + SBOM |
| 可访问性 | axe CI 检查，键盘可完全操作（bits-ui 提供正确的 ARIA） |
| shadcn-svelte 同步 | 组件源码在仓库内 → 建立季度性上游同步流程（记录在 `05-ops`） |

## 7. 测试

| 类型 | 内容 |
|---|---|
| E2E（Playwright） | 签发 → 激活（模拟客户端）→ 查看设备 → 吊销 → 验证生效 |
| E2E | 目录编辑 → 保存 → 新签发的凭证含新权益 |
| E2E | Policy simulator 的场景输出与 `copylocker policy simulate` CLI 一致 |
| E2E | 离线门户全流程（上传 AR → 下载 AResp → 客户端导入成功） |
| 护栏 | 尝试重命名已发布 feature → UI 禁用且给出原因 |
| 护栏 | 无 `--confirm` 的高危操作不执行 |
| 权限矩阵 | 每个 scope × 每个页面/操作 |
| 可访问性 | axe 无 critical/serious 违规；键盘全流程 |
| 视觉回归 | Playwright 截图对比（关键页面，明暗两套主题） |
