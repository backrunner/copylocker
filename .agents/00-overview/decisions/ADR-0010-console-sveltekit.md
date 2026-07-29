# ADR-0010：管理控制台采用 SvelteKit + shadcn-svelte / bits-ui

- **状态**：Accepted
- **日期**：2026-07-26
- **相关**：ADR-0003、ADR-0007、ADR-0008、ADR-0009、`03-modules/95-admin-console.md`

## 背景

控制台需要承担的职责：

- 授权列表 / 设备管理 / 吊销
- **权益目录与 Policy 编辑器**（ADR-0009：五个正交轴 + 预设 + 配置预览器）
- **Release 与变体管理**（ADR-0008：注册、状态、版本吊销、影响面预览）
- **分析看板**（ADR-0007：多维图表、cohort、导出、k-匿名抑制）
- 离线激活门户（公开路由）
- 密钥轮换引导、审计链验证

这是一个真正的管理系统，不是"给 API 加个页面"。需要成熟的表格、表单、图表生态，
以及能承载复杂交互（拖拽编辑目录、时间轴模拟器）的框架。

## 决策

用 **SvelteKit + TailwindCSS + shadcn-svelte（构建于 bits-ui 之上）** 实现，
部署为**独立的 Cloudflare Worker**，通过 **Service Binding** 调用 API Worker。

### 技术栈

| 层 | 选型 | 理由 |
|---|---|---|
| 框架 | **SvelteKit**（`@sveltejs/adapter-cloudflare`） | 原生跑在 Workers 上；SSR + 文件路由；产物体积小；无虚拟 DOM 运行时开销 |
| 组件 | **shadcn-svelte**（源码复制式）+ **bits-ui**（无头原语） | 代码进仓库、可完全定制、无版本锁死；bits-ui 提供可访问性正确的原语 |
| 样式 | TailwindCSS + `mode-watcher`（暗色） | 与 shadcn-svelte 配套 |
| 图标 | `lucide-svelte` | 同上 |
| 表单 | `sveltekit-superforms` + `zod` | 类型安全的表单校验，服务端/客户端共用 schema |
| 表格 | TanStack Table (Svelte adapter) | 授权/设备列表需要排序、筛选、虚拟滚动、分页 |
| 图表 | LayerChart（shadcn-svelte chart 的底座） | 与组件体系一致；避免引入 ECharts 这类重库 |
| 类型 | 由 Rust 经 `ts-rs` 生成 → `@copylocker/admin-sdk` | 与服务端类型单一来源，杜绝漂移 |
| i18n | Paraglide (inlang) | 编译期抽取，无运行时开销 |

### 部署拓扑

```
┌──────────────────┐   Service Binding    ┌──────────────────┐
│ copylocker-admin │ ───(内部 RPC，不走公网)──▶ │ copylocker (API) │
│ (SvelteKit SSR)  │                       │  (Rust Worker)   │
│  admin.<domain>  │                       │  api.<domain>    │
└──────────────────┘                       └──────────────────┘
        ▲                                           ▲
        │ Cloudflare Access（推荐默认）              │ Bearer / mTLS
        │ 或内置 passkey 会话                        │
     Vendor 员工                                 客户端 SDK
```

**为什么拆成两个 Worker**

| 理由 | 说明 |
|---|---|
| 威胁模型不同 | API 是机器对机器的 CBOR 接口；控制台是带会话的 SSR 人机界面（XSS/CSRF/会话劫持面完全不同） |
| 发布节奏不同 | 控制台改 UI 不应触发 API Worker 的重新部署与灰度 |
| 体积与冷启动 | API Worker 的 WASM 体积预算（NFR-PERF-003 ≤1.5MB）不应被前端资产挤占 |
| 权限收敛 | 控制台 Worker **不绑定** Epoch 私钥、不绑定 Secrets Store 的签名密钥；一切签发操作经 Service Binding 调 API Worker，在那里做 scope 检查与审计 |
| 可选部署 | 不想要控制台的 Vendor 可以只部署 API Worker |

**Service Binding 的收益**：Worker 间调用不出 Cloudflare 网络、无公网跳、无额外 TLS 握手、
延迟接近函数调用，且不需要给控制台发放长期 Admin Token。

### 认证

| 方案 | 定位 |
|---|---|
| **Cloudflare Access**（推荐默认） | 零信任、SSO、MFA、审计日志由 CF 承担；控制台只读 `Cf-Access-Jwt-Assertion` 并验证 |
| **内置会话认证**（回退） | 邮箱 + **Passkey/WebAuthn**（不做密码优先）；给没有 Access 的小团队 |

控制台自身**不实现**授权签发逻辑，只是 API Worker 的 UI。所有变更操作在 API Worker 侧
重新做一遍 scope 校验与审计 —— **控制台是不可信的前端**。

## 备选方案与否决理由

| 方案 | 否决 |
|---|---|
| Preact / 手写轻量前端 | 缺成熟的表格/表单/图表生态，会在造轮子上耗掉数周 |
| React + Next.js | 在 Workers 上的适配不如 SvelteKit 干净；运行时更重；与"轻量自持"定位不符 |
| 纯 shadcn/ui (React) | 用户明确要 SvelteKit；shadcn-svelte 是等价物 |
| 只用 bits-ui 不用 shadcn-svelte | bits-ui 是无头的，样式全要自己写，拖慢进度 |
| Vue/Nuxt | 无明显优势；团队与生态取舍 |
| 与 API Worker 同源部署 | 见"为什么拆成两个 Worker" |
| 桌面端管理工具（Tauri） | 分发与更新成本高；Web 控制台随处可用 |

## 后果

**正面**
- 有能力承载 Policy 编辑器、分析看板这类复杂 UI，不必砍功能。
- shadcn-svelte 的源码复制模式意味着组件在我们仓库里，可随需求改，不受上游 breaking change 影响。
- 控制台本身成为 SDK 的参考实现（它就是 `@copylocker/admin-sdk` 的第一个消费者）。

**负面 / 代价**
- **新增一个前端技术栈**的维护面（构建、依赖升级、可访问性、浏览器兼容）。
- 工期增加：原计划 ~1 周的最小控制台 → 约 4–5 周（见 roadmap M7）。
- shadcn-svelte 的"复制源码"模式意味着上游修 bug 不会自动同步 → 需要定期人工同步流程。
- 两个 Worker → 部署编排复杂度增加（`wrangler deploy` 需要按序、Service Binding 需要先建）。

## 落地约束

- 控制台的 CSP 必须严格（`script-src 'self'`，无 `unsafe-inline`；SvelteKit 支持 CSP nonce/hash 配置）。
- 所有变更操作必须走 POST + CSRF token（SvelteKit form actions 默认带 origin 校验）。
- 高危操作（吊销、Release 标记 compromised、Epoch 吊销）在 UI 上**必须**走
  "dry-run 影响面预览 → 输入目标 ID 确认"的两步流程，与 CLI 行为一致。
- 控制台不得缓存任何授权密钥材料到 localStorage / IndexedDB。
- 分析页面的 k-匿名抑制（ADR-0007）在 UI 层再校验一次，防止 API 变更导致泄露。
