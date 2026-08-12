# CopyLocker 管理控制台（apps/console）

M7 第一阶段：SvelteKit + adapter-cloudflare + Tailwind CSS + shadcn-svelte 风格组件（bits-ui
无头原语）。这是 API Worker 的**不可信前端**：不做任何授权判定、不持有签名密钥、不直连
D1/DO，一切变更经 Service Binding 调 API Worker，由后者重新做 scope 校验与审计
（ADR-0010、`.agents/03-modules/95-admin-console.md`）。

## 本地开发

```bash
rtk npm install
```

三种方式：

1. **Mock API（零依赖，推荐起步）**

   ```bash
   rtk npm run mock          # 内存态 mock，监听 :8788，覆盖 A 组全部端点
   PUBLIC_API_BASE=http://localhost:8788 rtk npm run dev
   ```

   登录页输入任意合法格式 token（`clat_` + 43 位 base64url 字符）即可。

2. **真实 API Worker（vite dev 直连）**

   ```bash
   (cd ../../crates/copylocker-worker && rtk npm run dev)   # API Worker on :8787
   PUBLIC_API_BASE=http://localhost:8787 rtk npm run dev
   ```

   注意：API Worker 的 `/v1/admin/*` 不带 CORS 头，浏览器直连会被拦截；
   此方式仅供本机 curl 类调试，常规开发用方式 1 或 3。

3. **Service Binding（最贴近生产）**

   ```bash
   rtk npm run preview       # vite build && wrangler dev
   ```

   `wrangler dev` 会按 `wrangler.jsonc` 建立到 `copylocker` 服务的 Service Binding
   （需本地同时 `wrangler dev` 起 API Worker）。页面请求走 `/admin-api/*` 代理，
   由 console Worker 经 binding 转发。

## 命令

```bash
rtk npm run dev         # vite dev
rtk npm run build       # 产物到 .svelte-kit/cloudflare
rtk npm run check       # svelte-check
rtk npm run test        # vitest 单测（mock fetch：两步吊销 / 422 护栏 / 幂等键 / token 不进 URL；
                        # Simulator wasm 三方一致性；axe 可访问性门禁）
rtk npm run build:wasm  # 构建 Simulator wasm（crates/copylocker-simulator-wasm → src/lib/simulator/wasm/）
rtk npm run mock        # 本地 mock Admin API
```

## 认证

| 环境 | 机制 |
|---|---|
| 生产 | **Cloudflare Access（默认）**：`hooks.server.ts` 检查 `Cf-Access-Jwt-Assertion` 的存在性做路由守卫（`ACCESS_ENFORCE=true` 开启）。**完整 JWKS 验签属部署期配置** —— 设置 `CF_ACCESS_TEAM_DOMAIN` / `CF_ACCESS_AUD` 后按 `hooks.server.ts` 中的 TODO 接入验签；在此之前不要把它当成授权边界。 |
| 开发 | 登录页输入 Admin token（`clat_*`），仅存 **sessionStorage**（不写 localStorage/IndexedDB），随请求经 `/admin-api` 代理转发。token 不进 URL、不进日志（有单测断言）。 |

无论哪条路径，真正的授权判定都在 API Worker 侧（Bearer + scope + 审计）。

## 与 ADR-0010 的一致性声明

- `wrangler.jsonc` 只声明 `services: [{ binding: "API", service: "copylocker" }]`；
  **不绑定** D1/DO/KV/R2，**不绑定**任何签名密钥或 Secrets Store。
- CSP 严格：`script-src 'self'`，无 `unsafe-inline`（`svelte.config.js`，SvelteKit nonce/hash 模式）。
- 变更操作只发 POST/PATCH + JSON；客户端自动携带 `Idempotency-Key`（`crypto.randomUUID()`）。
- 高危操作（License/Machine 吊销、Epoch 吊销）UI 强制
  "dry-run 影响面 → 输入完整目标 ID 确认"，与 CLI 行为一致；Epoch 吊销走
  replacement 就绪检查 + 双 actor / 15 分钟审批流。
- 明文 License Key 仅在签发响应中出现一次，UI 强制先下载 CSV 再手动从内存清除。
- 响应读取上限 4 MiB（与 CLI 一致）；只允许 `/v1/admin/*` 路径。

## 结构与接口预留（M7-B 已落地部分）

- `src/lib/api/client.ts` 是 **`@copylocker/admin-sdk` 的适配层**（单仓源码直引，
  `svelte.config.js` 的 kit.alias → `packages/admin-sdk/src/index.ts`），保留页面约定的
  方法名与返回形状；SDK 侧的类型经 ts-rs bindings + CI 漂移检查与 Rust 线格式对齐。
  `src/lib/api/` 仍是**唯一**的 API 访问层。
- `/policies/[id]/simulate`：配置预览器。wasm 核心
  `crates/copylocker-simulator-wasm` 包裹 `copylocker_server_core::simulator::simulate`
  （与 CLI、服务端同一函数）；场景库（正常续订/中途取消/支付失败/凭证过期）+ 时间轴
  可视化；三方一致性由 `crates/copylocker-simulator-wasm/tests/consistency.rs` 与
  `src/lib/simulator/consistency.test.ts` 双向锁定（共享同一对 fixture）。
- `/offline`：离线激活门户（公开路由）。AR 中继（raw canonical CBOR →
  `/offline-api/request` → `POST /v1/offline/request`，16 KiB 上限、Idempotency-Key、
  Retry-After/冷却 UX、可选 Turnstile）+ CLK1 armor → QR（纯客户端）。
  已知偏差与 agent.md M5-B 记录一致：AR 的 Base32 armor 与 QR-for-AR 未实现。
- 其余占位路由：`/releases`、`/analytics`、`/audit`、`/settings`
  （等全局 machines/audit 端点与 group-B 页面，见 roadmap）。

## 安全注意事项

- 依赖安装使用 `--ignore-scripts`（`.npmrc`）。
- 不要在日志、URL、分析事件中输出 Admin token 或明文 License Key。
- `/offline` 是公开路由，不共享任何 admin 认证代码路径（独立分支、无侧边栏）。
