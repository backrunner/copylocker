# ADR-0006：服务端以 Rust（workers-rs）为主，TS 边缘壳为受控回退

- **状态**：Accepted
- **日期**：2026-07-26
- **相关**：`03-modules/10-server-worker.md`

## 背景

需求要求「由 Rust 编写」。Cloudflare 官方提供 `workers-rs`（`worker` crate，当前 0.8.x），
支持 Fetch/D1/KV/R2/Queues/Durable Objects。但有已知摩擦：

- 全部依赖必须能编译到 `wasm32-unknown-unknown`（`tokio`、`async-std` 不可用）。
- Workers RPC 的 Rust 代码生成仍是 pre-alpha。
- 本地端到端测试通常仍要写 JS/TS（Miniflare 是 Node 包）。
- WASM 模块体积影响冷启动。

## 决策

1. **主线：纯 Rust Worker**（`copylocker-worker` crate，`workers-rs`）。
   - 路由/HTTP/D1/KV/R2/Queues/DO 全部用 `worker` crate。
   - 领域逻辑放在**平台无关**的 `copylocker-server-core`（纯 Rust，无 `worker` 依赖，
     通过 `trait Storage` / `trait Clock` / `trait Signer` 抽象），使其可在 native 上单元测试与 fuzz。
   - `copylocker-worker` 只做「适配层」：把 `worker::Env` 的绑定包成 `Storage` 实现。
2. **不使用 Workers RPC 的 Rust codegen**（pre-alpha）；DO 之间通过 HTTP `fetch` 通信（稳定）。
3. **端到端测试用 TS + Vitest + `@cloudflare/vitest-pool-workers`**，
   Rust 侧只做单元/属性测试。这不违背「Rust 编写」，测试脚手架是工具而非产品代码。
4. **受控回退**：若某个 Cloudflare 新能力在 workers-rs 上缺失且阻塞（历史上出现过），
   允许该单一 Worker 用 TS + `hono` 实现薄壳，并通过 `wasm-bindgen` 调用同一份
   `copylocker-server-core` 编译出的 WASM。领域逻辑与密码学**永远在 Rust 里**，不重复实现。
   - 触发回退需要写 ADR 补记，说明缺失能力与恢复条件。

## 体积与冷启动约束

- Worker WASM 目标 ≤ 1.5 MB（压缩后），通过：
  - `opt-level="z"` + `lto="fat"` + `codegen-units=1` + `panic="abort"`
  - `wasm-opt -Oz`
  - 只启用实际使用的 Suite
  - 避免 `serde_json`，统一用 `ciborium`/`minicbor`（CBOR）+ 手写 JSON 序列化边界
- 冷启动预算：P95 < 50ms（含 WASM 实例化）。M1 阶段建立基准并纳入 CI 回归门禁。

## 后果

- 服务端与客户端**共享**密码学与协议实现（同一 crate 编到不同 target）→
  格式不一致的 bug 几乎被消灭，KAT 可双向复用。
- Rust 生态限制会持续存在；选依赖时必须先验证 `wasm32-unknown-unknown` 可编译（CI 里加该 target 的 check）。
- 部分 Cloudflare 新特性会有滞后 → 通过 §4 的回退机制吸收，不阻塞路线图。
