# 仓库布局与依赖图

## 1. 目录结构（公开仓库）

```
copylocker/
├── Cargo.toml                     # workspace
├── rust-toolchain.toml            # 固定 toolchain（可复现构建）
├── deny.toml                      # cargo-deny 配置
├── justfile / xtask/              # 任务编排
├── .agents/                       # 本文档目录
│
├── crates/
│   ├── copylocker-types/          # 共享类型，no_std+alloc，零依赖倾向
│   ├── copylocker-suite/          # ★ 槽位 trait 契约（公开、稳定、慎改）
│   ├── copylocker-suite-testkit/  # Suite 一致性测试框架 + KAT 加载器
│   ├── copylocker-suite-std/      # CL-STD-1 开源参考套件
│   ├── copylocker-suite-compact/  # CL-CMP-1 紧凑签名套件（FN-DSA）
│   ├── copylocker-proto/          # 凭证编解码、信封、证书链、版本协商
│   ├── copylocker-core/           # ★ 客户端领域核心：状态机/时钟/密钥派生
│   ├── copylocker-fingerprint/    # 设备指纹提供者（win/mac/linux/web）
│   ├── copylocker-store/          # 本地安全存储（keychain/DPAPI/secret-service/file）
│   ├── copylocker-client/         # 客户端 facade：传输 + 触发调度 + core 组装
│   ├── copylocker-server-core/    # ★ 服务端领域逻辑（纯，无 CF 依赖）
│   │                              #   含权益引擎 resolve()、订阅状态机、版本范围判定
│   ├── copylocker-analytics/      # 指标口径、rollup、HLL 草图（纯逻辑）
│   ├── copylocker-worker/         # Cloudflare Worker 适配层（workers-rs）
│   ├── copylocker-wasm/           # 浏览器 WASM 核心（wasm-bindgen）
│   ├── copylocker-tauri/          # tauri-plugin-copylocker
│   ├── copylocker-node/           # napi-rs 原生模块（Electron）
│   ├── copylocker-ffi/            # C ABI（cbindgen）
│   └── copylocker-cli/            # 管理与开发 CLI
│
├── packages/
│   ├── web/                       # @copylocker/web        —— TS SDK（含二段变换）
│   ├── tauri/                     # @copylocker/tauri      —— Tauri TS 绑定
│   ├── electron/                  # @copylocker/electron   —— 主进程 API + 桥
│   ├── unplugin/                  # @copylocker/unplugin   —— 构建期完整性
│   ├── guard/                     # @copylocker/guard      —— 运行时校验 + decorator
│   ├── seal/                      # @copylocker/seal       —— 资产封印（CLI + 运行时）
│   ├── telemetry/                 # @copylocker/telemetry  —— T1 聚合遥测（可选）
│   └── admin-sdk/                 # @copylocker/admin-sdk  —— 管理 API 客户端（ts-rs 生成类型）
│
├── apps/
│   └── console/                   # copylocker-admin Worker（SvelteKit + shadcn-svelte）
│
├── examples/
│   ├── tauri-app/  electron-app/  vite-spa/  nextjs-app/
│
├── server-template/               # create-copylocker 脚手架产出的模板
│   ├── wrangler.jsonc  migrations/  src/
│
├── vectors/                       # 公开 KAT 向量
├── docs/                          # VitePress 文档站
└── .github/workflows/             # CI
```

## 2. 依赖图

```
                        copylocker-types
                               │
                        copylocker-suite  ◀────────────── copylocker-suite-testkit
                          ╱         ╲                            ▲
             suite-std  ◀╯           ╲▶ suite-compact            │
                    ▲                        ▲          suite-priv（私有仓库）
                    └────────┬───────────────┘                   │
                             │  （由使用者在应用层选择注入）        │
                             ▼                                   │
                     copylocker-proto ◀──────────────────────────┘
                       ╱            ╲
        copylocker-core              copylocker-server-core
          ╱     │     ╲                        │
  fingerprint store  client                copylocker-worker
                       │                    （workers-rs 适配）
        ┌──────────────┼──────────────┬─────────────┐
        ▼              ▼              ▼             ▼
  copylocker-tauri  -node       -wasm          -ffi        -cli
        │              │            │
        ▼              ▼            ▼
  @copylocker/tauri  /electron   /web ──▶ /guard ──▶ /unplugin
                                            │
                                            └──▶ /seal
```

**禁止的依赖方向**（CI 用 `cargo-deny`/自定义 lint 检查）：

- ❌ `copylocker-suite` 依赖任何具体套件实现
- ❌ `copylocker-core` / `-server-core` 依赖任何平台 crate（`worker`、`tauri`、`napi`、`wasm-bindgen`）
- ❌ `copylocker-proto` 依赖 `std`（必须 `no_std + alloc`）
- ❌ 公开仓库任何 crate 提到 `copylocker-suite-priv`

## 3. 各 crate 的契约摘要

### `copylocker-types`
纯数据类型：`LicenseId`、`MachineId`、`Fingerprint`、`SuiteId`、`Entitlements`、
`LicenseState`、`Timestamps`。`no_std + alloc`，`serde` 可选 feature。
**不含任何逻辑。**

### `copylocker-suite`
见 [`crypto-architecture.md` §2](../02-architecture/crypto-architecture.md)。
**语义化版本极其保守**：任何 trait 变更都是 breaking，需要私有套件同步升级。
新增能力优先用**新 trait + 默认实现**而非改现有 trait。

### `copylocker-proto`
```rust
pub fn encode<S: CryptoSuite, A: Artifact>(a: &A, sk: &SigningKey) -> Result<Envelope>;
pub fn decode_and_verify<S: CryptoSuite, A: Artifact>(
    bytes: &[u8], chain: &VerifiedChain, now: i64
) -> Result<A, ProtoError>;
pub struct VerifiedChain { root_pins: Vec<Digest>, epoch: EpochCert }
```
`no_std + alloc`，`#![forbid(unsafe_code)]`。所有解析有深度与长度限制。

### `copylocker-core`
```rust
pub struct Core<S: CryptoSuite> { state: LicenseState, clock: ClockState, ... }

impl<S: CryptoSuite> Core<S> {
    // 纯函数式：输入事件 → (新状态, 副作用列表)
    pub fn handle(&mut self, ev: Event, now: i64) -> Vec<Effect>;
    pub fn derive_feature_key(&self, feature: &str) -> Result<SecretKey, CoreError>;
    pub fn build_activation_request(&self, ...) -> ActivationRequest;
    pub fn ingest_credential(&mut self, mc: MachineCredential) -> Result<(), CoreError>;
    pub fn ingest_ticket(&mut self, vt: ValidationTicket) -> Result<(), FatalError>;
}

pub enum Event { Tick, NetworkAvailable, AppResumed, TicketReceived(..), NetworkFailed(..), ... }
pub enum Effect { RequestValidation, PersistState(Blob), WipeCredentials, Notify(StateChange) }
```
**无 I/O、无时间获取、无随机**（全部作为参数传入）→ 100% 可确定性测试。

### `copylocker-server-core`
```rust
pub trait Storage {
    async fn license_do(&self, id: LicenseId) -> Result<impl LicenseStore>;
    async fn read_policy(&self, id: &PolicyId) -> Result<PolicySnapshot>;
    async fn revocation_epoch(&self) -> Result<u64>;
}
pub trait Issuer {
    async fn sign<A: Artifact>(&self, kind: ArtifactKind, a: &A) -> Result<Envelope>;
}
pub trait Clock { fn now(&self) -> i64; }

pub async fn handle_activate<S: CryptoSuite>(
    st: &impl Storage, iss: &impl Issuer, clk: &impl Clock, req: ActivationRequest
) -> Result<ActivateOutcome, ServerError>;
```
可在 native 上用内存实现跑完整集成测试与 fuzz。

## 4. Feature Flags 约定

| Crate | Feature | 说明 |
|---|---|---|
| `copylocker-*` | `std`（默认） | 关闭后为 `no_std + alloc` |
| `copylocker-suite-std` | `pq-ml-dsa-44/65/87` | 参数集选择，默认 65 |
| `copylocker-core` | `offline`, `air-gapped` | 裁剪不需要的路径以减小体积 |
| `copylocker-client` | `transport-reqwest`（默认桌面）、`transport-fetch`（wasm） | |
| `copylocker-fingerprint` | `windows`/`macos`/`linux`/`web` | 自动按 target 选择 |
| `copylocker-store` | `keychain`（默认）、`file-only` | |
| `copylocker-worker` | `suite-std`、`multi-suite` | 服务端启用的套件 |

## 5. 构建配置

```toml
# 发布 profile（客户端与 Worker 共用思路）
[profile.release]
opt-level = "z"        # Worker/WASM；桌面可用 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
overflow-checks = true # ★ 安全相关：保留溢出检查

[profile.release.package."*"]
opt-level = "z"
```

- WASM 产物再过 `wasm-opt -Oz --enable-bulk-memory`。
- 桌面客户端保留 `overflow-checks = true`（性能损失可忽略，安全收益明确）。
- `SOURCE_DATE_EPOCH` + `--locked` + 固定 toolchain → 可复现构建（NFR-SEC-007）。

## 6. 版本与发布

- **统一版本号**：所有 crate 与 npm 包同版本，同步发布（简化兼容矩阵）。
- **发布顺序**：types → suite → suite-* → proto → core/server-core → 平台层 → npm 包。
- **`cargo-release` + changesets** 编排；CI 自动化。
- 产物签名：Sigstore（`cosign` / `cargo-sigstore`），npm provenance。

## 7. CI 矩阵

| Job | 内容 |
|---|---|
| `check` | `cargo check` × {native, wasm32-unknown-unknown} × {std, no_std} |
| `test` | `cargo nextest` + `wasm-pack test --headless` |
| `kat` | 全部 Suite 跑 `copylocker-suite-testkit`（含负向向量） |
| `lint` | `clippy -D warnings`、`fmt --check`、自定义架构 lint（依赖方向） |
| `security` | `cargo-deny`、`cargo-audit`、npm audit、二进制熵扫描（无私钥常量） |
| `size` | WASM 体积门禁（NFR-PERF-003/005），超阈值即失败 |
| `bench` | criterion 基准 + 回归阈值 15% |
| `e2e` | `wrangler dev` + Vitest（`@cloudflare/vitest-pool-workers`）+ Playwright（web 示例） |
| `fuzz` | nightly，`cargo-fuzz` 全部解析入口 |
| `repro` | 两次独立构建产物字节一致 |
