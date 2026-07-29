# 模块：原生 SDK（Tauri / Electron / C ABI）

需求：FR-NAT-*、NFR-PORT-002/005

## 1. 共同原则

1. **与宿主一起编译**，不作为可独立替换的动态库分发（Electron 的 `.node` 是例外，需额外加固）。
2. **接出到 JS 的不是布尔判定**，而是：
   - `unseal(featureId, sealedBytes) -> bytes`
   - `challenge(opaqueIn) -> opaqueOut`（供 JS 侧完成二段变换）
   - `state()`（仅 UI）
3. **模块自身摘要参与 Feature Key 派生**（`env_evidence`），替换模块 → 派生出错误的密钥。
4. 所有跨语言边界的数据是**不透明字节**，不是结构化的"验证结果对象"。

## 2. Tauri 插件（`tauri-plugin-copylocker`）

### 2.1 结构

```
crates/copylocker-tauri/
├── src/
│   ├── lib.rs         Builder / plugin init
│   ├── commands.rs    #[tauri::command] 定义
│   ├── state.rs       托管的 CopyLockerClient<S>
│   └── evidence.rs    自身二进制证据采集
├── permissions/       Tauri v2 权限定义（默认最小集）
└── guest-js/          TS 绑定源（由 ts-rs/specta 生成类型）
```

### 2.2 集成方式

```rust
// src-tauri/src/main.rs
use copylocker_suite_std::ClStd1;
use tauri_plugin_copylocker::CopyLockerConfig;

fn main() {
    let config = CopyLockerConfig::<ClStd1>::new(
        env!("CL_SERVER_URL"),
        "com.example.my-app",                 // 本地存储命名空间
        "my-app",                             // 服务端 product ID
        env!("CARGO_PKG_VERSION"),
        env!("CL_RELEASE_ID"),
        env!("CL_BUILD_FP"),
        include_bytes!("../root-key.bin").to_vec(),
        include_bytes!("../fingerprint-salt.bin").to_vec(),
        1,                                     // variant ID
        [0x42; 32],                            // variant constant
        [0x24; 32],                            // 注册过的 evidence fallback
    );

    tauri::Builder::default()
        .plugin(tauri_plugin_copylocker::init::<_, ClStd1>(config))
        .run(tauri::generate_context!())
        .expect("error");
}
```

**编译期常量注入**：server URL、应用/产品/发行标识、Root 验证公钥、fingerprint
salt、variant 常量、build fingerprint 与预期模块摘要均嵌入宿主，不从可写运行时配置读取。
Root 轮换可用 `with_next_root_key` 预置下一把验证公钥；仅本地开发可显式启用
`with_insecure_localhost(true)`，该开关只允许 loopback HTTP。

### 2.3 Commands

```rust
#[tauri::command] async fn cl_activate(key: String, st: State<'_, Cl>) -> Result<(), CmdErr>;
#[tauri::command] async fn cl_deactivate(st: State<'_, Cl>) -> Result<(), CmdErr>;
#[tauri::command] fn cl_state(st: State<'_, Cl>) -> StateDto;              // UI only
#[tauri::command] fn cl_unseal(feature: String, data: Vec<u8>, st: State<'_, Cl>) -> Result<Vec<u8>, CmdErr>;
#[tauri::command] fn cl_challenge(input: Vec<u8>, st: State<'_, Cl>) -> Result<Vec<u8>, CmdErr>;
#[tauri::command] fn cl_offline_request(key: String, st: State<'_, Cl>) -> Result<Vec<u8>, CmdErr>;
#[tauri::command] fn cl_offline_import(data: Vec<u8>, st: State<'_, Cl>) -> Result<(), CmdErr>;
#[tauri::command] fn cl_import_olk(data: String, st: State<'_, Cl>) -> Result<(), CmdErr>;
```

事件：`copylocker://state-changed`（payload = `StateDto`），前端订阅更新 UI。

### 2.4 权限（Tauri v2 ACL）

```toml
# permissions/default.toml
[[permission]]
identifier = "allow-state"
commands.allow = ["cl_state"]

[[permission]]
identifier = "allow-activation"
commands.allow = [
    "cl_activate",
    "cl_deactivate",
    "cl_offline_request",
    "cl_offline_import",
    "cl_import_olk",
]

[[permission]]
identifier = "allow-unseal"
commands.allow = ["cl_unseal", "cl_challenge"]
```

默认 capability 只给 `allow-state` + `allow-activation`；`allow-unseal` 需显式启用。

### 2.5 自身证据（`evidence.rs`）

```rust
pub fn collect() -> EnvEvidence {
    EnvEvidence {
        // object crate 解析 Mach-O / PE / ELF，BLAKE3 哈希 .text 或 __text
        module_digest: hash_own_text_segment_or_embedded_fallback(),
        build_fingerprint: env!("CL_BUILD_FP").as_bytes().to_vec(),
        extra: Vec::new(),
    }
}
```

> 注意：读取自身二进制在某些平台（如 macOS 的 hardened runtime、Linux 的 `/proc/self/exe`
> 被容器限制）可能失败。失败时**降级为固定占位值**并记录 —— 不能因证据采集失败就锁定用户。
> 证据的价值在于「替换了二进制的攻击者拿到的是不同的值」，而非「一定能采到」。
> 实现不依赖平台代码签名 API；当前统一哈希可执行文件代码段，且拒绝读取超过 512 MiB
> 的宿主。平台差异必须在发行注册数据中固定，否则会派生出不同的 FK。
> **实现纪律：证据采集必须是确定性的，并在首次激活时把采集结果的哈希写入 MC 的 AAD。**

### 2.6 Tauri 特有的加固建议（文档给使用者）

- 关闭 devtools（release）；`app.security.csp` 严格配置。
- 前端资源用 `copylocker-seal` 封印关键 chunk。
- 不要在前端存储任何授权状态；每次都问后端。
- `dangerousDisableAssetCspModification` 保持 false。

## 3. Electron（`copylocker-node` + `@copylocker/electron`）

### 3.1 结构

```
crates/copylocker-node/          napi-rs → copylocker.<platform>.node
packages/electron/
├── src/main/index.ts            主进程 API（唯一持有原生模块）
├── src/preload/index.ts         contextBridge 白名单
├── src/renderer/index.ts        渲染进程客户端（只发消息）
└── npm/                         各平台预编译包（optionalDependencies）
```

### 3.2 主进程 API

```ts
import { CopyLocker } from '@copylocker/electron/main'

const cl = await CopyLocker.create({
  serverUrl: CL_SERVER_URL,
  appId: 'com.example.my-app',
  productId: 'my-app',
  appVersion: APP_VERSION,
  releaseId: RELEASE_ID,
  buildFingerprint: BUILD_FINGERPRINT,
  currentRootKey: ROOT_VERIFYING_KEY,
  fingerprintSalt: FINGERPRINT_SALT,
  variantId: 1,
  variantConst: VARIANT_CONST,
  expectedModuleDigest: EXPECTED_MODULE_DIGEST,
})

app.whenReady().then(() => {
  cl.attachIpc({
    allowedFeatures: ['pro-config'],
    allowChallenge: false,
    rateLimit: { windowMs: 60_000, maxRequests: 120, maxBytes: 8 * 1024 * 1024 },
  })
})
```

配置必须由 release 构建过程注入；`modulePath` 默认取 `@copylocker/node` 实际加载路径，
`asarPath` 默认从 Electron 的 `app.getAppPath()` 推断。两者如显式提供，必须是绝对路径。

### 3.3 IPC 安全设计

```ts
// preload.ts —— SDK 只暴露固定 window.__cl bridge，不接受任意 channel
import { installCopyLockerBridge } from '@copylocker/electron/preload'
installCopyLockerBridge()
```

- `contextIsolation: true`、`nodeIntegration: false`、`sandbox: true` 为**硬性前提**，
  preload、现有窗口与后续新建 WebContents 都会被检查；不满足时拒绝/销毁。
- IPC 只接受顶层 `senderFrame`，拒绝 iframe；每次调用还会重新检查 sender 的
  WebPreferences，不能仅依赖窗口创建时的配置。
- `unseal` 的 feature 白名单在主进程配置，默认空；`challenge` 因无法从外层过滤 feature
  而默认关闭；激活/离线生命周期默认启用且可整体关闭。
- IPC handler 按 sender 同时限制窗口内请求数和输入字节数，默认每 60 秒 120 次、8 MiB。
- preload 与主进程都执行类型、NUL、UTF-8 字节长度和二进制大小检查；错误只跨边界返回
  稳定数字码，不泄漏原生错误细节。

### 3.4 Renderer 资源边界

示例应用使用预注册的标准安全协议 `copylocker://bundle`，不授予 `file:` 额外权限。
协议 handler 对 URL 解码、规范化并验证最终路径仍位于 renderer 根目录，然后在响应头设置
严格 CSP（包括 `frame-ancestors 'none'`）与 `X-Content-Type-Options: nosniff`。同时拒绝所有
新窗口，并只允许一次初始导航。生产宿主必须提供等价边界，不能直接放宽到任意本地文件。

### 3.5 `.node` 模块的加固（FR-NAT-005）

Electron 的原生模块是独立文件，最易被整体替换。缓解：

1. **`.node` 自身摘要参与 FK 派生**：
   主进程启动时以 domain-separated BLAKE3 同时哈希 `.node` 文件和可选 `app.asar` 头部，
   作为 `env_evidence.module_digest`；读取失败才使用已注册的 embedded fallback。
   替换 `.node` → 摘要变 → FK 错误 → Sealed Asset 解不开。
   > 注意：这个摘要由**同一个被替换的模块**计算，看似循环。
   > 真正的保障是：正确的 `module_digest` 值在**签发 MC 时**被服务端记录进 AAD，
   > 客户端伪造摘要会导致 AEAD 解封失败。攻击者必须让替换后的模块报告**原始**摘要，
   > 这可行 —— 但此时他仍然没有 `CredentialSecret`（在 KEM 密文里），依然解不开资产。
   > **摘要的作用是提高 stub 化的难度，不是根本保障；根本保障是 KEM 密封。**
2. **`app.asar` 完整性**：启用 `EnableEmbeddedAsarIntegrityValidation` 与
   `OnlyLoadAppFromAsar`；`.node` 保持在 `app.asar.unpacked`，renderer 必须仍位于 ASAR 内。
3. **代码签名 + 公证**：macOS notarization、Windows Authenticode。文档提供 CI 配置示例。
4. **收紧 fuses**：至少关闭 RunAsNode、Node options、CLI inspect 与 file protocol extra
   privileges，开启 cookie encryption；打包后读取实际 fuse wire 并逐项断言。

### 3.6 Challenge wire contract

`challenge(input)` 的输入输出都是 canonical CBOR，不是任意裸 nonce：

- 请求：`{ 0: 1, 1: feature_id text, 2: challenge bytes }`，完整消息不超过 64 KiB；
  feature ID 为 1..1024 bytes、无 NUL；challenge 为 1..60 KiB；不接受扩展字段。
- 响应：`{ 0: 1, 1: material bytes }`，material 固定 32 bytes。

宿主完成第二段 domain-separated 派生；不得把响应 material 当布尔授权结果或直接持久化。

### 3.7 跨平台预编译

napi-rs 标准做法：主包 + `optionalDependencies` 引入平台子包。

| Target | triple |
|---|---|
| macOS | `aarch64-apple-darwin`, `x86_64-apple-darwin` |
| Windows | `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc` |
| Linux | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` |

CI 用 GitHub Actions 矩阵构建 + npm provenance 发布。

## 4. `copylocker-ffi` —— C ABI

供 Qt / Flutter / C++ / .NET 等宿主接入。

```c
typedef struct cl_client cl_client;

struct cl_client* cl_create(const struct cl_config* cfg, struct cl_error* err);
void cl_destroy(struct cl_client* client);

int32_t cl_activate(struct cl_client* client, struct cl_str key, struct cl_error* err);
int32_t cl_deactivate(struct cl_client* client, struct cl_error* err);
int32_t cl_state(struct cl_client* client);       /* advisory only */

/* 返回堆分配缓冲，需 cl_free_buf */
struct cl_buf cl_unseal(struct cl_client* client, struct cl_str feature,
                        struct cl_bytes data, struct cl_error* err);
struct cl_buf cl_challenge(struct cl_client* client, struct cl_bytes input,
                           struct cl_error* err);
struct cl_buf cl_offline_request(struct cl_client* client, struct cl_str key,
                                 struct cl_error* err);
int32_t cl_offline_import(struct cl_client* client, struct cl_bytes data,
                          struct cl_error* err);
int32_t cl_import_olk(struct cl_client* client, struct cl_str data,
                      struct cl_error* err);
void cl_free_buf(struct cl_buf buffer);
```

- 头文件由 `cbindgen` 生成。
- 字符串与字节均用显式长度的借用值类型；`cl_buf` 带不可修改的 allocation handle，
  不得由宿主自行构造或改写。
- 所有 `unsafe` 局限在此 crate，且每个 `unsafe` 块有安全性注释与对应测试。
- 提供 `.def`/`.map` 导出符号最小化。
- 线程安全：`cl_client` 内部用 `Mutex`；文档声明可跨线程使用。

## 5. 接入示例（DX 目标：≤ 20 行）

```ts
// Tauri 前端
import { activate, unseal, onStateChanged } from '@copylocker/tauri'

await activate(userInputKey)

// 使用受保护资源（而非 if (licensed)）
const config = JSON.parse(new TextDecoder().decode(
  await unseal('pro-features', await loadSealed('config.sealed'))
))

onStateChanged(s => ui.showBadge(s))   // 仅展示
```

```ts
// Electron 渲染进程
const model = await window.__cl.unseal('ai-model', sealedModelBytes)
```

## 6. 测试

| 类型 | 内容 |
|---|---|
| 集成 | 每个宿主的 example app + Playwright/WebDriver 驱动完整激活流程 |
| 替换攻击 | 用 stub `.node` 替换 → 断言 unseal 失败 |
| 跨机 | 复制整个应用数据目录到另一台机器 → 断言失败 |
| 平台矩阵 | CI 在 macOS/Windows/Linux 上跑同一套集成测试 |
| 证据确定性 | 同一台机器多次运行 evidence 采集，结果必须一致（防 FK 抖动） |
| 降级 | 证据采集失败时不应锁定用户 |
