# 模块：Web SDK（Rust + WASM / TypeScript 混合）

Crate：`copylocker-wasm` · Package：`@copylocker/web`
需求：FR-WEB-*、NFR-PERF-005/006、NFR-SEC-011

## 1. 设计目标与现实

**目标**：让"替换 WASM"和"mock TS API"都不足以获得受保护内容。

**现实约束（必须诚实写进文档）**：浏览器环境中攻击者拥有 DevTools、可任意改 JS、
可用 `wasm-tools` 反编译与改写 WASM。任何客户端方案都是"提高门槛"。
Web 端的安全强度**本质上弱于原生端**。

## 2. WASM / TS 职责拆分

```
┌────────────────────── WASM（Rust）──────────────────────┐
│ · 证书链验证（Root pin → EpochCert → MC/VT）             │
│ · 混合 PQ 签名验证                                       │
│ · KEM 解封 → CredentialSecret                            │
│ · 状态机、时钟守卫、吊销判定                              │
│ · 凭证 CBOR 编解码                                        │
│ · SessionRoot 的【前半段】派生 → 输出"半熟"密钥材料 M     │
└────────────────────────┬────────────────────────────────┘
                         │ M（不透明 32B，不可直接用）
┌────────────────────────▼────────────────────────────────┐
│                  TS（@copylocker/web）                   │
│ · 触发调度（启动/online/visibilitychange/周期/插桩）       │
│ · 传输（fetch）与重试退避                                 │
│ · 环境探针（构建期注入的常量 K_build、清单根摘要 R）        │
│ · 【二段变换】FinalKey = H(M ‖ K_build ‖ R ‖ H(wasmBytes))│
│ · 资产解封与缓存管理                                       │
└─────────────────────────────────────────────────────────┘
```

**关键性质**
- 只替换 WASM → `M` 是伪造的 → `FinalKey` 错误 → 解不开资产。
- 只改 TS → `K_build`/`R` 硬编码在 bundle 中，改了就对不上；且 `M` 仍需真实 CredentialSecret。
- 同时改两边 → 仍缺 `CredentialSecret`（在 KEM 密文中，需设备私钥），**这才是根本保障**。
- 二段变换的真正价值：**把"一处 stub"变成"必须完整重实现密码学"**。

> ⚠️ 诚实说明：二段变换本身不提供密码学安全性（常量都在客户端）。
> 它提供的是**工程上的不可分割性** —— 攻击者无法只 patch 一个函数返回 `true`。
> 密码学安全性来自 KEM 密封 + 签名链，那部分是真的。

## 3. WASM 导出面设计

### 3.1 不透明 challenge/response

```rust
#[wasm_bindgen]
pub struct ClSession(Core<ClStd1>);

#[wasm_bindgen]
impl ClSession {
    #[wasm_bindgen(constructor)]
    pub fn new(cfg: &[u8]) -> Result<ClSession, JsValue>;   // cfg 为 CBOR

    /// 唯一的通用入口。输入输出都是 CBOR 不透明字节。
    /// op 编码在 CBOR 内部，外部看不出这次是"验证"还是"派生"还是"状态查询"。
    pub fn step(&mut self, input: &[u8]) -> Result<Vec<u8>, JsValue>;
}
```

- **没有** `isValid()`、`getState()`、`verify()` 这样的语义化导出。
- 所有操作走 `step`，op code 在加密/编码后的 CBOR 里。
- 错误统一为数值码，不含可 grep 的字符串（NFR-SEC-011）。
- `wasm-bindgen` 生成的 glue 中的函数名通过构建期重写随机化（见 §5）。

### 3.2 输出的"半熟"密钥材料

```rust
// WASM 内部
let m = Kdf::expand(&session_root_partial, b"cl/web/m/v1", 32);
// 返回 m，而不是 FeatureKey
```

TS 侧：
```ts
const finalKey = await sha256Concat(m, K_BUILD, MANIFEST_ROOT, wasmDigest)
const plaintext = await aeadOpen(finalKey, sealed)
```

## 4. TS 层（`@copylocker/web`）

### 4.1 公开 API

```ts
export interface CopyLockerOptions {
  serverUrl: string
  productId: string
  rootPins: string[]              // 构建期注入
  storage?: 'indexeddb' | 'memory'
  worker?: boolean                // 默认 true：核心跑在 Web Worker
  privacy?: { reportAttrs?: boolean; canvasFingerprint?: boolean }
  onStateChange?: (s: LicenseState) => void
}

export class CopyLocker {
  static async create(opts: CopyLockerOptions): Promise<CopyLocker>
  activate(key: string): Promise<void>
  activateWithAccount(token: string): Promise<void>
  deactivate(): Promise<void>

  /** 唯一的"使用授权"入口 */
  unseal(featureId: string, sealed: BufferSource): Promise<Uint8Array>
  /** 加载并解封由 @copylocker/seal 处理过的资源 */
  loadSealed(url: string, featureId: string): Promise<Uint8Array>

  /** 仅 UI 展示 —— 不可用于门禁 */
  readonly state: LicenseState
  hintOnline(): void
}
```

**API 红线**：无 `isLicensed()`、无 `check(): boolean`。
`state` 的 TSDoc 首行必须是 `@deprecated for gating — advisory only`（用 `@deprecated` 触发 IDE 警告是刻意的）。

### 4.2 Web Worker 隔离（FR-WEB-008）

默认在 Worker 中实例化 WASM：
- 减少主线程可被 hook 的表面（页面上的第三方脚本不能直接访问 Worker 内的对象）。
- Worker 脚本本身也在 IntegrityManifest 覆盖范围内。
- 通过 `MessageChannel` 通信，消息体为不透明字节。
- 降级：不支持 Worker 时回退主线程（记录降级标志，参与 evidence）。

### 4.3 触发器

```ts
// 内部注册，用户无需关心
window.addEventListener('online', () => sched.trigger('network'))
document.addEventListener('visibilitychange', () => { if (!document.hidden) sched.trigger('resume') })
// 周期：setTimeout 递归（非 setInterval，避免后台节流累积）
// 插桩：unseal() 内部检查 nextCheckAt
// 网络提示：可选的 fetch 包装器（默认不 monkey-patch 全局 fetch）
```

**不 monkey-patch 全局 `fetch`**（侵入性太强、与其他库冲突）；
改为提供 `hintOnline()` 与可选的 `wrapFetch()` helper。

### 4.4 存储（FR-WEB-007）

```ts
// device_kem_sk 的 X25519 部分：WebCrypto 非可提取 CryptoKey
const kp = await crypto.subtle.generateKey({ name: 'X25519' }, /* extractable */ false, ['deriveBits'])
await idbPut('cl:dk', kp.privateKey)   // 存 CryptoKey 对象，无法导出原始字节
```

- ML-KEM 部分 WebCrypto 尚不支持 → 只能软件保管，用非可提取的 AES-KW 密钥包裹后存 IndexedDB。
  **这是 Web 端的固有弱点，必须在文档中声明。**
- 凭证 blob 用非可提取 AES-GCM 密钥加密后存 IndexedDB。
- localStorage 只存非敏感的 device_id（作为 IndexedDB 被清时的冗余）。

### 4.5 SSR / 同构（FR-WEB-009）

```ts
// 仅在客户端初始化
if (typeof window !== 'undefined') { cl = await CopyLocker.create(...) }
```
提供 `@copylocker/web/ssr` 导出一个 no-op 存根，避免 SSR 阶段报错。
Next.js 示例中用 `dynamic(() => import(...), { ssr: false })`。

### 4.6 框架绑定（FR-WEB-010）

```ts
// React
const { state, unseal } = useCopyLocker()
// Vue
const { state, unseal } = useCopyLocker()
// Svelte
$: state = $copylocker.state
```
薄封装，不引入额外逻辑。

## 5. 构建期硬化

| 手段 | 实现 | 效果 |
|---|---|---|
| **导出符号随机化** | 构建期用 `wasm-bindgen` 输出后处理：按 `build_seed` 派生新名字，重写 wasm export 段与 JS glue | 通用 patch 脚本无法按名定位 |
| **WASM 摘要注入** | unplugin 计算 `.wasm` 摘要，注入 TS 常量并参与二段变换 | 替换 wasm 即失效 |
| **清单根注入** | `MANIFEST_ROOT` 常量 | 篡改任意 chunk 即失效 |
| **常量分散** | `K_BUILD` 被拆成多个片段散布在不同 chunk，运行时组合 | 提高定位成本 |
| **二进制多样化（可选）** | `wasm-mutate` 语义保持变换，每次发布产出不同字节序列 | 阻止基于字节模式的通用 patcher |
| **可选混淆** | 与 `javascript-obfuscator` 的集成顺序有文档与集成测试 | 提高阅读成本 |

> **明确声明**：以上都是 **obfuscation / diversification**，不是密码学保护。
> 它们提高的是"编写通用破解工具"的成本，不改变"单次手工破解"的可行性。

## 6. 与 unplugin / guard 的关系

```
@copylocker/unplugin  ──构建期──▶ 注入 K_BUILD / MANIFEST_ROOT / WASM_DIGEST / 随机符号名
                                 生成 IntegrityManifest（签名）
                                 封印 Sealed Assets
        │
        ▼
@copylocker/guard     ──运行时──▶ 校验 chunk 摘要 → 产出 R（清单根验证结果）
                                 校验 guarded 函数体
        │
        ▼
@copylocker/web       ──运行时──▶ WASM step() → M
                                 FinalKey = H(M ‖ K_BUILD ‖ R ‖ WASM_DIGEST)
                                 unseal(资产)
```

**关键**：`R` 不是"校验是否通过"的布尔值，而是**由实际计算出的摘要构成的值**。
校验失败 ⇒ `R` 不同 ⇒ `FinalKey` 错误 ⇒ 解不开。
删掉 guard ⇒ 拿不到 `R` ⇒ 同样解不开。这是 guard 不可被简单移除的原因。

## 7. 体积预算（NFR-PERF-005）

| 组成 | 预估（gzip） |
|---|---|
| ML-DSA-65 验证 | ~90 KB |
| Ed25519 验证 | ~15 KB |
| ML-KEM-768 decap + X25519 | ~60 KB |
| XChaCha20-Poly1305 + HKDF + SHA-2 + BLAKE3 | ~35 KB |
| CBOR + 协议 + 状态机 | ~45 KB |
| wasm-bindgen glue | ~15 KB |
| **合计** | **~260 KB** ✅ |

优化手段：`opt-level="z"`、`wasm-opt -Oz`、裁剪未用 feature、
只编译**验证**路径（不含签名/keygen 的服务端代码）。

若超标：降到 ML-DSA-44（仍 128-bit PQ）可省约 30 KB。

## 8. 兼容性

| 能力 | 要求 | 降级 |
|---|---|---|
| WebAssembly | 必须 | 无（明确不支持） |
| WebCrypto SubtleCrypto | 必须（需 secure context） | 无 |
| IndexedDB | 必须 | 内存存储（每次都要重新激活） |
| Web Worker | 推荐 | 主线程 |
| X25519 in WebCrypto | 推荐 | 软件实现（WASM 内） |
| CSP 严格模式 | 支持 | 需配置 `wasm-unsafe-eval`（文档给出说明） |

**CSP 注意**：加载 WASM 需要 `script-src 'wasm-unsafe-eval'`。
文档必须给出推荐 CSP 与与 `unplugin` SRI 的配合方式。

## 9. 测试

| 类型 | 内容 |
|---|---|
| 单元 | WASM 侧用 `wasm-pack test --headless --chrome/--firefox` |
| 集成 | Playwright 驱动 vite-spa 与 nextjs 示例，完整激活 → unseal |
| 攻击模拟 | ① 替换 wasm 为 stub ② 篡改 chunk 一字节 ③ 删除 guard ④ 覆写 `Function.prototype.toString` ⑤ 清空 IndexedDB |
| 体积回归 | CI 门禁，超阈值失败 |
| 性能 | LCP 影响测量（Lighthouse CI），< 20ms |
| 隐私 | 断言默认配置下不采集 canvas/WebGL 指纹 |
