# 模块：构建期完整性（`@copylocker/unplugin` + `@copylocker/guard` + `@copylocker/seal`）

需求：FR-BLD-*、AC-7、NFR-PERF-006

## 1. 为什么需要

Web 端的插桩很脆弱：一个 `if` 被删就完了。所以我们把防线前移到**构建产物本身**：

1. 构建期给每个产物 chunk 计算摘要，汇总成 `IntegrityManifest` 并签名。
2. 运行时 JS 自己校验自己的完整性。
3. **校验结果参与密钥派生**（不是上报，也不是抛异常）—— 这是它不可被简单移除的原因。
4. 额外提供 `@guarded` decorator，在函数被调用时校验函数体未被替换。

## 2. `@copylocker/unplugin`

### 2.1 配置

```ts
// vite.config.ts
import copylocker from '@copylocker/unplugin/vite'

export default defineConfig({
  plugins: [
    copylocker({
      productId: 'my-app',
      // 覆盖范围
      include: ['**/*.js', '**/*.css', '**/*.wasm'],
      exclude: ['**/*.map'],

      // ★ 可自定义签名与摘要算法（FR-BLD-003）
      hasher: 'blake3',                       // 'blake3' | 'sha256' | 自定义函数
      signer: {
        kind: 'remote',                       // 'local' | 'remote' | 自定义函数
        endpoint: process.env.CL_SIGN_URL,
        token: process.env.CL_SIGN_TOKEN,
      },
      verifierRuntime: 'default',             // 可替换整个运行时校验实现

      // 封印
      seal: {
        assets: ['assets/pro-*.json', 'assets/model-*.bin'],
        chunks: [{ match: /pro-features/, feature: 'pro' }],
      },

      // guarded 函数
      guard: {
        decorator: true,                      // 启用 @guarded transformer
        sampleRate: 0.15,                     // 运行时抽样校验比例
      },

      // 硬化
      randomizeWasmExports: true,
      splitConstants: 4,                      // K_BUILD 拆成 4 片
    }),
  ],
})
```

### 2.2 生命周期钩子

```
buildStart      → 生成 build_fingerprint（内容无关的随机 + git sha + 时间）
                  生成 build_seed（用于符号随机化、常量拆分）
transform       → 采集 @guarded 函数体、注入常量占位符 __CL_K_BUILD_0__ 等
renderChunk     → 记录 chunk 逻辑名 ↔ 文件名映射
generateBundle  → ① 对所有 chunk 计算摘要（hasher）
                  ② 构建 Merkle 树 → root
                  ③ 封印 Sealed Assets（用 seal 的 KEK）
                  ④ 回填常量占位符（K_BUILD 分片、MANIFEST_ROOT、WASM_DIGEST）
                  ⑤ ⚠️ 回填改变了 chunk 内容 → 需要二轮摘要（见 §2.3）
                  ⑥ 生成 IntegrityManifest → signer 签名
                  ⑦ 注入 manifest 与 guard runtime
writeBundle     → 输出 manifest 副本到 dist/.copylocker/manifest.cbor
                  可选：上传到 R2 归档
```

### 2.3 自引用问题（关键实现难点）

**问题**：清单里要包含 chunk 的摘要，但 chunk 里又要嵌入清单根摘要 → 循环依赖。

**解决**（两轮 + 占位符）：

```
Round 1: 用固定长度的占位符 "CL_ROOT_PLACEHOLDER_00...0"（32 字节）填充
         计算所有 chunk 的摘要时，先把占位符区域**归零**
Round 2: 计算 Merkle root R
         把 R 写入占位符位置（长度不变 → 不影响其他偏移）
运行时:  校验时同样把占位符区域归零后再计算摘要 → 与清单一致 ✅
```

占位符区域的位置记录在清单的 `excluded_ranges` 中（该字段本身也在签名覆盖内）。

同样的方式处理 `guard runtime` 自身的摘要（自校验的自引用）。

### 2.4 IntegrityManifest 内容

见 [`protocol-spec.md` §9](../02-architecture/protocol-spec.md)。
增加 web 特有字段：

```ts
{
  build_fingerprint: string
  hash_alg: 'blake3' | ...
  entries: { [urlPattern: string]: { digest: Uint8Array; excludedRanges?: [number, number][] } }
  guarded: { [fnId: string]: Uint8Array }   // 函数体摘要
  sealed:  { [assetId: string]: { feature: string; nonce: Uint8Array } }
  root: Uint8Array                          // Merkle root
}
```

**路径匹配**：产物用 content hash 文件名时，清单以 `logicalName → { file, digest }` 记录，
运行时通过注入的映射表定位（而非猜文件名）。CDN 部署时以 URL 后缀匹配。

### 2.5 signer 抽象（FR-BLD-003）

```ts
type Signer =
  | { kind: 'local';  keyFile: string }                       // 仅开发
  | { kind: 'remote'; endpoint: string; token: string }       // 推荐：CI OIDC → 签名服务
  | ((tbs: Uint8Array) => Promise<Uint8Array>)                // 完全自定义
```

- **生产环境禁止 `local`**：插件在 `NODE_ENV=production` 且 `kind==='local'` 时**警告并可配置为报错**。
- 远程签名服务是 `copylocker-worker` 的一个 Admin 端点，用 CI 的 OIDC token 认证。
- 自定义签名 → 对应的 `verifierRuntime` 也要自定义（成对替换）。

### 2.6 多打包器适配

unplugin 统一钩子，各打包器的差异点：

| 打包器 | 注意 |
|---|---|
| Vite / Rollup | `generateBundle` 顺序需 `enforce: 'post'`，在其他插件之后 |
| Webpack | 用 `compilation.hooks.processAssets`（`PROCESS_ASSETS_STAGE_REPORT`） |
| Rspack | 同 webpack，注意 hash 算法仅支持 sha256/384/512（我们自算摘要，不依赖其 SRI） |
| esbuild | 无 `generateBundle`，用 `onEnd` + 读写 outdir |
| Farm | 通过 unplugin 适配层 |

**与其他插件的顺序**：必须在压缩、混淆、SRI 插件**之后**运行，否则摘要对不上。
提供 `order: 'post'` 且文档给出与常见插件的兼容矩阵 + 集成测试。

## 3. `@copylocker/guard` —— 运行时校验

### 3.1 启动自校验

```ts
// 由 unplugin 注入到入口
import { bootGuard } from '@copylocker/guard'

const R = await bootGuard({
  manifest: __CL_MANIFEST__,          // 内联的签名清单
  rootPins: __CL_ROOT_PINS__,
  strategy: 'idle',                   // 'sync' | 'idle' | 'lazy'
})
// R 是"实际计算出的 Merkle root"，不是 boolean
```

**流程**
1. 验证清单签名（用 WASM 的验签能力，或独立的轻量验签）。
2. 收集本页加载的 chunk：`performance.getEntriesByType('resource')` + `import.meta.url` +
   注入的静态映射表。
3. `fetch(url, { cache: 'force-cache' })` 拿到字节（同源或带 CORS）。
4. 归零 `excludedRanges` → 计算摘要 → 与清单比对 → 构建 Merkle root `R`。
5. `R` 交给 `@copylocker/web` 参与 FinalKey 派生。

**性能**（NFR-PERF-006 < 20ms 影响 LCP）
- 默认 `strategy: 'idle'`：用 `requestIdleCallback` 分片执行，不阻塞首屏。
- 摘要计算在 Web Worker 中（BLAKE3 的 WASM 实现，或 `crypto.subtle.digest` 用 SHA-256）。
- 首屏只校验入口 chunk（同步、快），其余延迟。
- 结果缓存到内存；同一 session 不重复算。

**陷阱**
- `fetch` 自己的 chunk 会走 HTTP 缓存 —— 用 `cache: 'force-cache'` 拿缓存副本，
  避免额外网络请求。若被 Service Worker 拦截返回篡改内容 → 这是已知绕过路径，
  缓解：把 SW 脚本也纳入清单，并检测 `navigator.serviceWorker.controller`。
- 跨域 CDN 需要 CORS 头才能读取字节。文档给出 CDN 配置要求。
- 内联脚本（`<script>` 内容）无法通过 URL fetch → 用 `document.currentScript.textContent`
  或直接不支持（推荐全部外链）。

### 3.2 `@guarded` decorator

```ts
import { guarded } from '@copylocker/guard'

class Engine {
  @guarded('engine.render')
  render(scene: Scene) { /* 核心逻辑 */ }
}

// 或函数式
export const compute = guardedFn('compute', (x: number) => { ... })
```

**构建期**：transformer 提取函数源码 → 规范化（去空白/注释）→ 摘要 → 写入清单 `guarded[fnId]`。

**运行时**：
```ts
function guarded(id: string) {
  return (target, key, desc) => {
    const orig = desc.value
    desc.value = function (...args) {
      if (shouldSample()) {                    // 抽样，默认 15%
        const d = digest(normalize(orig.toString()))
        GuardState.mix(id, d)                  // ★ 混入 R，而不是抛异常
      }
      return orig.apply(this, args)
    }
  }
}
```

**关键**：不 `throw`，而是把摘要 **mix 进 `R`**。函数被替换 → `R` 变 → FinalKey 错 → 解不开资产。
这样攻击者删掉 `throw` 也没用。

**对抗 `Function.prototype.toString` 被覆写**：
```ts
// 在最早期（guard runtime 是第一个执行的 chunk）捕获原生引用
const NativeToString = Function.prototype.toString
const nativeMarker = NativeToString.call(NativeToString)   // 应含 "[native code]"
// 后续用 NativeToString.call(fn) 而非 fn.toString()
// 并周期性校验 NativeToString 仍是原来那个引用（===）
```
> 诚实说明：攻击者若在我们之前执行（如浏览器扩展、修改过的 index.html）仍可绕过。
> 这提高的是自动化工具的成本。

**限制**（写进文档）：
- decorator 只能校验**函数体文本**，无法校验闭包捕获的变量。
- 压缩/混淆后 `toString()` 的输出是压缩后的代码 —— 因此摘要必须在**最终产物**上采集
  （所以插件顺序必须 post）。
- 某些引擎对 `toString` 的输出有细微差异（换行、括号）→ 规范化函数必须充分测试，
  且在 CI 里跑多浏览器一致性测试。**这是最容易出误报的地方**，默认抽样率低且失败时
  只影响 `R`（进而是 FK），必须有清晰的诊断路径。

### 3.3 降级与诊断

误报会导致正版用户"功能缺失"，这是最危险的失败模式。缓解：

1. 提供 `@copylocker/guard/diagnose`：输出每个条目的期望/实际摘要，帮助定位。
2. 开发模式下 `strategy: 'report-only'`，只打日志不影响 `R`。
3. `unplugin --verify` 在 CI 中校验产物与清单一致（FR-BLD-010），防止发布事故。
4. 服务端 `/v1/integrity/report` 收集失败统计，Vendor 能看到"某版本大量校验失败" → 及时回滚。

## 4. `@copylocker/seal` —— 资产封印

### 4.1 构建期

```
KEK_asset = random(32)
sealed = XChaCha20-Poly1305.seal(KEK_asset, nonce, aad=assetId‖buildFp, plaintext)
wrap_online  = seal(FeatureKey_online(feature),  KEK_asset)
wrap_offline = seal(FeatureKey_offline(feature), KEK_asset)
```

**问题**：构建期没有 FeatureKey（那是每设备的）。

**解决**：封印分两层，且第二层在**服务端**完成：

```
构建期：  asset_ct = AEAD.seal(KEK_asset, ...)     ; KEK_asset 上传到服务端（Admin API）
签发时：  MC 中携带 wrapped_keks = { feature → AEAD.seal(FK_derived_for_this_device, KEK_asset) }
          —— 服务端知道 CredentialSecret，能算出该设备的 FK
运行时：  客户端用 FK 解开 wrapped_kek → 得 KEK_asset → 解开 asset_ct
```

- `KEK_asset` 存于服务端（D1，加密存储）；构建产物中只有密文。
- MC 体积会随封印的 feature 数增长（CL-STD-1 每个 +72 字节，再加 CBOR map 开销），控制在 ~32 个 feature 内。
- 大量资产共享同一个 `KEK_asset`（按 feature 分组），而非每个资产一个。

### 4.2 运行时

```ts
const bytes = await cl.loadSealed('/assets/model-abc123.bin.sealed', 'pro')
```
- 解密结果缓存在内存（`Map<string, Uint8Array>`），页面卸载即失效。
- 大文件用流式解密（分块 AEAD，每块独立 nonce + 序号防重排）。
- 解密失败区分「无授权」与「文件损坏」（AEAD tag 失败 vs 长度/格式错误），给出不同提示。

### 4.3 代码分片封印（L3 强度）

```ts
copylocker({ seal: { chunks: [{ match: /pro-features/, feature: 'pro' }] } })
```
- 命中的 chunk 被加密，产物中替换为一个 loader stub。
- 运行时通过 `cl.loadSealed()` 取得明文 → `new Function()` 或 Blob URL 动态执行。
- **CSP 冲突**：需要 `script-src 'unsafe-eval'` 或 `blob:`。
  文档必须明确说明这个安全权衡，并提供替代方案（WASM 段封印，不需要 eval）。
- 默认关闭，需显式开启。

## 5. 测试

| 类型 | 内容 |
|---|---|
| 单元 | Merkle 树、占位符归零、规范化函数 |
| 多打包器 | Vite/Rollup/Webpack/Rspack/esbuild 各跑一遍完整构建 + 校验 |
| 篡改 | 构建后修改任意 chunk 一个字节 → `R` 必须不同 → unseal 失败 |
| 移除 guard | 删除 guard 的调用 → 拿不到 `R` → unseal 失败 |
| toString 覆写 | 覆写 `Function.prototype.toString` → 检测到 |
| 误报 | 多浏览器（Chrome/Firefox/Safari）跑同一产物，`R` 必须一致 |
| 性能 | Lighthouse CI，LCP 增量 < 20ms |
| CI 一致性 | `--verify` 模式在两次独立构建间验证 |
