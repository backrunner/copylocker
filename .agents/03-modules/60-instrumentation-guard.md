# 模块：插桩范式与 Feature Key 使用指南

需求：ADR-0004、FR-CLI-008、FR-BLD-007

> 这是**给使用 CopyLocker 的开发者**的核心指南，也是我们 SDK API 设计的约束来源。
> 文档站上这一章是最重要的一章。

## 1. 核心心智模型

**❌ 错误心智**："我调用 SDK 检查一下有没有授权，没有就退出。"

**✅ 正确心智**："我的应用有一部分内容/能力，物理上只有在拿到有效授权后才能被解开。"

```
错误：  if (!license.valid) return;      // 一个 if 就能删掉
       doExpensiveWork();

正确：  const key = await cl.unseal('pro', sealedConfig);   // 拿不到 key 就没有 config
       doExpensiveWork(JSON.parse(decode(key)));
```

## 2. 强度分级（写进文档站，让使用者自选）

| 级别 | 做法 | 实现成本 | 破解成本 | 适用 |
|---|---|---|---|---|
| **L0** | 单点 `if (!valid) exit()` | 5 分钟 | 分钟级 | ❌ 不推荐，仅演示 |
| **L1** | 多点异步插桩 + 延迟失效 + 随机化 | 半天 | 小时级 | 低价工具、试用限制 |
| **L2** | 关键**配置/数据**用 FeatureKey 封印 | 1 天 | 需要一份合法凭证 | ✅ **默认推荐** |
| **L3** | 关键**代码分片/WASM 段**封印 | 2–3 天 | 合法凭证 + 每版本重复劳动 | 高价值软件 |
| **L4** | 关键计算在服务端 | 视业务 | 无法离线破解 | SaaS 型、AI 型 |

脚手架默认生成 L2。文档中每一级都给出完整可复制的示例。

## 3. L1：插桩范式（当 L2+ 不适用时）

### 3.1 原则

| 原则 | 说明 |
|---|---|
| **多点** | 至少 5–10 个插桩点，分布在不同模块 |
| **异步** | 插桩点只是"提示"，实际校验异步进行，不阻塞用户操作 |
| **延迟** | 发现问题后不立即崩溃，而是在随机延迟（分钟～小时）后降级 |
| **多样** | 不同插桩点用不同的失效方式（功能缺失、结果错误、静默降级） |
| **深入** | 插在核心业务流程内部，而非启动时 |
| **无字符串** | 不出现 `"license"`、`"trial expired"` 等可 grep 的字符串 |

### 3.2 反模式

```ts
// ❌ 集中式检查点 —— 一处 patch 全部失效
function checkLicense() { if (!ok) process.exit(1) }

// ❌ 启动时一次性检查
app.on('ready', () => { if (!checkLicense()) quit() })

// ❌ 明显的字符串
if (!ok) alert('Your license is invalid')

// ❌ 同步阻塞
const ok = await validateBlocking()   // 用户等待 → 断网即卡死
```

### 3.3 推荐写法

```ts
// 在业务函数内部，作为副作用触发校验，不改变控制流
async function exportProject(project: Project) {
  cl.hintOnline()                        // 提示可能在线，触发机会性校验
  const key = await cl.unseal('export', SEALED_EXPORT_PROFILE)   // ← 真正的门禁
  return runExport(project, decodeProfile(key))
}
```

## 4. L2：数据封印（默认推荐）

### 4.1 选什么去封印

好的候选：
- **配置/参数表**：算法参数、渲染预设、导出配置、规则库
- **模板/资源**：专业版模板、字体、图标集、音效
- **模型权重**：AI 模型、推荐参数
- **API 端点与密钥**：连接自家服务的凭据（同时解决"免费用户滥用后端"）
- **业务规则**：定价规则、税率表、格式转换映射表

差的候选：
- 可从 UI 反推的东西（如"按钮是否可见"）
- 体积巨大且很少变的资源（每次都解密开销大 → 用 KEK 缓存）
- 开源库（本来就公开）

### 4.2 使用

```ts
// vite.config.ts
copylocker({ seal: { assets: ['src/assets/pro/**'] } })
```

```ts
// 运行时
const preset = JSON.parse(new TextDecoder().decode(
  await cl.loadSealed('/assets/pro/presets.json', 'pro')
))
```

桌面端：
```rust
let bytes = client.unseal("pro", include_bytes!("../assets/pro/presets.sealed"))?;
```

### 4.3 失败处理 UX（重要）

封印解不开时，用户看到的应该是有意义的提示，而不是崩溃：

```ts
try {
  data = await cl.loadSealed(url, 'pro')
} catch (e) {
  if (e.code === 'NOT_ENTITLED')  showUpgradePrompt()
  else if (e.code === 'NEEDS_ONLINE') showConnectPrompt()
  else if (e.code === 'CORRUPT')  showReinstallPrompt()   // 区分文件损坏
  else showGenericError()
}
```

**必须区分**「无授权」与「文件损坏/网络问题」，否则正版用户遇到 CDN 问题会以为自己被当成盗版。

## 5. L3：代码分片封印

### 5.1 Web

```ts
copylocker({ seal: { chunks: [{ match: /features\/pro\//, feature: 'pro' }] } })
```

产物中该 chunk 被替换为 loader：
```js
// 生成的 stub
export default async function load() {
  const code = await __cl.loadSealed('/chunks/pro-x7f2.js.sealed', 'pro')
  return import(URL.createObjectURL(new Blob([code], { type: 'text/javascript' })))
}
```

**CSP 权衡**：需要 `script-src blob:`。若不可接受，用 WASM 变体（§5.2）。

### 5.2 WASM 段封印（无 eval，推荐）

把 pro 功能编译成独立的 `.wasm`，整体封印：
```ts
const wasmBytes = await cl.loadSealed('/pro.wasm.sealed', 'pro')
const { instance } = await WebAssembly.instantiate(wasmBytes, imports)
```
- 不需要 `unsafe-eval`（`WebAssembly.instantiate` 从 ArrayBuffer 实例化只需 `wasm-unsafe-eval`）。
- 更适合计算密集的核心逻辑。

### 5.3 桌面端

```rust
// 把关键逻辑编译成独立的 .wasm 或数据驱动的字节码，封印后随应用分发
let module = client.unseal("pro", PRO_MODULE_SEALED)?;
let engine = wasmtime::Module::from_binary(&engine, &module)?;
```

或更简单：把关键**数据表/规则**封印，代码保持明文但没有数据就跑不了。

## 6. Feature Key 的正确用法

```rust
// ✅ 正确：用 key 做实际的事
let key = client.feature_key("pro")?;
let plaintext = aead_open(&key, &sealed_data)?;

// ❌ 错误：把 key 退化成 bool
let has_pro = client.feature_key("pro").is_ok();
if has_pro { ... }     // 这就回到 L0 了
```

SDK 层面的防呆：
- `feature_key()` 返回 `Secret<[u8;32]>`，**不实现** `Debug`/`Display`/`PartialEq`，
  避免被随手打印或比较。
- 文档中每个 `feature_key` 的示例都紧跟一次 `unseal`。
- Lint 规则（可选提供的 eslint/clippy 规则）：警告 `.is_ok()` / `.ok()` 紧跟 `feature_key()`。

## 7. 在线/离线双密钥的处理

见 [`crypto-architecture.md` §6](../02-architecture/crypto-architecture.md)。
使用者无需关心 —— SDK 内部自动选择在线或离线的 SessionRoot 并解开对应的 wrapped KEK。

**但需要知道的行为差异**：
- 在线校验成功后，`SessionRoot_online` 刷新 → 已缓存的解密结果**保持有效**（KEK 不变）。
- 进入 `Locked` 后，`feature_key()` 返回 `Err(NotEntitled)`，已缓存的明文需要由使用者主动清理。
  SDK 提供 `onStateChange` 让使用者在转 `Locked`/`Revoked` 时清缓存。

```ts
cl.onStateChange(s => {
  if (s === 'Locked' || s === 'Revoked') assetCache.clear()
})
```

## 8. 试用期（Trial）的实现

不需要特殊机制 —— 用 entitlements + `not_after`：

```
Policy: mode=offline_hybrid, duration=14d, seats=1, entitlements.features=['trial']
```
- 试用版资产用 `trial` feature 封印；正式版用 `pro`。
- 试用到期 → `not_after` 到 → `Locked` → 拿不到 key。
- 防重复试用：服务端按指纹去重（同一指纹只发一次 trial license）。

## 9. 常见问题（写进 FAQ）

| 问题 | 回答 |
|---|---|
| 用户断网了还能用吗？ | Mode O：能，直到 grace 结束。Mode E：能，直到 refresh+grace |
| 用户换硬盘/网卡后失效吗？ | 指纹容差（默认 70 分）通常能容忍；超出则走换机流程 |
| 我的 CI 怎么跑测试？ | `copylocker-cli dev-license` 生成绑定 CI build fingerprint 的开发凭证 |
| 解密开销大吗？ | XChaCha20 约 1–2 GB/s；100MB 资产约 50–100ms，且可缓存 |
| 如果我的服务器挂了？ | 客户端进入 Grace 继续可用；这是刻意设计（NFR-REL-002） |
| 能防住所有破解吗？ | 不能。见 `threat-model.md` §6 |
| 会不会误伤正版用户？ | 这是最大风险。默认配置偏保守（长 grace、report-only guard）；上线前必须做灰度 |

## 10. 上线检查清单（给使用者）

- [ ] 选定强度级别（推荐 L2 起步）
- [ ] 至少封印了一项真正必要的资产
- [ ] `feature_key()` 的每一处调用后都紧跟真实的解密使用
- [ ] 没有任何 `if (state === 'Active')` 形式的门禁
- [ ] 错误 UX 区分「无授权 / 需联网 / 文件损坏」
- [ ] `grace_window` 设置合理（首次上线建议 ≥ 30 天）
- [ ] guard 先用 `report-only` 跑一个版本，确认无误报再启用
- [ ] 灰度 1% → 10% → 100%，监控 `/v1/integrity/report` 与激活失败率
- [ ] 准备好客服话术与手动补发凭证的流程
- [ ] Root 公钥已 pin，`root_next` 已预置
- [ ] 生产环境的 signer 不是 `local`
