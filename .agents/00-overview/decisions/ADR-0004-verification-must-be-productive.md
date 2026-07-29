# ADR-0004：验证必须是「生产性」的，而非「判定性」的

- **状态**：Accepted
- **日期**：2026-07-26
- **相关**：`03-modules/60-instrumentation-guard.md`、`02-architecture/threat-model.md`

## 背景

绝大多数 License 方案最终归结为客户端某处的：

```rust
if !license.is_valid() { exit(); }
```

这个模式的致命缺陷是：**验证结果是一个可被短路的控制流判定**。攻击者只需要
把一条跳转指令取反、或把一个函数 stub 成 `return true`，整套密码学就完全失效——
无论用的是 Ed25519 还是 ML-DSA-87。这是所有「加了后量子签名就更安全了」的错觉的根源。

## 决策

**校验成功的产物必须是应用真正需要、且无法从别处获得的密钥材料。**

### 4.1 Feature Key 派生

```
CredentialSecret = KEM-Decap(device_sk, MC.kem_ct)            // 只有正确设备能算出
SessionRoot      = KDF(CredentialSecret, VT.server_nonce ‖ VT.epoch ‖ build_fingerprint)
FeatureKey(f)    = KDF(SessionRoot, "copylocker/fk/v1" ‖ product_id ‖ f)
```

- `CredentialSecret` 由服务端在签发 MC 时用设备的 KEM 公钥封装，**从不以明文出现在网络或磁盘上**。
- 本地持久化的是被 OS keychain / 指纹派生密钥保护的密文。
- `FeatureKey(f)` 用来解密 **Sealed Asset**：受保护的资源、配置、模型权重、
  甚至用 `copylocker-seal` 加密的 JS chunk / Rust 数据段。

### 4.2 API 设计强制约束

- 公开 API **不得**提供返回 `bool` 的顶层校验函数。
- WASM 与原生模块的导出面是 **challenge/response 形态**：`step(session, opaque_in) -> opaque_out`，
  输入输出都是不透明 CBOR，不存在 `isValid()` 这样的 hook 点。
- 状态查询 API（`state() -> LicenseState`）只用于 UI 展示，**不参与任何解密路径**，
  文档中明确标注 "advisory only, do not gate features on this"。

### 4.3 分层建议（写进接入文档）

| 层级 | 做法 | 破解成本 |
|---|---|---|
| L0（不推荐） | `if !valid { exit() }` | 分钟级 |
| L1 | 核心流程多点异步插桩 + 延迟失效 + 随机化 | 小时级 |
| L2 | 关键配置/资产用 FeatureKey 加密（`copylocker-seal`） | 需要拿到一份合法凭证才能提取明文 |
| L3 | 关键代码分片（WASM 段 / JS chunk）用 FeatureKey 加密并动态加载 | 需要合法凭证 + 每版本重复劳动 |
| L4 | 关键计算依赖服务端（在线模式下的服务端算子） | 无法离线破解 |

默认脚手架生成 L2；文档强烈推荐 L3；L4 由使用者自行设计业务侧。

## 备选方案与否决理由

| 方案 | 否决 |
|---|---|
| 只做签名验证 + bool | 见背景 |
| 依赖代码混淆 | 提高的是阅读成本而非破解成本；且与 sourcemap/CI 冲突；只作为可选叠加 |
| 反调试为主 | 军备竞赛，误伤正常用户（安全软件、虚拟机、无障碍工具） |

## 后果

- **对使用者的要求变高**：必须愿意把一部分资产/代码交给我们的构建工具加密。
  → 用脚手架 + unplugin 自动化，把心智负担降到「在配置里列出要保护的文件 glob」。
- **失效模式变严重**：如果凭证损坏，应用会「功能缺失」而不是「弹出提示」。
  → 必须有清晰的降级 UX 与恢复路径；Sealed Asset 必须有完整性校验以区分"未授权"和"文件损坏"。
- **测试复杂度**：CI 需要有一套「开发用 License」使得本地/CI 能解密资产。
  → `copylocker-cli dev-license` 生成仅对 dev build fingerprint 有效的凭证。
