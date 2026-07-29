# ADR-0008：每发布版本一个变体（Variant），并支持版本级吊销

- **状态**：Accepted
- **日期**：2026-07-26
- **相关**：ADR-0001、ADR-0004、`02-architecture/versioning-and-variants.md`、`03-modules/80-private-suite.md`

## 背景

`80-private-suite.md` 的价值主张是"每 Vendor 独立参数 → 破解不可跨厂商复用"。
但在**同一个 Vendor 内部**，破解仍然可以跨版本复用：
针对 v1.2 写的 patch 通常对 v1.3、v1.4 一样有效，因为二进制布局与校验逻辑几乎没变。

离线激活尤其脆弱：离线路径没有服务端参与，一旦某个版本的离线验证被绕过，
该绕过对所有版本长期有效，且无法通过在线手段回收。

## 决策

### 1. 引入 Release 与 Variant

- 每一次**对外发布**注册为一个 `Release`（`release_id`），登记到服务端。
- 每个 Release 绑定一个 `variant_id` 与 `variant_seed`。
- `variant_seed` 由 `HKDF(vendor_seed, "cl/variant/v1" ‖ release_id)` 派生（私有套件），
  或独立随机生成并登记（开源套件，变体维度较少但仍有效）。

`variant_seed` 派生出的每版本差异：

| 维度 | 说明 |
|---|---|
| Codec 掩码与字段置换 | 凭证外层编码形态每版本不同 |
| FK 派生的 info 常量 | `variant_id` 参与 Feature Key 派生 |
| Binder 调度参数 | 设备绑定变换的轮数/切片方案 |
| WASM 导出符号名 | Web 端 |
| 常量拆分布局 | `K_BUILD` 的分片方式 |
| Guard 规范化盐 | 函数体摘要的计算参数 |
| **离线验证路径参数** | OLK/AResp 的 armor 编码、KDF label、校验顺序 |

### 2. 变体的作用域限制（关键约束）

**Variant 只改变"形态"，绝不改变协议语义。**

| Variant **影响** | Variant **不影响** |
|---|---|
| 外层 codec 掩码/置换 | 签名算法与签名覆盖的 `tbs` 内容 |
| FeatureKey 派生的 info | KEM 封装与 `CredentialSecret` |
| 客户端符号名与常量布局 | 证书链验证逻辑 |
| 本地 **FK 派生**路径 | 本地**存储封装**（存储封装保持 variant 无关，见下） |

**本地存储的最外层封装必须 variant 无关**（密钥来自 OS keychain）。
否则升级客户端后解不开自己的凭证，用户被迫重新激活 —— 不可接受。

### 3. 升级路径

| 场景 | 行为 |
|---|---|
| 在线升级 | 新版本读取本地凭证（存储封装 variant 无关，可解）→ 一次 validate → VT 携带新 variant 的 `wrapped_keks` → 完成 |
| **离线升级** | ⚠️ 新 variant 的 `wrapped_keks` 需要服务端计算。选项见下 |

**离线升级的三个选项**（由 Policy `offline_upgrade_policy` 选择）：

| 选项 | 机制 | 权衡 |
|---|---|---|
| `require_online`（默认） | 升级后必须联网一次 | 最安全；对纯离线用户不友好 |
| `preload_n`（推荐折中） | 签发 MC 时预置未来 N 个已登记 variant 的 `wrapped_keks` | MC 体积 +N×(feature 数×72B，加 CBOR 开销)；只能覆盖签发时已登记的版本 |
| `variant_stable` | 该 License 的所有版本共用一个 variant | 便利性最高，放弃版本隔离；纯离线场景专用 |

### 4. 版本级吊销（Release Revocation）—— 变体的真正回报

`releases.status ∈ { active, deprecated, compromised }`

当某个版本被广泛破解：

```
$ copylocker release mark-compromised <release_id> --action force_upgrade --dry-run
```

`compromised_action`：

| 动作 | 效果 |
|---|---|
| `warn` | VT 中带提示，客户端显示升级横幅，不影响功能 |
| `force_upgrade` | 服务端拒绝为该 release 签发**新**激活；已有设备在 `refresh_after` 到期后需升级才能续期 |
| `revoke` | 该 release 的所有设备下次校验即收到 KillOrder（**高危，需双确认**） |

**这才是每版本变体的核心价值**：破解的爆炸半径被限制在单个版本，且**可以被单独下线**，
而不必让所有用户重新激活。

### 5. 防降级（`security_floor`）

引入单调递增的 `security_floor: u32`，写入 MC 与 VT 的签名 payload。

- 客户端持久化 `max_seen_security_floor`，**拒绝** `security_floor` 低于该值的凭证。
- 某版本被破解 → 递增 `security_floor` → 攻击者无法把客户端"喂回"旧版本的凭证。
- 与 `revocation_epoch` 语义不同：后者是吊销集版本，前者是最低安全基线。
- 存储与 MC 一起放在被 AEAD 保护的 blob 中，并与 `clock.last_seen_max` 一样多处冗余。

## 备选方案与否决理由

| 方案 | 否决 |
|---|---|
| 只靠私有套件（每 Vendor 一个参数） | 不解决同 Vendor 内的跨版本复用；离线路径尤其脆弱 |
| 每次发布换 `suite_id` | `suite_id` 是协议层概念，滥用会破坏套件协商与迁移语义；且服务端要为每版本编译一个套件 |
| 每次发布换 Root/Epoch 密钥 | 密钥层级与发布节奏耦合，运维灾难；且不解决"客户端逻辑被 patch"的问题 |
| 完全随机化每次构建（不登记） | 服务端无法计算该客户端的 FK，`wrapped_keks` 无从生成 |
| 不做变体，靠混淆 | 混淆不改变"一次逆向 → 长期有效"的性质 |

## 后果

**正面**
- 破解的时效性被压缩到"一个版本的生命周期"。
- 版本吊销给了运营一个真正的回收手段，且粒度远小于吊销 Epoch。
- 与既有的 `build_fingerprint`、IntegrityManifest 天然对齐（都是每构建一份）。

**负面 / 代价**
- **发布流程变重**：每次发布必须注册 Release（CI 一步，`copylocker release register`）。
  忘记注册 → 该版本的客户端无法激活。需要强门禁与清晰报错。
- **离线升级变复杂**：见 §3。这是真实的用户体验代价，必须在 Policy 层显式选择。
- **MC 体积增长**（`preload_n` 模式）：需要限制 feature 数与 N。
- **Sealed Asset 每版本重新加密**：本来就是（构建期产物），无额外成本。
- **测试矩阵扩大**：需要跨版本兼容性 CI（见 `05-ops/testing-strategy.md`）。

## 未决

- `preload_n` 的默认 N 值需要在 M5 用真实的 MC 体积数据确定（初定 N=3）。
- 开源套件（无 `vendor_seed`）的 variant 维度较少 —— 需要评估其实际隔离效果，
  可能的结论是"变体主要面向私有套件用户"，需在文档中说明。
