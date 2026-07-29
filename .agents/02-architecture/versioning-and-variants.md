# 版本兼容性与发布变体（Versioning & Release Variants）

需求：FR-VER-*、ADR-0008、NFR-REL-007

## 1. 六个独立的版本轴

混淆这几个轴是这类系统最常见的架构错误。它们**必须独立演进**。

| 轴 | 标识 | 谁定义 | 变更频率 | 兼容承诺 |
|---|---|---|---|---|
| **协议版本** | `proto_ver: u8` | CopyLocker | 极低（年级） | 服务端支持 N 与 N-1；客户端支持 N 与 N-1 |
| **算法套件** | `suite_id: [u8;4]` | CopyLocker / Vendor | 低 | 服务端可并存多套件；凭证自描述 |
| **发布变体** | `variant_id: u32` | Vendor（每次发布） | **每次发布** | 客户端支持自身 + 最近 N 个 |
| **SDK 版本** | `sdk_version: semver` | CopyLocker | 中 | 服务端支持范围由 `min_sdk_version` 声明 |
| **应用版本** | `app_version: semver` | Vendor | 中高 | 由 `entitlements.version_range` 约束权益 |
| **安全基线** | `security_floor: u32` | Vendor（运营动作） | 事件驱动 | **单调递增，客户端拒绝降级** |

### 1.1 关键区分

```
proto_ver   变了 → 线格式变了（字段增删）→ 需要双向兼容期
suite_id    变了 → 密码学算法变了 → 凭证需要换发
variant_id  变了 → 只是形态变了（编码掩码、符号名、FK info）→ 语义完全不变
app_version 变了 → 业务权益判定可能变 → 不影响密码学
```

**最重要的一条**：`variant_id` **不改变任何协议语义**。
它是同一个 Suite 的参数化，不是新 Suite。若某个变更改变了语义，那它就该是新的 `suite_id` 或 `proto_ver`。

## 2. 发布变体（Release Variant）

### 2.1 Release 的注册

每次对外发布必须先注册：

```bash
$ copylocker release register \
    --product my-app \
    --app-version 1.4.2 \
    --build-fingerprint $CL_BUILD_FP \
    --manifest dist/.copylocker/manifest.cbor \
    --channel stable

→ release_id  = rel_01J9X7...
→ variant_id  = 0x0000002A
→ variant_seed 已派生并写入 .copylocker/variant.lock（用于构建）
```

**这一步是 CI 的强门禁**：未注册的 release_id 在服务端不存在 → 该版本的客户端无法激活。
错误信息必须明确（`RELEASE_NOT_REGISTERED`，并给出注册命令）。

### 2.2 variant_seed 的派生

```
私有套件（推荐）：
  variant_seed = HKDF(vendor_seed, "cl/variant/v1" ‖ release_id ‖ app_version)

开源套件：
  variant_seed = CSPRNG(32)，登记到服务端
  ⚠️ 开源套件的变体维度较少（无私有 Codec/Binder），隔离效果弱于私有套件
```

### 2.3 variant_seed 派生出什么

| 维度 | 作用位置 | 是否影响服务端 |
|---|---|---|
| Codec 掩码与字段置换 | 凭证外层编码 | ✅ 服务端按 `release_id` 查表使用对应掩码 |
| FeatureKey 派生的 info 常量 | `FK = KDF.derive_from("copylocker/fk/v1", SessionRoot, [product_id, u64_be(variant_id), variant_const, feature_id])` | ✅ 服务端算 `wrapped_keks` 时需要 |
| Binder 调度参数 | 设备绑定变换 | ✅ 同上 |
| WASM 导出符号名 | Web 客户端 | ❌ 纯客户端 |
| `K_BUILD` 常量拆分布局 | Web 客户端 | ❌ 纯客户端 |
| Guard 规范化盐 | 函数体摘要 | ❌ 纯客户端 |
| **离线验证路径参数** | OLK/AResp 的 armor 编码、KDF label、字段校验顺序 | ✅ 签发时需要 |

**离线路径是变体价值最高的地方**：离线验证没有服务端参与，
一旦被绕过就是永久的、不可远程回收的。每版本换参数把这个损失关进单个版本。

### 2.4 作用域红线（重申 ADR-0008）

| Variant **可以**影响 | Variant **绝不**影响 |
|---|---|
| 外层编码形态 | 签名算法、签名覆盖的 `tbs` 内容 |
| FK 派生的 info | KEM 封装与 `CredentialSecret` |
| 客户端符号名/常量布局 | 证书链验证逻辑、`revocation_epoch` 语义 |
| — | **本地存储的最外层封装**（必须 variant 无关） |

> **本地存储封装必须 variant 无关。**
> 否则用户升级客户端后打不开自己的凭证，被迫重新激活。
> 存储封装的密钥来自 OS keychain + 指纹，与 variant 完全解耦。
> 这条约束在 `copylocker-store` 的测试里有专门的"跨 variant 读写"用例。

## 3. 升级路径

### 3.1 在线升级（默认，无感）

```
1. 用户安装 v1.4.2（variant B），本地凭证是 v1.3.0（variant A）签发时封装的
2. 存储封装 variant 无关 → 新客户端能读出 MC + 设备私钥 ✅
3. MC 的签名 payload 与 variant 无关 → 验签通过 ✅
4. 但 wrapped_keks 是按 variant A 的 FK 包装的 → 新客户端算出的 FK 是 variant B 的 → 解不开
5. 客户端检测到 variant 不匹配 → 立即触发一次 validate（带新的 release_id）
6. 服务端返回的 VT 携带 variant B 的 wrapped_keks → 完成，用户无感
```

若步骤 5 无网络：进入 `NeedsRevalidation`，UI 提示"首次运行新版本需要联网一次"。

### 3.2 离线升级（三个策略）

Policy 字段 `offline_upgrade_policy`：

| 策略 | 机制 | 权衡 | 适用 |
|---|---|---|---|
| **`require_online`**（默认） | 升级后必须联网一次拿新 wrapped_keks | 最安全 | 绝大多数场景（用户偶尔有网） |
| **`preload_n`** | 签发 MC 时预置未来 N 个已登记 variant 的 wrapped_keks | MC 体积 +N×(features×72B，加 CBOR 开销)；只覆盖签发时已登记的版本 | 内网部署，升级节奏可预测 |
| **`variant_stable`** | 该 License 的所有版本共用一个 variant | 便利性最高，**放弃版本隔离** | 纯 air-gapped，且接受该权衡 |

`preload_n` 的默认 N = 3（待 M5 用真实体积数据确认）。
选择 `variant_stable` 时，CLI 与控制台必须显示明确的安全警告。

### 3.3 降级（回滚到旧版本）

用户回滚到旧版本是合法场景（新版本有 bug）。处理：

- 旧客户端的 `variant_id` 仍在服务端登记表里 → 可以正常签发对应的 wrapped_keks。
- **但** `security_floor` 检查会拦截：若该旧版本已被标记 compromised 并递增了 floor，
  则旧客户端拿不到有效凭证。这是刻意的。
- 正常回滚（未被标记 compromised）不受影响。
- Admin 可对单个 License 临时豁免（`--allow-downgrade-until`），用于支持个案。

## 4. 版本级吊销（Release Revocation）

### 4.1 状态机

```
active ──deprecate──▶ deprecated ──▶ (自然淘汰)
   │                       │
   └───mark-compromised────┴──▶ compromised
```

### 4.2 操作

```bash
$ copylocker release mark-compromised rel_01J9X7 --action force_upgrade
[DRY RUN] 影响面：
  Release:  rel_01J9X7 (my-app 1.4.2, variant 0x2A, 发布于 2026-05-01)
  设备数:   8,432 台（其中 6,109 台在过去 7 天签到）
  动作:     force_upgrade
    - 拒绝该 release 的新激活
    - 已有设备在 refresh_after 到期后需升级才能续期
    - 不会立即使任何设备失效
  建议:     先确认 1.4.3 已发布且可下载,再执行
确认执行请加 --confirm
```

| 动作 | 效果 | 用户感受 |
|---|---|---|
| `warn` | VT 携带提示标记 | 应用内出现升级横幅，功能不受影响 |
| `force_upgrade` | 拒绝新激活；已有设备到期后需升级才能续期 | 到期时提示"请升级到最新版本" |
| `revoke` | 该 release 所有设备下次校验即收 KillOrder | **立即失效** —— 高危，双确认 |

### 4.3 为什么这是变体的核心价值

没有变体时，破解 v1.4.2 = 破解所有版本，唯一的回收手段是吊销 Epoch（影响**全部**用户）。

有变体 + release 吊销后：

```
破解 v1.4.2  →  只对 v1.4.2 有效（变体隔离）
             →  标记 rel_01J9X7 为 compromised（精确打击）
             →  发布 v1.4.3（新变体）
             →  8,432 台设备升级，其余 200,000 台用户完全无感
```

**爆炸半径从"全部用户"缩小到"单个版本的用户"，且回收动作不需要密钥仪式。**

### 4.4 `security_floor` 防降级

```rust
// 客户端持久化（与 clock.last_seen_max 一样多处冗余、AEAD 保护）
if credential.security_floor < self.max_seen_security_floor {
    return Err(FatalError::SecurityFloorRollback);   // fail-closed
}
self.max_seen_security_floor = max(self.max_seen_security_floor, credential.security_floor);
```

- 每次标记 compromised 时可选择递增全局 `security_floor`。
- 攻击者无法把客户端"喂回"旧版本签发的凭证。
- 与 `revocation_epoch` 并列但语义不同（吊销集版本 vs 最低安全基线）。

## 5. 兼容性矩阵与承诺

### 5.1 承诺

| 组合 | 承诺 |
|---|---|
| 老客户端（N-1）× 新服务端（N） | ✅ 必须工作。服务端用 N-1 格式响应 |
| 新客户端（N）× 老服务端（N-1） | ✅ 必须工作。客户端降级到 N-1 协商 |
| 老客户端（N-2）× 新服务端（N） | ❌ 返回 `1004 UnsupportedProto` + 升级提示 |
| 老凭证（老 suite）× 新客户端 | ✅ 必须能验证（保留旧套件验证能力至凭证自然过期） |
| 老凭证（老 variant）× 新客户端 | ✅ 能验证；wrapped_keks 需刷新（§3） |
| 新凭证 × 老客户端 | ⚠️ 服务端按客户端声明的能力签发，不下发它不支持的套件 |

### 5.2 弃用流程

任何轴的弃用必须：

```
1. 在 ver.*_dist 指标中确认目标版本占比 < 1%（用 §9 的数据驱动决策）
2. 发布公告 + 客户端内提示（VT 携带 deprecation 标记）
3. 观察 ≥ 2 个 Epoch（约 180 天）
4. 服务端 min_* 提升，返回明确的升级指引
5. 保留验证能力至已签发凭证自然过期
```

**协议/套件的弃用节奏受 `refresh_after` 与 `not_after` 的最长值约束** ——
一个 `not_after = 永久` 的买断制 License，理论上要求我们永久保留其套件的验证能力。
因此 Policy 层建议：即使买断制也设置一个较长的 `not_after`（如 5 年）并支持免费续期。

## 6. 服务端数据模型

Schema 定义见 [`data-model.md §7`](data-model.md)（`releases`、`security_floor_log`）。

语义要点：

- **`releases.published_at` 是版本封顶的权威判定依据**（`VersionScope::ReleasedBefore`），
  见 [`licensing-model.md §4`](licensing-model.md)。
- **`releases.variant_params` 用 Secrets Store 主密钥 AEAD 加密后存储**（格式见 ADR-0013）：它泄露不导致凭证可伪造（红线保证），
  但会削弱变体的隔离效果，因此仍按机密数据对待。
- **`security_floor_log.floor` 全局单调递增**：与 `revocation_epoch` 并列但语义不同
  （吊销集版本 vs 最低安全基线）。

## 7. 协议字段补充

```cddl
; ActivationRequest / ValidateRequest 的 client_info 增加
client_info = {
  0: tstr,        ; app_version
  1: tstr,        ; sdk_version
  2: tstr,        ; os
  3: tstr,        ; arch
  4: tstr,        ; build_fingerprint
  5: tstr,        ; release_id        ★ 新增
  6: uint,        ; variant_id        ★ 新增
  7: [* bytes],   ; supported_suites
  8: [* uint],    ; supported_variants  ★ 新增（自身 + 可接受的旧变体）
}

; machine_cred_tbs 增加
  19: uint,       ; security_floor    ★ 新增
  20: uint,       ; variant_id        ★ 新增
  21: ? { * tstr => bytes },  ; wrapped_keks（按 feature）
  22: ? { * uint => { * tstr => bytes } },  ; preloaded_keks（按 variant_id，preload_n 模式）

; validation_ticket_tbs 增加
  13: uint,       ; security_floor    ★ 新增
  14: ? uint,     ; release_status    ★ 新增 (0=active 1=deprecated 2=compromised)
  15: ? { * tstr => bytes },  ; refreshed wrapped_keks（variant 切换时下发）
```

## 8. 客户端支持的变体集合

```rust
// 构建期注入
const VARIANT_CURRENT: u32 = 0x0000002A;
const VARIANT_ACCEPT: &[VariantParams] = &[ /* 当前 + 最近 3 个 */ ];
```

- 新客户端内置最近 N 个变体的**解封参数**（用于读旧凭证），默认 N=3。
- 攻击者可以从新客户端提取旧变体参数 —— **这没关系**：
  破解者要破的是新版本，而新版本用的是新变体。反方向（用旧参数破新版本）不成立。
- 跨越超过 N 个版本的升级 → 需要一次在线 re-wrap（`require_online` 的自然结果）。

## 9. 与分析模块的联动

版本决策必须数据驱动，而不是拍脑袋。控制台的 Versions 页面直接给出可执行建议：

| 数据 | 触发的建议 |
|---|---|
| `ver.proto_suite_dist`：proto_ver=1 占比 < 1% | "可以停止支持 proto_ver 1" |
| `ver.sdk_dist`：某 SDK 版本 < 1% | "可以提升 min_sdk_version" |
| `ver.adoption_curve`：新版本 7 天采纳率 < 30% | "升级推送可能有问题" |
| `health.integrity_fail` 按 release 分组突增 | "rel_xxx 可能有 guard 误报，考虑回滚" |
| 某 release 的 `dev.checked_in` 异常高于销量 | "rel_xxx 可能被破解，考虑标记 compromised" |

最后一条是**破解检测的主要信号**：某个版本的活跃设备数显著高于该版本对应的销量/席位总数。

## 10. 测试：跨版本兼容性矩阵

CI job `compat-matrix`，保留最近 4 个发布版本的客户端产物：

| 测试 | 断言 |
|---|---|
| 旧客户端 × 新服务端 | 激活与校验成功 |
| 新客户端 × 旧凭证（旧 variant） | 能读存储、能验签、触发 re-wrap 后可用 |
| 新客户端 × 旧凭证（旧 suite） | 能验签 |
| 跨 variant 存储读写 | `copylocker-store` 的 blob 在任意 variant 间可读 |
| 跨 4 个版本的连续升级 | 每一步都无需用户重新输入 Key |
| 离线升级 `require_online` | 无网时进入 `NeedsRevalidation`，有网后自动恢复 |
| 离线升级 `preload_n` | 无网时直接可用（N 个版本内） |
| `security_floor` 回滚 | 喂入低 floor 的凭证 → `FatalError::SecurityFloorRollback` |
| Release compromised | `force_upgrade` 后新激活被拒、已有设备到期前不受影响 |
| 未注册的 release_id | 返回 `RELEASE_NOT_REGISTERED` 且错误信息含注册命令 |

历史版本的 KAT 向量必须**永久保留**在 `vectors/history/<version>/`，
这是唯一能保证"我们没有悄悄破坏老客户端"的手段。
