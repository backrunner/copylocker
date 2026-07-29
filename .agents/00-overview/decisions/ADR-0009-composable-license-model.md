# ADR-0009：可组合的授权模型（而非授权类型枚举）

- **状态**：Accepted
- **日期**：2026-07-26
- **相关**：ADR-0004、ADR-0008、`02-architecture/licensing-model.md`

## 背景

需要支持的授权形态：

- 分档位（tier）解锁不同功能 / 功能组
- 限时试用（trial）
- 永久 / 买断（perpetual、lifetime）
- 按计费周期的订阅（monthly / annual）
- 限时授权（time-limited）
- 限版本授权（version-limited）
- **订阅 + 版本封顶的永久回退授权**（订阅取消后保留某版本的永久使用权）

## 决策

**不建立 `LicenseType` 枚举。** 把上述形态分解为五个**正交轴**，用 Policy 组合表达：

```
Policy = Entitlement × Validity × VersionScope × Seats × Mode
```

| 轴 | 取值 |
|---|---|
| **Entitlement（权益）** | `tier` + `feature_groups` + `grants`（加购）+ `limits`（配额） |
| **Validity（有效期）** | `perpetual` \| `fixed_term(duration)` \| `subscription(period, dunning)` \| `trial(duration, once_per)` |
| **VersionScope（版本范围）** | `unlimited` \| `semver_range(r)` \| **`released_before(cutoff_at)`** \| `pinned(release_id)` |
| **Seats（席位）** | 数量 + 换机限额 + 心跳回收 |
| **Mode** | `offline_hybrid` \| `enforced_online` |

常见商业形态只是这些轴的组合，以**具名预设（Preset）**提供开箱即用：

| 预设 | Validity | VersionScope |
|---|---|---|
| `trial-14d` | `trial(14d, once_per=fingerprint)` | `unlimited` |
| `perpetual` | `perpetual` | `unlimited` |
| `perpetual-major` | `perpetual` | `semver_range("^3")` |
| **`perpetual-fallback`**（买断制主流） | `perpetual` | **`released_before(purchase_at + 1y)`** |
| `sub-monthly` | `subscription(1mo, dunning=7d)` | `unlimited` |
| `sub-annual-with-fallback` | `subscription(1y)` + `fallback_after=12mo` | 取消时转 `released_before(fallback_earned_at)` |
| `edu-1y` | `fixed_term(1y)` | `unlimited` |

## 关键子决策

### 1. 版本封顶按「发布日期」而非 semver

`released_before(cutoff_at)` 比 `semver_range` 更准确也更好运营：

```
semver_range("<=3.9")   → 3.10 算不算？发了 4.0 但只是改包装怎么办？
released_before(T)      → 精确：releases.published_at <= T
```

ADR-0008 引入的 `releases` 注册表让这成为可能 —— 每个发布都有权威的 `published_at`。
这是两个决策之间的意外协同，应在文档中显式说明。

### 2. 版本范围由**服务端**强制，客户端检查仅用于 UX

客户端的 `app_version` 是自报的、可篡改的。因此：

- **服务端**：签发/续期时校验 `release.published_at` 是否在范围内；超范围则拒绝下发
  该 release 对应的 `wrapped_keks` → 客户端拿不到 FeatureKey → 受保护功能不可用。**这是真正的强制**。
- **客户端**：本地比对 `version_range` 只为了快速给出友好提示（"此版本需要升级授权"），
  不承担安全职责。

### 3. 权益在签发时解析并快照进凭证

```
Catalog（features / groups / tiers）→ resolve() → ResolvedEntitlements → 快照进 MC
```

- 客户端**不需要**知道 tier/group 目录，只看到展开后的 feature 集合与 limits。
- 目录变更不影响已签发凭证；变更在下次续期或通过 VT 的 `entitlements` 字段生效。
- `resolve()` 是 `copylocker-server-core` 中的纯函数，可完全单元测试。

### 4. Feature ID 一旦发布即不可变

`FeatureKey(f) = KDF(SessionRoot, ... ‖ feature_id)` —— 重命名 feature 会让所有已封印的资产解不开。

| 对象 | 可变性 |
|---|---|
| `feature_id` | **不可变**（可弃用，不可改名、不可复用） |
| `feature_group` | 可变（增删成员） |
| `tier` | 可变（改包含的 group、改展示名） |
| `limits` 的 key | 不可变；值可变 |

CLI 与控制台在尝试重命名/删除已发布 feature 时**必须硬拦截**并解释原因。

### 5. 订阅的到期不等于锁定

```
not_after = current_period_end + dunning_grace   （默认 dunning_grace = 7 天）
refresh_after ≤ billing_period / 4               （保证取消能及时传播）
```

支付回调延迟、银行处理时间、卡过期都会造成 `current_period_end` 到点但用户其实已付款。
把 `not_after` 直接设成 `current_period_end` 会锁死大量正常付费用户 —— 这是订阅制软件最常见的自伤。

### 6. 永久回退（perpetual fallback）是服务端的状态机

```
订阅活跃 → 累计连续付费月数 continuous_paid_months
到达 fallback_after（默认 12 个月）→ 记录 fallback_earned_at = now，并持久化
订阅取消/过期 → 若已 earned → 自动签发 perpetual + released_before(fallback_earned_at)
             → 否则 → 正常过期
```

必须**幂等**、**可审计**、**可 dry-run**。退款场景需要能撤销已 earned 的回退权（走吊销流程）。

## 备选方案与否决理由

| 方案 | 否决 |
|---|---|
| `enum LicenseType { Trial, Perpetual, Subscription, ... }` | "订阅+永久回退+版本封顶"这类组合会导致枚举爆炸；每加一个商业形态都要改协议 |
| 用一个自由的 `metadata_json` 让 Vendor 自己解释 | 判定逻辑落到客户端 → 可篡改；且无法做服务端强制 |
| 权益目录下发给客户端自行解析 | 增大客户端攻击面与体积；目录本身是商业机密（定价结构） |
| 版本范围只用 semver | 见 §1 |
| 内置计费与订阅管理 | 见 `vision-and-scope.md §5` 非目标；我们只消费支付商的 webhook |

## 后果

**正面**
- 新商业形态通常不需要改代码，只需新 Policy 组合 + 可能一个新预设。
- 版本封顶与 Release 注册表天然对齐。
- 权益解析是纯函数 → 高测试覆盖、可 property test。

**负面 / 代价**
- Policy 的配置面变大 → 控制台需要好的编辑器与**预览器**（"这个配置下用户会经历什么"）。
- 预设是必需的，否则新用户面对五个轴会不知所措。
- 权益快照进 MC → MC 体积随 feature 数增长（与 `wrapped_keks` 叠加）；限制 feature 数 ≤ 64，
  超出时用 group 位图压缩表示（M5 评估）。

## 未决

- `limits` 的运行时强制（如 `max_projects`）由谁负责？当前决定：**由 Vendor 的应用负责**，
  我们只提供签名的数值。若未来要强制，需要把计数上报到服务端 → 属于新范围，另行决策。
