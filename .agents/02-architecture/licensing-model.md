# 授权模型（Licensing Model）

需求：FR-LIC-*、ADR-0009
相关：[`versioning-and-variants.md`](versioning-and-variants.md)、[`protocol-spec.md`](protocol-spec.md)

## 1. 五个正交轴

```
Policy = Entitlement × Validity × VersionScope × Seats × Mode
```

不要把商业形态做成枚举 —— 它们是这五个轴的组合（[ADR-0009](../00-overview/decisions/ADR-0009-composable-license-model.md)）。

```rust
pub struct Policy {
    pub entitlement: EntitlementSpec,
    pub validity:    Validity,
    pub version_scope: VersionScope,
    pub seats:       SeatSpec,
    pub mode:        Mode,
    pub runtime:     RuntimeSpec,   // refresh_after / grace / heartbeat / 指纹容差等
}
```

## 2. 轴一：Entitlement（权益）

### 2.1 四级结构

```
Feature（原子能力）
   ↑ 被包含于
FeatureGroup（命名集合，可引用其他 group）
   ↑ 被包含于
Tier（档位：一组 group + limits + 展示信息 + 排序）
   ↑ 叠加
Grant（加购 / 单独授予，可带独立有效期）
```

```rust
pub struct EntitlementSpec {
    pub tier: TierId,
    pub extra_groups: Vec<GroupId>,          // 在 tier 之外额外包含
    pub grants: Vec<Grant>,                  // 加购，可有独立有效期
    pub excluded_features: Vec<FeatureId>,   // 显式排除（少用，但企业定制需要）
    pub limit_overrides: BTreeMap<LimitKey, LimitValue>,
}

pub struct Grant {
    pub target: GrantTarget,                 // Feature | Group
    pub valid_from: Option<i64>,
    pub valid_until: Option<i64>,            // None = 跟随 License 有效期
    pub source: String,                      // 订单号 / 促销码，用于审计
}
```

### 2.2 解析（Resolution）

服务端在**签发时**解析成扁平快照，写进 MachineCredential：

```rust
pub fn resolve(
    catalog: &Catalog, spec: &EntitlementSpec, now: i64
) -> Result<ResolvedEntitlements, PolicyError>

pub struct ResolvedEntitlements {
    pub tier: TierId,                        // 展示用
    pub tier_label: String,
    pub features: BTreeSet<FeatureId>,       // 完全展开、去重、有序
    pub limits: BTreeMap<LimitKey, LimitValue>,
    pub resolved_at: i64,
    pub catalog_version: u32,                // 目录版本，用于排查
}
```

解析规则（必须确定性，有 property test）：

1. `tier` → 其包含的 groups → 递归展开（**检测循环引用，深度上限 8**）
2. 并入 `extra_groups`
3. 并入当前有效的 `grants`（`valid_from <= now < valid_until`）
4. 减去 `excluded_features`
5. `limits`：`tier.limits` ← `grant.limits` ← `limit_overrides`，**后者覆盖前者**；
   数值型 limit 的合并策略由 `LimitMergePolicy` 声明（`max` / `sum` / `override`），
   默认 `max`（加购只会让配额变大，不会变小）
6. 输出 `BTreeSet` / `BTreeMap` → **有序 → 编码确定性 → 签名可复现**

**客户端不需要目录**：它只看到 `ResolvedEntitlements`。这既减小客户端体积与攻击面，
也避免把定价结构（商业机密）下发到客户端。

### 2.3 Feature ID 的不可变性（硬约束）

因为 `FeatureKey(f) = KDF(SessionRoot, ... ‖ feature_id)`：

| 对象 | 可变性 | 违反后果 |
|---|---|---|
| `feature_id` | **永不可变、不可复用** | 已封印的资产全部解不开 |
| `feature_group` 成员 | 可变 | 无 |
| `tier` 包含的 group | 可变 | 无 |
| `limit` 的 key | 不可变 | 客户端读不到该 limit |
| `limit` 的值 | 可变 | 无 |

`feature` 支持 `deprecated_at` 标记（仍可解析，但新 tier 不应引用），
CLI 与控制台在尝试改名/删除已发布 feature 时**硬拦截**。

命名建议：`<domain>.<capability>`，如 `export.pdf`、`ai.assist`、`render.4k`。
支持 glob 引用：group 里可写 `export.*`（**解析时展开为具体 feature，不下发通配**）。

### 2.4 Tier 的典型配置

```jsonc
{
  "features": [
    { "id": "export.png",  "label": "PNG 导出" },
    { "id": "export.pdf",  "label": "PDF 导出" },
    { "id": "export.svg",  "label": "SVG 导出" },
    { "id": "ai.assist",   "label": "AI 助手" },
    { "id": "render.4k",   "label": "4K 渲染" },
    { "id": "team.share",  "label": "团队共享" }
  ],
  "groups": [
    { "id": "export-basic", "features": ["export.png"] },
    { "id": "export-pro",   "includes": ["export-basic"], "features": ["export.pdf", "export.svg"] },
    { "id": "pro-suite",    "includes": ["export-pro"], "features": ["ai.assist", "render.4k"] }
  ],
  "tiers": [
    { "id": "free",  "label": "免费版", "rank": 0, "groups": ["export-basic"],
      "limits": { "max_projects": 3 } },
    { "id": "pro",   "label": "专业版", "rank": 10, "groups": ["pro-suite"],
      "limits": { "max_projects": 100 } },
    { "id": "team",  "label": "团队版", "rank": 20, "groups": ["pro-suite"],
      "features": ["team.share"],
      "limits": { "max_projects": -1, "max_members": 25 } }
  ]
}
```

`-1` 约定为「无限制」。`rank` 用于比较升降级方向。

### 2.5 limits 的强制责任（明确边界）

我们**只提供签名过的数值**；运行时强制由 Vendor 的应用负责。

理由：`max_projects` 这类配额的语义完全依赖业务，且强制它需要把计数上报到服务端
（引入新的隐私与可用性问题）。**这一点必须在文档中写清楚**，避免 Vendor 误以为我们会拦截。

若 Vendor 需要强不可绕过的配额 → 用 Feature Key 封印相关能力（L2/L3），而不是靠数字。

## 3. 轴二：Validity（有效期）

```rust
pub enum Validity {
    Perpetual,                                     // 永久 / 买断
    FixedTerm  { duration: Duration },             // 限时（教育版、NFR、活动）
    Subscription {
        period: BillingPeriod,                     // Monthly | Annual | Custom(days)
        dunning_grace: Duration,                   // 默认 7d
        fallback: Option<PerpetualFallback>,       // 永久回退（见 §5）
    },
    Trial {
        duration: Duration,
        once_per: TrialScope,                      // Fingerprint | Account | Email
        extendable_by: Option<Duration>,           // 允许人工延长的上限
    },
}
```

### 3.1 时间字段的推导

```
license.expires_at   ← 由 Validity 计算（Perpetual = NULL）
mc.not_after         ← min(license.expires_at + safety_margin, ...)
mc.refresh_after     ← now + policy.runtime.refresh_after
mc.grace_seconds     ← policy.runtime.grace_seconds
```

**订阅的关键约束（防自伤）**：

```
not_after      = current_period_end + dunning_grace     ← 不是 current_period_end
refresh_after ≤ billing_period / 4                      ← 保证取消能及时传播
```

支付回调延迟、发卡行处理、卡片过期都会让 `current_period_end` 到点但用户其实已付费。
把 `not_after` 直接设成 `current_period_end` 会周期性锁死一批正常付费用户 —— 这是订阅制软件最常见的自伤。

### 3.2 订阅状态机

```
        ┌──────────── renew (webhook) ────────────┐
        ▼                                          │
  active ──payment_failed──▶ past_due ──dunning 到期──▶ suspended
    │  │                        │                            │
    │  └──payment_ok────────────┘                            │
    │                                                        │
  cancel_at_period_end                        reactivate (webhook)
    │                                                        │
    ▼                                                        ▼
  canceling ──period_end──▶ ended ──(若 earned)──▶ perpetual_fallback
                              └──(否则)──▶ expired
```

| 状态 | 客户端可用性 |
|---|---|
| `active` | 正常 |
| `past_due` | 正常（dunning 期内），VT 携带提示标记 → 应用内提示"支付失败,请更新付款方式" |
| `canceling` | 正常至周期结束 |
| `suspended` | 拒绝续期；已有凭证到 `not_after` 后 Locked |
| `ended` / `expired` | 同上 |
| `perpetual_fallback` | 转为永久 + 版本封顶（§5） |

所有转换由支付 webhook 驱动，必须**幂等**（按 `event_id` 去重）且写审计。

### 3.3 Trial 的防滥用

| 手段 | 说明 |
|---|---|
| `once_per: Fingerprint` | 同指纹只能领一次；用指纹容差匹配（避免换网卡就能重来） |
| `once_per: Email` | 需邮箱验证；配合一次性邮箱域名黑名单 |
| 速率限制 | 按 IP / 指纹 / 邮箱域三个维度 |
| Turnstile | 可选，挂在试用申请端点前 |
| `extendable_by` | 允许客服人工延长（有上限、有审计），比"再发一个 trial"更可控 |

**诚实说明**：试用防滥用不可能做到滴水不漏（虚拟机 + 新邮箱）。
目标是把成本抬到"不如直接买"的水平，而不是消灭。

## 4. 轴三：VersionScope（版本范围）

```rust
pub enum VersionScope {
    Unlimited,
    SemverRange(String),          // "^3", ">=2.0 <4.0"
    ReleasedBefore(i64),          // ★ 推荐：releases.published_at <= cutoff
    Pinned(Vec<ReleaseId>),       // 企业锁定特定版本
}
```

### 4.1 为什么推荐 `ReleasedBefore`

```
SemverRange("<=3.9")  → 3.10 算不算？只改包装的 4.0 怎么办？语义争议多
ReleasedBefore(T)     → 精确、无歧义：这个版本是不是在 T 之前发布的
```

ADR-0008 的 `releases` 注册表提供了权威的 `published_at`。
这也正是买断制软件"买了送一年更新"的标准做法。

### 4.2 强制点（重要）

| 位置 | 作用 | 强度 |
|---|---|---|
| **服务端签发/续期** | 校验 `client_info.release_id` → 查 `releases.published_at` → 超范围则**不下发该 release 的 `wrapped_keks`** | ✅ 真正的强制 |
| 客户端本地检查 | 比对本地 `version_range` 给出友好提示 | ⚠️ 仅 UX，可篡改 |

客户端自报的 `app_version` 不可信；但 `release_id` 也是自报的 —— 攻击者可以谎报一个旧的 `release_id`。
**这没关系**：谎报旧 release_id 会拿到旧 variant 的 `wrapped_keks`，而它运行的是新版本
（新 variant 的 FK 派生），解不开新版本的 Sealed Asset。**变体机制在这里承担了版本范围的强制作用** ——
这是 ADR-0008 与 ADR-0009 的第二处协同。

### 4.3 超范围时的用户体验

```
用户装了 4.0，但授权是 released_before(2026-01-01)
→ 服务端返回 VT.verdict = version_out_of_scope
→ 客户端进入"受限模式"：显示"你的授权支持到 3.8，可继续使用 3.8 或升级授权"
→ 提供一键回退到最后一个可用版本的下载链接（由 releases 表算出）
```

**绝不能表现为"崩溃"或"这是盗版"**。这是正版用户的正常场景。

## 5. 永久回退（Perpetual Fallback）

```rust
pub struct PerpetualFallback {
    pub after: Duration,               // 连续付费多久后获得，默认 12 个月
    pub scope_at: FallbackScopeAt,     // EarnedAt | SubscriptionStart | Custom
}
```

### 5.1 状态机

```
订阅激活 → 每个成功计费周期累加 continuous_paid_months
         → 若中断（suspended 超过 dunning）则清零并记录
到达 after → 记录 fallback_earned_at = now（持久化、写审计、一次性）
订阅结束  → earned?  是 → 签发 perpetual + ReleasedBefore(fallback_earned_at)
                     否 → 正常过期
```

### 5.2 实现纪律

- **幂等**：webhook 可能重放；`fallback_earned_at` 一旦写入不再更新。
- **可 dry-run**：`copylocker license preview-fallback <id>` 显示"若现在取消会得到什么"。
- **可撤销**：退款/欺诈场景需要能撤销已 earned 的回退权 → 走标准吊销流程 + 审计。
- **对用户可见**：VT 中携带 `fallback_progress`（已连续付费月数 / 阈值），
  应用内可展示进度 —— 这是很强的续订动机，属于产品能力而非技术负担。

## 6. 轴四 / 轴五：Seats 与 Mode

已在 `data-model.md` 与 `prd.md §5` 定义。补充与其他轴的交互：

| 交互 | 规则 |
|---|---|
| Trial × Seats | Trial 强制 `seats = 1`，且不允许换机（防止"轮转试用"） |
| Subscription × Seats | 席位可随计费周期调整；缩减席位时**不立即踢人**，而是在下次续期时生效并提示 |
| Perpetual × Mode E | 允许但需警告：永久授权 + 强制在线意味着服务端必须永久运行 |
| VersionScope × Seats | 无交互 |

## 7. 权益变更的传播

| 变更 | 传播路径 | 延迟 |
|---|---|---|
| 升级 tier（用户付费） | webhook → 更新 License → 下次 validate 的 VT 携带新 `entitlements` + 新 `wrapped_keks` | ≤ `refresh_after`；可主动推 |
| 降级 tier | 同上；**建议在周期结束时生效**（`scheduled_changes`），避免用户刚付完钱就被降级 | 周期结束 |
| 加购 grant | 同上 | ≤ `refresh_after` |
| 目录变更（group 增删 feature） | 只影响**新签发**的凭证；已签发的快照不变 | 下次续期 |
| 席位变更 | 立即写 DO；超出部分不踢人，等自然释放 | 立即 |

**主动推送**：Mode E 或开启心跳时，服务端可在下次心跳返回 `refresh_now` 标记，
把权益变更的传播延迟压到分钟级。Mode O 无心跳时只能等 `refresh_after`。

### 7.1 计划变更

降级、席位缩减、版本范围收紧这类**对用户不利**的变更，默认排到计费周期结束生效
（用户刚付完钱就被降级是最糟的体验）。由 `scheduled_changes` 表承载
（schema 见 [`data-model.md §6`](data-model.md)），Cron 扫描并应用，应用后写审计并推送 webhook。

升级、加购这类**对用户有利**的变更立即生效。

## 8. 数据模型

Schema 定义见 [`data-model.md`](data-model.md) —— §3 权益目录、§4 Policy、§6 订阅与计划变更。

语义要点：

- **`catalog_versions` 的不可变快照**：出现"为什么这个用户的权益是这样"的争议时，
  用签发时记录的 `licenses.catalog_version` 精确复现当时的解析结果。
- **`licenses.entitlement_override_json`**：单个 License 的权益覆盖，用于企业定制，
  不污染共享的 Policy。
- **`subscriptions.fallback_earned_at` 一旦写入不再更新**：这是永久回退幂等性的关键。
- **`billing_events` 表**：按 `(provider, event_id)` 去重，webhook 可安全重放。

## 9. 协议影响

```cddl
; 替换 protocol-spec.md 中的 entitlements 定义
entitlements = {
  0: [* tstr],              ; features —— 完全展开的有序集合
  1: { * tstr => int },     ; limits（-1 = 无限制）
  2: tstr,                  ; tier_id
  3: tstr,                  ; tier_label（展示用）
  4: uint,                  ; catalog_version
  5: ? version_scope,       ; 客户端 UX 用（非强制点）
  6: ? subscription_hint,   ; { state, period_end, fallback_progress }
}

version_scope = { 0: uint }                    ; Unlimited
              / { 1: tstr }                    ; SemverRange
              / { 2: int }                     ; ReleasedBefore(ts)
              / { 3: [* tstr] }                ; Pinned(release_ids)

subscription_hint = {
  0: uint,       ; state (0=active 1=past_due 2=canceling 3=suspended)
  1: int,        ; current_period_end
  2: ? uint,     ; fallback_progress_months
  3: ? uint,     ; fallback_required_months
}
```

`subscription_hint` 让应用能显示"支付失败,请更新付款方式"或"再续订 3 个月即获得永久授权"，
这些是**产品能力**，不是安全判定。

## 10. 预设（Presets）

`copylocker policy create --preset <name>` 一步生成常见配置：

| 预设 | Validity | VersionScope | Seats | Mode | 备注 |
|---|---|---|---|---|---|
| `trial-14d` | Trial(14d, per=fingerprint) | Unlimited | 1 | O | 不可换机 |
| `perpetual` | Perpetual | Unlimited | 1 | O | 最宽松，慎用 |
| `perpetual-major` | Perpetual | SemverRange("^N") | 1 | O | 大版本内永久 |
| `perpetual-fallback` | Perpetual | ReleasedBefore(购买时 +1y) | 1 | O | **买断制主流** |
| `sub-monthly` | Subscription(1mo, dunning 7d) | Unlimited | 1 | O | |
| `sub-annual` | Subscription(1y, dunning 14d) | Unlimited | 1 | O | |
| `sub-annual-fallback` | Subscription(1y) + fallback(12mo) | 取消时转 ReleasedBefore | 1 | O | JetBrains 式 |
| `team-sub` | Subscription(1y) | Unlimited | 25 | O | 心跳回收开启 |
| `enterprise-airgap` | FixedTerm(1y) | Pinned | N | O | `offline_upgrade_policy=preload_n` |
| `saas-client` | Subscription(1mo) | Unlimited | 3 | **E** | 强制在线 |
| `edu-1y` | FixedTerm(1y) | Unlimited | 1 | O | |

预设只是"生成一份 Policy 的起点"，生成后可自由修改。

## 11. 配置预览器（Policy Simulator）

Policy 有五个轴 → 组合空间大 → **必须有预览器**，否则配置错误只能在生产环境发现。

`copylocker policy simulate <policy_id> --scenario <name>` 与控制台的可视化时间轴：

```
场景：用户 2026-01-01 购买 sub-annual-fallback，2027-06-01 取消

2026-01-01  激活成功，tier=pro，features=[export.*, ai.assist, render.4k]
2026-01-08  首次在线校验（refresh_after=7d）
2027-01-01  订阅续期，continuous_paid_months=12 → ★ fallback_earned_at 记录
2027-06-01  用户取消 → state=canceling
2027-12-31  周期结束 → ★ 转为永久授权，版本封顶：2027-01-01 之前发布的版本
2027-12-31  当前最新版 4.2（发布于 2027-11-01）→ ⚠️ 超出范围
            用户可用的最高版本：3.9（发布于 2026-12-20）
            → 客户端进入受限模式，提示可回退到 3.9 或续订
```

这个模拟器**必须**在 M1 就有 CLI 版本（服务端逻辑是纯函数，容易做），
控制台的可视化版本排在 M7。它同时是最好的回归测试载体。

## 12. 测试

| 类型 | 内容 |
|---|---|
| 解析确定性 | 同一 catalog + spec + now → 字节级相同的 `ResolvedEntitlements` |
| 循环引用 | group 互相引用 → 检出并报错，不栈溢出 |
| glob 展开 | `export.*` 展开正确；不下发通配 |
| limits 合并 | `max`/`sum`/`override` 三种策略的边界 |
| 订阅状态机 | 全部转换 × 幂等（同一 webhook 重放 3 次结果不变） |
| dunning | `current_period_end` 到点但在 dunning 内 → 仍可用 |
| 永久回退 | 到达阈值 → earned；中断 → 清零；退款 → 可撤销 |
| 版本范围 | `ReleasedBefore` 的边界（恰好等于 cutoff 的 release） |
| 谎报 release_id | 拿到旧 variant 的 keks → 新版本解不开 Sealed Asset |
| Trial 防滥用 | 同指纹二次申请被拒；容差范围内的指纹变化仍被拒 |
| 权益变更传播 | 升级 tier → 下次 validate 拿到新 features + 新 keks |
| 预设 | 每个预设生成的 Policy 通过 simulator 的场景断言 |
| Feature 不可变 | 尝试重命名已发布 feature → CLI/API 拒绝 |
