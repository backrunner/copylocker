# 模块：授权分析与遥测（License Analytics & Telemetry）

Crate：`copylocker-analytics`（server-core 的子模块）· Package：`@copylocker/telemetry`（可选）
需求：FR-TLM-*、NFR-COMP-*、ADR-0007

> **一句话**：Vendor 想要的绝大多数指标不需要额外采集 —— 它们已经在授权协议里了。
> 我们把这部分做扎实（T0），把真正需要采集的部分做成可选、需同意、默认关闭（T1/T2）。

## 1. 三层模型

| 层 | 默认 | 采集什么 | 谁能开 |
|---|---|---|---|
| **T0 协议派生** | ✅ 开启 | 无额外采集，纯服务端派生 | 自动 |
| **T1 聚合遥测** | ❌ 关闭 | 客户端预聚合的计数与分桶，无事件流 | Vendor 开启 + 终端用户同意 |
| **T2 事件遥测** | ❌ 关闭 | 事件流（假名 ID + 时间戳 + 属性） | Vendor 开启 + 终端用户明确同意 + 独立隐私声明 |

三层的字段边界见 [ADR-0007](../00-overview/decisions/ADR-0007-analytics-tiering.md)。

## 2. 指标目录（Metric Catalog）

**所有指标必须有唯一 ID 与精确定义**，避免"活跃"这类词在不同页面含义不同。

### 2.1 激活类（T0）

| ID | 名称 | 定义 | 口径注意 |
|---|---|---|---|
| `act.new` | 新激活数 | 窗口内新产生 `machine_id` 的次数 | 指纹容差命中导致的复用**不计**；这是刻意的 |
| `act.reactivation` | 重新激活数 | 已 `released`/`revoked` 的设备再次激活 | 与 `act.new` 分开统计 |
| `act.by_path` | 按路径分布 | `online` / `offline_ar` / `olk` / `account` | 即"离线/在线激活比例" |
| `act.failed` | 激活失败数 | 按失败原因分组（席位满 / 无效 key / 指纹不符 / 限流） | 失败原因是运营洞察的金矿 |
| `act.time_to_first` | 首次激活耗时 | License 签发 → 首次激活的时长分布（P50/P90） | 反映交付链路质量 |
| `act.transfer` | 换机次数 | 窗口内 deactivate→activate 配对数 | 异常高 = 可能被共享 |

### 2.2 活跃类（T0）

> ⚠️ **分辨率约束**：见 §3。我们不提供叫 "DAU" 的指标。

| ID | 名称 | 定义 |
|---|---|---|
| `dev.checked_in` | 签到设备数（窗口） | 窗口内至少成功完成一次 `validate` 或 `heartbeat` 的唯一 `machine_id` 数 |
| `dev.checked_in_7d` / `_28d` | 周 / 月签到设备 | 同上，固定窗口。**这是最接近 WAU/MAU 的可靠指标** |
| `lic.active` | 活跃 License 数 | 窗口内至少有 1 台签到设备的唯一 `license_id` 数 |
| `dev.stickiness` | 粘性 | `checked_in_7d / checked_in_28d` |
| `dev.dormant` | 沉默设备 | 状态为 `active` 但超过 `refresh_after + grace` 未签到 |
| `dev.state_mix` | 状态分布 | 服务端推断的 `Active / NeedsRevalidation / Grace(推断) / 沉默` 占比 |

### 2.3 版本类（T0）

| ID | 定义 |
|---|---|
| `ver.app_dist` | 按 `app_version` 的签到设备分布 |
| `ver.release_dist` | 按 `release_id` / `variant_id` 的分布（见 `versioning-and-variants.md`） |
| `ver.sdk_dist` | 按 `sdk_version` 分布 —— 用于判断能否停止支持老 SDK |
| `ver.adoption_curve` | 新版本发布后的采纳曲线（按天，累计占比） |
| `ver.upgrade_lag` | 从新版本发布到设备升级的时长分布 |
| `ver.os_arch_dist` | `os` × `arch` 分布 |
| `ver.proto_suite_dist` | `proto_ver` × `suite_id` 分布 —— 用于判断能否推进协议/套件迁移 |

`ver.sdk_dist` 与 `ver.proto_suite_dist` 是**我们自己**做兼容性决策的依据，
也让 Vendor 知道"还有多少人在老版本上，我能不能砍掉兼容层"。

### 2.4 商业类（T0）

| ID | 定义 |
|---|---|
| `seat.utilization` | `seats_used / seats`，按 License 与按 Policy 聚合 |
| `seat.exhausted` | 因席位满而被拒的激活次数 —— **强烈的加购信号** |
| `lic.churn` | 上个窗口签到、本窗口未签到的 License 占比 |
| `lic.renewal` | 到期前完成续期的 License 占比 |
| `trial.conversion` | 同指纹从 trial license 到 paid license 的转化率与转化时长 |
| `geo.dist` | 按 `cf.country` 的签到设备分布（国家级，不落 IP） |
| `mode.dist` | Mode O / Mode E 的分布 |

### 2.5 健康类（T0）

| ID | 定义 |
|---|---|
| `health.validate_success` | 校验成功率 |
| `health.grace_rate` | 推断处于宽限期的设备占比 —— **突增 = 服务端或网络出问题** |
| `health.integrity_fail` | 完整性上报失败数（按 `release_id` 分组）—— **突增 = guard 误报,需回滚** |
| `health.suspicion` | `suspicion_score > 80` 的设备数 |
| `health.clock_rollback` | 检出时钟回拨的设备数 |

### 2.6 T1 可选指标（需同意）

| ID | 定义 | 上报形态 |
|---|---|---|
| `use.session_count` | 会话数 | 窗口内计数（客户端本地累加，签到时随请求带上） |
| `use.session_duration` | 会话时长 | **分桶直方图**（<5m / 5-30m / 30m-2h / >2h），不上报精确值 |
| `use.feature_hits` | 功能使用次数 | 按 `feature_id` 的计数（feature 清单由 Vendor 在配置中白名单声明） |
| `use.days_active` | 窗口内活跃天数 | 0–28 的整数 —— 这是获得日粒度的低成本方式 |

**T1 的设计纪律**
- 只上报**已聚合的计数与分桶**，不上报时间戳序列、不上报顺序。
- 随已有的 `validate` 请求搭车（`telemetry` 字段），**不新增网络请求**。
- 上报体积上限 512 字节；超出则丢弃最低优先级项。
- 客户端本地聚合窗口 = `refresh_after`；上报后本地计数归零。
- feature 白名单必须在 SDK 配置中显式列出，SDK 拒绝上报未声明的 feature id。

### 2.7 T2 事件遥测（需明确同意）

超出 T1 的需求（漏斗、路径分析）不由我们实现 —— 提供 `onEvent` 钩子让 Vendor
接自己选择的分析服务。**我们不做通用事件分析平台**（见 `vision-and-scope.md §5` 非目标）。

## 3. 分辨率约束（必须在 UI 与文档中反复说明）

```
活跃度的时间分辨率 ≈ min(refresh_after, heartbeat_sec)
```

| 配置 | 可靠的最细粒度 |
|---|---|
| `refresh_after = 7d`，无心跳 | 周 / 月 |
| `refresh_after = 24h` | 日 |
| `heartbeat_sec = 6h` | 日（甚至小时） |
| Mode E（`refresh_after = 24h`） | 日 |

控制台在展示活跃类指标时**必须**显示当前配置下的分辨率提示：

> ⚠️ 当前 `refresh_after = 7 天`,日粒度数据不可靠。
> 要获得日粒度：缩短 refresh_after、开启心跳，或开启 T1 遥测。

**这是诚实性问题**：如果不说，Vendor 会拿一条锯齿状的"DAU"曲线去做决策。

## 4. 唯一数排重：HyperLogLog

### 4.1 为什么

- 精确排重需要扫描明细表 → 长窗口（如"过去 12 个月的 MAU 趋势"）查询极慢。
- 明细表受 GDPR 删除影响 → 历史聚合会随删除而变化，不可复现。
- HLL 草图**不含个人数据** → 可长期保留，删除设备明细不影响历史聚合。

### 4.2 方案

```
每日 Cron（UTC 00:15）：
  for each 预定义 cube:
      sketch = HLL(p=14)                      # ~16KB/草图，误差 ~0.81%
      for each 当日签到的 machine_id:
          sketch.add(HMAC(analytics_pepper, machine_id))
      存入 D1: analytics_hll(date, cube_key, sketch_blob)

查询任意窗口：merge(日草图) → cardinality
```

**Cube 定义（固定集合，防止基数爆炸）**：

```
cube_0: (product)
cube_1: (product, app_version)
cube_2: (product, os, arch)
cube_3: (product, country)
cube_4: (product, activation_path)
cube_5: (product, mode)
cube_6: (product, release_id)
cube_7: (product, policy_id)
cube_8: (product, sdk_version)
```

- **不做**任意维度组合（会导致 O(2^n) 个草图）。需要新 cube 走配置 + 评审。
- 单产品单日约 9 个 cube × 各维度取值数；控制在数百个草图 / 天，D1 存储可接受。
- `analytics_pepper` 用于草图内的 machine_id 哈希，防止跨 cube 关联推断。

### 4.3 精确路径（小规模）

当 `machines` 表行数 < 100 万时，同时提供从 D1 明细精确计算的路径。
UI 上标注数据来源：`精确` / `约 (HLL, ±0.8%)`。

## 5. 数据管线

```
                        ┌──── T0：无需客户端参与 ────┐
客户端 validate/activate │                            │
        │                ▼                            │
        └──▶ Worker ──▶ LicenseDO（写 last_seen 等）  │
                │                                      │
                ├──▶ Analytics Engine.writeDataPoint() │  实时、采样、按维度
                │      （低延迟看板、近实时告警）        │
                │                                      │
                └──▶ Queue(EVENTS) ──▶ R2 raw/         │  明细，短保留
                                          │
                        Cron（每日 00:15）│
                                          ▼
                            ┌── D1 rollup 表（精确计数）
                            └── D1 analytics_hll（唯一数草图）
                                          │
                                          ▼
                     Admin API /v1/admin/analytics/*  ──▶ 控制台 / CSV / Webhook
```

**双写的理由**
- **Analytics Engine**：写入极便宜、支持 SQL 查询、适合近实时看板与告警。但它有采样与保留期限制，不适合做精确的月度报表。
- **Queue → R2 → Cron rollup → D1**：精确、可控保留、可导出。延迟到 T+1。

控制台的"今日"用 Analytics Engine（标注"近实时,含采样"），"历史"用 D1 rollup（标注"精确"）。

## 6. 遥测上报协议（T1）

搭车在 `validate` 请求里，**不新增端点、不新增请求**：

```cddl
validate_request = {
  ...                          ; 见 protocol-spec.md §10.2
  11: ? telemetry_block,
}

telemetry_block = {
  0: uint,                     ; consent_version —— 用户同意的隐私声明版本号
  1: uint,                     ; window_start (服务端时间,来自上一次 VT)
  2: uint,                     ; session_count
  3: [uint, uint, uint, uint], ; session_duration_histogram (4 个桶的计数)
  4: { * tstr => uint },       ; feature_hits（key 必须在 SDK 配置白名单内）
  5: uint,                     ; days_active (0..28)
}
```

**安全与可信度**

| 问题 | 处理 |
|---|---|
| 客户端可以伪造遥测 | ✅ 已知。遥测被标记为 `untrusted`,与 T0 的 `trusted` 指标在**不同的表、不同的 UI 区域**展示 |
| 攻击者投毒污染商业指标 | 必须携带设备签名 `proof`（与 validate 同一签名覆盖）→ 只能污染自己那一台的数据；异常值（如 `session_count > 10000`）在入库前被裁剪并计数 |
| 遥测成为侧信道 | 上报体积固定上限；不含时间戳序列；不含顺序 |
| 无同意却上报 | `consent_version = 0` 时服务端**丢弃**遥测块并计数（用于发现 SDK 集成错误） |

**关键设计**：T0 指标是**可信的**（源于签名凭证的使用记录），T1 是**不可信的**（客户端自报）。
控制台必须视觉区分，否则 Vendor 会把两者混在一张图上做决策。

## 7. 已知盲区（必须写进文档）

| 盲区 | 说明 | 缓解 |
|---|---|---|
| **完全离线设备不可观测** | air-gapped 设备永不联网,我们只知道它被激活过 | ① 统计"离线激活签发数"作为下界 ② 可选的"离线使用回执"：设备偶尔联网时上传一个签名的计数摘要（需 Policy 开启） |
| **OLK 无法统计安装数** | 未绑定指纹的 OLK 可无限复制 | 这是 OLK 模式的固有代价；控制台对 OLK 类 License 显示"安装数不可观测"标记 |
| **指纹容差导致的重装不计新激活** | 用户重装系统若指纹相似度仍 ≥ 阈值,不产生新 `machine_id` | 提供 `act.fingerprint_drift` 辅助指标（指纹字节变化但匹配成功的次数） |
| **同一人多设备无法识别** | 我们统计的是设备,不是人 | Mode E 下可按 `account_id` 聚合"用户数"；Mode O 下明确标注"设备数 ≠ 用户数" |
| **VM / 云环境的设备计数** | 自动扩缩容会产生大量短命设备 | Policy 的随机 UUID 指纹模式下,提供 `dev.ephemeral_rate` 标记 |
| **Analytics Engine 的采样** | 高流量下可能采样 | 近实时看板标注"含采样"；精确数走 D1 rollup |

## 8. Admin API

```
GET /v1/admin/analytics/metrics
      ?ids=act.new,dev.checked_in_28d,ver.app_dist
      &from=2026-06-01&to=2026-06-30
      &granularity=day|week|month
      &group_by=app_version,country
      &product=my-app
→ { series: [...], meta: { source: "exact"|"hll", error_pct, suppressed_buckets } }

GET  /v1/admin/analytics/export?format=csv|ndjson&...     # 大导出走 R2 预签名 URL
POST /v1/admin/analytics/subscriptions                    # 定期报表推送（邮件/Webhook）
GET  /v1/admin/analytics/definitions                      # 返回完整指标目录与口径定义
```

- `definitions` 端点让口径可被程序化获取,避免文档与实现漂移。
- 所有返回都携带 `meta.source` 与 `meta.error_pct`，k-匿名抑制的桶在 `suppressed_buckets` 中说明。
- Admin scope：`analytics:r`（独立 scope，可以只给市场同事读分析而不给授权管理权限）。

## 9. 控制台页面

| 页面 | 内容 |
|---|---|
| **Overview** | 激活趋势、签到设备趋势、席位利用率、健康度红绿灯 |
| **Activations** | 按路径（在线/离线/OLK/账号）、失败原因、首次激活耗时、地理分布 |
| **Versions** | 版本分布饼图、采纳曲线、升级滞后、SDK/协议/套件分布（含"可以停止支持 X 了"的提示） |
| **Retention** | 签到留存队列（cohort）、流失、续期率、试用转化 |
| **Seats** | 席位利用率排行、席位耗尽事件（**加购线索列表**） |
| **Health** | 校验成功率、宽限期占比、完整性失败（按 release 分组）、时钟回拨 |
| **Usage (T1)** | 仅在开启 T1 时出现；**独立标注"客户端自报，不可信"** |

每个图表旁边有 `ⓘ` 显示该指标的精确定义与数据来源，链接到 `definitions`。

## 10. SDK 配置

```rust
CopyLockerConfig {
    telemetry: TelemetryConfig {
        tier: TelemetryTier::T0,               // T0（默认）| T1 | Off
        consent: ConsentProvider::None,        // T1 必须提供
        feature_whitelist: &["export", "render", "ai-assist"],
        session_buckets: SessionBuckets::default(),
    },
    ..
}
```

```ts
const cl = await CopyLocker.create({
  telemetry: {
    tier: 'T1',
    consent: () => userConsentStore.get('analytics'),   // 每次上报前调用
    featureWhitelist: ['export', 'render'],
  },
})
cl.track('export')     // 只在 T1 且已同意时计数；否则 no-op
```

**防呆**
- `tier: 'T1'` 但未提供 `consent` → SDK 初始化时**报错**（不是警告）。
- `track()` 传入未白名单的 feature → 开发模式抛错，生产模式静默丢弃。
- `TelemetryTier::Off` 会关闭 T0 的**可选字段**（如 `app_version` 上报），
  但无法关闭协议必需的字段（`machine_id`、`release_id` 等）—— 文档必须说清这一点，
  避免 Vendor 以为 `Off` 等于"服务端什么都不知道"。

## 11. 数据保留

| 数据 | 保留 | 理由 |
|---|---|---|
| R2 raw 明细 | 90 天 | 支持回溯重算 rollup |
| D1 rollup（精确计数） | 3 年 | 商业趋势分析 |
| D1 HLL 草图 | 3 年 | 不含个人数据,可长期保留 |
| Analytics Engine | 按 CF 保留策略 | 近实时看板 |
| T1 原始上报 | 30 天后只保留聚合 | 最小化 |

GDPR 删除请求：删除 `machines` 明细 + R2 raw 中的对应记录；
**HLL 草图与 rollup 计数不回溯修改**（不含个人数据，且回溯会破坏历史可比性）—— 这一点需在隐私政策模板中说明。

## 12. 测试

| 类型 | 内容 |
|---|---|
| 口径一致性 | 同一指标从"精确路径"与"HLL 路径"计算，误差在 ±1% 内 |
| Rollup 幂等 | 重跑某日 Cron，结果不变 |
| HLL 合并 | 日草图合并 = 直接对该窗口计算，误差在界内 |
| k-匿名 | 构造 < 5 的桶，断言被抑制 |
| 遥测投毒 | 提交 `session_count = 10^9` → 被裁剪并计入异常计数 |
| 无同意 | `consent_version = 0` → 遥测被丢弃 |
| 分辨率提示 | `refresh_after = 7d` 时，日粒度查询返回警告标记 |
| 盲区标记 | OLK 类 License 的响应中含"不可观测"标记 |
