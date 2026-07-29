# ADR-0007：分析数据分三层，默认层零额外采集

- **状态**：Accepted
- **日期**：2026-07-26
- **相关**：ADR-0004、`03-modules/90-analytics-telemetry.md`、`06-legal/privacy-and-legal-pack.md`

## 背景

Vendor 需要用真实的授权数据做市场决策：激活量、活跃设备数、离线/在线激活比例、
版本分布、席位利用率、试用转化率、流失率。

同时我们在 `vision-and-scope.md` 与 `threat-model.md` 中承诺了强隐私姿态
（指纹只上报 HMAC 摘要、`telemetry: off` 可关）。这两者看似冲突。

## 关键观察

**上述指标中的绝大多数，其数据在授权协议里已经存在了。**

| 指标 | 数据来源 | 是否需要额外采集 |
|---|---|---|
| 激活总数 / 趋势 | `LicenseDO.activations` 的插入记录 | ❌ 不需要 |
| 离线 vs 在线激活比例 | `activation.path`（激活时就知道走的哪条路径） | ❌ 不需要 |
| 版本分布 | `client_info.app_version` / `sdk_version` / `release_id`（校验请求本就携带） | ❌ 不需要 |
| 活跃设备数 | `activation.last_seen_at`（每次 validate/heartbeat 更新） | ❌ 不需要 |
| 席位利用率 | `seats_used / seats` | ❌ 不需要 |
| 地理分布（国家级） | Cloudflare 的 `cf.country`（请求元数据，非客户端上报） | ❌ 不需要 |
| 流失 / 续期率 | 上述数据的时间序列 | ❌ 不需要 |
| 试用转化率 | 同指纹从 trial license 到 paid license | ❌ 不需要 |
| **功能使用频次** | — | ✅ 需要 |
| **会话时长 / 启动次数** | — | ✅ 需要 |
| **应用内漏斗** | — | ✅ 需要 |
| **真正的 DAU（日粒度）** | — | ⚠️ 见下方"分辨率约束" |

## 决策

### 分三层

| 层 | 名称 | 默认 | 数据来源 | 法律基础（GDPR 语境） |
|---|---|---|---|---|
| **T0** | 协议派生分析（Protocol-Derived） | **开启** | 授权协议本身已有的字段与请求元数据 | 合同履行 / 正当利益（授权管理本就必需） |
| **T1** | 聚合遥测（Aggregate Telemetry） | **关闭** | 客户端上报的**预聚合、无事件流**的计数与分桶 | 需终端用户同意（consent） |
| **T2** | 事件级遥测（Event Telemetry） | **关闭** | 客户端上报的事件流（带假名 ID） | 需明确同意 + 单独的隐私声明 |

### T0 的边界（硬性）

T0 **只能**使用以下字段，不得扩充：

```
来自已有的 activate / validate / heartbeat 请求：
  machine_id（服务端分配的假名）、license_id、product_id、policy_id
  fingerprint（HMAC 摘要，不可逆）
  app_version、sdk_version、release_id、variant_id、proto_ver、suite_id
  os、arch、activation_path、mode
  timestamps（服务端时间）
来自 Cloudflare 请求元数据（非客户端上报）：
  cf.country（国家级，不落 IP）
```

**明确排除**：IP 地址（只用于限流，不入分析、不落库）、原始设备属性、
用户名/邮箱（除非 Mode E 且 Vendor 自己已持有）、任何应用内行为。

### T0 的分辨率约束（必须诚实告知 Vendor）

"活跃设备"的时间分辨率**受 `refresh_after` 限制**：

```
refresh_after = 7d  → 只能可靠计算 WAU / MAU，不能计算 DAU
refresh_after = 24h → 可以计算 DAU
```

因此我们**不提供名为 "DAU" 的指标**，而提供定义明确的 **Checked-in Devices (窗口)**。
若 Vendor 需要日粒度，选项是：
1. 缩短 `refresh_after`（增加服务端请求量与成本）
2. 开启轻量心跳（`heartbeat_sec`，一个几百字节的请求，仍属 T0）
3. 开启 T1

### 唯一数排重用 HyperLogLog 草图

跨维度、跨长时间窗口的唯一设备计数用 **HLL 草图**（每个 (日期, 维度组合) 一个草图）：

- 草图可合并 → 任意时间窗口（周/月/季）由日草图合并得出，无需重新扫描明细。
- 草图**不含个人数据** → 可长期保留，且在 GDPR 删除某设备后统计口径不被破坏
  （这一点很重要：明细可删，历史聚合不必回溯重算）。
- 误差 ~0.8%（p=14），对市场决策足够。
- 小规模（< 100 万设备）同时提供从 D1 明细精确计算的路径，二者在 UI 上标注来源。

### k-匿名抑制

任何分组展示，若桶内唯一设备数 < 5，显示为 `<5` 而不显示精确值。
防止"某国家只有 1 个用户"这类可重识别的输出。

## 备选方案与否决理由

| 方案 | 否决 |
|---|---|
| 接入第三方分析 SDK（PostHog/Amplitude/GA） | 引入第三方数据处理者、增加合规负担、与"数据自持"定位冲突、增加客户端体积与攻击面 |
| 默认开启事件级遥测 | 违背隐私承诺；多数 Vendor 用不上；法律风险转嫁给 Vendor |
| 不做分析，让 Vendor 自己从 D1 里查 | 口径不统一（"活跃"的定义会人人不同）；缺 HLL 会导致长窗口查询极慢；缺 k-匿名保护 |
| 把 IP 存进分析表做地理分析 | IP 是个人数据；`cf.country` 已足够且不落 IP |

## 后果

**正面**
- 开箱即得的分析不需要任何隐私妥协，Vendor 不必为 T0 单独获取用户同意（但仍需在隐私政策中披露）。
- T1/T2 是纯增量，可以晚做（排到 M5+）。
- HLL 让"保留 3 年的聚合趋势 + 90 天的明细"成为可能。

**负面 / 代价**
- T0 的时间分辨率受 `refresh_after` 约束，需要在文档中反复解释，否则 Vendor 会问"为什么没有 DAU"。
- **完全离线的设备对 T0 不可见**：只能统计其激活与续期，无法统计其使用。见 `90-analytics-telemetry.md §7`。
- HLL 引入近似性 → UI 必须标注"约"并给出误差范围，避免 Vendor 拿去做精确对账。

## 数据归属

分析数据属于 Vendor，存在 Vendor 自己的 Cloudflare 账号内。
CopyLocker 项目方**不接收、不聚合、不跨 Vendor 分析**任何数据。这一点写进 README 与销售材料。
