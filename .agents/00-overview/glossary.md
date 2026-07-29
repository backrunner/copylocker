# 术语表 / Glossary

全项目统一命名。代码标识符、API 字段、文档必须使用本表中的英文名。

## 实体（Entities）

| 中文 | 英文 / 标识符 | 定义 |
|---|---|---|
| 厂商 | **Vendor** | 使用 CopyLocker 的软件开发者/公司。一个 Vendor 一套部署、一套根密钥 |
| 产品 | **Product** | Vendor 的一个软件产品，`product_id` 全局唯一 |
| 产品策略 | **Policy** | 挂在 Product 下的授权策略模板：模式、席位数、有效期、宽限期、校验周期 |
| 授权 | **License** | 一次销售所产生的授权实例，绑定 Policy，含 `license_id` |
| 授权密钥 | **License Key (LK)** | 用户可见的短字符串，形如 `CL1-XXXXX-XXXXX-XXXXX-XXXXX`。**只是标识符，不自含签名** |
| 离线授权密钥 | **Offline License Key (OLK)** | 自含签名的长凭证（Base32 blob 或 `.clk` 文件），可完全离线验证 |
| 席位 | **Seat** | License 允许的并发激活数量上限 |
| 设备 | **Machine** | 一次激活对应的物理/逻辑设备，由 Fingerprint 标识 |
| 激活 | **Activation** | Machine 占用 Seat 的记录，含状态、时间、心跳 |
| 账号 | **Account** | Mode E 下的终端用户账号（邮箱 + 凭据） |
| 发布 | **Release** | 一次对外发布，注册到服务端，含 `release_id`、`published_at`、`variant_id` |
| 变体 | **Variant** | 每个 Release 独有的形态参数集合（编码掩码、FK info、符号名…），不改变协议语义 |

## 授权模型（ADR-0009）

| 中文 | 英文 / 标识符 | 定义 |
|---|---|---|
| 功能 | **Feature** | 原子能力，`feature_id` **发布后不可变、不可复用**（FeatureKey 派生依赖它） |
| 功能组 | **FeatureGroup** | 命名的 feature 集合，可嵌套引用其他 group，支持 glob |
| 档位 | **Tier** | 一组 group + limits + 展示信息 + `rank`（用于比较升降级方向） |
| 配额 | **Limits** | 数值型约束（如 `max_projects`）。**运行时强制由 Vendor 应用负责**，我们只提供签名数值 |
| 加购 | **Grant** | 在 tier 之外单独授予的 feature/group，可带独立有效期 |
| 权益规格 | **EntitlementSpec** | Policy 中的权益配置（tier + extra_groups + grants + overrides） |
| 权益快照 | **ResolvedEntitlements** | `resolve()` 的输出：完全展开的有序 feature 集合 + 合并后的 limits，写入 MC |
| 目录版本 | **CatalogVersion** | 权益目录的不可变快照，用于复现历史解析结果 |
| 有效期 | **Validity** | `Perpetual` / `FixedTerm` / `Subscription` / `Trial` |
| 版本范围 | **VersionScope** | `Unlimited` / `SemverRange` / **`ReleasedBefore`** / `Pinned` |
| 计费周期 | **BillingPeriod** | monthly / annual / custom |
| 催缴宽限 | **Dunning Grace** | 支付失败后仍可用的缓冲期（默认 7 天），防止支付延迟锁死正常付费用户 |
| 永久回退 | **Perpetual Fallback** | 连续付费达阈值后，订阅取消时自动转为"永久 + 版本封顶"的授权 |
| 安全基线 | **security_floor** | 单调递增的整数，写入凭证；客户端拒绝低于已见最大值的凭证（防降级） |
| 受限模式 | **Restricted Mode** | 版本超出授权范围时的客户端状态：提示可用最高版本，**不是盗版警告** |
| 计划变更 | **ScheduledChange** | 排到未来生效的 tier/席位/版本范围变更 |

## 分析与遥测（ADR-0007）

| 中文 | 英文 / 标识符 | 定义 |
|---|---|---|
| 协议派生分析 | **T0** | 默认开启，**零额外采集**，全部来自授权协议已有字段与请求元数据 |
| 聚合遥测 | **T1** | 默认关闭，需同意；客户端预聚合的计数与分桶，搭车 `validate` 上报 |
| 事件遥测 | **T2** | 我们不自建，只提供 `onEvent` 钩子供 Vendor 接自己的分析服务 |
| 签到设备 | **Checked-in Device** | 窗口内至少成功完成一次 validate/heartbeat 的唯一 `machine_id`。**我们不提供名为 DAU 的指标** |
| 分辨率约束 | **Resolution Constraint** | 活跃度的时间分辨率 ≈ `min(refresh_after, heartbeat_sec)` |
| 草图 | **HLL Sketch** | HyperLogLog（p=14，误差 ~0.8%），可合并、不含个人数据、可长期保留 |
| 立方体 | **Cube** | 预定义的维度组合（固定集合，防基数爆炸） |
| k-匿名抑制 | **k-Anonymity Suppression** | 桶内唯一设备数 < 5 时显示为 `<5` |

## 凭证与工件（Artifacts）

| 中文 | 英文 / 标识符 | 定义 |
|---|---|---|
| 激活请求 | **ActivationRequest (AR)** | 客户端 → 服务端：指纹、随机数、临时 KEM 公钥、客户端声明 |
| 设备凭证 | **MachineCredential (MC)** | 服务端签发的核心工件：签名 + 对设备封装（sealed），本地持久化。含权益、有效期、下次校验期限 |
| 校验票据 | **ValidationTicket (VT)** | 一次在线校验的签名响应，含服务端时间、nonce 回显、下次校验期限、Feature Key 材料 |
| 吊销批次 | **RevocationBatch (RB)** | 签名的吊销列表增量 + 单调递增的 `revocation_epoch` |
| 停用指令 | **KillOrder** | 针对特定 Activation 的签名停用指令，客户端收到后立即擦除本地凭证 |
| 完整性清单 | **IntegrityManifest (IM)** | Web 构建产物的分片摘要集合 + 签名，由 unplugin 生成 |
| 功能密钥 | **Feature Key (FK)** | 由校验结果派生的对称密钥，用于解密受保护的资产/代码分片。见 `60-instrumentation-guard.md` |
| 封印包 | **Sealed Asset** | 被 Feature Key 加密的应用资产或代码分片 |

## 密码学（Cryptography）

| 中文 | 英文 / 标识符 | 定义 |
|---|---|---|
| 算法套件 | **Crypto Suite** | 一组算法实现的集合（签名/KEM/AEAD/KDF/Hash/Fingerprint），由 `SuiteId` 标识 |
| 套件槽位 | **Suite Slot** | 架构中可插入 Suite 实现的抽象点（trait 对象/泛型参数） |
| 开源参考套件 | **CL-STD-1** | 开源默认套件：Ed25519+ML-DSA-65 混合签名、X-Wing KEM、XChaCha20-Poly1305 |
| 紧凑套件 | **CL-CMP-1** | 面向 OLK 的紧凑签名套件：FN-DSA-512（Falcon-512） |
| 私有套件 | **CL-PRIV-n** | 闭源套件，独立仓库，接口兼容 |
| 根密钥 | **Root Key** | 离线保管的最高层签名密钥，客户端 pin 其公钥 |
| 纪元密钥 | **Epoch Key** | 由 Root Key 签发的短期在线签名密钥（默认 90 天） |
| 设备指纹 | **Fingerprint** | 设备属性的规范化 HMAC 摘要，`fp = HMAC(vendor_salt, canonical_attrs)` |
| PQ/T 混合 | **Hybrid (PQ/T)** | 后量子 + 传统算法的复合构造，需两者都验证通过 |

## 模式与状态（Modes & States）

| 中文 | 英文 / 标识符 | 定义 |
|---|---|---|
| 离线优先混合模式 | **Mode O** (`offline_hybrid`) | 可离线激活；有网即校验；判非法立即停用 |
| 强制在线模式 | **Mode E** (`enforced_online`) | 首次必须在线激活；周期内必须成功在线校验一次 |
| 宽限期 | **Grace Window** | 校验期限过后仍允许运行的缓冲时长（网络不可达导致） |
| 硬期限 | **Hard Deadline** (`not_after`) | 超过即锁定，无论是否有网 |
| 校验期限 | **Refresh Deadline** (`refresh_after`) | 建议/要求下一次成功在线校验的时间点 |
| 时钟守卫 | **Clock Guard** | 检测系统时间回拨的机制 |
| 停用 | **Deactivate** | 释放 Seat 并擦除本地 MC |
| 锁定 | **Locked** | 客户端进入不可用状态，需重新激活/联网 |

## 客户端状态机状态

```
Unlicensed → Activating → Active ⇄ NeedsRevalidation → Grace → Locked
                                                  ↘ Revoked (terminal until re-activation)
```

| 状态 | 含义 |
|---|---|
| `Unlicensed` | 无本地凭证 |
| `Activating` | 激活流程进行中 |
| `Active` | 凭证有效且在 `refresh_after` 之前 |
| `NeedsRevalidation` | 超过 `refresh_after`，应尽快联网校验，仍可用 |
| `Grace` | 联网失败，处于宽限期内，仍可用但功能可降级 |
| `Locked` | 超过硬期限或宽限期耗尽 |
| `Revoked` | 收到 KillOrder 或吊销命中 |
| `Tampered` | 完整性校验失败（本地文件/清单/函数体） |

## 构建与工程

| 术语 | 定义 |
|---|---|
| **Instrumentation（插桩）** | 在应用核心流程中插入异步校验点的做法 |
| **Guarded Function** | 被 `@guarded` 装饰、其函数体摘要在构建期被记录、调用时校验的函数 |
| **Build Fingerprint** | 每次构建产生的唯一标识，参与 Feature Key 派生，防跨版本重放 |
| **Suite Binding** | 构建期把 Vendor 的私有套件参数编入产物的过程 |
| **Variant Binding** | 构建期把 Release 的变体参数编入产物的过程 |
| **Wrapped KEK** | 用设备的 FeatureKey 包装的资产 KEK，随 MC/VT 下发 |
| **Release Registration** | `copylocker release register`，CI 强门禁；未注册的版本无法激活 |
| **Policy Simulator** | 给定 Policy + 场景，输出用户会经历的时间轴（CLI + 控制台） |
