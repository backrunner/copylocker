# 威胁模型

> **写代码前必读。** 每一条缓解措施都应能追溯到具体的 FR/NFR 与代码位置。

## 1. 资产（Assets）

| ID | 资产 | 价值 | 泄露/破坏后果 |
|---|---|---|---|
| A1 | **Root 私钥** | 极高 | 可伪造任意凭证 → 全线失守，需砖化所有客户端并换根 |
| A2 | **Epoch 私钥** | 高 | 可伪造凭证直到该 epoch 被吊销（≤90 天窗口） |
| A3 | **CredentialSecret（每设备）** | 中 | 该设备的凭证可被复制到别处（若指纹绑定被绕过） |
| A4 | **Feature Key / Sealed Asset 明文** | 中高 | 受保护功能被永久提取（对该版本） |
| A5 | **Vendor 指纹 salt** | 中 | 可离线复算指纹 → 便于伪造/关联分析 |
| A6 | **Admin token** | 高 | 可任意签发/吊销 License |
| A7 | **License 数据库** | 中 | 客户名单泄露（隐私）、可枚举有效 Key |
| A8 | **私有套件源码** | 中 | 破解可复用性提高（但不导致伪造，见 NFR-SEC-001） |
| A9 | **客户端可用性** | 中 | 误吊销/服务端故障导致正版用户被锁 → 商誉损失 |

## 2. 攻击者画像

| 编号 | 画像 | 能力 | 动机 |
|---|---|---|---|
| **T1 休闲用户** | 搜索"XX 破解版"、用现成 patch | 无逆向能力 | 免费使用 |
| **T2 熟练破解者** | IDA/Ghidra/Frida/Chrome DevTools、Rust 逆向、WASM 反编译 | 高，单机 | 名声、发布 crack |
| **T3 keygen 作者** | T2 + 密码学知识，目标是做出通用注册机 | 很高 | 影响力 |
| **T4 内部人员** | 有 CI/Cloudflare/仓库访问权 | 极高 | 报复、牟利 |
| **T5 网络攻击者** | MITM、DNS 劫持、恶意代理 | 中 | 拦截/篡改校验 |
| **T6 服务滥用者** | 脚本、僵尸网络 | 中 | 撞 Key、DoS、席位耗尽 |
| **T7 供应链攻击者** | 污染 npm/crates 依赖或构建流水线 | 高 | 大规模植入 |
| **T8 未来量子攻击者** | CRQC（密码学相关量子计算机） | 未来 | 伪造历史签名 / 解密留存流量 |

## 3. STRIDE 分析

### 3.1 Spoofing（伪装）

| 威胁 | 攻击者 | 缓解 | 需求 |
|---|---|---|---|
| 伪造 License Server（DNS/代理劫持），返回"合法" | T5 | 应用层签名（TLS 之上）+ Root 公钥 pin + nonce 挑战；**TLS 不承担安全语义** | FR-CRY-011、FR-CLI-010 |
| 伪造客户端刷激活 | T6 | 限流（IP/license/fp 三维）、Idempotency、可选 Turnstile | FR-SRV-020/027/028 |
| 伪造设备指纹以复制凭证 | T2 | MC 用设备 KEM 公钥密封 → 无对应私钥则解不开；指纹进 AAD | AC-6、NFR-SEC-008 |
| 冒充 Admin | T6 | Admin token 高熵 + scope + 审计 + 可选 Cloudflare Access 前置 | FR-ADM-002 |
| 谎报 `release_id` 以绕过版本范围 | T2 | 谎报旧 release → 拿到旧 variant 的 `wrapped_keks`，而运行的是新版本（新 variant 的 FK）→ 解不开 Sealed Asset | FR-LIC-019、FR-VER-005 |
| 伪造遥测污染商业指标 | T6 | 遥测被 `proof` 签名覆盖 → 只能污染自己那台；异常值入库前裁剪；T0/T1 分表且 UI 分区 | FR-TLM-020/021 |

### 3.2 Tampering（篡改）

| 威胁 | 攻击者 | 缓解 | 残余风险 |
|---|---|---|---|
| Patch 客户端二进制去掉验证 | T2/T3 | **ADR-0004 生产性验证**：跳过验证 → 拿不到 FeatureKey → Sealed Asset 无法解密 | 若 Vendor 只用 L0/L1 强度则无效；文档强推 L2+ |
| 替换 WASM 为 stub | T2 | 拆分密钥派生（WASM 输出 + TS 常量 + WASM 自身摘要），单边替换必失败 | 攻击者可同时替换两边 → 但仍拿不到 FK（FK 需要真实 CredentialSecret） |
| 篡改 JS bundle | T2 | IntegrityManifest + guard 运行时校验 + FK 派生绑定 build fingerprint | guard 本身可被删；因此 guard 结果必须参与 FK 派生而非仅上报 |
| 篡改本地凭证文件延长有效期 | T1/T2 | 凭证被签名 + AEAD 密封；篡改 → 验签失败 → `Tampered` | — |
| 修改系统时钟 | T1/T2 | Clock Guard（单调高水位 + 服务端时间锚 + 回拨阈值）→ 强制在线校验 | 完全离线 + 时钟回拨仍可延长 Grace；因此 Mode E 用硬 `not_after` |
| 篡改 hosts / 防火墙屏蔽校验域名 | T1/T2 | 无网 = Grace，Grace 有硬上限；Mode E 硬 `not_after` | 这是 Mode O 的固有权衡，文档必须说明 |
| 供应链污染依赖 | T7 | lockfile + `cargo-deny`/`cargo-audit` + npm `--ignore-scripts` + 可复现构建 + SLSA provenance + SBOM | NFR-SEC-006/007 |
| **降级攻击**：喂入旧版本签发的凭证以绕过已修复的漏洞 | T2/T3 | `security_floor` 单调递增，客户端持久化最大值并拒绝更低凭证；与 `clock.last_seen_max` 一样多处冗余 + AEAD 保护 | FR-VER-012/013 |
| 把 v1.2 的破解 patch 用到 v1.5 | T2/T3 | 每 Release 一个变体（编码掩码、FK info、binder、离线验证参数全不同）→ 破解不可跨版本复用 | ADR-0008 |
| 破解某版本后长期有效 | T3 | `release mark-compromised` × `force_upgrade` → 精确回收单个版本，不影响其他用户 | FR-VER-011 |

### 3.3 Repudiation（抵赖）

| 威胁 | 缓解 |
|---|---|
| Vendor 内部人员偷偷签发 License 后否认 | `IssuerDO` 单调序号 + 哈希链审计日志 + Queue 落 R2（不可变） |
| 用户否认曾激活 | Activation 记录含服务端时间、IP 粗粒度、指纹摘要，签名归档 |

### 3.4 Information Disclosure（信息泄露）

| 威胁 | 缓解 |
|---|---|
| 客户端二进制中提取密钥 → 通用 keygen | **客户端只有公钥**（NFR-SEC-002）；CI 里做熵扫描确认无私钥常量 |
| 从 KV/D1 读取敏感数据 | Epoch 私钥只在 Secrets Store；D1 中不存明文 CredentialSecret（只存 KEM 密文） |
| 指纹被用于跨应用追踪用户 | 只上报 HMAC 摘要，salt 每 Vendor 独立 |
| 错误响应区分"key 不存在/已用尽"→ 枚举 | 统一通用错误码，细节仅入审计 |
| Harvest-now-decrypt-later | PQ 混合 KEM（X-Wing），敏感字段今日即抗量子 |

### 3.5 Denial of Service

| 威胁 | 缓解 |
|---|---|
| 打爆 Worker | Cloudflare 天然抗 DDoS；端点限流；WAF 规则模板 |
| 单 DO 热点（一个 License 被全网共享狂刷） | DO ~1000 req/s；超阈值即触发异常检测并自动挂起该 License |
| 解析型 DoS（超大 CBOR/深嵌套） | 解析前长度 + 深度限制；fuzz 覆盖（NFR-SEC-015） |
| 恶意占满席位 | 需要有效 LK 才能占位；Idempotency 防重复占位；异常检测 |
| **误吊销导致大规模锁定**（自伤 DoS） | 吊销操作需二次确认 + dry-run 影响面预览 + 可撤销窗口；runbook |

### 3.6 Elevation of Privilege

| 威胁 | 缓解 |
|---|---|
| 普通 License 伪造出更高 entitlements | entitlements 在签名 payload 内；权益在**服务端**解析并快照，客户端拿不到目录 |
| 篡改本地 tier 以解锁高档功能 | 高档 feature 的 Sealed Asset 用对应 FeatureKey 加密；未被授予则派生不出密钥 |
| Renderer 进程通过 IPC 直接调用特权 API（Electron） | `contextIsolation: true` + 严格 preload 白名单；核心逻辑只在主进程；`unseal` 的 feature 白名单在主进程 |
| Web 页面上第三方脚本调用 SDK 内部 | 核心跑在 Web Worker 中；不挂全局对象；闭包封装 + 每构建随机符号名 |
| **控制台被 XSS/CSRF 后越权签发** | 控制台不绑定签名密钥、不直连 D1/DO；一切经 Service Binding 调 API Worker 并在那里**重新**做 scope 校验与审计；严格 CSP + form action origin 校验 |
| 拿到 `analytics:r` 的人越权看到授权明细 | scope 独立；分析 API 只返回聚合值；k-匿名抑制在 API 与 UI 两层各校验一次 |

## 4. 攻击树：目标 = 无授权使用软件

```
无授权使用
├── A. 获得合法凭证
│   ├── A1 盗用他人 LK ────────────▶ 席位限制 + 异常检测 + 吊销
│   ├── A2 复制他人 MC 到本机 ─────▶ KEM 密封到设备私钥 + 指纹绑定  ✅强
│   ├── A3 伪造 MC（需要私钥）─────▶ PQ 混合签名，客户端无私钥      ✅强
│   ├── A4 窃取 Epoch 私钥 ────────▶ Secrets Store + RBAC + 90d 轮换 + 吊销
│   └── A5 窃取 Root 私钥 ─────────▶ 离线签名机 + 硬件密钥 + 多人仪式 ✅强
├── B. 绕过验证逻辑
│   ├── B1 patch "if invalid → exit" ──▶ ADR-0004：无此分支         ✅强(L2+)
│   ├── B2 替换 WASM/原生模块 ────────▶ 拆分派生 + 自摘要 + FK 依赖真实密钥
│   ├── B3 hook 网络返回伪造成功 ─────▶ 响应必须验签 + nonce 回显    ✅强
│   ├── B4 冻结/回拨时钟 ────────────▶ Clock Guard + 硬 not_after
│   └── B5 屏蔽校验域名 ────────────▶ Grace 有上限；Mode E 硬上限
├── C. 提取受保护内容（绕过 FK）
│   ├── C1 从内存 dump 中提取 FK ─────▶ ⚠️ 可行。缓解：短生命周期、
│   │                                     用后 zeroize、分片解密、
│   │                                     不一次性解全部资产
│   ├── C2 一个合法用户解密后再分发明文 ▶ ⚠️ 固有风险（"一个买家泄露"）。
│   │                                     缓解：水印/每用户密钥/版本轮换
│   └── C3 重新实现被保护功能 ─────────▶ 这就是我们要的：破解成本 = 重写成本
└── D. 攻击服务端
    ├── D1 逻辑漏洞越权签发 ─────────▶ 领域逻辑纯函数 + 属性测试 + 外部审计
    ├── D2 供应链 ─────────────────▶ NFR-SEC-006/007
    └── D3 内部人员 ───────────────▶ 审计哈希链 + Root 离线 + 最小权限
```

**标注 ⚠️ 的是已知残余风险，必须写进公开文档，不假装解决了。**

## 5. 缓解措施矩阵（实现清单）

| 缓解 | 实现位置 | 需求 | 验证 |
|---|---|---|---|
| PQ 混合签名（两分量都必过） | `copylocker-suite-std::sig` | FR-CRY-002/004 | KAT + 负向测试（单分量伪造必失败） |
| Root→Epoch 链 + 客户端 pin（主+备） | `copylocker-proto::chain` | FR-CRY-011/012 | 集成测试：换根不砖化 |
| MC 密封到设备 KEM 公钥 | `copylocker-core::activation` | AC-6 | 跨机复制测试 |
| 指纹进 AAD | `copylocker-proto::envelope` | NFR-SEC-008 | 篡改 AAD 必失败 |
| nonce 防重放（客户端 + 服务端双向） | `LicenseDO::nonce_cache` | FR-SRV-021 | 重放测试 |
| Clock Guard | `copylocker-core::clock` | FR-CLI-004、AC-9 | 时间回拨模拟测试 |
| fail-open/closed 双 error 类型 | `copylocker-core::error` | FR-CLI-006 | 类型系统 + lint |
| 席位原子事务 | `LicenseDO` | FR-SRV-005、AC-10 | 100 并发压测 |
| Feature Key 派生（含 build fp、WASM 摘要、TS 常量） | `copylocker-core::fk` + `@copylocker/web` | ADR-0004、AC-8 | stub 替换测试 |
| IntegrityManifest + guard | `@copylocker/unplugin` + `guard` | FR-BLD-002/003、AC-7 | 单字节篡改测试 |
| 限流三维 | `copylocker-worker::ratelimit` | FR-SRV-020 | 压测 |
| 统一错误码不泄露 | `copylocker-server-core::error` | FR-SRV-026 | 响应差分测试 |
| 密钥 Zeroize | 全 crate | FR-CRY-009 | Clippy + 内存扫描测试 |
| 无 unsafe | `#![forbid(unsafe_code)]` | NFR-SEC-005 | CI |
| 可复现构建 + provenance | CI | NFR-SEC-007 | 第三方复算 |

## 6. 明确不防护的（残余风险声明）

必须原样写进 `SECURITY.md` 与文档站：

1. **拥有物理机器控制权的攻击者最终总能提取当前版本已解密的内容。** 我们提高的是成本与可复用性，不是不可能性。
2. **合法用户主动泄露解密后的资产**（"一个买家泄露"）无法通过技术阻止；缓解手段是每用户水印与版本轮换。
3. **完全离线 + 时钟操纵**在 Mode O 下可延长使用期至 `not_after`；需要更强保证请用 Mode E。
4. **浏览器环境的防护强度本质弱于原生**。Web 端的 SDK 是"提高门槛"，不是"等同原生"。
5. **私有套件泄露**会降低破解成本的不可复用性，但不导致凭证可伪造。
6. **guard 的运行时完整性校验可被移除**；其价值来自于结果参与 FK 派生，而非上报本身。

## 7. 红队演练场景（GA 前必做，见 `05-ops/testing-strategy.md`）

| 场景 | 通过标准 |
|---|---|
| RT-1：给出一个 Tauri 示例 App 与 MITM 代理，尝试伪造校验成功 | 无法在不拿到私钥的情况下让 App 进入 Active |
| RT-2：把 MC 从 A 机复制到 B 机 | B 机无法使用 |
| RT-3：替换 `copylocker.wasm` 为总是成功的 stub | Sealed Asset 无法解密 |
| RT-4：篡改 vite 产物中的一个 chunk | guard 检出 + FK 失效 |
| RT-5：系统时钟回拨 1 年 | 检测到并强制在线校验 |
| RT-6：并发 100 次激活同一 3 席位 License | 恰好 3 个成功 |
| RT-7：向所有端点发送畸形 CBOR / 超大 body / 深嵌套 | 无 panic、无 500、无资源耗尽 |
| RT-8：假设私有套件源码泄露，尝试伪造凭证 | 不可行 |
| RT-9：把 vN 的破解方法应用到 vN+1；并尝试用旧 `security_floor` 的凭证降级 | 两者都失败 |
| RT-10：谎报 `release_id`/`app_version` 以绕过版本范围封顶 | 拿不到新版本可用的 Feature Key |
