# 非功能需求（Non-Functional Requirements）

编号：`NFR-<域>-<序号>`。域：`SEC` 安全 / `PERF` 性能 / `REL` 可靠性 / `COST` 成本 /
`DX` 开发体验 / `OPS` 可运维 / `COMP` 合规 / `PORT` 可移植。

---

## SEC — 安全

| ID | 需求 | 验证方式 |
|---|---|---|
| NFR-SEC-001 | **Kerckhoffs 合规**：私有套件源码完整泄露后，系统仍不可伪造凭证；安全性降级至 CL-STD-1 等级 | 设计评审 + 红队推演 |
| NFR-SEC-002 | 客户端**永不**持有任何可用于签发凭证的密钥材料 | 代码审计 + 二进制 strings/熵扫描 CI 检查 |
| NFR-SEC-003 | 所有服务端签名操作使用 Epoch 私钥；Root 私钥仅在离线签名机上使用 | 密钥仪式记录 |
| NFR-SEC-004 | 所有密码学比较为常数时间；密钥内存 `Zeroize` | Clippy lint + 审计 |
| NFR-SEC-005 | 无 `unsafe` 代码（除 FFI 边界与经审计的 `copylocker-node`/`copylocker-ffi`），`#![forbid(unsafe_code)]` 覆盖核心 crate | CI 门禁 |
| NFR-SEC-006 | 依赖供应链：`cargo-deny`（license/advisory/bans）、`cargo-audit`、npm `--ignore-scripts` + lockfile 审查、SBOM（CycloneDX）随 release 发布 | CI 门禁 |
| NFR-SEC-007 | 发布产物可复现构建（Rust `--locked` + 固定 toolchain + `SOURCE_DATE_EPOCH`），并附 Sigstore 签名与 SLSA provenance | 第三方可复算 |
| NFR-SEC-008 | 凭证防重放：nonce + 时间窗 + 指纹绑定 + KEM 密封，四重 | 集成测试 |
| NFR-SEC-009 | 服务端拒绝任何客户端提供的时间戳作为判定依据 | 代码审计 + 测试 |
| NFR-SEC-010 | 模糊测试覆盖所有解析入口（凭证解码、CBOR、指纹字符串），CI 每日跑 `cargo-fuzz` | Nightly job |
| NFR-SEC-011 | 客户端二进制中不出现可被 grep 的显著特征字符串（如 `"license invalid"`）；错误码为数值 | 二进制扫描 |
| NFR-SEC-012 | 关键校验路径**内联并分散**（`#[inline(always)]` + 多点插桩），无单一 choke point | 反汇编抽查 |
| NFR-SEC-013 | 第三方安全审计：v1.0 GA 前完成一次针对密码学与协议的外部审计 | 审计报告 |
| NFR-SEC-014 | 漏洞响应：P0 漏洞 72 小时内出补丁，90 天协调披露 | SECURITY.md |
| NFR-SEC-015 | 服务端所有输入在解析前做长度与深度限制，防解析型 DoS | 单测 + fuzz |

## PERF — 性能

| ID | 指标 | 目标 |
|---|---|---|
| NFR-PERF-001 | 在线校验端到端 P50 / P95 | < 60ms / < 120ms（全球，不含客户端网络劣化） |
| NFR-PERF-002 | Worker 冷启动（含 WASM 实例化）P95 | < 50ms |
| NFR-PERF-003 | Worker WASM 体积（压缩后） | ≤ 1.5 MB |
| NFR-PERF-004 | 客户端本地凭证校验（含 ML-DSA-65 验签） | < 5ms（桌面）/ < 15ms（浏览器 WASM） |
| NFR-PERF-005 | 浏览器 WASM 核心体积（gzip / br） | ≤ 350 KB / ≤ 280 KB |
| NFR-PERF-006 | Web guard 首屏完整性校验对 LCP 的影响 | < 20ms（异步 + 空闲期执行，不阻塞渲染） |
| NFR-PERF-007 | 桌面 SDK 内存占用增量 | < 8 MB |
| NFR-PERF-008 | 单 `LicenseDO` 吞吐 | ≥ 200 req/s（远低于 CF 的 ~1000 软上限） |
| NFR-PERF-009 | 签名操作（服务端 ML-DSA-65 + Ed25519） | < 3ms CPU |
| NFR-PERF-010 | 客户端后台校验的网络开销 | 单次 < 8 KB 上行 + < 12 KB 下行 |

> 所有 PERF 指标在 M1/M3 建立基准，纳入 CI 回归门禁（超阈值 15% 即失败）。

## REL — 可靠性

| ID | 需求 |
|---|---|
| NFR-REL-001 | 服务端 SLO 99.9% 月可用；错误预算耗尽即冻结功能发布 |
| NFR-REL-002 | 服务端完全不可用时，Mode O 客户端在宽限期内不受影响；Mode E 在 `refresh+grace` 内不受影响 |
| NFR-REL-003 | 所有写操作幂等（`Idempotency-Key` 或自然幂等键） |
| NFR-REL-004 | DO → D1 投影用 outbox 模式，至少一次投递 + 幂等消费，最终一致延迟 P95 < 5s |
| NFR-REL-005 | 数据可恢复：DO SQLite PITR 30 天；D1 定期导出到 R2；审计日志不可变追加 |
| NFR-REL-006 | 客户端凭证存储双写（keychain + 加密文件），任一损坏可恢复 |
| NFR-REL-007 | 客户端升级不导致已有凭证失效（凭证格式向后兼容，版本协商） |
| NFR-REL-008 | 灰度：Worker 支持按百分比灰度发布与快速回滚（Cloudflare Versions & Gradual Deployments） |

## COST — 成本

| ID | 需求 |
|---|---|
| NFR-COST-001 | 10 万活跃设备 / 月（每设备每日 1 次校验）Cloudflare 账单 < $20 |
| NFR-COST-002 | 客户端校验请求可被 Cache/KV 短路的部分（公钥集、吊销 epoch）必须走边缘缓存，不进 DO |
| NFR-COST-003 | 审计与遥测走 Queue 批量落 R2，不走 D1 高频写 |
| NFR-COST-004 | 提供成本估算脚本 `copylocker-cli estimate --devices N --interval D` |

## DX — 开发体验

| ID | 需求 |
|---|---|
| NFR-DX-001 | 桌面端接入 ≤ 20 行代码；Web 端 ≤ 15 行 + 1 个 unplugin 配置 |
| NFR-DX-002 | 全部公开 API 有 rustdoc / TSDoc，且有可运行示例；`#![warn(missing_docs)]` |
| NFR-DX-003 | TS 类型由 Rust 类型自动生成（`ts-rs` 或 `specta`），杜绝两侧漂移 |
| NFR-DX-004 | 本地开发全链路可离线：`wrangler dev` + 本地 dev 密钥 + `copylocker-cli dev-license` |
| NFR-DX-005 | 错误信息对开发者可诊断（含错误码 + 文档链接），对终端用户可读且不泄露内部细节 |
| NFR-DX-006 | 提供 4 个可运行 example：tauri-app、electron-app、vite-spa、nextjs-app |
| NFR-DX-007 | 单条命令跑通全部测试：`just test` / `cargo xtask test` |
| NFR-DX-008 | 文档站（VitePress），含"5 分钟上手"、"安全强度分级指南"、"迁移指南" |

## OPS — 可运维

| ID | 需求 |
|---|---|
| NFR-OPS-001 | 结构化日志（JSON），敏感字段自动脱敏；接入 Workers Logs / Logpush |
| NFR-OPS-002 | 指标：激活/校验 QPS、成功率、延迟直方图、DO 存储量、席位使用率；可导出到 Analytics Engine |
| NFR-OPS-003 | 关键告警：签发失败率、Epoch 密钥剩余有效期 < 14 天、异常激活突增 |
| NFR-OPS-004 | 密钥轮换可在不中断服务下完成，客户端兼容窗口 ≥ 2 个 Epoch |
| NFR-OPS-005 | 提供 runbook：密钥泄露、大规模误吊销、D1 迁移失败、DO 热点 |
| NFR-OPS-006 | 所有 schema 迁移可回滚，且有 dry-run |

## COMP — 合规与隐私

| ID | 需求 |
|---|---|
| NFR-COMP-001 | 指纹只上报 HMAC 摘要，原始属性不出设备；属性清单公开 |
| NFR-COMP-002 | 支持数据删除请求（GDPR/CCPA），30 天内完成 |
| NFR-COMP-003 | 支持 Cloudflare Data Localization Suite 的区域约束配置指引 |
| NFR-COMP-004 | 提供隐私政策模板与 DPA 模板供 Vendor 复用 |
| NFR-COMP-005 | 密码学选型可出具 PQC 迁移说明（用于客户的合规问卷） |
| NFR-COMP-006 | 开源许可清晰：Apache-2.0 OR MIT；依赖许可通过 `cargo-deny` 白名单管控 |
| NFR-COMP-007 | **T0 分析零额外采集**：默认分析能力不引入任何超出授权协议必需的字段 |
| NFR-COMP-008 | **`legal-sync` CI 门禁**：采集字段 schema 单一来源 → 自动生成数据清单 → 不一致即失败 |
| NFR-COMP-009 | IP 地址仅用于限流，**不落库、不入分析** |
| NFR-COMP-010 | 唯一子处理者为 Cloudflare；**CopyLocker 项目方不接收任何终端用户数据** |
| NFR-COMP-011 | HLL 草图与 rollup 不含个人数据，DSR 删除不回溯修改（须写入隐私政策） |
| NFR-COMP-012 | 明确不具备且不会添加：跨应用追踪、广告定向、内容采集、精确定位、静默采集 |

## 授权模型与版本治理

| ID | 需求 |
|---|---|
| NFR-LIC-001 | 权益解析是纯函数，确定性、可 property test，行覆盖 ≥ 95% |
| NFR-LIC-002 | 所有支付 webhook 处理幂等，乱序到达按事件时间戳判定 |
| NFR-LIC-003 | MC 体积上限 8 KB（权益快照 + `wrapped_keks` + `preloaded_keks` 合计），CI 门禁 |
| NFR-LIC-004 | 配置预览器的输出与服务端实际行为**必须一致**（三方一致性测试） |
| NFR-VER-001 | 客户端升级**永不**因变体切换而要求用户重新输入 License Key |
| NFR-VER-002 | 历史 KAT 向量永久保留；`compat-matrix` 覆盖最近 4 个版本 |
| NFR-VER-003 | 版本级吊销的影响面 dry-run 必须在执行前给出精确设备数 |

## PORT — 可移植性

| ID | 需求 |
|---|---|
| NFR-PORT-001 | 核心 crate `no_std + alloc` 可用；`std` 为可选 feature |
| NFR-PORT-002 | 支持目标：`wasm32-unknown-unknown`、`x86_64/aarch64-{apple-darwin,pc-windows-msvc,unknown-linux-gnu,unknown-linux-musl}` |
| NFR-PORT-003 | 客户端最低支持：Windows 10、macOS 12、glibc 2.28 / musl；浏览器 Baseline 2023（支持 WASM + WebCrypto + IndexedDB） |
| NFR-PORT-004 | 服务端逻辑与 Cloudflare 解耦（`trait Storage`），理论上可移植到其他 Serverless（不承诺，但保持接口纯净） |
| NFR-PORT-005 | MSRV 明确声明并在 CI 验证；Node.js ≥ 20；Electron ≥ 30；Tauri ≥ 2.0 |
