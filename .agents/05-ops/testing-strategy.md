# 测试策略

需求：全部 AC-*、NFR-SEC-010、NFR-PERF-*

## 1. 测试金字塔与责任

```
                    ┌──────────────┐
                    │  红队演练     │  GA 前，手工，RT-1~RT-8
                    ├──────────────┤
                    │  E2E          │  4 个示例应用，Playwright/WebDriver
                    ├──────────────┤
                    │  集成         │  wrangler dev + 真实 DO/D1，跨平台矩阵
                    ├──────────────┤
                    │  契约 / KAT   │  ★ 最重要：服务端与客户端的双向验证
                    ├──────────────┤
                    │  属性 / Fuzz  │  proptest + cargo-fuzz
                    ├──────────────┤
                    │  单元         │  纯逻辑，L1–L3 层 100% 可测
                    └──────────────┘
```

**核心设计使测试变容易**：`copylocker-core` 与 `copylocker-server-core` 无 I/O、无时间、无随机
→ 所有业务逻辑都可以在 native 上确定性地测试，不需要跑 Worker 或真实设备。

## 2. 单元测试

| 目标 | 内容 |
|---|---|
| 状态机 | **穷尽** (state × event) 组合的迁移断言；新增状态/事件时编译器强制补齐 |
| Clock Guard | 回拨 1s/1天/1年、前进 10 年、高水位被删除、单调时钟与墙钟不一致 |
| 指纹 | 规范化确定性、属性缺失的表示、相似度计算的边界 |
| 权益判定 | features 匹配、limits、version_range（semver） |
| 时间窗 | `TimeWindow::contains` 的边界（`>=` vs `>`） |
| 编解码 | 所有工件的往返；canonical CBOR 的字节级一致性 |
| 错误分类 | `TransientError` 与 `FatalError` 不可互转（编译期保证 + 测试） |

覆盖率目标：`copylocker-core`、`-server-core`、`-proto` 行覆盖 ≥ 90%，分支 ≥ 85%。
（不追求全仓库高覆盖 —— 平台适配层用集成测试覆盖更有意义。）

## 3. 属性测试（`proptest`）

关键不变式：

```rust
proptest! {
    /// 任意事件序列下，Locked/Revoked 后不经过成功的在线校验不能回到 Active
    #[test] fn no_resurrection_without_validation(evs: Vec<Event>) { ... }

    /// 任意事件序列下，剩余有效期不会因为墙钟回拨而增加
    #[test] fn rollback_never_extends(evs: Vec<Event>, clock_jumps: Vec<i64>) { ... }

    /// 席位数永不超卖（server-core 层，随机并发交错）
    #[test] fn seats_never_oversold(ops: Vec<ActivateOp>, seats: u8) { ... }

    /// revocation_epoch 单调：任意批次序列下本地 epoch 只增不减
    #[test] fn revocation_epoch_monotonic(batches: Vec<RevBatch>) { ... }

    /// 编解码往返：encode(decode(x)) == x 对所有合法字节串
    #[test] fn codec_roundtrip(a: Artifact) { ... }

    /// FeatureKey 确定性：相同输入必产生相同密钥
    #[test] fn fk_deterministic(cred: Credential, feature: String) { ... }
}
```

## 4. KAT / 契约测试（最重要的一层）

### 4.1 结构

```
vectors/
├── CL-STD-1/
│   └── kat.json               format 2，当前套件的完整固定向量
└── CL-CMP-1/ ...
```

`kat.json` format 2 是统一容器，包含 `signatures`、`kem`、`aead`、`kdf`、
`fingerprints`、`artifacts` 与 `chains` 七组向量。M0 的 CL-STD-1 固定文件共 40 条：

| 组 | 数量 | 内容 |
|---|---:|---|
| signatures | 16 | 10 个工件域的正向签名 + 6 个伪造/重放/篡改负向向量 |
| kem | 3 | X-Wing 正向、密文篡改、错误设备密钥 |
| aead | 4 | 正向、错误 AAD、错误密钥、标签篡改 |
| kdf | 3 | bind、session-root、feature-key |
| fingerprints | 1 | 全部属性类型的规范化摘要 |
| artifacts | 10 | 所有工件/请求的 canonical CBOR |
| chains | 3 | 完整正向链、未 pin Root、过期 EpochCert |

`copylocker kat check` 同时检查确定性生成结果未漂移；`copylocker kat verify` 独立回放
提交文件。历史版本发布后复制到 `vectors/history/<version>/`，只增不改。

### 4.2 双向契约

```
服务端签发 → 客户端验证    （服务端 CI 产出工件，客户端 CI 消费）
客户端构造 → 服务端解析    （AR、ValidateRequest）
```

用一个共享的 `vectors/` 目录 + 两侧的 CI job，任何一侧改了格式而另一侧没跟上 → CI 红。

### 4.3 负向向量（同等重要）

必须覆盖：
- [x] 混合签名单分量伪造（PQ 对、传统错 / 传统对、PQ 错）→ 必失败
- [x] 跨 `artifact_kind` 重放 → 必失败
- [x] 任意 AAD 字节变化 → 必失败（结构化 suite_id / 指纹场景仍待协议集成测试）
- [x] 过期的 EpochCert → 必失败
- [x] 未 pin 的 Root → 必失败
- [ ] nonce 不回显 → 必失败
- [ ] `revocation_epoch` 回退 → 必失败
- [ ] 错误的 `machine_id` → 必失败
- [ ] 非 canonical CBOR 编码 → 必失败（否则签名可延展）
- [ ] 深度/长度超限 → 必失败且不 panic

### 4.4 Suite 一致性测试（`copylocker-suite-testkit`）

任何 Suite（含私有套件）必须通过：

```rust
copylocker_suite_testkit::assert_conformant::<MySuite>();
// 覆盖签名、KEM、AEAD、KDF、Hash、指纹与设备绑定器的正向/负向契约。
```

固定字节与跨版本一致性由 `kat.json` 回放承担；畸形输入由 fuzz target 承担。常数时间统计
检验和 Zeroize 内存扫描尚未进入公开 testkit，不把上游实现声明当作本地测试证据。

## 5. Fuzz（`cargo-fuzz`）

| Target | 输入 |
|---|---|
| `fuzz_decode_cbor` | 任意字节 → 有界 canonical CBOR 解析 |
| `fuzz_decode_envelope` | 任意字节 → 信封解析 |
| `fuzz_decode_artifacts` | 任意字节分别尝试解析全部 10 种工件/请求 |
| `fuzz_license_key_parse` | 任意字符串 → LK 解析 |

M1 增加 `fuzz_core_handle`、`fuzz_server_activate`、`fuzz_server_validate`；私有仓库增加
`fuzz_priv_codec`。

- scheduled CI 对上述每个现有 target 跑 4 小时；PR 上各跑 1 分钟 smoke。
- 2026-07-27 已完成四个 target 各 10 秒的本地 smoke，无崩溃；M0 的“4h 无崩溃”
  验收项仍需一次成功的 scheduled workflow 运行记录，不能用 smoke 替代。
- 语料库持久化到 R2 尚未实现。
- 断言：无 panic、无 OOM、无无限循环。

本地复现单个 target：

```bash
cd fuzz
cargo +nightly fuzz run fuzz_decode_artifacts -- -max_total_time=60 -max_len=65536
```

## 6. 集成测试

### 6.1 服务端

```
wrangler dev（本地 DO/D1/KV/R2/Queues）
  + Vitest（@cloudflare/vitest-pool-workers）
```

| 场景 | 断言 |
|---|---|
| 完整激活流程 | 返回可验证的 MC |
| 100 并发激活 3 席位 | 恰好 3 成功（AC-10） |
| 幂等重试 | 同 Idempotency-Key 重试不占新席位 |
| 吊销传播 | 吊销后下次 validate 返回 KillOrder（AC-4） |
| nonce 重放 | 同 nonce 二次提交被拒 |
| 限流 | 超限返回 1005 |
| 僵尸回收 | 心跳超时后席位被 alarm 释放 |
| 投影同步 | DO 变更后 5s 内 D1 一致 |
| 混沌 | 注入 D1/KV 失败 → 返回 5xx（客户端 fail-open），不返回错误的"无效" |
| 畸形输入 | 所有端点收到垃圾字节 → 4xx，无 500（RT-7） |
| 错误不泄露 | "key 不存在" 与 "key 已用尽" 的响应不可区分（差分测试） |

### 6.2 客户端跨平台

CI 矩阵：`macos-latest`、`windows-latest`、`ubuntu-latest`（+ musl 容器）

| 场景 | 断言 |
|---|---|
| 激活 → 重启 → 仍 Active | 存储正确持久化 |
| keychain 不可用 | 回退到文件，功能正常 |
| 删除文件保留 keychain（与反之） | 恢复成功且时钟高水位不被重置 |
| 复制存储到另一指纹环境 | 失败（AC-6） |
| 断网 grace | 可用至 grace 结束（AC-2） |
| 恢复网络 | 60s 内自动校验（AC-3） |
| 时钟回拨 | 检出且不延长（AC-9） |
| evidence 确定性 | 同机 10 次采集结果一致（R-08） |
| evidence 采集失败 | 降级不锁定用户 |

### 6.3 Web

| 场景 | 断言 |
|---|---|
| Playwright × Chrome/Firefox/WebKit | 激活 → unseal → 断网 → 恢复 |
| 替换 WASM 为 stub | unseal 失败（AC-8 / RT-3） |
| 篡改 chunk 一字节 | `R` 变化 → unseal 失败（AC-7 / RT-4） |
| 删除 guard 调用 | unseal 失败 |
| 覆写 `Function.prototype.toString` | 检出 |
| 清空 IndexedDB | 优雅进入 Unlicensed，提示重新激活 |
| 多浏览器 `R` 一致 | **同一产物在三个引擎上摘要必须一致**（R-04） |
| CSP 严格模式 | 可运行（含 `wasm-unsafe-eval`） |
| SSR (Next.js) | 服务端渲染不报错，hydrate 后初始化 |
| 6 个打包器 | 各自构建产物都能通过运行时校验 |

## 7. 性能与体积门禁

| 指标 | 工具 | 阈值 | 失败动作 |
|---|---|---|---|
| Worker WASM 体积 | `wc -c` on gzip | 1.5 MB | CI 失败 |
| M0 完整链 verifier WASM | `scripts/check-wasm-size.sh` | 300 KiB gzip | CI 失败 |
| 完整客户端 WASM（M3） | `wc -c` on gzip | 350 KB gzip | CI 失败 |
| Worker 冷启动 | 部署到 preview + 探测 | P95 50ms | 告警 |
| 校验端到端 | 分布式探测（多区域） | P95 120ms | 告警 |
| 本地验签 | release harness | 5ms(native) / 15ms(wasm) | CI 失败 |
| 签名 | release harness | 3ms | CI 失败 |
| LCP 影响 | Lighthouse CI | +20ms | CI 失败 |
| 内存增量 | 集成测试测量 | 8 MB | 告警 |

基准随 M0/M1/M3 分阶段建立并纳入 CI。M0 先执行上述绝对门限；有稳定的多次 CI 样本后，
再增加相对基线回归 15% 门限，避免用单次共享 runner 噪声伪造精度。

### 7.1 M0 基线（2026-07-27，Apple M4）

| 测量 | 结果 | 门禁 |
|---|---:|---:|
| Hybrid sign（native release，平均） | 1.803 ms | ≤ 3 ms |
| Hybrid verify（native release，平均） | 0.241 ms | ≤ 5 ms |
| X-Wing keygen / encap / decap（平均） | 0.145 / 0.199 / 0.542 ms | 记录基线 |
| Root → Epoch → MC（Node + Wasm，平均 / P95） | 1.006 / 1.197 ms | P95 ≤ 15 ms |
| 同一路径 Wasm 体积（raw / gzip） | 170,243 / 71,974 B | gzip ≤ 307,200 B |

Wasm harness 执行真实 Root → Epoch → MachineCredential 链验证，不是空导出或算法 stub。
复现命令：

```bash
cargo bench --locked -p copylocker-suite-std --bench pq
bash scripts/check-wasm-size.sh
node scripts/bench-wasm-verifier.mjs
```

### 7.2 M1 Worker 基线（2026-07-28，Apple M4）

`scripts/check-worker-wasm-size.sh` 使用 `worker-build --profile worker-release` 构建实际部署的
`build/index_bg.wasm`，再以 `gzip -9 -n` 测量。门限固定为 1,500,000 B（NFR-PERF-003）；
raw 体积仅作诊断，不作为该压缩后指标的失败条件。CI 同时运行 Workerd 集成测试和此门禁。
`scripts/check-worker-startup.mjs` 复用一个 release upload bundle，通过
`wrangler check startup` 启动 20 个独立本地 profiler，按 nearest-rank 计算 P95 并执行
`< 50 ms` 回归门禁。由于本机 CPU 与 Cloudflare edge 不等价，preview 探测仍是发布验收门禁。

复现命令：

```bash
cd crates/copylocker-worker
npm test
npm run size
npm run startup
```

## 8. 红队演练（GA 门禁）

见 [`threat-model.md` §7](../02-architecture/threat-model.md)。执行方式：

- **内部红队**：由未参与实现的工程师执行，给定 3 天时间与完整源码（模拟私有套件泄露）。
- **外部审计**：委托第三方做密码学与协议审计（NFR-SEC-013）。
- **交付物**：每个场景的尝试记录、成功/失败、发现的问题、修复验证。

| 场景 | 通过标准 | 状态 |
|---|---|---|
| RT-1 MITM 伪造校验成功 | 无法在无私钥情况下进入 Active | ☐ |
| RT-2 MC 跨机复制 | B 机不可用 | ☐ |
| RT-3 WASM stub 替换 | Sealed Asset 解不开 | ☐ |
| RT-4 篡改单个 chunk | guard 检出 + FK 失效 | ☐ |
| RT-5 时钟回拨 1 年 | 检出 + 强制在线 | ☐ |
| RT-6 并发超席位激活 | 恰好 N 个成功 | ☐ |
| RT-7 畸形输入轰炸 | 无 panic/500/资源耗尽 | ☐ |
| RT-8 假设私有套件泄露 | 无法伪造凭证 | ☐ |
| RT-9 跨版本复用破解 + `security_floor` 降级 | 两者都失败 | ☐ |
| RT-10 谎报 `release_id` 绕过版本封顶 | 拿不到新版本可用的 Feature Key | ☐ |

**额外声明**：红队**不需要**证明"无法破解单个客户端"——那是已知可行的（`threat-model.md` §6）。
红队的目标是验证**密码学与协议层面**没有捷径，以及**通用化破解**不可行。

## 8.5 授权模型、变体、分析、控制台的专项测试

### 授权模型（ADR-0009）

| 测试 | 断言 |
|---|---|
| 权益解析确定性 | 同目录+规格+时间 → 字节级相同的 `ResolvedEntitlements` |
| 循环引用 / glob / limits 合并 | 检出不栈溢出；glob 展开正确不下发通配；`max`/`sum`/`override` 边界正确 |
| Feature 不可变护栏 | 重命名/删除已发布 feature → CLI 与 API 均拒绝 |
| 订阅状态机 | 全部转换 × webhook 重放 3 次 × 乱序到达 → 幂等 |
| dunning | `current_period_end` 到点但在宽限内 → 仍可用 |
| 永久回退 | 达阈值 earned；中断清零；退款可撤销；`fallback_earned_at` 不被二次写入 |
| 版本范围边界 | `ReleasedBefore` 恰好等于 cutoff 的 release 的归属 |
| Trial 防滥用 | 同指纹二次申请被拒；容差范围内的指纹变化仍被拒 |
| 预设 | 11 个预设各自通过 simulator 场景断言 |
| 支付 webhook | Stripe/Paddle/Lemon Squeezy 原始字节验签；三次重放幂等；旧事件不回滚；dunning/取消/退款定时收敛 |

### 变体与版本（ADR-0008）— `compat-matrix` CI

保留最近 4 个发布版本的客户端产物，交叉测试：

| 测试 | 断言 |
|---|---|
| 旧客户端 × 新服务端 | 激活与校验成功 |
| 新客户端 × 旧 variant 凭证 | 能读存储、能验签、re-wrap 后可用 |
| **跨 variant 存储读写** | `copylocker-store` 的 blob 在任意 variant 间可读 |
| 跨 4 个版本连续升级 | 每步都无需重新输入 Key |
| 离线升级 `require_online` / `preload_n` | 前者进 `NeedsRevalidation` 后自动恢复；后者 N 个版本内直接可用 |
| `security_floor` 回滚 | 低 floor 凭证 → `FatalError::SecurityFloorRollback` |
| Release compromised | `force_upgrade` 拒新激活、已有设备到期前不受影响 |
| 未注册 release | 返回 `1007` 且错误含注册命令 |

历史 KAT 向量**永久保留**于 `vectors/history/<version>/` —— 这是唯一能保证
"我们没有悄悄破坏老客户端"的手段。

### 分析与遥测（ADR-0007）

| 测试 | 断言 |
|---|---|
| 口径一致性 | 精确路径 vs HLL 路径误差 ≤ ±1% |
| Rollup 幂等 / HLL 合并 | 重跑某日结果不变；日草图合并 = 直接对窗口计算 |
| k-匿名 | < 5 的桶被抑制为 `<5` |
| 分辨率提示 | `refresh_after=7d` 时日粒度查询返回警告标记 |
| 遥测投毒 | `session_count = 10^9` → 裁剪 + 计入异常，只影响该设备 |
| 无同意 | `consent_version = 0` → 服务端丢弃并计数 |
| SDK 防呆 | `tier:'T1'` 无 `consent` → 初始化报错；未白名单 feature → 开发模式抛错 |
| 盲区标记 | OLK 类 License 的响应含"安装数不可观测"标记 |
| **`legal-sync` 门禁** | 新增采集字段而未同步数据清单 → CI 失败 |

### 控制台（ADR-0010）

| 测试 | 断言 |
|---|---|
| E2E 主流程 | 签发 → 激活（模拟客户端）→ 查看设备 → 吊销 → 验证生效 |
| E2E 目录 | 编辑目录 → 保存 → 新签发凭证含新权益 |
| **Simulator 三方一致** | 控制台输出 = CLI 输出 = 服务端实际行为 |
| E2E 离线门户 | 上传 AR → 下载 AResp → 客户端导入成功 |
| 护栏 | 已发布 feature 的改名/删除按钮禁用；高危操作无二次确认不执行 |
| 权限矩阵 | 每个 scope × 每个页面/操作 |
| 可访问性 | axe 无 critical/serious；键盘全流程 |
| 视觉回归 | 关键页面截图对比（明暗双主题） |
| 安全 | CSP `script-src 'self'` 生效；无 localStorage/IndexedDB 写入 |

## 9. 可用性测试（DX 验证）

M2 与 M3 各做一次：

- 找 2–3 名**外部**开发者（未参与项目），给他们文档与脚手架。
- 计时：从零到完成一次成功激活。
- 目标：≤ 30 分钟（AC-1），桌面 ≤ 20 行代码，Web ≤ 15 行 + 1 个配置。
- 记录卡点，据此改文档与 API。

## 10. 发布前检查清单

- [ ] 全部 CI job 绿（含 nightly fuzz 无新崩溃）
- [ ] 全部 KAT 正向 + 负向通过
- [ ] 性能与体积门禁通过
- [ ] 跨平台矩阵通过
- [ ] 多浏览器 `R` 一致性通过
- [ ] 可复现构建验证（两次独立构建字节一致）
- [ ] SBOM 生成、Sigstore 签名、npm provenance
- [ ] `cargo-deny` / `cargo-audit` / npm audit 无 High+
- [ ] 二进制熵扫描：无私钥常量、无可 grep 的授权相关字符串
- [ ] CHANGELOG 与迁移说明完整
- [ ] 灰度计划就绪（1% → 10% → 100%）
- [ ] 回滚方案验证过
