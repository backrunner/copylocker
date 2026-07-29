# ADR-0002：后量子算法选型

- **状态**：Accepted
- **日期**：2026-07-26
- **M0 尽调复核**：2026-07-27
- **相关**：ADR-0001、ADR-0003、`02-architecture/crypto-architecture.md`

## 背景

需求要求默认实现用到后量子加密。License 系统的密码学需求有三类：

1. **签名**（服务端签、客户端验）：MachineCredential、ValidationTicket、RevocationBatch、IntegrityManifest、OfflineLicenseKey
2. **密钥封装/机密性**：把凭证密封给特定设备；客户端 → 服务端的敏感字段
3. **对称加密与派生**：本地存储加密、Feature Key 派生、Sealed Asset

关键约束：
- 客户端要跑在 **wasm32-unknown-unknown**（浏览器 + Cloudflare Workers）以及桌面原生，要求 `no_std` 友好、无 C 依赖最佳。
- **签名尺寸**直接决定 UX：ML-DSA-44 签名 2420 字节，ML-DSA-65 为 3309 字节，FN-DSA-512 仅 666 字节。
- 服务端在 Workers 上有 CPU 时间限制，签名操作要快。

## 决策

### 2.1 默认开源套件 CL-STD-1

| 槽位 | 算法 | 理由 |
|---|---|---|
| 签名 | **PQ/T 混合：Ed25519 + ML-DSA-65**（复合，域分隔，两者都必须验证通过） | ML-DSA 是 FIPS 204 定稿标准；混合 Ed25519 保证「不劣于经典方案」，抵御 PQ 实现 bug 与格密码分析进展 |
| KEM | **X-Wing（X25519 + ML-KEM-768）** | 使用规范实现及其 RFC KAT，不在项目内自行实现组合器；ML-KEM 是 FIPS 203 |
| AEAD | **XChaCha20-Poly1305** | 无需硬件 AES 也快（WASM 场景关键）；24 字节 nonce 可随机生成，规避 nonce 复用 |
| KDF | **HKDF-SHA-512**；口令/低熵材料用 **Argon2id** | 标准、可审计 |
| Hash | **SHA-256**（协议/兼容）+ **BLAKE3**（大文件/清单摘要，可并行） | — |
| 指纹 | **HMAC-SHA-256** over 规范化属性 | 便于服务端复算与匿名化 |

### 2.2 紧凑套件 CL-CMP-1（保留，暂不启用）

| 槽位 | 算法 |
|---|---|
| 签名 | 候选：**FN-DSA-512（Falcon-512）**；尚未冻结 wire format |

理由：自含签名的离线密钥需要能被复制粘贴/扫码。666 字节 → Base32 约 1066 字符，勉强可用；
ML-DSA-65 的 3309 字节 → 约 5300 字符，只能走文件。**FN-DSA 的签名端实现难点（浮点常数时间）
只影响服务端**，而服务端在我们自己受控的环境（且可用离线签名机），客户端只做验证（简单且无秘密）。

**M0 结论**：`fn-dsa 0.4.0` 上游在 2026-07-22 仍明确说明 FN-DSA 草案尚未发布，
当前实现只是对未来草案的“best guess”，并且 1.0 前不承诺密钥或签名字节兼容。
许可证凭证必须长期可验证，不能冻结在这种不稳定格式上。因此：

- `0x02_00_00_01` 仅保留，不得由生产签发器发出；
- M5 的 OLK 先使用 **CL-STD-1 + 文件形态**；不承诺可复制文本或单 QR；
- 只有在 FN-DSA 标准发布、Rust 实现提供稳定 wire format，且完成独立审计或项目外审后，
  才能用新 ADR 启用 CL-CMP-1；
- 若未来启用，仍只用于 OLK，并与 Ed25519 混合。

### 2.3 私有套件 CL-PRIV-1

见 [`03-modules/80-private-suite.md`](../../03-modules/80-private-suite.md)。原则：
使用**相同或更高强度的标准原语**（默认 ML-DSA-87 + ML-KEM-1024 + 混合），
私有化的是**组合方式、域分隔、编码布局、设备绑定变换、厂商参数化**。

## 备选方案与否决理由

| 方案 | 否决 |
|---|---|
| 纯 ML-DSA（不混合） | 格密码分析仍在演进；实现 bug 风险；多地监管建议混合 |
| SLH-DSA / SPHINCS+ | 签名 7856–49856 字节，尺寸完全不可接受 |
| 纯 Ed25519 | 不满足后量子要求 |
| RSA | 尺寸大、PQ 不安全、无收益 |
| liboqs（C 绑定） | 引入 C 依赖，wasm32-unknown-unknown 与 `no_std` 上摩擦大；纯 Rust 生态已足够 |
| 自研 PQ 算法 | 绝对禁止 |

## M0 实现库尽调与定稿

锁文件与实现以以下版本为准。`cargo audit`/`cargo deny` 通过只说明没有已知公告或策略违规，
**不等于密码实现经过独立审计**。

| 用途 | 定稿实现 | 标准与上游测试 | 可移植性 | 独立审计状态 | M0 结论 |
|---|---|---|---|---|---|
| ML-DSA | RustCrypto `ml-dsa 0.1.1` | FIPS 204 final；NIST ACVP keygen/sign/verify；Wycheproof | 纯 Rust、`#![no_std]`、MSRV 1.85；44/65/87 参数集均通过公开 testkit | **上游明确：从未独立审计** | 接受用于 CL-STD-1；必须保持 Ed25519 混合、固定 KAT，GA 前外审 |
| X-Wing | RustCrypto `x-wing 0.1.0`，间接使用 `ml-kem 0.3.2` + `x25519-dalek 3.0.0` | X-Wing draft 06 RFC KAT；其测试向量与 2026-07-27 的 draft 10 向量 JSON 语义相同；ML-KEM 为 FIPS 203 final，含 ACVP + Wycheproof | 全部纯 Rust、`no_std`；MSRV 1.85 | `x-wing` 与 `ml-kem` **均明确未独立审计** | 用上游组合器替代本地组合代码；固定 KAT；GA 前外审 |
| Ed25519 | `ed25519-dalek 3.0.0` | RFC 8032 生态实现 | 纯 Rust、`no_std` | 不把经典分量当作 PQ 安全来源 | 与 ML-DSA 两分量均须通过 |
| FN-DSA | 仅评估 `fn-dsa 0.4.0`，未加入锁文件 | 尚无 FN-DSA 草案；上游称实现为 best guess | 纯 Rust、`no_std`、MSRV 1.82 | 未形成可冻结标准/审计证据 | **不启用**；使用 CL-STD-1 文件回退 |
| AEAD/KDF/Hash | `chacha20poly1305 0.11`、`hkdf 0.13`、`sha2 0.11`、`blake3 1.8`、`argon2 0.6.0-rc.8` | 各自标准/上游向量 + CopyLocker KAT | native 与 wasm32 `no_std` 构建通过 | 随 GA 密码协议外审一并复核 | 接受 |

选择 RustCrypto `ml-dsa` 而非初始候选 `libcrux-ml-dsa`，是因为当前锁定版本已经满足三套参数、
`no_std`、ACVP/Wycheproof 与统一 trait 生态，且实际 KAT/体积/性能均通过。这里不声称它比
`libcrux` 更安全；若后续外审或公告要求替换，必须分配新 `SuiteId` 并保留旧套件验证能力。

### 可复现实测（Apple M4，Rust 1.96.0，release，2026-07-27）

| 检查 | 结果 | 门限/结论 |
|---|---:|---|
| Hybrid Ed25519 + ML-DSA-65 签名 | 1.803 ms/op | < 3 ms，通过 |
| Hybrid 验签 | 0.241 ms/op | < 5 ms，通过 |
| X-Wing keygen / encap / decap | 0.145 / 0.199 / 0.542 ms/op | 记录基线 |
| Root → Epoch → MC 的 wasm32 完整链验证 | avg 1.006 ms，P95 1.197 ms | < 15 ms，通过 |
| 同一 Wasm 验证路径体积 | 170,243 B raw；71,974 B gzip | ≤ 300 KiB gzip，通过 |
| native + wasm32 `no_std` | 均编译通过 | NFR-PORT-001/002 通过 |

复现命令和 CI 门禁见 `05-ops/testing-strategy.md §7`。Wasm 体积数字仅证明 M0 的
**证书链验证路径**；M3 加入浏览器状态机、KEM 解封和 JS glue 后仍须单独满足 350 KB 门限。

## 后果

- M0 验证路径实测为 71,974 B gzip；M3 完整浏览器核心继续受 350 KB gzip / 280 KB br 门限约束。
- 本机混合签名实测 1.803 ms，满足 3 ms 目标；Worker 环境仍须在 M1 preview 上单独测量。
- 上游未独立审计是已知风险，不得被 KAT、fuzz、`cargo audit` 或混合方案掩盖；
  NFR-SEC-013 的外部审计仍是 GA 硬门禁。
- 所有算法都有纯 Rust 实现 → 服务端 workers-rs（wasm32）与客户端共用同一份代码。
