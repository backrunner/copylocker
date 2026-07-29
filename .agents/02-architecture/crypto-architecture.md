# 密码学架构

## 1. 设计目标

1. **后量子起步**：签名与密钥封装默认 PQ/T 混合，今天签发的凭证在 CRQC 出现后仍不可伪造。
2. **算法敏捷**：算法是可替换实现，不是架构假设（ADR-0001）。
3. **Kerckhoffs 合规**：算法全公开也安全（NFR-SEC-001）。
4. **WASM 友好**：纯 Rust、`no_std + alloc`、无 C 依赖、体积可控。
5. **不自研原语**：只组合与参数化标准原语。

## 2. 槽位契约（`copylocker-suite`）

```rust
#![no_std]
extern crate alloc;

/// 4 字节套件标识，写入每个凭证头部，被签名/AAD 覆盖
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SuiteId(pub [u8; 4]);

pub trait SignatureScheme {
    type SigningKey: Zeroize;
    type VerifyingKey: Clone;
    const SIG_MAX_LEN: usize;
    const VK_LEN: usize;

    fn sign(sk: &Self::SigningKey, ctx: DomainCtx<'_>, msg: &[u8]) -> Result<Signature, CryptoError>;
    fn verify(vk: &Self::VerifyingKey, ctx: DomainCtx<'_>, msg: &[u8], sig: &Signature)
        -> Result<(), CryptoError>;
    fn security_level() -> SecurityLevel;
}

pub trait KeyEncapsulation {
    type DecapKey: Zeroize;
    type EncapKey: Clone;
    fn keygen(rng: &mut dyn CryptoRng) -> (Self::DecapKey, Self::EncapKey);
    fn encap(ek: &Self::EncapKey, rng: &mut dyn CryptoRng) -> (Ciphertext, SharedSecret);
    fn decap(dk: &Self::DecapKey, ct: &Ciphertext) -> Result<SharedSecret, CryptoError>;
}

pub trait AeadScheme {
    const KEY_LEN: usize; const NONCE_LEN: usize; const TAG_LEN: usize;
    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait KeyDerivation {
    fn extract(salt: &[u8], ikm: &[u8]) -> Prk;
    fn expand(prk: &Prk, info: &[u8], out: &mut [u8]) -> Result<(), CryptoError>;
}

pub trait HashScheme {
    const OUT_LEN: usize;
    fn hash(data: &[u8]) -> Digest;
    fn hasher() -> Self::Hasher;   // 流式
}

pub trait FingerprintScheme {
    /// 把设备属性规范化并生成摘要；salt 每 Vendor 独立
    fn compute(salt: &[u8], attrs: &DeviceAttrs) -> Fingerprint;
    /// 容差比较：返回匹配得分 0..=100
    fn similarity(a: &DeviceAttrs, b: &DeviceAttrs) -> u8;
}

/// 凭证的二进制编码（私有套件可完全私有化布局）
pub trait ArtifactCodec {
    fn encode<T: Artifact>(a: &T) -> Result<Vec<u8>, CodecError>;
    fn decode<T: Artifact>(b: &[u8]) -> Result<T, CodecError>;
}

/// 设备绑定变换：把指纹与环境证据混入密钥调度（私有化重点）
pub trait DeviceBinder {
    fn bind(secret: &SharedSecret, fp: &Fingerprint, env: &EnvEvidence) -> BoundSecret;
}

pub trait CryptoSuite: Send + Sync + 'static {
    const SUITE_ID: SuiteId;
    const PROTO_VER: u8;
    type Sig: SignatureScheme;
    type Kem: KeyEncapsulation;
    type Aead: AeadScheme;
    type Kdf: KeyDerivation;
    type Hash: HashScheme;
    type Fpr: FingerprintScheme;
    type Codec: ArtifactCodec;
    type Binder: DeviceBinder;

    fn with_vendor_params(p: &VendorParams) -> Self;
}
```

### 域分隔（Domain Separation）

所有签名与 KDF 调用必须携带域上下文，防止跨用途重放：

```
DomainCtx = "copylocker/v1/" ‖ <artifact_kind> ‖ 0x00 ‖ suite_id ‖ product_id
artifact_kind ∈ { "epoch-cert", "machine-cred", "validation-ticket",
                  "kill-order", "revocation-batch", "olk", "manifest", "ar",
                  "aresp", "validate-request", "heartbeat-request",
                  "deactivate-request" }
```

**规则**：新增任何被签名的工件都必须分配新的 `artifact_kind`。
`copylocker-suite-testkit` 含"跨域重放必失败"的自动化测试。

## 3. 开源参考套件 CL-STD-1

`SuiteId = 0x01_00_00_01`

| 槽位 | 算法 | 参数 | 库（初选） |
|---|---|---|---|
| Sig | **Hybrid(Ed25519, ML-DSA-65)** | PQ 128→192bit 级 | `ed25519-dalek` + `libcrux-ml-dsa` |
| Kem | **X-Wing (X25519 + ML-KEM-768)** | — | `x25519-dalek` + `ml-kem` |
| Aead | **XChaCha20-Poly1305** | 256bit key, 192bit nonce | `chacha20poly1305` |
| Kdf | **HKDF-SHA-512**；低熵输入 **Argon2id**(m=64MiB,t=3,p=1) | — | `hkdf`,`sha2`,`argon2` |
| Hash | **SHA-256**（协议）/ **BLAKE3**（清单、大文件） | — | `sha2`,`blake3` |
| Fpr | **HMAC-SHA-256** over 规范化属性 | — | `hmac` |
| Codec | 确定性 CBOR（RFC 8949 §4.2.1 canonical） | — | `minicbor` |
| Binder | `HKDF(shared ‖ fp ‖ H(env))` | — | — |

### 3.1 混合签名的构造

**不是简单拼接。** 使用与 IETF Composite ML-DSA 一致的思路：

```
M' = DomainSep ‖ len(ctx) ‖ ctx ‖ H(msg)          // 两个分量签同一个绑定后的消息
sig = len(sig_pq) ‖ sig_pq ‖ len(sig_trad) ‖ sig_trad
verify: ML-DSA.verify(M') == OK  AND  Ed25519.verify(M') == OK
```

**硬性要求（FR-CRY-004）**
- 两个分量都必须验证通过。任一失败 → 整体失败。
- **禁止**任何"降级到单分量"的代码路径。
- 若只有一个分量通过（说明有人在做剥离攻击），记录 `HYBRID_STRIP_DETECTED` 到审计。
- 长度前缀在签名消息 `M'` 之外，但整个 `sig` 结构在上层信封里被 AAD 覆盖。

### 3.2 X-Wing 而非自行拼接 KEM

使用已有规范的 X-Wing（X25519 + ML-KEM-768 的组合 KEM），
其组合器已有安全证明，避免自行设计 KEM combiner 的陷阱。
输出 32 字节 shared secret。

### 3.3 为什么 XChaCha20-Poly1305 而非 AES-GCM

- WASM 中无 AES-NI，ChaCha 显著更快且天然常数时间。
- 192-bit nonce 可安全随机生成，无需维护 nonce 计数器（我们有多设备/多实例场景）。
- AES-256-GCM 作为可选实现保留（`AeadScheme` 的另一实现），供有 FIPS 需求的 Vendor 选择。

## 4. 紧凑套件 CL-CMP-1（保留，未启用）

`SuiteId = 0x02_00_00_01` 仅作保留。M0 尽调确认 `fn-dsa 0.4.0` 在 FN-DSA 草案发布前
不保证 wire format 兼容，因此生产签发器当前不得发出该 SuiteId（ADR-0002 §2.2）。

| 槽位 | 算法 |
|---|---|
| Sig | **Hybrid(Ed25519, FN-DSA-512)** → 64 + 666 = 730 B + 长度前缀 |

尺寸预算（OLK 总长）：

```
header(8) + payload(CBOR ~180B) + sig(736B) + epoch_cert_ref(8) ≈ 932 B
Base32(Crockford) ≈ 1,492 字符  → 可复制粘贴 / 可存为 .clk 文件
gzip 后 ≈ 900 B → QR v40 (2953 B binary) 单码可容纳 ✅
```

**当前回退**：OLK 只走文件形态并使用 CL-STD-1。待标准、稳定实现和外审证据齐备后，
必须另写 ADR 才能启用 CL-CMP-1；届时仍只用于 OLK，并与 Ed25519 混合。

## 5. 密钥层级与生命周期

```
                    ┌─────────────────────────────────────────┐
                    │  Root Key Pair (Hybrid PQ/T)            │
                    │  · 离线签名机生成，永不联网              │
                    │  · 私钥：硬件密钥(FIDO2/YubiHSM) + Shamir│
                    │    3-of-5 纸质备份，异地保管             │
                    │  · 公钥：pin 进所有客户端（主 + 备双 pin）│
                    │  · 有效期 10 年                          │
                    └────────────────┬────────────────────────┘
                                     │ 签发 EpochCert
                    ┌────────────────▼────────────────────────┐
                    │  Epoch Key Pair (Hybrid PQ/T)           │
                    │  · 90 天有效，重叠期 14 天               │
                    │  · 私钥存 Cloudflare Secrets Store       │
                    │  · EpochCert = Sign_root(epoch_vk ‖      │
                    │      epoch_id ‖ not_before ‖ not_after ‖ │
                    │      suite_id ‖ product_scope)          │
                    └────────────────┬────────────────────────┘
                                     │ 签发
        ┌──────────────┬─────────────┼─────────────┬────────────────┐
        ▼              ▼             ▼             ▼                ▼
  MachineCredential  ValidationTicket  KillOrder  RevocationBatch  IntegrityManifest
```

### 5.1 客户端验证链

```rust
// 客户端必须完整验证，禁止跳过任何一步
verify_root_pin(epoch_cert.issuer_vk_digest)?;      // 必须命中 pinned root 之一
Sig::verify(root_vk, ctx("epoch-cert"), epoch_cert.tbs, epoch_cert.sig)?;
check_time_window(epoch_cert.not_before, epoch_cert.not_after, now)?;
check_epoch_not_revoked(epoch_cert.epoch_id, local_revocation_state)?;
Sig::verify(epoch_cert.vk, ctx("machine-cred"), mc.tbs, mc.sig)?;
```

### 5.2 Root 轮换（不砖化客户端）

客户端内置 **两个** root 公钥：`root_current` 与 `root_next`（预置）。
轮换流程见 `05-ops/security-operations.md`。要点：
- `root_next` 在客户端发布时就已内置，激活 `root_next` 只需服务端开始用它签 EpochCert。
- 老客户端（只认 `root_current`）在兼容窗口内仍收到 `root_current` 签的 EpochCert（双签发）。
- 兼容窗口 ≥ 2 个 Epoch（180 天）。

### 5.3 Epoch 密钥泄露的应对

1. Admin 触发 `revoke-epoch`，`revocation_epoch++`，把 `epoch_id` 加入吊销集。
2. 用 Root 签发新 Epoch（离线签名机，需人工仪式）。
3. 客户端在下次校验时收到新的吊销集 → 拒绝该 epoch 签的所有凭证 → 全部需重新校验。
4. 已离线的客户端在 `refresh_after` 后自然回来校验；Mode O 的最坏暴露窗口 = `refresh + grace`。

**这是为什么 `refresh_after` 不能设太长的核心理由**，需写进 Policy 配置文档。

## 6. Feature Key 派生（核心防护）

```
① CredentialSecret（服务端随机 32B，密封给设备）
   kem_ct, ss = KEM.Encap(device_ek)
   wrap_key   = KDF.derive_from("copylocker/cs-wrap/v1", ss,
                    [suite_id, product_id, license_id, machine_id])
   sealed_cs  = nonce(24) ‖ AEAD.seal(key=wrap_key,
                    aad=canonical(credential_seal_aad_v1), pt=CredentialSecret)

② 客户端解封
   ss           = KEM.Decap(device_dk, kem_ct)
   CredentialSecret = AEAD.open(...)                        // 换机则失败

③ 设备绑定
   BoundSecret  = Binder::bind(CredentialSecret, fp, env_evidence)
                  // CL-STD-1: HKDF(CredentialSecret ‖ fp ‖ H(env))
                  // CL-PRIV-1: 私有变换

④ 会话根（每次成功在线校验刷新）
   SessionRoot  = HKDF-Expand(BoundSecret,
                    info = "copylocker/sr/v1" ‖ vt.server_nonce ‖ vt.epoch_id
                         ‖ build_fingerprint ‖ module_digest)

⑤ 功能密钥
   FeatureKey(f) = KDF.derive_from("copylocker/fk/v1", SessionRoot,
                     [product_id, u64_be(variant_id), variant_const, f])
```

`env_evidence` / `module_digest` 的组成（按平台）：

| 平台 | 输入 |
|---|---|
| Tauri | 主二进制 `.text` 段摘要（或 code signature 摘要）、插件版本 |
| Electron | `.node` 文件摘要 + `app.asar` 摘要 |
| Web | WASM 二进制摘要 + IntegrityManifest 根摘要 + TS 侧构建期常量 |

**离线可用性设计**：`SessionRoot` 依赖 `vt.server_nonce`，但离线时没有 VT。
解决：MC 中包含一个 `offline_nonce`（签发时固定），离线路径用它派生
`SessionRoot_offline`；Sealed Asset 用**两个** SessionRoot 各封装一次 KEK
（或用 KEK 包装：`Enc(FK_online, KEK)` 与 `Enc(FK_offline, KEK)`），
使得在线/离线都能解出同一份资产 KEK。

```
资产加密：asset_ct = AEAD.seal(KEK_asset, ...)
KEK 包装： wrap_online  = nonce ‖ AEAD.seal(FeatureKey_online(f),
                                  aad=canonical(kek_wrap_aad_v1(kind=1)), KEK_asset)
          wrap_offline = nonce ‖ AEAD.seal(FeatureKey_offline(f),
                                  aad=canonical(kek_wrap_aad_v1(kind=0)), KEK_asset)
```

`credential_seal_aad_v1`、`kek_wrap_aad_v1` 的 CBOR key、KDF 的长度前缀和服务端静态密钥
存储格式由 [ADR-0013](../00-overview/decisions/ADR-0013-credential-sealing-and-kek-wrapping.md)
冻结。CL-STD-1 的 `sealed_cs` 和每条 wrapped KEK 均恰好为 72 字节。

## 7. 随机数

| 环境 | 来源 |
|---|---|
| Cloudflare Workers | `crypto.getRandomValues`（经 `worker` crate / `getrandom` 的 wasm 后端） |
| 桌面原生 | `getrandom`（OS CSPRNG） |
| 浏览器 | `crypto.getRandomValues` |
| 测试 | `ChaCha20Rng::seed_from_u64`，仅 `#[cfg(test)]` 与 CLI `--deterministic` |

**禁止**：任何形式的自研 PRNG；任何在生产路径可注入的确定性 RNG。

## 8. 常见陷阱与规避（实现须知）

| 陷阱 | 规避 |
|---|---|
| nonce 复用 | XChaCha 192-bit 随机 nonce；每次 seal 新随机；nonce 与密文一起存 |
| 签名可延展 / 剥离 | 混合签名两分量都验；长度前缀 + 域分隔；`suite_id` 进 AAD |
| 时序侧信道 | 全部用 `subtle::ConstantTimeEq`；服务端用 `crypto.subtle.verify` 语义等价路径 |
| 错误信息泄露 | 密码学错误统一为 `CryptoError::Invalid`，细节仅本地日志 |
| 密钥留在内存 | `ZeroizeOnDrop`；`Secret<T>` 包裹；禁止 `Debug`/`Clone` 派生 |
| CBOR 非确定性编码破坏签名 | 强制 canonical CBOR；签名对**编码后字节**而非结构体 |
| 时间比较用 `>` 而非 `>=` 的边界 bug | 统一 helper `TimeWindow::contains(now)`；属性测试 |
| PQ 库的 RNG 质量假设 | 显式传入 RNG，不用库默认；文档标注 |
| WASM 中 `getrandom` 未配置 | Cargo feature `getrandom/js` / `getrandom/custom` 明确配置并在 CI 校验 |

## 9. KAT 与测试向量

- 每个 Suite 必须提供 `vectors/<suite_id>/*.json`：密钥对、消息、期望签名/密文。
- 公开套件的向量公开；私有套件的向量在私有仓库。
- **跨语言/跨版本一致性**：服务端（wasm32）与客户端（native/wasm）跑同一套向量。
- 负向向量必须覆盖：单分量伪造、跨域重放、篡改 AAD、nonce 重放、过期时间窗、错误 suite_id。

## 10. 迁移路径（PQ 参数升级）

未来若需从 ML-DSA-65 升到 ML-DSA-87 或换算法：

1. 定义新 `SuiteId`（如 `0x01_00_00_02`）。
2. 服务端同时启用新旧套件；新签发用新套件，老凭证仍能验证。
3. 客户端发新版本，同时支持新旧套件验证。
4. 等待客户端渗透率达标（通过 `client_version` 遥测判断）。
5. Policy 提升 `min_security_level` → 强制续期时换发新套件凭证。
6. 停止签发旧套件；保留验证能力至所有旧凭证自然过期。

**全程无需改协议、无需改 API、无需砖化客户端。** 这就是槽位设计的回报。
