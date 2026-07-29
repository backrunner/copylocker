# 模块：闭源私有算法套件（CL-PRIV-*）

> 本文档**公开**（因为它只描述接口契约与设计原则）。
> 具体参数、常量、变换细节在私有仓库 `copylocker-suite-priv/docs/` 中。

需求：FR-CRY-008、NFR-SEC-001、ADR-0001、`00-overview/open-closed-boundary.md`

## 1. 目的与红线

### 目的
制造**成本不对称**：使得针对 CopyLocker 开源版的通用破解工具，无法直接用于使用私有套件的厂商。

### 红线（每次评审必查）
> **假设 `copylocker-suite-priv` 的完整源码今天被公开，系统是否仍然安全？**
> 答案必须是「是 —— 安全性降级为 CL-STD-1 的等级，凭证仍不可伪造」。

因此：
- ✅ 私有化的是**组合方式、参数、编码、绑定变换、探针**
- ❌ 绝不自研密码学原语
- ❌ 绝不让任何机密性/完整性属性依赖算法保密

## 2. 实现契约

`CL-PRIV-1` 只需实现 `copylocker-suite` 的公开 trait 族：

```rust
pub struct ClPriv1 { params: VendorParams }

impl CryptoSuite for ClPriv1 {
    const SUITE_ID: SuiteId = SuiteId([0x80, 0x00, 0x00, 0x01]);   // 高位=1 表示私有
    const PROTO_VER: u8 = 1;
    type Sig   = PrivHybridSig;      // 见 §3.1
    type Kem   = PrivHybridKem;      // 见 §3.2
    type Aead  = PrivAead;
    type Kdf   = PrivKdf;
    type Hash  = PrivHash;
    type Fpr   = PrivFingerprint;    // 见 §3.4
    type Codec = PrivCodec;          // 见 §3.3
    type Binder = PrivBinder;        // 见 §3.5
    fn with_vendor_params(p: &VendorParams) -> Self { Self { params: p.clone() } }
}
```

**必须通过** `copylocker-suite-testkit` 的全部一致性测试（公开的测试套件）：
- 签名/验证往返、跨域重放必失败、篡改必失败
- KEM encap/decap 往返、错误密文必失败
- AEAD 往返、AAD 篡改必失败、nonce 复用检测
- Codec 往返、畸形输入不 panic、深度/长度限制生效
- Fingerprint 确定性、规范化一致性
- 常数时间性质（`dudect` 风格统计检验）

## 3. 私有化的具体维度（设计纲要）

### 3.1 签名（`PrivHybridSig`）

| 维度 | CL-STD-1 | CL-PRIV-1 |
|---|---|---|
| PQ 算法 | ML-DSA-65 | **ML-DSA-87**（更高安全等级） |
| 传统算法 | Ed25519 | Ed25519（不变，已足够） |
| 消息绑定 `M'` 的构造 | 公开的域分隔字符串 | **厂商专属的域分隔构造**，含由 vendor seed 派生的常量 |
| 分量顺序与编码 | 长度前缀顺序拼接 | **交错/掩码编码**（不改变安全性，改变字节形态） |
| 上下文注入 | ctx 追加 | ctx 参与 PQ 的 context string（FIPS 204 支持 ctx 参数） |

> ML-DSA 的 FIPS 204 定义了可选的 context string —— 用厂商专属 ctx 是**标准内**的做法，
> 不是自创构造，风险可控。

### 3.2 KEM（`PrivHybridKem`）

| 维度 | CL-STD-1 | CL-PRIV-1 |
|---|---|---|
| 组合 | X-Wing (X25519 + ML-KEM-768) | X25519 + **ML-KEM-1024** |
| Combiner | X-Wing 规范 | **X-Wing 结构 + 厂商专属 label**（保持结构，换 label） |

### 3.3 编码（`PrivCodec`）

这是私有化收益最大、风险最低的维度 —— **纯格式，不承担安全性**。

- 字段顺序按 vendor seed 打乱（确定性排列）
- 字段 tag 重映射
- 长度字段用变长编码 + 掩码（`len ^ KDF(seed, offset)`）
- 结构中插入确定性的伪随机填充（长度由 seed 决定）
- 整体外层再套一层由 `KDF(vendor_seed, "codec-mask")` 派生的流掩码

**效果**：现成的 CBOR 解析器无法直接看懂凭证；逆向者必须先还原编码规则。
**安全声明**：这是 **obfuscation**，认证与机密性完全由下层 AEAD/签名提供。

### 3.4 指纹（`PrivFingerprint`）

- **属性集合不同**：加入 CL-STD-1 不采集的属性（各平台差异化，详见私有文档）
- **权重与规范化不同**：厂商专属
- **摘要构造**：`HMAC(vendor_salt, PrivCodec(attrs))` —— 与编码私有化叠加
- 容差算法：厂商可调的加权 + 阈值曲线

### 3.5 设备绑定（`PrivBinder`）★ 私有化重点

这是最有价值的私有化维度：把设备指纹与环境证据**深度混入密钥调度**。

```rust
// CL-STD-1（公开、简单）
fn bind(secret, fp, env) -> HKDF(secret ‖ fp ‖ H(env), "cl-bind/v1")

// CL-PRIV-1（结构公开、参数私有）
fn bind(secret, fp, env) -> {
    // 多轮：每轮用不同的 vendor 派生常量，混入指纹的不同切片与环境证据
    // 轮数、切片方式、常量表 由 vendor_seed 派生
    // 底层仍然只用 HKDF/HMAC/SHA-2 —— 不自创原语
}
```

**效果**：即使攻击者拿到了 `CredentialSecret`（例如通过内存 dump），
在另一台设备上也需要复现**该厂商专属**的绑定变换才能派生出正确的 FeatureKey。
对通用工具而言这是逐厂商的额外工作量。

### 3.6 环境探针（`EnvEvidence` 的私有实现）

- 反调试检测（各平台）、VM/沙箱检测、hook 检测（IAT/PLT/inline hook）、
  时间异常检测（指令级计时）
- 探针结果**混入 `env_evidence`**，而非"检测到调试器就退出"
- **纪律**：探针失败（无法采集）必须降级为固定值，不能导致误伤；
  探针命中（检测到调试器）导致的是**派生出不同的密钥**，而非崩溃

## 4. 厂商参数化（`copylocker-suite-priv-gen`）

```
vendor_seed (256 bit, 每个 Vendor 唯一, 由我们生成并交付)
        │
        ├─ HKDF → domain_constants[]      签名/KDF 的域分隔常量
        ├─ HKDF → codec_permutation       字段顺序与 tag 映射
        ├─ HKDF → codec_mask_key          编码掩码
        ├─ HKDF → binder_schedule         绑定变换的轮数与切片方案
        ├─ HKDF → fpr_attr_weights        指纹属性权重
        └─ HKDF → probe_config            探针配置
```

- `vendor_seed` 在**构建期**通过 `build.rs` 编入客户端与服务端（不在运行时读取配置）。
- 交付形式：加密的 `.clvendor` 文件 + 解密口令（分渠道交付）。
- **`vendor_seed` 不是密钥**：泄露它只是让该厂商退化到"私有套件已知"的状态，
  不影响凭证不可伪造性（红线保证）。

## 5. 私有仓库的工程要求

| 要求 | 说明 |
|---|---|
| 依赖方向 | 只依赖 `copylocker-suite` + `copylocker-types` + 标准原语 crate |
| 测试 | 必须跑公开的 `copylocker-suite-testkit` 全绿 |
| KAT | 私有向量在私有仓库；CI 验证跨版本一致性（**格式变更 = 已签发凭证失效**，需极度谨慎） |
| 常数时间 | `dudect` 统计检验纳入 CI |
| Fuzz | `PrivCodec` 的解析入口必须 fuzz |
| 审计 | 每个 major 版本做一次内部密码学自审；红线检查表逐条签字 |
| 版本 | 与公开仓库同版本号；trait 变更时同步升级 |
| 仓库 | 独立私有仓库；在授权 checkout 中挂载为 `private/copylocker-suite-priv` submodule |
| 分发 | 私有 cargo registry、受控 submodule path 或 Git + deploy key；不得进入公开 release job |
| 许可 | 专有商业许可；与 GPL 公开代码组合分发前必须完成商业许可或法律审查 |

## 6. 使用方式（对 Vendor）

以下依赖只存在于私有仓库维护的组合构建 manifest，不写入公开 workspace：

```toml
# private build overlay Cargo.toml
[dependencies]
copylocker-client = "1"
copylocker-suite-priv = { version = "1", registry = "copylocker-private" }
```

```rust
type Suite = copylocker_suite_priv::ClPriv1;
let client = CopyLockerClient::<Suite>::new(config)?;
```

服务端同样改一行。**切换成本 = 改类型别名 + 重新签发所有凭证**（AC-12）。

submodule 仅隔离仓库访问，不改变组合二进制的 GPL 义务。向第三方分发前必须遵循
`LICENSING.md` 的组合分发策略。

### 迁移（CL-STD-1 → CL-PRIV-1）

1. 服务端同时启用两个套件（`multi-suite` feature）。
2. 客户端新版本同时支持两个套件的验证。
3. 新签发的 MC 用 CL-PRIV-1；老 MC 在 `refresh_after` 到期后换发。
4. 等待渗透率达标 → 停止签发 CL-STD-1。
5. 保留 CL-STD-1 的验证能力至所有老凭证过期。

## 7. 明确的局限（诚实声明，写进销售材料）

1. **私有套件不会让破解变得不可能**，只会让「一次编写、全网通用」的破解工具不可行。
2. **足够有动机的攻击者可以逆向出私有套件的行为**（从客户端二进制中）。
   这需要数天到数周的工作量，且每个厂商需要重做一次。
3. **私有套件的价值随 Vendor 数量增长**：Vendor 越多，攻击者要做的重复劳动越多。
4. **私有套件不替代 L2/L3 的封印策略**。二者是叠加关系，不是替代关系。
5. **私有套件源码泄露后**，我们会发布 CL-PRIV-2 并提供迁移路径；
   已泄露版本的 Vendor 仍然安全（凭证不可伪造），只是失去成本不对称优势。

## 8. 定价与交付（商业侧，供参考）

| 项 | 内容 |
|---|---|
| 交付物 | 私有 crate 访问权 + 厂商专属 `vendor_seed` + 内部设计文档 + 优先支持 |
| 授权 | 按 Vendor / 按产品，年度订阅 |
| 升级 | 包含 CL-PRIV-n 的后续版本与迁移支持 |
| 不含 | 定制密码学开发（另行报价） |
