# ADR-0001：以「算法套件槽位」实现密码学敏捷

- **状态**：Accepted
- **日期**：2026-07-26
- **相关**：ADR-0002、ADR-0004、`02-architecture/crypto-architecture.md`

## 背景

需求要求「提供合适的加解密算法 slots，允许一定程度的客制化」，同时要能默认实现一个闭源的
后量子算法套件。同时后量子算法本身仍在演进（FIPS 203/204 已定稿，FIPS 206/FN-DSA 较新，
未来可能有新标准或参数调整），协议必须能在不破坏已签发凭证的前提下迁移算法。

## 决策

1. 定义 `copylocker-suite` crate，包含一组 trait：
   `SignatureScheme` / `KeyEncapsulation` / `AeadScheme` / `KeyDerivation` / `HashScheme` /
   `FingerprintScheme` / `ArtifactCodec` / `DeviceBinder`，由 `CryptoSuite` 聚合。
2. 每个 Suite 有 4 字节 `SuiteId`，**写入每一个凭证/消息的头部**（明文、在 AAD 中被认证）。
3. 客户端与服务端通过**泛型单态化**绑定 Suite（`Client<S: CryptoSuite>`），不使用 `dyn`。
   服务端可编译进多个 Suite，通过头部 `suite_id` 静态分派（`match` + 各自单态实例）。
4. 提供 `copylocker-suite-testkit`（公开）：一组 trait 一致性测试 + 属性测试 + KAT 框架，
   任何 Suite（含私有套件）必须全绿才允许发布。
5. 凭证格式对算法**完全不可知**：所有密码学产物是长度前缀的不透明字节串，
   格式层不假设签名长度、公钥长度、nonce 长度。

## 备选方案与否决理由

| 方案 | 否决理由 |
|---|---|
| 硬编码单一算法（如仅 Ed25519） | 无法满足客制化需求；无 PQ 迁移路径 |
| 运行时 `dyn CryptoSuite` 注册表 | 引入可被 hook 的 vtable，客户端侧是明确的攻击面（替换 vtable 即绕过验签）；且失去内联优化 |
| 用 COSE/JOSE 标准算法标识 | 标准算法 ID 空间不支持私有套件；且 JOSE 的 `alg` 混淆历史教训多 |
| 每个厂商 fork 代码改算法 | 无法维护、无法升级、无法审计 |

## 后果

**正面**
- 私有套件与开源套件是同一等公民，无特殊分支代码。
- 迁移算法 = 新增 Suite + 双签发过渡期 + 灰度，不需要改协议。
- 单态化后客户端的验签路径被内联进调用点，比集中式 `verify()` 更难一刀切 patch。

**负面 / 代价**
- 泛型传染：`Client<S>`、`Core<S>` 会污染大量签名 → 用类型别名与 facade 缓解。
- 二进制体积随启用的 Suite 数量线性增长 → 客户端通常只启用 1 个。
- 服务端多套件并存时代码路径增多 → 通过 testkit 的矩阵测试覆盖。

## 落地约束

- `SuiteId` 分配：`0x01xxxxxx` 开源官方，`0x02xxxxxx` 紧凑套件，`0x80xxxxxx`+ 私有/厂商（高位为 1）。
- 凭证头部一旦发布，`suite_id` 不可复用于不同算法组合。
- 任何 Suite 必须实现 `fn security_level() -> SecurityLevel`，服务端拒绝低于 Policy 要求的套件。
