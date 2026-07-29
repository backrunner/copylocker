# ADR-0015：OLK Bundle 与生产性密钥

- **状态**：Accepted
- **日期**：2026-07-29
- **相关**：ADR-0004、ADR-0005、ADR-0008、ADR-0013、`protocol-spec.md §8`

## 背景

原始 `OfflineLicenseKey` 只有签名授权字段。它没有可进入 Feature Key 密钥链的材料，
也没有携带 Root 签名的 Epoch 证书。这样的文件即使能解析，也无法在完全断网的新设备上独立验链，
更无法解开 Sealed Asset。用公开字段的临时 hash 充当密钥会制造未版本化、不可互操作的协议，禁止这样做。

## 决策

### 1. OLK v1 的生产性字段

保留 `OfflineLicenseKey` 字段 0–9，并追加以下签名字段：

| key | 值 |
|---:|---|
| 10 | 16 字节 `machine_id`；unbound OLK 的所有副本共享该逻辑机器 ID |
| 11 | 32 字节 `offline_nonce` |
| 12 | 32 字节 CSPRNG `key_seed` |
| 13 | text `build_fingerprint` |
| 14 | uint `variant_id` |
| 15 | uint `security_floor` |
| 16 | uint `revocation_epoch` |
| 17 | `{ * tstr => bytes } wrapped_keks`，均为 offline wrap |

`key_seed` 是签名文件中的 bearer capability，不承诺保密。它不能单独授权任何 feature；客户端必须先
验证 Root → Epoch → OLK 全链、产品、suite、期限、设备绑定、build、variant 与单调计数器。

### 2. 域分离派生

客户端和签发端先计算：

```text
binding_fingerprint = bound_fingerprint
  or UTF8("copylocker/olk-unbound/v1")

OlkCredentialSecret = KDF.derive_from(
  salt  = ASCII("copylocker/olk-seed/v1"),
  ikm   = key_seed,
  parts = [suite_id, product_id, license_id, machine_id,
           epoch_id, u64_be(variant_id), binding_fingerprint])
```

每个 `parts` 元素继续使用 suite 已冻结的长度前缀编码。所得 32 字节值作为
`KeyMaterial::bind` 的输入；后续 Binder、offline SessionRoot、FeatureKey 和 wrapped KEK AAD
完全复用 ADR-0013。`offline_nonce`、`machine_id`、Epoch、variant、build/module evidence 因而都会
进入最终密钥或 AEAD AAD。

### 3. 自含 Bundle

`.clk` 二进制内容是 canonical CBOR：

```cddl
olk_bundle_v1 = {
  0: 1,          ; schema
  1: bytes,      ; envelope(OfflineLicenseKey)
  2: [1*8 bytes] ; Root-signed EpochCert envelopes
}
```

客户端只 pin Root。导入时必须先从有界 OLK body 读取 `issued_at`，在该签发时刻验证 EpochCert
有效窗口，再验证 OLK 签名；随后用当前 Clock Guard 时间检查 OLK 自身期限。Bundle 不携带 Root
私钥或新的信任锚。

### 4. Armor

文本/QR 形态使用 Crockford Base32、无 padding：

```text
CLK1:<UPPERCASE_CROCKFORD_BASE32_OF_BINARY_BUNDLE>
```

文件可增加固定 PEM 风格边界并每 64 字符换行：

```text
-----BEGIN COPYLOCKER OFFLINE LICENSE-----
CLK1:<payload>
-----END COPYLOCKER OFFLINE LICENSE-----
```

解析器只忽略 ASCII 空白，不接受任意标点；尾部未使用 bit 必须为 0。签名负责完整性，Base32
只负责无损载体编码。更改 prefix、字母表或 padding 规则必须分配新的 `CLK` 版本。

### 5. 安全等级与生命周期

- **bound OLK**：必须精确匹配当前 fingerprint，且该 fingerprint 参与密钥派生；仍弱于
  AR/AResp，因为 bearer 文件包含公开 seed，不能获得设备 KEM 提供的 secret confidentiality。
- **unbound OLK**：可无限复制，所有副本导出相同的离线密钥。客户端默认拒绝，宿主必须显式设置
  `allow_unbound_olk = true`；服务端 Policy 也必须独立允许。
- `max_seats` 在无服务端场景仅为声明，不得描述为可强制席位数。
- OLK 不启动在线 validate scheduler；`deactivate()` 只擦除本地文件，不声称释放服务端席位。
- OLK 只能通过导入更新，无法获得实时吊销。签发时的 `revocation_epoch` 和 `security_floor` 仍参与
  本地防回滚，但不能替代在线 revocation feed。
- `not_after = 0` 表示永久；否则到期立即 Locked。OLK 没有 refresh/grace 延长。

## 后果

- `copylocker-proto` 新增 `OfflineLicenseBundle` 与 armor codec，并扩展 OLK v1 signed body。
- `copylocker-core` 提供唯一的 OLK seed 派生入口，客户端与签发端不得各自重写 KDF。
- snapshot 继续保存原始签名 envelope 与 EpochCert chain；重启时重新完成全链验证和密钥派生。
- OLK 的签发 API、CLI 和门户必须生成 `wrapped_keks`，否则产物不能通过生产性导入测试。

