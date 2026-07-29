# ADR-0013：CredentialSecret 密封与资产 KEK 包装线格式

- **状态**：Accepted
- **日期**：2026-07-27
- **相关**：ADR-0004、ADR-0008、`02-architecture/crypto-architecture.md`、FR-CRY-009、FR-LIC-019

## 背景

原规格只写了 `HKDF(ss, "cs-wrap")`、`aad = mc_header || fp` 和
`wrapped_keks = { feature => bytes }`。它没有固定 HKDF 的 salt/info、`mc_header` 的字段与边界、
AEAD nonce 的存放位置，也没有区分 MC 的离线包装和 VT 的在线包装。服务端和客户端若分别实现，
即使都选了正确原语，也很容易生成不兼容的字节。

Release 的 `variant_params` 同样只有“服务端算 FK 需要”的描述，而
`FeatureKey` 实现此前没有混入 `variant_id` 或 variant 常量，无法兑现“谎报旧 release 只能拿到旧
variant 的 KEK”这一安全边界。

## 决策

以下规则组成协议版本 1 的 key-wrap schema。协议可见常量、CBOR key、字段顺序或长度前缀一旦发布
不得原地修改；变更必须分配新 schema 或协议版本并提供双读窗口。

### 1. CredentialSecret 与 `sealed_cs`

`CredentialSecret` 是服务端为每次 MC 签发生成的 32 字节 CSPRNG 输出。X-Wing encapsulation 得到
32 字节 `ss` 后，CL-STD-1 按以下方式派生 XChaCha20-Poly1305 key：

```text
PRK  = HKDF-SHA-512-Extract(
         salt = ASCII("copylocker/cs-wrap/v1"),
         IKM  = ss)
key  = HKDF-SHA-512-Expand(PRK,
         LP(suite_id) || LP(product_id) || LP(license_id) || LP(machine_id),
         32)
LP(x) = u32_be(byte_length(x)) || x
```

AEAD AAD 是以下 map 的 RFC 8949 deterministic CBOR：

| key | 值 |
|---:|---|
| 0 | text `copylocker/cs-aad/v1` |
| 1 | `proto_ver` uint |
| 2 | 4 字节 `suite_id` |
| 3 | text `product_id` |
| 4 | 16 字节 `license_id` |
| 5 | 16 字节 `machine_id` |
| 6 | `fingerprint` bytes |
| 7 | `kem_ct` bytes |
| 8 | 32 字节 `offline_nonce` |
| 9 | 8 字节 `epoch_id` |
| 10 | `variant_id` uint |

`sealed_cs = nonce || ciphertext || tag`。CL-STD-1 中 nonce 为 24 字节、明文为 32 字节、tag 为
16 字节，因此 `sealed_cs` 必须恰好为 72 字节。解封必须先检查总长度，再验证 tag；X-Wing 的
implicit rejection 只有在该 AEAD 验证成功后才算成功。

### 2. Variant 参数与 FeatureKey

CL-STD-1 每个 release 的 `variant_const` 是 32 字节。FeatureKey 固定为：

```text
FeatureKey(feature) = KDF.derive_from(
  salt  = ASCII("copylocker/fk/v1"),
  ikm   = SessionRoot,
  parts = [product_id, u64_be(variant_id), variant_const, UTF8(feature_id)])
```

`parts` 逐项使用上述 `LP` 编码。`variant_id` 与 `variant_const` 任一个改变都必须导出不同 key。

`releases.variant_params` 的解密后明文为 canonical CBOR：

```cddl
variant_params_v1 = {
  0: 1,                 ; schema_version
  1: uint,              ; variant_id，必须等于 releases.variant_id
  2: bytes .size 32,    ; variant_const
  3: bytes .size 32,    ; module_digest
  4: [* bytes],         ; binder_extra，顺序有语义
  5: ? bytes,           ; suite_private_params；CL-STD-1 必须省略
}
```

D1 列不存明文。`variant_params` 用 Secrets Store 的 32 字节 `VARIANT_PARAMS_KEY` 通过
XChaCha20-Poly1305 加密，仍采用 `nonce || ciphertext || tag`。AAD 是 canonical CBOR map：

| key | 值 |
|---:|---|
| 0 | text `copylocker/variant-at-rest/v1` |
| 1 | text `release_id` |
| 2 | text `product_id` |
| 3 | `variant_id` uint |
| 4 | text `build_fingerprint` |
| 5 | 4 字节 `suite_id` |

解密后必须逐项核对 D1 明文列与参数 blob；不一致是存储损坏，返回服务端错误，不得继续签发。

### 3. 每 release/feature 的资产 KEK

构建上传的资产 KEK 固定 32 字节，按 `(release_id, feature_id)` 存于 D1
`release_feature_keks`。`encrypted_kek` 用 Secrets Store 的 32 字节 `ASSET_KEK_KEY` 通过
XChaCha20-Poly1305 加密，格式同样为 `nonce || ciphertext || tag`。AAD map 为：

| key | 值 |
|---:|---|
| 0 | text `copylocker/asset-kek-at-rest/v1` |
| 1 | text `release_id` |
| 2 | text `product_id` |
| 3 | text `feature_id` |
| 4 | `key_version` uint |

只有表中登记的 feature 需要下发 wrapped KEK；并非每个 entitlement 都必须有 sealed asset。
但读取、解密或核对已登记 KEK 失败时，激活/校验必须返回 5xx，禁止静默删除该 feature 或返回空 map。

### 4. 面向设备的 wrapped KEK

资产 KEK 用对应的 32 字节 FeatureKey 再包装一次。AAD 是 canonical CBOR map：

| key | 值 |
|---:|---|
| 0 | text `copylocker/kek-aad/v1` |
| 1 | `proto_ver` uint |
| 2 | 4 字节 `suite_id` |
| 3 | text `product_id` |
| 4 | 16 字节 `license_id` |
| 5 | 16 字节 `machine_id` |
| 6 | 8 字节 `epoch_id` |
| 7 | `variant_id` uint |
| 8 | text `feature_id` |
| 9 | `wrap_kind` uint：0=offline，1=online |
| 10 | 32 字节 session nonce：offline 用 MC `offline_nonce`，online 用 VT `server_nonce` |

输出仍是 `nonce || ciphertext || tag`，CL-STD-1 下恰好 72 字节。

- MC field 21 是当前 variant 的 **offline** 包装。
- MC field 22 是预加载目标 variant 的 **offline** 包装。
- VT field 15 是该 VT `server_nonce` 的 **online** 包装。
- 客户端必须使用与容器、variant、feature 和 session kind 完全匹配的 AAD；不得只以 feature 名作 AAD。

### 5. KAT

公共 `vectors/CL-STD-1/kat.json` 固定以下语义向量：

- `credential-wrap-key`
- `positive/credential-secret-seal-v1`
- 含 `variant_id + variant_const` 的 `feature-key`
- `positive/offline-kek-wrap-v1`

单元测试另覆盖 fingerprint、feature、variant、online/offline 或 AAD 任一变化均解封失败。

## 备选方案与否决理由

| 方案 | 否决理由 |
|---|---|
| 裸拼接 `mc_header || fp` | 可变长字段没有边界，跨语言实现容易歧义 |
| 固定/省略 XChaCha nonce | 多实例无法安全协调计数器；省略会让解封方无法恢复随机 nonce |
| AAD 只用 feature 名 | wrapped KEK 可跨 License、machine、variant 或 online/offline 容器移植 |
| FeatureKey 不含 variant 参数 | 谎报旧 release 仍可能拿到新构建可用的 key，破坏版本范围强制 |
| D1 存明文 variant 参数或资产 KEK | 数据库泄露会扩大到所有 sealed asset，违反最小暴露原则 |

## 后果

- 服务端与客户端共享 `copylocker-proto::keywrap`，不再各自解释密码学伪代码。
- 每个 32 字节 secret 的 CL-STD-1 包装成本是 72 字节；旧文档中的 48 字节预算作废。
- Worker 部署新增 `VARIANT_PARAMS_KEY` 与 `ASSET_KEK_KEY` Secrets Store bindings。
- activation/validate 必须加载并验证 release 参数和已登记资产 KEK，不能用空 map 代替未实现的包装流程。
