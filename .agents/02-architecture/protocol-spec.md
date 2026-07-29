# 协议与凭证格式规范

版本 `proto_ver = 1`。编码：**确定性 CBOR**（RFC 8949 canonical）。
所有整数时间为 Unix 秒（i64，UTC）。所有字节串为 CBOR byte string。

## 1. 通用信封（Envelope）

每个被签名的工件都用同一信封结构，签名覆盖 `tbs`（to-be-signed）的规范编码。

```cddl
envelope = {
  0: uint,          ; proto_ver
  1: bytes .size 4, ; suite_id
  2: uint,          ; artifact_kind (见下表)
  3: bytes,         ; tbs  —— 内层工件的 canonical CBOR
  4: bytes,         ; sig  —— Hybrid 签名（长度前缀拼接）
  5: ? bytes,       ; epoch_cert_ref —— 8 字节 epoch_id，客户端据此取链
}
```

`artifact_kind`：

| 值 | 名称 | 签名者 |
|---|---|---|
| 1 | `epoch-cert` | Root |
| 2 | `machine-cred` | Epoch |
| 3 | `validation-ticket` | Epoch（见 §5 双层） |
| 4 | `kill-order` | Epoch |
| 5 | `revocation-batch` | Epoch |
| 6 | `offline-license-key` | Epoch（CL-CMP-1） |
| 7 | `integrity-manifest` | 构建签名密钥（可独立于 Epoch） |
| 8 | `activation-request` | 客户端设备密钥（自签，非信任锚） |
| 9 | `activation-response` | Epoch |
| 10 | `validate-request` | 客户端设备密钥（自签，非信任锚） |
| 11 | `heartbeat-request` | 客户端设备密钥（自签，非信任锚） |
| 12 | `deactivate-request` | 客户端设备密钥（自签，非信任锚） |

> **域分隔**：签名时 `ctx = "copylocker/v1/" ‖ kind_name ‖ 0x00 ‖ suite_id ‖ product_id`。

## 2. LicenseKey（LK）

用户可见短标识符，**不含签名**（ADR-0005）。

```
格式:  CL1-XXXXX-XXXXX-XXXXX-XXXXX
       └┬┘ └──────────┬────────────┘
        │             └── 20 字符 Crockford Base32 = 100 bit
        └── 前缀：CL + proto_ver

编码字节布局（100 bit → 分组前）:
  bits[0..8]    product_short  (u8, 由 product_id 的 SHA-256 前 8 bit 派生，用于本地快速路由/校验)
  bits[8..88]   key_random     (80 bit CSPRNG)
  bits[88..100] crc12          (CRC-12 over 前 88 bit，用于输入纠错提示)
```

- Crockford Base32 字母表：去除 `I L O U`，输入时 `i/l→1`、`o→0` 自动纠正，大小写不敏感。
- 熵：80 bit 随机 → 在服务端限流下不可穷举。
- 展示时用 `-` 分组；解析时忽略所有非字母数字字符。
- **服务端存储的是 `HMAC(server_pepper, lk_bytes)`**，不存明文，防数据库泄露即枚举。

## 3. ActivationRequest（AR）

```cddl
activation_request = {
  0: uint,             ; proto_ver
  1: bytes .size 4,    ; suite_id
  2: tstr,             ; product_id
  3: credential,       ; 见下
  4: bytes,            ; fingerprint (Fpr 输出，通常 32B)
  5: device_attrs,     ; 规范化属性（用于服务端容差比较，可选上报，受隐私配置控制）
  6: bytes,            ; device_kem_ek —— 设备长期 KEM 公钥
  7: bytes .size 32,   ; nonce_c
  8: int,              ; client_time（**仅供参考，服务端不信任**）
  9: client_info,      ; 见 §3.1
  10: ? bytes,         ; attestation（平台可选：Play Integrity / App Attest / TPM 报价）
  11: bytes,           ; device_sig_vk —— 后续 validate proof 的 Ed25519 公钥
  12: bytes .size 64,  ; proof —— Ed25519.sign(device_sig_sk, DomainCtx(ar) ‖ proof_input)
}

credential = { 0: tstr }            ; license_key（Mode O）
           / { 1: bytes }           ; account_token（Mode E，来自 /v1/auth/login）

; AR 由独立的设备签名密钥自签（防止中间人替换 device_kem_ek/device_sig_vk）
; 注意：AR 的自签不是信任锚，只用于把请求字段绑定到 nonce 与两个设备公钥
```

`proof_input` 是删除 key `12` 后整个 AR map 的 canonical CBOR；credential、fingerprint、
device attrs、两个设备公钥、nonce、client_info 与 attestation 均被覆盖。服务端必须在占席位或
封装 CredentialSecret 前，用请求内的 `device_sig_vk` 验证 proof。

AR 的两种载体：
- **在线**：CBOR 直接 POST。
- **离线**：`.clar` 文件（CBOR + Base32 armor）或 QR（gzip + Base45）。

### 3.1 `client_info`

```cddl
client_info = {
  0: tstr,        ; app_version   (semver)
  1: tstr,        ; sdk_version   (semver)
  2: tstr,        ; os
  3: tstr,        ; arch
  4: tstr,        ; build_fingerprint
  5: tstr,        ; release_id          —— 未注册则服务端返回 1007
  6: uint,        ; variant_id
  7: [* bytes],   ; supported_suites
  8: [* uint],    ; supported_variants  —— 自身 + 可接受的旧变体（默认 4 个）
}
```

`release_id` 由构建期注入（`copylocker release register` 写入 `.copylocker/variant.lock`）。
服务端据此查 `releases` 表得到 `published_at`（版本范围判定）与 `variant_params`（FK 计算）。

## 4. MachineCredential（MC）

**核心持久化工件。**

```cddl
machine_cred_tbs = {
  0: uint,             ; proto_ver
  1: bytes .size 4,    ; suite_id
  2: tstr,             ; product_id
  3: bytes .size 16,   ; license_id
  4: bytes .size 16,   ; machine_id (服务端分配)
  5: bytes,            ; fingerprint（签发时的指纹，绑定用）
  6: bytes,            ; kem_ct —— KEM.Encap(device_kem_ek) 的密文
  7: bytes,            ; sealed_cs —— AEAD 密封的 CredentialSecret
  8: bytes .size 32,   ; offline_nonce —— 离线路径的 SessionRoot 输入
  9: entitlements,     ; 权益
  10: int,             ; issued_at (服务端时间)
  11: int,             ; not_after —— 硬期限（0 = 无限）
  12: int,             ; refresh_after —— 建议/要求下次在线校验时间
  13: uint,            ; grace_seconds
  14: uint,            ; mode  (0=offline_hybrid, 1=enforced_online)
  15: uint,            ; revocation_epoch —— 签发时的吊销纪元
  16: bytes .size 8,   ; epoch_id
  17: ? tstr,          ; build_fingerprint 约束（若设置，仅该构建可用）
  18: ? policy_flags,  ; 位标志：allow_vm, require_attestation, strict_fingerprint...
  19: uint,            ; security_floor —— 单调安全基线，客户端拒绝低于已见最大值
  20: uint,            ; variant_id
  21: { * tstr => bytes },      ; wrapped_keks —— 按 feature、用离线 SessionRoot 包装的资产 KEK
  22: ? { * uint => { * tstr => bytes } },
                       ; preloaded_keks —— 按 variant_id 预置（offline_upgrade_policy=preload_n）
}
```

`entitlements` 的定义见 [`licensing-model.md §9`](licensing-model.md)（单一事实源）。
`wrapped_keks` / `preloaded_keks` 的语义见 [`versioning-and-variants.md §3`](versioning-and-variants.md)。
其字节格式见 [ADR-0013](../00-overview/decisions/ADR-0013-credential-sealing-and-kek-wrapping.md)：
CL-STD-1 的 `sealed_cs` 与每个 map value 都是 `24B nonce ‖ 32B ciphertext ‖ 16B tag`。
MC fields 21/22 只携带 offline 包装；VT field 15 携带其 `server_nonce` 对应的 online 包装。

**存储形态**：客户端把 `envelope(MC)` 原样存盘（外层再套一层本地 AEAD，密钥来自 OS keychain）。
**永不**把 `CredentialSecret` 明文落盘。

## 5. ValidationTicket（VT）—— 双层设计

**问题**：每次在线校验都做一次 ML-DSA-65 签名，服务端 CPU 成本高（Workers 有 CPU 限制）。

**方案**：VT 分两层。

```
Layer A（每请求，对称）：
  vt_mac = HMAC-SHA256(K_epoch_mac, canonical(vt_tbs))
  其中 K_epoch_mac = HKDF(epoch_secret, "vt-mac" ‖ epoch_id)
  客户端能验证 vt_mac 的前提是它持有 K_epoch_mac 吗？—— 不持有。

  ✗ 对称 MAC 不可行：客户端不能持有服务端的 MAC 密钥（否则可自签）。
```

**因此采用：Layer A 用非对称签名，但用便宜的经典算法 + 周期性 PQ 锚定。**

```
Layer A（每请求）: sig_fast = Ed25519.sign(K_epoch_fast_sk, ctx ‖ vt_tbs)
                              // ~50µs，可忽略
Layer B（周期性）: K_epoch_fast_vk 本身由 Epoch 的 PQ 混合密钥签名，
                  作为 EpochCert 的一部分一次性下发。
```

即：**PQ 保护的是密钥链（长期、低频），Ed25519 承担高频的每请求签名**。

安全性分析：
- 攻击者要伪造 VT，需要 `K_epoch_fast_sk`（Ed25519 私钥），存 Secrets Store，与 Epoch PQ 私钥同等保护。
- 量子攻击者可破 Ed25519 → 可伪造 VT。但 **VT 只能让客户端"延长有效期"，不能创造凭证**：
  没有 MC（PQ 签名 + KEM 密封）就没有 CredentialSecret，就没有 Feature Key。
  → VT 的伪造收益受限于"延长一个已合法的凭证"。
- 对于要求全 PQ 的 Vendor：Policy 开关 `vt_signature = "pq"` 强制 VT 也用混合签名，
  代价是服务端 CPU 与响应体积（+3.3KB）。**默认 `fast`，可切 `pq`。**

```cddl
validation_ticket_tbs = {
  0: uint,             ; proto_ver
  1: bytes .size 4,    ; suite_id
  2: bytes .size 16,   ; machine_id
  3: bytes .size 32,   ; nonce_c_echo —— 必须等于请求中的 nonce_c
  4: bytes .size 32,   ; server_nonce —— 参与 SessionRoot 派生
  5: int,              ; server_time
  6: int,              ; next_refresh_after
  7: int,              ; not_after (可被服务端延长/缩短)
  8: uint,             ; revocation_epoch
  9: uint,             ; verdict (0=ok 1=needs_reactivation 2=version_out_of_scope)
  10: ? entitlements,  ; 权益变更（升级套餐、加购后即时生效）
  11: bytes .size 8,   ; epoch_id
  12: ? uint,          ; suspicion_score (0..100，客户端可用于降级体验)
  13: uint,            ; security_floor
  14: ? uint,          ; release_status (0=active 1=deprecated 2=compromised)
  15: ? { * tstr => bytes },  ; 当前 server_nonce 的在线 wrapped_keks；切换 variant/权益时下发
  16: ? bool,          ; refresh_now —— 服务端请求客户端尽快再次校验（权益已变更）
}
```

**客户端校验 VT 的必做检查**（缺一不可，写进 checklist 测试）：

1. 信封 `proto_ver` / `suite_id` 被支持
2. `epoch_id` 对应的 EpochCert 已被 Root 验证且在有效期内、未被吊销
3. 签名验证通过（fast 或 pq，按 EpochCert 声明）
4. `nonce_c_echo == 本次请求发出的 nonce_c`（**防重放**）
5. `machine_id == 本地 MC.machine_id`
6. `|server_time - 本地单调时间估计| < max_skew`（默认 24h），超出 → 记录但不拒绝（客户端时钟可能就是错的）
7. `revocation_epoch >= 本地已知 revocation_epoch`（**防回滚到旧吊销状态**）
8. `next_refresh_after > server_time`

## 6. KillOrder

```cddl
kill_order_tbs = {
  0: uint,             ; proto_ver
  1: bytes .size 4,    ; suite_id
  2: bytes .size 16,   ; machine_id
  3: bytes .size 32,   ; nonce_c_echo
  4: int,              ; server_time
  5: uint,             ; reason (1=revoked_license, 2=revoked_activation,
                       ;         3=seat_reclaimed, 4=fraud, 5=refund, 6=epoch_revoked)
  6: ? tstr,           ; user_message —— 显示给终端用户的文案
  7: uint,             ; revocation_epoch
}
```

客户端收到并验签通过后**必须立即**：
1. 擦除本地 MC、设备 KEM 私钥、所有已派生的 FeatureKey（zeroize）。
2. 删除已解密的 Sealed Asset 缓存。
3. 状态 → `Revoked`。
4. 展示 `user_message`。

> KillOrder 必须用**非对称签名**（不能用 fast-only？—— 可以用 fast，
> 因为 KillOrder 的危害方向是"让合法用户失效"，攻击者伪造它只能 DoS 自己。
> 但为了防止攻击者对**别人**做 DoS，KillOrder 必须绑定 `machine_id` + `nonce_c_echo`，
> 因此只能在该设备自己的会话中生效。✅ 用 fast 签名即可）

## 7. RevocationBatch

```cddl
revocation_batch_tbs = {
  0: uint,             ; proto_ver
  1: bytes .size 4,    ; suite_id
  2: uint,             ; from_epoch
  3: uint,             ; to_epoch   —— 单调递增
  4: int,              ; issued_at
  5: [* bytes .size 16], ; revoked_license_ids
  6: [* bytes .size 16], ; revoked_machine_ids
  7: [* bytes .size 8],  ; revoked_epoch_ids
  8: ? bytes,          ; bloom_filter —— 大规模时用 Bloom（假阳性 → 强制在线校验，安全）
}
```

- `to_epoch` 单调递增，客户端拒绝 `to_epoch < 本地已知` 的批次（防回滚）。
- 大规模吊销用 Bloom filter（假阳性只导致多一次在线校验，**fail-safe 方向正确**）。
- 客户端在**离线**时也能用最后一次拿到的 RB 做本地吊销判定。

## 8. OfflineLicenseKey（OLK）

```cddl
olk_tbs = {
  0: uint,             ; proto_ver
  1: bytes .size 4,    ; suite_id（当前为 CL-STD-1 文件形态；CL-CMP-1 尚未启用）
  2: tstr,             ; product_id
  3: bytes .size 16,   ; license_id
  4: entitlements,
  5: int,              ; issued_at
  6: int,              ; not_after
  7: ? bytes,          ; bound_fingerprint —— 若存在则只在该设备可用
  8: uint,             ; max_seats（无服务端时无法强制，仅声明）
  9: bytes .size 8,    ; epoch_id
  10: bytes .size 16,  ; machine_id（unbound 副本共享）
  11: bytes .size 32,  ; offline_nonce
  12: bytes .size 32,  ; key_seed（签名 bearer capability，不承诺保密）
  13: tstr,            ; build_fingerprint
  14: uint,            ; variant_id
  15: uint,            ; security_floor
  16: uint,            ; revocation_epoch
  17: { * tstr => bytes }, ; offline wrapped_keks
}
```

- 当前载体为 `.clk` 二进制/armored 文件；在 CL-CMP-1 正式启用前不承诺单 QR 或短文本形态。
- `.clk` 二进制是 `olk_bundle_v1 = {0: 1, 1: bytes .cbor envelope(OLK),
  2: [1*8 bytes .cbor envelope(EpochCert)]}`，因此只 pin Root 的新设备也能完全离线验链。
- armor 固定为无 padding 的 Crockford Base32：`CLK1:<bundle>`；可使用固定
  `BEGIN/END COPYLOCKER OFFLINE LICENSE` 文件边界与 64 字符换行。
- `key_seed` 必须按 ADR-0015 的 `copylocker/olk-seed/v1` KDF 进入既有 Binder →
  SessionRoot → FeatureKey 链；禁止直接 hash 公开字段充当 Feature Key。
- **安全声明**：不带 `bound_fingerprint` 的 OLK 可被无限复制。
  Policy 中默认 `allow_unbound_olk = false`。

## 9. IntegrityManifest（IM）

```cddl
integrity_manifest_tbs = {
  0: uint,             ; proto_ver
  1: bytes .size 4,    ; suite_id
  2: tstr,             ; product_id
  3: tstr,             ; build_fingerprint —— 参与 FeatureKey 派生
  4: int,              ; built_at
  5: tstr,             ; hash_alg  ("blake3" | "sha256" | 自定义标识)
  6: { * tstr => bytes },  ; path/url pattern => digest
  7: ? { * tstr => bytes },; guarded function id => body digest
  8: ? [* tstr],       ; sealed asset ids
  9: bytes,            ; root —— 上述条目的 Merkle 根（用于分片校验）
}
```

签名密钥可独立于 Epoch 密钥（构建签名密钥），由 Root 或 Epoch 签发其证书。

### 9.1 SealedAsset v1

```cddl
sealed_asset_v1 = {
  0: 1,                ; schema
  1: bytes .size 4,    ; suite_id
  2: tstr,             ; product_id
  3: uint,             ; variant_id
  4: tstr,             ; feature_id
  5: tstr,             ; asset_id
  6: bytes,            ; nonce || ciphertext || tag
}
```

- 整个 canonical-CBOR 容器（不是仅字段 6）上限为 64 MiB；更大的资产必须使用后续分块格式。
- `product_id`、`feature_id`、`asset_id` 均非空、最长 1024 bytes，且不得含 NUL。
- AEAD AAD 是 canonical CBOR
  `{0: "copylocker/asset-aad/v1", 1: suite_id, 2: product_id, 3: variant_id,
  4: feature_id, 5: asset_id}`。上述任一元数据变化都必须导致解封失败。
- 字段 6 使用该 suite 的 AEAD；KEK 由对应 `wrapped_keks[feature_id]` 解包取得。
- `schema != 1`、suite 不匹配、非 canonical 编码、越界或 AEAD 失败统一视为资产损坏，
  不得回退到明文资源。

## 10. HTTP 线协议

### 10.1 通用

| 项 | 规定 |
|---|---|
| Base URL | `https://<vendor>.workers.dev` 或自定义域 |
| Content-Type | `application/cbor`（客户端端点）/ `application/json`（Admin 端点） |
| 编码 | 请求与响应体均为 CBOR（客户端面） |
| 版本 | Header `X-CL-Proto: 1`；不匹配返回 426 |
| 幂等 | Header `Idempotency-Key: <uuid>`（activate/deactivate 必带） |
| 请求体上限 | 16 KiB（客户端端点） |
| CBOR 嵌套深度上限 | 16 |
| 压缩 | 支持 `Content-Encoding: br/gzip`，解压后仍受上限约束 |

### 10.2 端点

| 方法 | 路径 | 请求 | 响应 | 幂等 |
|---|---|---|---|---|
| POST | `/v1/activate` | `ActivationRequest` | `envelope(MachineCredential)` + `EpochCertChain` | ✅ |
| POST | `/v1/validate` | `ValidateRequest` | `envelope(VT)` \| `envelope(KillOrder)` | ✅ |
| POST | `/v1/heartbeat` | `HeartbeatRequest` | `{ ok, next_after }` | ✅ |
| POST | `/v1/deactivate` | `DeactivateRequest` | `{ ok }` | ✅ |
| GET | `/v1/keys` | — | `{ epoch_certs[], revocation_epoch }`（可 CDN 缓存 300s） | ✅ |
| GET | `/v1/revocations?since=N` | — | `envelope(RevocationBatch)` | ✅ |
| POST | `/v1/offline/request` | `ActivationRequest` | `envelope(ActivationResponse)` | ✅ |
| POST | `/v1/auth/login` | `{ email, password/oauth }` | `{ account_token, refresh_token }` | ❌ |
| POST | `/v1/auth/refresh` | `{ refresh_token }` | `{ account_token }` | ❌ |
| POST | `/v1/integrity/report` | `{ build_fp, failures[] }` | `202` | ✅ |

```cddl
validate_request = {
  0: uint,             ; proto_ver
  1: bytes .size 4,    ; suite_id
  2: bytes .size 16,   ; machine_id
  3: bytes,            ; fingerprint（当前指纹，可能已漂移）
  4: bytes .size 32,   ; nonce_c
  5: int,              ; client_time (不信任)
  6: uint,             ; known_revocation_epoch
  7: client_info,
  8: bytes,            ; proof —— Ed25519.sign(device_sk, ctx ‖ 上述字段)
                       ;          证明请求方持有设备私钥（防止 machine_id 被冒用）
  9: ? bytes,          ; integrity_summary（可选，客户端自校验摘要）
  10: uint,            ; known_security_floor
  11: ? telemetry_block, ; T1 遥测（可选，需同意）—— 见 90-analytics-telemetry.md §6
  12: bytes .size 16,  ; license_id —— LicenseDO 强一致路由键，必须被 proof 覆盖
}
```

`proof` 使用独立的 `validate-request` 域（wire kind 10）；不得复用
`activation-request` 域，否则两类设备自签名消息之间会失去用途隔离。

**遥测搭车原则**：T1 遥测复用 `validate` 请求，**不新增端点、不新增网络请求**。
`proof` 的签名覆盖包含 `telemetry_block`，因此攻击者只能污染自己那一台设备的数据。
服务端把遥测标记为 `untrusted`，与 T0 的协议派生指标分表、分区域展示。

```cddl
telemetry_block = {
  0: uint,             ; consent_version；0 表示无有效同意，服务端丢弃
  1: uint,             ; window_start（来自上一张 VT 的服务端时间）
  2: uint,             ; session_count
  3: [uint, uint, uint, uint], ; session_duration_histogram
  4: { * tstr => uint },       ; feature_hits（服务端按白名单裁剪）
  5: uint,             ; days_active（语义范围 0..28）
}

heartbeat_request = {
  0: uint,             ; proto_ver
  1: bytes .size 4,    ; suite_id
  2: bytes .size 16,   ; license_id
  3: bytes .size 16,   ; machine_id
  4: bytes .size 32,   ; nonce_c
  5: int,              ; client_time（不信任）
  6: bytes .size 64,   ; proof —— Ed25519，heartbeat-request 域
}

deactivate_request = {
  0: uint,             ; proto_ver
  1: bytes .size 4,    ; suite_id
  2: bytes .size 16,   ; license_id
  3: bytes .size 16,   ; machine_id
  4: bytes .size 32,   ; nonce_c
  5: int,              ; client_time（不信任）
  6: bytes .size 64,   ; proof —— Ed25519，deactivate-request 域
}

heartbeat_response = { 0: bool, 1: int } ; ok, next_after（服务端 Unix 秒）
deactivate_response = { 0: bool }         ; ok
```

激活后的三类请求都必须按 `license_id` 路由到 LicenseDO，再核对该对象、License 和
`machine_id` 的归属。D1 `machines` 只是投影，禁止用于反查路由。proof 输入为删除本请求 proof
key 后的完整 canonical CBOR；三个请求使用不同 wire kind，签名不得跨用途复用（ADR-0012）。

### 10.3 错误响应

```cddl
error_response = { 0: uint, 1: ? tstr, 2: ? uint }  ; code, message(用户可读), retry_after
```

| code | 含义 | 客户端行为 |
|---|---|---|
| 1000 | 通用无效凭证（**故意不区分具体原因**） | → `Unlicensed` / 提示重新激活 |
| 1001 | 席位已满 | 提示"请先在其他设备停用" |
| 1002 | 需要重新激活 | → `Unlicensed` |
| 1003 | 账号需要登录 | Mode E 登录流程 |
| 1004 | 协议版本不支持 | 提示升级客户端 |
| 1005 | 请求过于频繁 | 指数退避 |
| 1006 | 指纹不匹配（超容差） | 提示换机流程 |
| 1007 | Release 未注册 | 提示"此版本未正确发布"；错误详情含 `copylocker release register` 命令 |
| 1008 | 版本超出授权范围 | **受限模式**：提示可用的最高版本 + 升级授权入口。**不可表现为盗版警告** |
| 1009 | Release 已标记 compromised | 按 `compromised_action` 提示升级 |
| 5000 | 服务端错误 | **按网络失败处理 → 进 Grace**，不失效 |

> **关键**：所有 5xx 与网络错误对客户端等价，走 fail-open 路径。
> 只有 1000–1006 中的凭证类错误 + 密码学校验失败才 fail-closed。

## 11. 状态同步与时间

| 时间源 | 用途 |
|---|---|
| 服务端时间 | 唯一权威。写入所有签名工件 |
| 客户端墙钟 | 仅用于"距上次校验多久"的粗略判断，受 Clock Guard 约束 |
| 客户端单调时钟 | `Instant`/`performance.now()`，用于会话内计时，重启后失效 |
| 单调高水位 `last_seen_max` | 持久化的"见过的最大时间"，任何小于它的墙钟读数视为回拨 |

**Clock Guard 算法**

```rust
fn check_clock(now_wall: i64, st: &mut ClockState) -> ClockVerdict {
    if now_wall + SKEW_TOLERANCE < st.last_seen_max {
        st.rollback_count += 1;
        return ClockVerdict::Rollback { delta: st.last_seen_max - now_wall };
    }
    st.last_seen_max = st.last_seen_max.max(now_wall);
    // 额外：用单调时钟交叉验证会话内的墙钟跳变
    ClockVerdict::Ok
}
```

- `Rollback` → 立即强制在线校验；若无网，**不延长** Grace（用 `last_seen_max` 而非当前墙钟计算剩余期限）。
- `last_seen_max` 与 MC 一起存于被 AEAD 保护的 blob 中（篡改即验签失败）。
- 多存储位置冗余（keychain + 文件 + 平台特定位置），取最大值，防止单点删除即重置。

## 12. 版本协商

```
客户端发 X-CL-Proto: 1
服务端支持 [1]        → 正常
服务端支持 [1,2]      → 用 1 响应，并在响应中带 { upgrade_available: 2 }
服务端仅支持 [2]      → 426 Upgrade Required + 提示信息
```

Suite 协商：客户端在 AR 中声明支持的 `suite_id` 列表（`client_info.suites`），
服务端选择双方都支持的最高安全等级套件。协商结果写入 MC，后续固定。
