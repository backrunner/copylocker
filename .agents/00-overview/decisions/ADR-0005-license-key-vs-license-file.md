# ADR-0005：License Key 是标识符，签名凭证走文件/凭证

- **状态**：Accepted
- **日期**：2026-07-26
- **相关**：`02-architecture/protocol-spec.md`

## 背景

需求要求「支持离线激活（即通过特定的 License Key）」。但存在一个硬性物理约束：

| 签名算法 | 签名长度 | Base32 后长度 |
|---|---|---|
| Ed25519 | 64 B | ~103 字符 |
| FN-DSA-512 | 666 B | ~1066 字符 |
| ML-DSA-44 | 2420 B | ~3872 字符 |
| ML-DSA-65 | 3309 B | ~5295 字符 |

一个「可以让用户手输/口述」的 Key 最多容纳 ~30 个字符。
**自含后量子签名的短 License Key 在数学上不可能存在。**

## 决策

拆成三种工件，各司其职：

### 5.1 `LicenseKey (LK)` —— 短标识符（默认，面向所有用户）

```
CL1-K7M2N-4PQR8-XW3TY-9BVCD
│   └─────── 100 bit 随机 key_id（Crockford Base32，去除易混字符）
└── 版本前缀（含 product 短码）
最后 1 组的低位含 CRC-16 校验位，用于本地即时纠错提示
```

- **不含签名**，纯标识符 + 校验位。防猜测靠 100 bit 熵 + 服务端限流。
- 激活时发送给服务端换取 `MachineCredential`。
- **这是 99% 用户的路径**：有网 → 输入 Key → 激活 → 之后长期离线可用。

### 5.2 `OfflineLicenseKey (OLK)` —— 自含签名凭证（air-gapped）

- 格式：`.clk` 文件 或 长 Base32 blob 或 QR（分片）。
- 套件 CL-CMP-1（FN-DSA-512 + Ed25519 混合）→ 约 730 B 签名，整体约 1.1–1.5 KB → 单个 QR 勉强可容（QR v40 最多 2953 B 二进制）。
- 含：license_id、entitlements、not_after、可选的 fingerprint 绑定、suite_id、epoch_key_id。
- 客户端用内置的 pinned root 公钥离线验证，无需任何网络。

### 5.3 离线激活的挑战-响应（`ActivationRequest` / `ActivationResponse`）

真正的 air-gapped 激活流程（设备永不联网）：

```
[离线设备] copylocker activate --offline
   → 生成 AR 文件 / QR：{fingerprint, nonce, device_kem_pk, product_id, license_key}
[用户带到联网设备] 上传到 Vendor 门户 / 用手机扫码
[服务端] 校验席位 → 签发 MachineCredential（对 device_kem_pk 密封）
   → 输出 AResp 文件 / QR
[离线设备] 导入 AResp → 验签 → 解封 → 落地本地凭证
```

这解决了「OLK 可以被无限复制到多台机器」的问题——AR/AResp 流程天然绑定设备指纹与席位。

## 决策矩阵：什么时候用什么

| 场景 | 工件 |
|---|---|
| 普通买断制桌面软件，用户有网 | LK + 在线激活 → MC |
| 用户偶尔无网，激活时有网 | 同上（MC 本身就支持长期离线） |
| 设备**永久**无网（内网/军工/工控） | AR/AResp 挑战-响应 |
| 批量预授权、不需要设备绑定、可接受被复制 | OLK（明确标注为"低强度模式"） |
| Mode E 强制在线 | 账号登录 → MC，无 LK |

## 备选方案与否决理由

| 方案 | 否决 |
|---|---|
| 短 Key 内嵌对称 HMAC（客户端持共享密钥离线验证） | 共享密钥必然被从客户端提取 → 通用 keygen。**绝对禁止** |
| 短 Key + 截断签名 | 截断签名不安全，破坏安全证明 |
| 短 Key + 服务端在线才能验证 | 就是 5.1 的方案 |
| 只提供 OLK | UX 差；且不绑定设备则可无限复制 |

## 后果

- 文档必须清楚说明「License Key 本身不是凭证」，避免使用者误以为可以离线验证 LK。
- Vendor 门户需要提供「离线激活」网页（上传 AR / 扫码 → 下载 AResp）。CLI 与最小控制台都要覆盖。
- OLK 路径必须在文档中标注安全权衡，默认关闭，需 Policy 显式开启。
