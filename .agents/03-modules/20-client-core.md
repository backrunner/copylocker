# 模块：客户端核心（`copylocker-core` / `-client` / `-store` / `-fingerprint`）

需求：FR-CLI-*、NFR-PORT-001、NFR-PERF-004/007

## 1. `copylocker-core` —— 纯领域核心

**设计约束（不可妥协）**：无 I/O、无 `std::time`、无随机源、无网络。
所有外部输入以参数传入 → 100% 确定性、可回放、可 fuzz。

```rust
#![no_std] // + alloc
#![forbid(unsafe_code)]

pub struct Core<S: CryptoSuite> {
    state:  LicenseState,
    cred:   Option<StoredCredential>,   // MC + 派生材料（内存中 zeroize）
    clock:  ClockState,
    chain:  VerifiedChain,              // pinned roots + 当前 epoch cert
    rev:    RevocationState,
    cfg:    CoreConfig,
}

pub enum Event<'a> {
    Tick { now: i64 },
    NetworkAvailable,
    AppResumed { monotonic_gap_ms: u64 },
    CredentialLoaded(&'a [u8]),
    ActivationResponse(&'a [u8]),
    ValidationResponse(&'a [u8]),
    NetworkFailed(NetFailKind),
    IntegrityResult(IntegrityReport),
    UserDeactivate,
}

pub enum Effect {
    Persist(PersistTarget, Vec<u8>),
    SendValidation { body: Vec<u8>, nonce: [u8; 32] },
    SendActivation { body: Vec<u8> },
    WipeAll,
    StateChanged(LicenseState, StateReason),
    ScheduleWake { at: i64 },
}

impl<S: CryptoSuite> Core<S> {
    pub fn handle(&mut self, ev: Event<'_>, now: i64, rng: &mut dyn CryptoRng) -> Vec<Effect>;
    pub fn derive_feature_key(&self, feature: &str) -> Result<Secret<[u8;32]>, CoreError>;
    pub fn state(&self) -> LicenseState;   // ⚠️ advisory only —— 文档明确标注
}
```

### 1.1 错误类型的强制分离（FR-CLI-006）

```rust
/// 网络/瞬态失败 —— fail-open，进入 Grace
#[non_exhaustive]
pub enum TransientError { Offline, Timeout, ServerError(u16), RateLimited { retry_after: u32 } }

/// 密码学/协议/吊销失败 —— fail-closed，立即失效
#[non_exhaustive]
pub enum FatalError {
    SignatureInvalid, ChainInvalid, EpochRevoked, NonceMismatch,
    MachineMismatch, RevocationRollback, Revoked(KillReason), CredentialCorrupt,
}
```

- 两个类型**没有** `From` 相互转换，也没有共同的父 enum。
- `handle()` 对 `TransientError` 与 `FatalError` 走完全不同的分支。
- Clippy 自定义 lint（或 code review checklist）确保不出现 `Err(_) => fail_open()` 这类通配。

### 1.2 状态机实现

见 [`system-architecture.md` §6](../02-architecture/system-architecture.md) 的迁移表。
实现为显式的 `match (state, event)`，**穷尽匹配、无 `_ =>` 通配**，
新增状态/事件时编译器强制处理所有组合。

```rust
match (self.state, &ev) {
    (Active, Event::ValidationResponse(b)) => match self.verify_ticket(b, now) {
        Ok(Verdict::Ok(vt))   => self.apply_ticket(vt, now),
        Ok(Verdict::Kill(ko)) => self.revoke(ko),               // 立即擦除
        Err(FatalError::..)   => self.tamper(),
    },
    (Active, Event::NetworkFailed(_)) => vec![],                // 无状态变化
    (NeedsRevalidation, Event::NetworkFailed(_)) => self.enter_grace(now),
    // ... 全部组合显式列出
}
```

### 1.3 Clock Guard

```rust
pub struct ClockState {
    last_seen_max: i64,        // 持久化，多处冗余
    last_server_time: i64,     // 最近一次 VT 中的服务端时间
    boot_monotonic_base: i64,  // 本次会话启动时的墙钟，与单调时钟配对
    rollback_events: u32,
}
```

规则：
1. 所有剩余期限的计算用 `effective_now = max(wall_clock, last_seen_max)`。
   → 回拨时钟**不会**延长任何期限。
2. 若 `wall_clock + SKEW < last_seen_max` → `rollback_events += 1`，
   状态转 `NeedsRevalidation` 并立即请求在线校验。
3. `rollback_events > threshold`（默认 3）且无法联网 → 直接 `Locked`（可 Policy 配置）。
4. 会话内用单调时钟交叉验证：若单调时钟走了 10 分钟但墙钟走了 10 天 → 记录异常。
5. `ClockState` 与 MC 一起放在被 AEAD 保护的 blob 里（篡改 = 验签失败）。

### 1.4 触发调度（`copylocker-client::scheduler`）

```
触发源                              条件                          实现
─────────────────────────────────────────────────────────────────────────
应用启动                            总是                          初始化时
网络恢复                            offline → online              平台事件监听
系统唤醒                            resume 事件                    平台事件监听
周期定时                            now > next_check_at            定时器
插桩点调用                          距上次校验 > min_interval      derive_feature_key 内触发
任意网络请求成功（宿主可上报）        距上次校验 > min_interval      公开 hint API
```

**退避与抖动**（防惊群 + 防被识别为固定模式）：

```rust
next_check_at = last_success + refresh_after * (0.85 + rand() * 0.30)
// 失败后：base * 2^min(fail_count, 6)，上限 6h，同样加 ±15% 抖动
```

**并发保护**：同一时刻只允许一个在途校验请求（`AtomicBool` guard），
避免多个触发源同时打服务端。

### 1.5 Feature Key 派生

见 [`crypto-architecture.md` §6](../02-architecture/crypto-architecture.md)。

```rust
pub fn derive_feature_key(&self, feature: &str) -> Result<Secret<[u8;32]>, CoreError> {
    let cred = self.cred.as_ref().ok_or(CoreError::NoCredential)?;
    // 状态检查在这里，但失败返回 Err 而非 bool，且调用方拿不到密钥
    if matches!(self.state, Locked | Revoked | Tampered) { return Err(CoreError::NotEntitled); }
    if !cred.entitlements.features.iter().any(|f| f == feature) {
        return Err(CoreError::NotEntitled);
    }
    let session_root = self.session_root()?;   // 在线用 VT.server_nonce；离线用 MC.offline_nonce
    Ok(S::Kdf::expand_key(&session_root, &[b"copylocker/fk/v1", product_id, feature.as_bytes()]))
}
```

- `Secret<T>` 是 `ZeroizeOnDrop` 包裹，不实现 `Debug`/`Clone`/`Display`。
- 副作用：调用时若 `now > next_check_at` 则 push 一个 `Effect::SendValidation`（插桩即触发）。

## 2. `copylocker-store` —— 本地安全存储

### 2.1 平台后端

| 平台 | 主存储 | 备份 |
|---|---|---|
| macOS | Keychain（`security-framework`），item 带 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | `~/Library/Application Support/<app>/cl.bin`（AEAD） |
| Windows | DPAPI（`CryptProtectData`, `CRYPTPROTECT_LOCAL_MACHINE` 可选）+ Credential Manager | `%LOCALAPPDATA%\<app>\cl.bin`（AEAD） |
| Linux | Secret Service（`libsecret` via DBus），失败则纯文件 | `$XDG_DATA_HOME/<app>/cl.bin`（AEAD） |
| Web | IndexedDB + 非可提取 `CryptoKey`（`extractable: false`）包裹 | — |

### 2.2 加密与冗余

```
磁盘上的 blob = AEAD.seal(
    key   = HKDF(os_protected_secret ‖ fingerprint_material, "cl-store/v1"),
    nonce = random 24B,
    aad   = app_id ‖ store_version ‖ platform_tag,
    pt    = CBOR{ mc_envelope, device_kem_sk, device_sig_sk, clock_state, rev_state }
)
```

- `os_protected_secret`：由 keychain 保管的 32 字节随机值（首次运行生成）。
- **双写**：keychain + 文件；读取时取二者中 `clock_state.last_seen_max` 更大的一份，
  防止"删除文件即重置时钟高水位"。
- Web 端：`device_kem_sk` 尽可能用 WebCrypto 非可提取密钥（X25519 部分可以；
  ML-KEM 部分 WebCrypto 尚不支持 → 该部分只能软件保管，文档标注为 Web 端固有弱点）。

### 2.3 API

```rust
pub trait KeyStore {
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError>;
    fn save(&self, blob: &[u8]) -> Result<(), StoreError>;
    fn wipe(&self) -> Result<(), StoreError>;     // 必须覆写而非仅 unlink
}
```

`wipe()` 语义：删除 keychain item + 覆写文件内容后删除 + 清理平台冗余位置。

## 3. `copylocker-fingerprint` —— 设备指纹

### 3.1 属性集（公开列出，供 Vendor 写隐私政策）

| 平台 | 属性 | 权重 | 稳定性 |
|---|---|---|---|
| Windows | `MachineGuid`（注册表）| 40 | 重装系统会变 |
| | `Win32_Processor.ProcessorId` | 15 | 高 |
| | `Win32_BaseBoard.SerialNumber` | 15 | 高 |
| | 系统盘 `VolumeSerialNumber` | 10 | 格式化会变 |
| | `InstallDate` | 10 | 高 |
| | MAC 地址集合（排除虚拟网卡） | 5 | 中 |
| | 主机名 | 5 | 低 |
| macOS | `IOPlatformUUID` | 45 | 极高 |
| | 硬件型号 + 序列号 | 20 | 极高 |
| | 启动卷 UUID | 15 | 中 |
| | MAC 地址集合 | 10 | 中 |
| | 主机名 | 10 | 低 |
| Linux | `/etc/machine-id` | 40 | 高 |
| | DMI product_uuid / board_serial | 20 | 高（容器内不可用） |
| | 根文件系统 UUID | 15 | 中 |
| | MAC 地址集合 | 15 | 中 |
| | 主机名 | 10 | 低 |
| Web | 持久化随机 device_id（IndexedDB + localStorage 双写） | 60 | 中（清缓存会丢） |
| | UA-CH（平台、架构、位数） | 15 | 高 |
| | `hardwareConcurrency`、`deviceMemory` | 10 | 中 |
| | 时区 + 语言 | 5 | 低 |
| | Canvas/WebGL 渲染器字符串（**可选，默认关闭**，隐私敏感） | 10 | 中 |

### 3.2 规范化与输出

```rust
pub struct DeviceAttrs { entries: BTreeMap<AttrKey, AttrValue> }  // 有序 → 确定性

fingerprint = HMAC-SHA256(vendor_salt, canonical_cbor(attrs))
```

- **规范化规则**必须严格定义（大小写、空白、集合排序、缺失属性的表示），
  写进 `copylocker-suite-testkit` 的一致性测试。
- 缺失属性用 `null` 而非跳过（否则不同缺失组合可能碰撞）。

### 3.3 虚拟机与容器

- 检测 VM/容器标志（hypervisor bit、DMI vendor、`/.dockerenv` 等）→ 写入 `attrs.env_class`。
- Policy 的 `allow_vm = false` 时服务端拒绝激活。
- 云环境（节点共享硬件）建议 Policy 走"随机 UUID 指纹"模式：
  客户端生成随机 device_id 持久化，不采集硬件属性。

### 3.4 隐私

- 默认只上报 `fingerprint` 摘要。
- 上报 `attrs`（用于容差匹配）需 Vendor 显式开启 `report_attrs = true`，
  且 SDK 初始化时要求传入 `privacy_ack: true`（强制开发者意识到）。
- 提供 `FingerprintProvider` trait，Vendor 可完全自定义（如只用自家账号 ID）。

## 4. `copylocker-client` —— Facade

```rust
pub struct CopyLockerClient<S: CryptoSuite> { /* Core + Transport + Store + Scheduler */ }

impl<S: CryptoSuite> CopyLockerClient<S> {
    pub async fn new(cfg: Config) -> Result<Self>;
    pub async fn activate(&self, key: &str) -> Result<(), ActivateError>;
    pub async fn activate_with_account(&self, token: &str) -> Result<(), ActivateError>;
    pub async fn deactivate(&self) -> Result<(), ActivateError>;

    /// 唯一的"使用授权"入口 —— 返回密钥而非 bool
    pub fn feature_key(&self, feature: &str) -> Result<Secret<[u8;32]>, CoreError>;
    /// 便捷封装：直接解封受保护资产
    pub fn unseal(&self, feature: &str, sealed: &[u8]) -> Result<Vec<u8>, CoreError>;

    /// 建议在网络请求成功后调用，作为"可能在线"的提示
    pub fn hint_online(&self);
    /// 仅用于 UI 展示
    pub fn state(&self) -> LicenseState;
    pub fn subscribe(&self) -> impl Stream<Item = StateChange>;

    /// 离线激活
    pub fn build_offline_request(&self) -> Result<Vec<u8>>;
    pub fn import_offline_response(&self, data: &[u8]) -> Result<()>;
    pub fn import_olk(&self, armored: &str) -> Result<()>;
}
```

**API 设计红线**
- 无 `is_valid()` / `is_licensed()` / `check() -> bool`。
- `state()` 的 rustdoc 首行必须是：
  `/// ⚠️ Advisory only. Do NOT gate features on this value — use `feature_key()`.`
- 传输层用 `trait Transport`，默认 `reqwest`（桌面）/ `fetch`（wasm）。

## 5. 测试

| 类型 | 内容 |
|---|---|
| 状态机穷尽测试 | 所有 (state, event) 组合的迁移断言 |
| 属性测试 | 随机事件序列下不变式：`Locked` 后不能不经在线校验回到 `Active` |
| 时钟测试 | 回拨 1 天 / 1 年 / 前进 10 年 / 高水位删除 |
| 跨机测试 | 复制 store blob 到另一指纹环境 → 必失败 |
| Fuzz | `handle()` 的所有字节输入路径 |
| 回放测试 | 记录真实事件序列，回放验证确定性 |
