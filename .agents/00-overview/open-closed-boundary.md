# 开源 / 闭源边界

## 1. 原则

半开源的目的不是「藏住安全性」，而是制造**成本不对称**：

- **开源部分**保证系统可审计、可被信任、可被生态采用；安全性完全建立在标准密码学与密钥保密之上。
- **闭源部分**保证「针对 CopyLocker 的通用破解工具」无法直接复用到使用私有套件的厂商上；
  每个厂商还可以进一步用自己的套件参数，使破解从「一次编写全网通用」退化为「逐厂商定制」。

> **红线**：任何一条安全属性都不允许仅依赖闭源部分的保密性。
> 评审时的判定标准：*假设私有套件源码今天被完整公开，系统是否仍然安全？* 答案必须是「是，降级为 CL-STD-1 的安全等级」。

## 2. 仓库拆分

```
github.com/<org>/copylocker                 [Public, GPL-3.0-only]
├── crates/copylocker-types
├── crates/copylocker-suite          ← trait 定义（槽位契约）
├── crates/copylocker-suite-std      ← CL-STD-1 开源参考套件
├── crates/copylocker-suite-compact  ← CL-CMP-1 紧凑签名套件
├── crates/copylocker-proto
├── crates/copylocker-core
├── crates/copylocker-client
├── crates/copylocker-fingerprint
├── crates/copylocker-store
├── crates/copylocker-server-core
├── crates/copylocker-worker
├── crates/copylocker-wasm
├── crates/copylocker-tauri
├── crates/copylocker-node
├── crates/copylocker-ffi
├── crates/copylocker-cli
├── packages/web | electron | tauri | unplugin | guard | admin-sdk
├── .agents/                          ← 本文档与仓库级 skills（公开）
└── private/copylocker-suite-priv     ← 可选 submodule gitlink；默认不初始化

git.<internal>/<org>/copylocker-suite-priv  [Private, 商业许可；独立仓库]
├── crates/copylocker-suite-priv     ← CL-PRIV-1 实现，仅依赖 copylocker-suite + copylocker-types
├── crates/copylocker-suite-priv-gen ← 厂商参数生成器（vendor seed → suite params）
├── vectors/                          ← 内部 KAT（不公开）
└── docs/                             ← 内部密码学设计说明与自审记录
```

### 关键约束

1. **依赖方向单向**：`copylocker-suite-priv` → `copylocker-suite`（公开）。
   公开源码、默认 manifest 与 lockfile **不得**依赖私有 crate；边界文档与可选 submodule
   gitlink 可以标明其位置。
2. 公开仓库必须能**独立**编译、测试、运行、发布，CI 不接触私有仓库。
3. 私有仓库有独立 CI，跑「与公开 trait 契约的一致性测试套件」（`copylocker-suite-testkit`，公开）。
4. 私有仓库固定挂载到 `private/copylocker-suite-priv`；未获授权的开发环境不初始化 submodule。
5. 私有 crate 通过私有 registry 或 submodule path 仅进入获授权的组合构建，不进入公开 release job。
6. submodule 只提供源码与访问控制隔离，不改变 GPL 对组合分发的判断。

## 3. 槽位契约（Slot Contract）

私有套件唯一需要实现的是 `copylocker-suite` 中的 trait 集合。这个契约本身**完全公开**：

```rust
// crates/copylocker-suite/src/lib.rs (公开)
pub trait CryptoSuite: Send + Sync + 'static {
    const SUITE_ID: SuiteId;              // 4 字节，写进每个凭证头部
    type Sig:  SignatureScheme;
    type Kem:  KeyEncapsulation;
    type Aead: AeadScheme;
    type Kdf:  KeyDerivation;
    type Hash: HashScheme;
    type Fpr:  FingerprintScheme;
    type Codec: ArtifactCodec;            // 凭证编码（可私有化：非标准布局/混淆编码）
    type Binder: DeviceBinder;            // 指纹 → 密钥调度的绑定变换（私有化重点）

    /// 厂商参数化：同一算法，不同厂商不同常量/域分隔/编码扰动
    fn with_vendor_params(params: &VendorParams) -> Self;
}
```

完整定义见 [`03-modules/80-private-suite.md`](../03-modules/80-private-suite.md)。

## 4. 私有套件可以私有化什么 / 不可以

| 可以（且推荐） | 不可以（红线） |
|---|---|
| 域分隔字符串、上下文标签、KDF info 的构造方式 | 自创分组密码、自创哈希函数、自创签名方案 |
| 凭证的二进制编码布局、字段顺序、填充与掩码 | 用编码混淆替代真正的认证加密 |
| 指纹属性集合、规范化方式、权重与容错策略 | 把密钥 hardcode 进客户端来实现"离线校验" |
| 密钥调度中把设备指纹混入的方式（DeviceBinder） | 依赖 security-by-obscurity 承担机密性 |
| 参数集选择（ML-DSA-65 vs 87、KEM 强度、AEAD 选择） | 降低标准算法的安全参数以换性能 |
| 反调试/环境探针的具体实现与阈值 | 让探针失败等价于验证通过（fail-open 到不安全） |
| 每厂商衍生的常量表（由 vendor seed 经 KDF 生成） | 让不同厂商共享同一份私有常量 |
| WASM 导出符号名的每构建随机化方案 | — |

## 5. 许可与商业模式

| 组件 | 许可 |
|---|---|
| 公开仓库全部原创代码与文档 | `GPL-3.0-only` |
| `copylocker-suite-priv` | 商业许可，按 Vendor 授权，含厂商专属参数种子 |
| 托管服务（未来） | 订阅制 |

**销售命题**：开源版本足以让你上线并保证安全；私有套件版本让攻击者无法复用别人的破解成果。

### GPL 与私有组合分发

- submodule、私有 registry 或单向依赖都不会自动形成 GPL linking exception。
- 向第三方分发包含私有 crate 的单一二进制前，必须选择以下路径之一：取得公开组件的
  独立商业许可、把私有能力隔离为独立进程/服务，或经法律审查确认完整履行 GPL 义务。
- 仅内部使用或由 CopyLocker 托管、不向客户交付私有二进制的模式仍须由适用法律与合同确认。
- 详细政策见仓库根目录 `LICENSING.md`。这不是法律意见。

## 6. 构建时的组装方式

公开 checkout 不初始化私有 submodule，且默认 `Cargo.toml` 只使用公开套件：

```bash
git clone https://github.com/<org>/copylocker.git
cargo test --workspace
```

取得私有仓库权限且其真实 remote 已写入 `.gitmodules` 后，授权构建可显式初始化：

```bash
git submodule update --init --recursive private/copylocker-suite-priv
```

私有仓库维护自己的组合构建 manifest；不得把私有依赖写回公开 workspace。概念上的应用侧
选择如下：

```toml
[dependencies]
copylocker-client = "1"

# 开源用户（默认）
copylocker-suite-std = "1"

# 私有套件用户
# copylocker-suite-priv = { version = "1", registry = "copylocker-private" }
```

```rust
// 开源
type Suite = copylocker_suite_std::ClStd1;
// 私有
// type Suite = copylocker_suite_priv::ClPriv1;

let client = CopyLockerClient::<Suite>::new(config);
```

- 套件通过**泛型参数单态化**，不走 `dyn`，避免运行时可替换的 vtable 成为攻击面。
- 服务端同理：Worker 编译期选定套件；支持同时启用多套件用于迁移期（按凭证头部 `suite_id` 分派）。

## 7. 贡献与安全披露

- 公开仓库接受 PR，但**密码学核心目录**（`copylocker-suite*`, `copylocker-proto`）需两名 maintainer 审核 + 必过 KAT。
- 安全漏洞走 `SECURITY.md` 私下披露流程，90 天协调披露窗口。
- 私有套件的漏洞不公开细节，仅发布「请升级到 x.y.z」与影响范围。
