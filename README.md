# EspFrame

供多个 Android 项目复用的 Rust 原生组件库，Cargo 包名为 `espframe`。独立仓库包含源码、示例和测试固定数据，可以单独运行 Cargo 测试，也可以作为 Git 依赖或子模块加入调用方 workspace。

## 接入

~~~toml
[dependencies]
espframe = { git = "ssh://git@github2.com/yowal2024/espframe-rs.git", branch = "main", default-features = false, features = ["xdl", "jni", "binder"] }
~~~

该地址使用本机配置的 SSH 别名 `github2.com`。使用子模块时可保持路径依赖：

~~~toml
espframe = { path = "../espframe", default-features = false, features = ["xdl", "jni", "binder"] }
~~~

| Feature | 用途 |
| --- | --- |
| `xdl`（默认） | Android 符号解析，以及窗口、输入、渲染和传感器模块 |
| `jni` | JNI 交互及显示查询 |
| `binder` | Android 原生 Binder 显示查询 |
| `soloader` | 内存 ELF 加载器 |

认证模块接收调用方提供的服务地址、appid、APPKEY、TLS 材料及握手公钥。库内不提供任何应用的生产认证凭据。

DFCOL 上传器的默认导出前缀为 `EspFrame_`。现有项目需要显式指定自己的前缀：

~~~rust,ignore
let uploader = espframe::physics::dfcol::DfcolUploader::with_symbol_prefix(
    remote,
    memory,
    c"Uam_", // DeltaEdge 使用 c"Delta_"；其他应用指定自身的导出前缀。
);
~~~

DFCOL 的包格式、目录和固定大小校验沿用已有协议；支持不同资源包不等于只更换导出前缀。

日志使用 `espframe_log!`，编译期变量为 `ESPFRAME_NATIVE_LOG` 和 `ESPFRAME_MEMORY_LOG`，默认关闭。为已有调用方保留 `uam_inject_log!`、`delta_inject_log!`；环境变量依次采用 `ESPFRAME_*`、`UAM_*`、`DELTA_*` 中第一个已设置的值，显式的 `0` 或空值仍优先。

## 构建与测试

工具链固定为 Rust 1.94.0。仓库自带 Cargo.lock；调用方 workspace 使用其自己的锁文件。

~~~powershell
cargo test --locked --all-features
cargo check --locked --no-default-features
~~~

Android 使用 ARM64、API 31 起的构建配置。Windows 上的 NDK、libclang 和 Binder 参数见 [窗口构建说明](src/window/README.md)，设备示例见 [Android 回归说明](tests/android/README.md)。宿主机测试通过不能证明所有 Android 私有 ABI 在所有 ROM 上可用。

## 模块

| 模块 | 内容 |
| --- | --- |
| `auth` | 认证传输、会话、心跳和远端配置 |
| `kernel`、`inject` | 内核 ABI、目标内存和远程调用抽象 |
| `window`、`render` | 显示查询、Surface、输入和渲染 |
| `ue`、`math`、`projection` | UE 结构、数学和投影 |
| `physics::dfcol` | DFCOL 包解析、碰撞查询和上传事务 |
| `monarch` | ARM64 执行与系统服务模型 |
| `xdl`、`soloader` | 动态符号和 ELF 加载 |
| `sensor`、`gyro_aim` | 传感器与角速度控制 |

## 可选的 D-cache 清理读取

配套内核支持 `CallMemory_Dcache = 0x10` 时，可通过
`CallMemoryFlags::Read | CallMemoryFlags::Dcache` 显式开启读取前的缓存清理。
内核仅在普通读取到用户缓冲区时执行 `dc cvac` 和 `dsb sy`；写入、
`NoCache`（包括 `NoCache | Io`）和内核目标缓冲区均不执行。
公开的内存调用入口会在内核内部补上 `CallMemory_User`，调用方无需手动设置。

`CallMemoryFlags::for_mem_mode()` 和默认读取行为保持原样，不自动开启该标志。
清理到一致性点不保证游戏相机与显示画面同帧，也不保证降低延迟。

## RSA redirect 内核接口

`kernel::KernelDriver` 通过统一的 `CMD_NET_SPOOF_*` 命令提供 UAM 网络接口，
首参数固定为 `SpoofType::Uam`（0）；命令接在 `CMD_GYRO_EVENT_CONFIGURE` 后
连续递增（`0x1003d`–`0x10040`）。需要配套使用统一 TYPE 布局的内核模块，
目标 UID 仍通过内核已有 `add_black_user` 路径登记。
这些方法不使用 `KernelDriver::Pid()`，也不接收包名或文件描述符。

| 方法 | 返回 | 用途 |
| --- | --- | --- |
| `UamNetSet(&config)` | `Result<(), isize>` | 登记一份配置，同步复制借用缓冲 |
| `UamNetStop(expected_crc)` | `Result<(), isize>` | 删除配置、文件绑定及其排队结果 |
| `UamNetRead(&mut records)` | `Result<RsaRedirectReadStats, isize>` | 消费最多 16 条 key/nonce 结果 |
| `UamNetStats()` | `Result<RsaRedirectStats, isize>` | 读取配置数量和全局计数 |

以下密钥、CRC 和 entry 数据由调用方从自己的应用构建产物提前准备：

~~~rust,ignore
use espframe::kernel::{RsaRedirectConfig, RsaRedirectFile};
use espframe::kernel::abi::{RsaRedirectResult, RSA_REDIRECT_READ_MAX};

let config = RsaRedirectConfig {
    expected_crc,              // CRC32(替换密钥的 256 字节小端模数)
    original_crc,              // CRC32(原业务公钥的 256 字节小端模数)
    key_id,                    // 协议中的 KeyId，u8
    capture_pid: 0,            // 可在目标进程启动前注册；不限制结果 PID
    private_der: &replacement_private_der,
    public_der: &original_public_der,
    file: Some(RsaRedirectFile {
        original_entry: &original_entry,
        replacement_entry: &replacement_entry,
    }),
};
driver.UamNetSet(&config)?;

// 在 SET 成功后启动目标应用，并在管理端定期读取。
let mut records = [RsaRedirectResult::default(); RSA_REDIRECT_READ_MAX];
let batch = driver.UamNetRead(&mut records)?;
for record in &records[..batch.count as usize] {
    // record.key: [u8; 32]，record.nonce: [u8; 8]
    // 用 pid/remote_addr 关联会话；sequence 用于重试去重。
}
let stats = driver.UamNetStats()?;

// 停止该配置；更新时先 STOP 再 SET。
driver.UamNetStop(expected_crc)?;
~~~

两份密钥必须是 RSA-2048 / PKCS#1 DER。`file: None` 只启用回封；`Some` 仅提供
原/新 entry 字节模式（等长，1..4096 字节），不接收文件偏移或要求调用方打开源文件。
内核复用同一 `vfs_read` inline hook，在匹配 UID 的实际 `read/pread` 返回区间附近
进行有界精确搜索，只有唯一配置和唯一位置才绑定实际文件并替换重叠字节；不覆盖
`mmap/readv`，SET 成功不等于文件已匹配。`capture_pid` 的正值只过滤结果，回封始终按
UID、KeyId 和 CRC 匹配。最多 8 份配置；相同原始 FILE 模式在 SET 时冲突，不同模式
可共存。读取区间出现多个候选配置或位置时返回 `-76`（ENOTUNIQ），不新增绑定或改写。
DEL 不删除已有 UID 登记；RSA 配置与 Signs 模式互斥。

SET 请求为 72 字节、8 字节对齐，不包含文件偏移、整包大小、哈希或版本字段。
结果记录仍为 80 字节，STATS 仍为 64 字节；IPv4 地址使用 `::ffff:a.b.c.d`。
APK 与内核须按同一调用约定配套升级，无旧结构回退。RSA 沿用自身的目的缓冲写入错误
处理，不声明 Signs 的全页 pin/verify 后写入保证。

错误返回负 errno：例如 `-22` 为参数错误、`-17` 为重复配置；越界计数
或异常正返回值报告 `-71`（EPROTO），其余内核错误保留原值。READ 成功后只使用
`records[..batch.count]`，出错时忽略缓冲；`batch.dropped` 为 64 条内核队列累计溢出数。
记录的地址为网络字节排列，其他整数为主机字节序。接口不会输出会话密钥日志。

针对接口的宿主机测试：`cargo test --locked -p espframe --no-default-features --test kernel_rsa_redirect`。
这组测试使用 transport 替身验证真实驱动封装，不代表已在 Android 设备上调用新版内核。

## 来源

初始提取于 2026-10-27，来自 UamEdge 中继承的 EspFrame；原始 DeltaEdge 提交为 `4520a0eb9f4f1cb99ca4402908fc95fa8071e9f4`。提取前的差异均为项目命名替换。独立化调整包括通用日志命名及兼容入口、可配置的 DFCOL 导出前缀、本地测试数据和构建说明。

测试数据中的历史 schema 和 provenance 保留原值。xDL 的原有声明位于 [LICENSE.xDL](src/xdl/LICENSE.xDL)，SoLoader 的来源与许可标注见 [模块说明](src/soloader/README.md)；此次提取保留这些声明。
