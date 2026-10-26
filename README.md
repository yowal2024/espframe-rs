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

## 来源

初始提取于 2026-10-27，来自 UamEdge 中继承的 EspFrame；原始 DeltaEdge 提交为 `4520a0eb9f4f1cb99ca4402908fc95fa8071e9f4`。提取前的差异均为项目命名替换。独立化调整包括通用日志命名及兼容入口、可配置的 DFCOL 导出前缀、本地测试数据和构建说明。

测试数据中的历史 schema 和 provenance 保留原值。xDL 的原有声明位于 [LICENSE.xDL](src/xdl/LICENSE.xDL)，SoLoader 的来源与许可标注见 [模块说明](src/soloader/README.md)；此次提取保留这些声明。
