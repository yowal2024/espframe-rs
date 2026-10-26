# Android 12-16 Surface 与显示查询

本实现面向 Android 12、12L、13、14、15、16，当前验证目标为 ARM64。
推荐最低构建 SDK 为 31；Android 17/SDK 37 不会自动套用旧 Binder 布局或镜像 ABI。
调用方的 compileSdk/targetSdk 不代表私有 Surface/Binder 协议已完成相同版本适配；原生兼容范围按运行设备的版本检查。
Android 编译和 host 测试不代表所有厂商系统都已实机验证。

## 查询与绘制边界

主屏窗口、尺寸和方向仍使用现有 libgui SurfaceComposerClient 实现。
镜像显示枚举通过 `AndroidSurfaceComposerBackend::SetDisplayQueryMode` 设置：

| 模式 | 行为 |
| --- | --- |
| `DisplayQueryMode::Auto` | espframe 默认；检查实际 Binder 对象，远程服务使用 Binder，本地服务使用 JNI；未启用 binder feature 时使用 JNI |
| `DisplayQueryMode::Jni` | 只使用 JNI；失败直接返回错误 |
| `DisplayQueryMode::Binder` | 只使用原生 Binder；失败直接返回错误 |

显式选择未启用的 feature 会立即报错并保留原设置。切换后会使镜像查询缓存失效，下次更新立即重新获取。
调用方创建显示后端时可以选择 **Auto**：

```rust
let mut backend = AndroidSurfaceComposerBackend::ResolveProduction(skip_screenshot)?;
backend.SetDisplayQueryMode(DisplayQueryMode::Auto)?;
let service = NativeWindowService::new(backend);
```

需要切换时修改这一行，读取当前模式可调用 `backend.DisplayQueryMode()`。
日志 `surface.mirror.query_mode` 记录模式切换；`surface.mirror.auto_backend` 记录 `remote=true/false` 和所选后端。
Auto 探测失败、所选后端不可用或查询失败时直接返回错误，不再尝试另一条路径。
此设置作用于镜像显示枚举，主屏的 libgui 窗口和尺寸查询保持上述路径。

JNI 沿用 main 的查询链：

```text
DisplayManagerGlobal.getDisplayIds()
  -> LocalServices.getService(DisplayManagerInternal.class)
  -> DisplayManagerInternal.getDisplayInfo(id)
```

Binder 模式直接使用下面的查询链；Auto 模式下，实际服务对象为远程 Binder 时使用该链（需启用 `binder` feature）：

```text
ServiceManager: display
  -> android.hardware.display.IDisplayManager
  -> getDisplayIds / getDisplayInfo
```

Binder 使用固定提交的 [yowal2024/binder_rs](https://github.com/yowal2024/binder_rs/tree/6627342872bf62ddea05e2d8f98f4fda3120256d)，Cargo 包名为 `binder_ndk`。
它负责 Binder 对象、事务和 Parcel 生命周期，项目负责 DisplayInfo 私有协议解码。
不会注册服务、修改 Binder 线程池或启动额外采集线程；没有 dumpsys、shell、文本解析回退。
调用按 main 每秒节流。同步 JNI/Binder 仍可能受系统服务延迟影响，节流不是超时保障。
Binder 以调用方的实际身份访问服务；运行环境至少为用户约定的 shell 权限。

### 本地与远程 Binder

纯 native 客户端不等于服务由 native 实现。独立进程访问 `display` 时走远程 Binder，客户端不需要 JavaVM；服务端可以由 Java 实现。
与服务同进程时拿到的是本地 `JavaBBinder`，连 `AIBinder_associateClass` 的描述符检查都可能进入 Java，不能在未附加 JVM 的原生线程上直接调用。
Auto 在关联接口前用 `AIBinder_isRemote` 检查实际对象：远程对象关联后缓存并复用同一连接；本地对象不关联、不缓存，改用 JNI 显示查询。不能根据 JVM 存在、UID 或进程名推断本地/远程。
本地 Java Binder 的引用释放同样可能进入 Java。当 JNI 与 Binder 均启用且存在 VM 时，Auto 将获取服务、探测、释放本地引用和查询都放在已有 JNI 附加作用域内，避免环境过早失效。
VM 查询失败或返回格式异常会明确报错，不能当作“没有 VM”继续探测。确认没有 VM 的独立 native 进程继续走远程 Binder；若未编入 JNI 却探测到本地服务，会报告 JNI 后端不可用。
当前 host 使用 Auto；本地 JNI 查询失败时不会改调本地 Binder。显式 Binder 模式仍拒绝本地对象并返回 `remote display Binder required`；这项拒绝检查不保证任意未附加线程上的本地 Java 对象最终析构安全。
独立示例保持纯 native 远程访问，不启动 JavaVM，也不调用 dumpsys。
此前独立进程 Binder 查询和本地对象拒绝测试的结论保持不变；Auto 的自有进程测试范围见下方验证记录。

镜像失败只影响镜像更新，不阻断主屏绘制。失败的枚举不是空列表，不会误清理全部现有镜像。
显示 token 成功时保留 owned 引用；查询失败先释放，再最多重取并查询一次。显示拓扑或主 LayerStack 变化也会失效缓存。

显示 token 返回的是 `sp<IBinder>`。Android 15 的 `IBinder` [虚继承 `RefBase`](https://android.googlesource.com/platform/frameworks/native/+/refs/tags/android-15.0.0_r1/libs/binder/include/binder/IBinder.h)，因此引用计数不能直接把 `IBinder*` 当作 `RefBase*`。
`surface.rs` 的 `acquire_display_token` 使用 `RefBaseLayout::BinderVirtual`：按 Android ARM64 Itanium ABI 从虚表 address point 前第三项读取有符号虚基偏移。`OwnedStrongPointer` 保留原始指针供显示查询使用，另外保存转换后的 `RefBase` 地址用于 `incStrong`、返回值接管和最终 `decStrong`。不能固定增加某个对象内偏移，也不能只修获取而遗漏释放。
`SurfaceControl`、`Surface` 的现有返回路径继续使用各自已约定的直接基址。回归测试位于 `surface/refbase_tests.rs`，检查不同虚基位置下查询参数与引用计数参数的区别，以及引用获取和释放是否配对。

2026-09-09 验证：28 项 Surface 相关单元测试通过，`:app:assembleRelease` 与 `:app:verifyRustApkRelease` 通过。用户在联想 TB322FC、Android 15 / SDK 35 上安装修复版后确认该次 `system_server` 闪退已解决；这项反馈仅验证上述引用计数崩溃，不代表全部窗口、镜像场景或其他机型都已验证。

同日 `20260909_205128_110_7fced2` 采集的复查：设备 APK 更新于 20:22:25，原始 tombstone 中最新的 RefBase 崩溃发生在 19:54:22，不能将旧归档当作更新后的复发。当前内核日志另有 5 组触摸中断线程 `irq/356-NVT-ts` 的 `scheduling while atomic`，调用链为 `new_input_pass_values [SyrpoWEI] → kernel_write → pipe_write → mutex_lock`，指向触摸内核回调在不可睡眠上下文等待管道锁的问题。采集对应版本的 Rust `input.rs` 使用非阻塞单事件读取并在 `EAGAIN` 后立即重试；main 保留内核返回的 fd flags，未显式设置 `O_NONBLOCK`，实际是否阻塞仍取决于内核实现。这项差异可能增加锁竞争，但尚不能确认是该异常的触发原因。5 组异常按内核时间锚点换算约发生在 20:45:05–20:48:58，晚于 20:43:57 的 `init` abort；缺少重启前的致命日志，不能据此归因此前重启，也没有管道已满或读取收到 `EINTR` 的证据。

## main 触摸监听

触摸路径对照 main 历史原生子模块提交 `92c8c8f08b727bd0794bf41b136f4bf1c71e3d3d` 的 `system/native/native_surface/event_touch.cpp/.h` 和 main 的 `module.cpp` 回调。历史源码仅用于 Git 对照，当前源码树不保留该实现。

`KernelInputBackend::new` 通过 `input/listener.rs` 的进程级监听器创建一次 fd，仅接受正数。后续 idle、局内、旋转和 supervisor 切换复用同一个 fd。`StartDetached` 启动一次独立读取线程，后续启动只替换当前回调槽，线程一直保留原来的事件缓冲和槽位状态。直接使用驱动返回的 fd，不设置 `O_NONBLOCK`，没有 `poll`、`dup` 或额外读取等待；阻塞读取不持有屏幕更新共用的后端锁。

`input/reader.rs` 每次读取 8 字节，缓冲只在读取线程启动时清零一次。与 main 的 `while (read(...) != 0)` 一致：正数和 `-1` 都处理当前缓冲并进入下一轮，错误时复用旧值；短读覆盖前缀、保留旧后缀，不拼接。只有 `read == 0` 自然返回。按用户约定退出即结束进程，不对触摸线程做主动停止、join 或 close；EOF 后也不自动重开。

`KernelInputParser::Push` 使用有符号槽位映射。新槽默认坐标为零、动作为 UP，初始化仅创建槽 0 并设为 MOVE。收到 SLOT 时选中对应槽并将其设为 MOVE；TRACKING 仅在值为 -1 时设 UP，其他值均设 DOWN；X/Y 各自更新坐标。每次 SYN_REPORT 输出全部已有槽，保留 UP 槽及坐标，不自动将 DOWN 改成 MOVE，也不以 active 状态过滤。触摸解析忽略 EV_KEY；原音量 hook 接口保留为通用组件，SurfaceFlinger 生产路径不再安装它。

屏幕更新在方向为 1/3 时交换宽高后下发，系统调用失败只记录诊断，不阻断窗口。idle 和局内的 `InputService::SetCallback` 都调用 host 的 `render/ui/touch.rs::HandleKernelTouch`：读取线程回调只处理槽 0，每次检查 `igGetCurrentContext`，上下文为空就忽略；存在时直接通过 `igGetIO_Nil` 写 MousePos。非 MOVE 动作设置 MouseDown[0] 为是否 DOWN，MOVE 保留按下状态。事件另送手势队列，由两条运行时的 `DrainInput` 使用 `TopLeftDoubleTap` 识别菜单开关，不重放 ImGui 输入。左上角正方形边长为屏幕短边的 8%；500 ms 内两次抬起切换，重复 DOWN/UP 不重复计数，拖动、长按和尺寸变化会取消。此迁移已做主机测试，尚未实机验证。

此入口采用 main 的共享 ImGui 上下文跨线程访问方式，不缓存 IO 指针，也不把 Rust `Context`/`Ui` 引用传给读取线程。空上下文检查不提供并发同步：线程测试验证回调结束后 IO 立即可见，顺序重建测试验证不会复用旧 IO 地址；这些测试不证明与渲染或上下文销毁并发时的线程安全。

启用 `ESPFRAME_NATIVE_LOG` 后，`window.input.listener.open` 记录首次创建的 fd；`window.input.read_retry` 在错误计数为 1、2、4、8…时记录 errno 文本；`window.input.reader.eof` 记录自然返回；`window.input.screen.error` 记录屏幕参数下发失败。没有逐事件日志或主动退出清理。

修改读取和旧值复用看 `input/reader.rs`，修改进程级监听和回调交接看 `input/listener.rs`，修改槽位动作看 `KernelInputParser::Push`，修改菜单触摸响应看 host 的 `render/ui/touch.rs::HandleKernelTouch`，修改触摸注册看 `runtime/bootstrap.rs`。这些对齐尚不能证明解决日志中的内核异常或设备重启，仍需 Android 15 真机复测。

2026-09-09 本次验证：12 项直接回调、UI、队列过滤和音量切换测试通过；`:app:assembleRelease` 与 `:app:verifyRustApkRelease` 通过。测试包含读取线程回调返回后立即检查 IO，不调用帧前消费或 NewFrame；上下文切换测试采用顺序销毁/重建。本次未安装 APK 到设备，未验证并发渲染/重建安全性。

## 版本矩阵

| 系统 | SDK | Binder getDisplayIds 参数 | Parcel 布局 | Surface transaction |
| --- | --- | --- | --- | --- |
| Android 12 / 12L | 31 / 32 | 无参数 | Android12 | apply(bool)，setLayerStack(uint32_t) |
| Android 13 / 14 | 33 / 34 | bool includeDisabled=false | Android13To14 | apply(bool,bool)，setLayerStack(ui::LayerStack) |
| Android 15 / 16 | 35 / 36 | bool includeDisabled=false | Android15To16 | apply(bool,bool)，setLayerStack(ui::LayerStack) |

`getDisplayInfo(int)` 是 `FIRST_CALL_TRANSACTION + 0`，`getDisplayIds` 是 `+ 1`，基于已核对的 SDK 31-36 AOSP AIDL。
Parcel 先读取 Binder Status，再读取 nullable DisplayInfo 标记。
所需字段为 displayId、LayerStack、logicalWidth、logicalHeight、rotation；必须按顺序经过 DisplayAddress、DeviceProductInfo、String8 名称和 DisplayCutout，不能按固定字节偏移跳到宽高。

Android 13 起，嵌套 `Parcel.writeValue` 的 Parcelable 带字节长度，Cutout 增加物理尺寸和像素比例；Android 15 起 Cutout 增加 sideOverrides。
解码器限制总回复 1 MiB、字符串 16 KiB、显示器数量 256，并校验截断、负长度、嵌套长度、类名、重复 ID、尺寸及方向。

`mirrorSurface` 按实际符号选择：

```text
旧：_ZN7android21SurfaceComposerClient13mirrorSurfaceEPNS_14SurfaceControlE
新：_ZN7android21SurfaceComposerClient13mirrorSurfaceEPNS_14SurfaceControlES2_
```

新签名第二参数是 `stopAt`，默认空指针，不能当父层使用。Android 16 初版仍可能是旧签名，QPR2 出现双参版本。
父子关系通过 Transaction::reparent 设置。返回的 C++ sp 通过 ARM64 间接返回存储接管，不当作普通指针返回。
缺少相应版本的可选符号时关闭镜像能力，不猜测调用原型。

根层继续使用 main 验证过的 `0x4000` 和源窗口尺寸，没有替换为 `0x80000` 容器类型。
源与目标均使用逻辑尺寸等比居中，SurfaceFlinger 已处理输出旋转，不重复叠加。
源窗口销毁、目标移除时，先隐藏与解除父子关系，再释放镜像及根层的 owned 引用。

## 文件职责

| 文件 | 职责 |
| --- | --- |
| input.rs | main 触摸槽位解析、输入服务接入、进程级监听句柄和屏幕参数更新；另保留音量双击识别 |
| input/listener.rs | 进程级单 fd/单读取线程、直接读取与当前回调交接；监听随进程结束 |
| input/listener/tests.rs | 验证 fd 与读取线程只创建一次、界面交接保留槽位状态、回调替换和 EOF 后不自动重开 |
| input/reader.rs | main 的持久 8 字节缓冲、读取错误复用旧值与 EOF 自然返回 |
| input/reader/tests.rs | 验证单事件读取、错误时重复处理旧值、短读覆盖前缀、事件顺序与 EOF |
| input/parser_tests.rs | 验证 main 的槽位默认值、切槽、TRACKING、SYN 状态保留、负槽位及按键忽略规则 |
| input/service_tests.rs | 验证 detached 接入不创建额外读取线程，回调更新和界面析构不影响进程级监听 |
| surface.rs | 主屏 ABI 计划、符号解析、窗口和显示 token |
| surface/display_cache.rs | token 有界重取与引用释放策略 |
| surface/mirror_abi.rs | 单/双参数 mirror、单/双 bool apply、LayerStack 类型的调用封装 |
| surface/mirror_android.rs | JNI/Binder 选择、镜像状态更新、事务与资源清理 |
| surface/refbase_tests.rs | 验证 IBinder 虚基地址与原始接口指针分离，以及引用获取、复制和释放的参数与顺序 |
| mirror_jni.rs | main 的 JNI 显示枚举路径 |
| mirror_binder.rs | 原生 IDisplayManager 客户端、Status 和有界 Parcel reader |
| binder_display_codec.rs | SDK 31-36 的 DisplayInfo 前缀解码与纯测试 |
| mirror.rs | DisplayQueryMode 分派、共享 DisplaySnapshot 校验、去重、布局和拓扑变化判断 |
| ../../examples/display_snapshot.rs | 不依赖 JNI 的独立 native 查询示例 |
| ../../tests/android/DisplayBinderProbe.java、display_binder_probe.rs | 自有进程内验证本地 Binder 被拒绝，且没有描述符和事务调用 |

## Windows 构建依赖

继续使用 NDK r26d `26.3.11579264`、Rust 1.94.0 和 cargo-ndk 4.1.2。
Binder 的旧 bindgen 0.64 需要 **libclang 17**。Clang 18+ 的 AST 变化会使该版本漏掉 extern C 声明；不要把 Amice 的 LLVM 21 目录当作 Binder 的 libclang。

在独立仓库根目录安装到本地工具目录：

```powershell
python -m pip install --target build/bindgen/libclang17 --no-deps libclang==17.0.6
```

默认 DLL 为 `build/bindgen/libclang17/clang/native/libclang.dll`；将它所在目录传给 `LIBCLANG_PATH`。
下面的命令设置带连字符与下划线两种 bindgen 变量，避免 cargo-ndk 的参数覆盖优先级造成误用。
更换 libclang 或绑定参数后，应清理 `binder_ndk_sys` 的目标构建缓存再编译。

`binder_rs` 会生成一个空实现的 `libbinder_ndk.so` **链接占位库**。它只供链接，不得复制到设备或打包进 APK；运行使用系统的真实 `libbinder_ndk.so`。
本次使用的 Binder 导入均属于 Android 12 已有符号，其中服务管理等包含平台导出。没有使用 Android 13 才加入的 `AIBinder_DeathRecipient_setOnUnlinked`。

## 无 JNI 使用

库依赖可以只启用：

```toml
espframe = { path = "../espframe", default-features = false, features = ["xdl", "binder"] }
```

直接查询调用 `espframe::window::query_displays_native()`，返回 `Vec<DisplaySnapshot>`。
只启用 Binder 时，镜像后端的默认 Auto 仍检查实际对象，远程服务使用 Binder，本地服务报告 JNI 后端不可用。`jni` 和 `binder` 可以独立开关。

独立 ARM64 示例的构建命令（仓库根目录 PowerShell）：

```powershell
$env:ANDROID_NDK_HOME = "D:/Android/Sdk/ndk/26.3.11579264"
$env:LIBCLANG_PATH = (Resolve-Path "build/bindgen/libclang17/clang/native").Path
$toolchain = "$env:ANDROID_NDK_HOME/toolchains/llvm/prebuilt/windows-x86_64"
$bindgenArgs = "--target=aarch64-linux-android31 --sysroot=`"$toolchain/sysroot`" -nostdinc -isystem `"$toolchain/lib/clang/17/include`" -isystem `"$toolchain/sysroot/usr/include`" -isystem `"$toolchain/sysroot/usr/include/aarch64-linux-android`""
$env:BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android = $bindgenArgs
[Environment]::SetEnvironmentVariable("BINDGEN_EXTRA_CLANG_ARGS_aarch64-linux-android", $bindgenArgs, "Process")
cargo +1.94.0 ndk -t arm64-v8a -P 31 build --locked --no-default-features --features xdl,binder --example display_snapshot --release
```

输出为 `target/aarch64-linux-android/release/examples/display_snapshot`，可由具备权限的 Android shell 运行；不需要启动 JavaVM。

2026-09-07 在一台 Android 16/SDK 36 ARM64 设备上，以 shell 和 root 身份均读到 `id=0 stack=0 logical=1600x2560 rotation=Portrait`。
独立示例支持 `--uid-1000`：要求已取得 root，然后清空附加组、设置 real/effective/saved UID/GID 为 1000，校验身份和能力位后才获取 Binder 服务。
同日该参数实测成功，UID/GID 四列均为 1000，附加组为空，CapPrm/CapEff/CapAmb 均为 0，SELinux 为 `u:r:su:s0`，显示结果同上。
输出 `java_runtime_mapped=false` 表示进程映射中没有匹配 libart、libnativehelper 或 libandroid_runtime；该构建仅启用 `xdl,binder`，依赖树没有 JNI crate。
UID 1000 不决定本地/远程 Binder，也不等于 system_server 的 SELinux 域；本项验证独立进程中的远程读取。
自有 app_process 回归验证强制 Binder 两次拒绝本地对象，Auto 两次选择本地 JNI 回调，并在同一个有 VM 的进程内两次选择 Binder 读取真实远程 display 服务。本地对象的描述符与事务调用均为 0。
本地 JNI 回调验证的是自有对象身份，不是完整 DisplayManagerInternal 枚举或 host 绘制生命周期。测试步骤见 [设备回归说明](../../tests/android/README.md)。
上述独立 Binder 测试结果不代表 Android 12-15、其他 OEM 或镜像旋转/插拔已经完成对应测试；Android 15 显示 token 引用计数修复的实机反馈见前文。

## 验证与 Android 17 升级

```powershell
cargo +1.94.0 test --locked --features jni,binder --lib
cargo +1.94.0 test --locked --all-features
```

适配 Android 17 时，依次执行：

1. 对照该版本 AOSP `IDisplayManager.aidl`，核对 descriptor、事务顺序、getDisplayIds 参数和 getDisplayInfo 返回形式。
2. 逐项对照 `DisplayInfo.writeToParcel` 以及 DisplayAddress、DeviceProductInfo、DisplayCutout、Parcel.writeValue。即使只读取到 rotation，也必须确认前面所有可变长度字段。
3. 在 binder_display_codec.rs 新增明确布局组及实际格式 fixture；测试空对象、非空嵌套对象、截断、异常长度、未知类名与方向/尺寸。
4. 核对目标系统 libgui 的 mirrorSurface、setLayerStack、apply 符号及对应 C++ 参数/返回 ABI；使用精确类型调用，不只把上限 16 改成 17。
5. 用 llvm-readelf 检查示例与 payload 的未定义 Binder 符号，确认最低 Android 12 仍有这些 API。链接占位库不能作为设备支持的证据。
6. 构建 JNI+BINDER 和仅 BINDER 两种配置。在 Android 12、12L、13、14、15、16 做回归，在 17 验证真实 Binder 往返、显示器插拔、旋转与分辨率变化，并检查主屏不受镜像失败影响。
7. 验证通过后，再更新 mirror_binder.rs 的 SDK gate、codec 布局表、Surface ABI 计划和本 README 的矩阵。未确认的版本继续明确拒绝，不猜旧协议。

参考：[A12 IDisplayManager](https://android.googlesource.com/platform/frameworks/base/+/android-12.0.0_r1/core/java/android/hardware/display/IDisplayManager.aidl)、[A16 DisplayInfo](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/view/DisplayInfo.java)、[A12 Binder 导出表](https://android.googlesource.com/platform/frameworks/native/+/android-12.0.0_r1/libs/binder/ndk/libbinder_ndk.map.txt)。
