# SurfaceFlinger Skia 后端

生产 payload 注入 surfaceflinger，继续使用仓库当前固定 revision 的 dear-imgui-rs。hook、系统 Skia ABI、绘制、纹理和刷新逻辑均在 espframe；host 保留菜单、业务、输入及原有 BackendDevice 接口。

## 对接接口

SkiaBackend 保留原 AndroidBackend 的 new、initialize、begin_frame、render、present、upload_texture、delete_texture、shutdown 接口。host/backend/android.rs 只替换内部实现。SkiaWindowBackend 适配原 SurfaceComposerBackend 和 NativeWindowService 生命周期，其窗口指针是逻辑 viewport token，不能传给 ANativeWindow、EGL 或其他 Android 窗口 API。

UI workers snapshot the current imgui-rs DrawData. RenderEngine draws immediately before flushAndSubmit, using the live canvas of the submitted SkSurface. Recording canvases are never retained past endCapture. The frame/texture API and ownership remain unchanged.

## 安装与生命周期

The payload supervisor calls skia::initialize before UI/input startup: select Android API 31?37, resolve symbols, park SF/main and RenderEngine, then install hooks. Build ID and device name are not checked. Missing required symbols fail initialization.

quiescence.rs 在进程内选择一个尚无处理器的实时信号，等待注入器解除对 SF 主线程的 ptrace，再让 SF/main 和全部 RenderEngine 线程在各自 libc epoll/futex 等待指令处进入同步点。厂商多屏/线程池可有多个同名 RenderEngine；同步槽位支持最多 16 个工作线程，超限拒绝安装，不能只暂停其中一个。每次重试重新枚举线程，并在全部暂停后复核线程集合，发现变化则释放后重试。信号回调只使用无锁原子与系统调用，安装成功或失败都会唤醒已暂停的线程。两秒内无法同步会拒绝安装。超时后未送达的信号保持取消状态，收到确认前不复用该状态；处理器随 payload 常驻，避免迟到信号触发默认终止动作。不能替换这个已占用的信号处理器或卸载 payload。远程调用在遇到实时信号时转发给目标处理器，并保持原调用超时上限。

Android ARM64 信号上下文按 NDK 布局读取，保留完整的 128 字节信号掩码区域，mcontext 位于偏移 176、PC 位于偏移 440。当前 libc 0.2.186 的 Android ucontext_t 缺少这段填充，不能直接用于此回调；偏移由布局回归和 NDK 编译断言核对。

Composition scopes now use drawLayersInternal and the optional drawLayersFadeInternal. Entry records output geometry; returning from the original clears the thread-local scope even on an early return. Each scope can draw only once on a matching RenderEngine submission. tryCapture is optional and, where present, provides an additional destination-surface match; its recording canvas is never retained. initCanvas is no longer hooked. Without tryCapture, the inspected draw/fade bodies' destination submit is selected within that scope; this is not a guarantee for uninspected vendor control flow.

Output::beginFrame, Output::composeSurfaces, GL and Ganesh Vulkan flushAndSubmit remain hooked. Cache handling always uses composeSurfaces with an instruction-derived member offset; the exists hook and selection branch are removed. See [cache discovery](AUTO_LAYOUT.md). API 37 also hooks Graphite Vulkan submission. Binder 1008 requests client composition; 1010 preserves the previous HWC state for shutdown.

Shutdown clears frames and disables drawing. Skia resources are released in the next RenderEngine submission callback; hooks remain resident. Do not dlclose/unmap the payload. Frames older than 500 ms are discarded.

payload 自有线程入口通过 [threading.rs](../../threading.rs) 显式设置 SCHED_OTHER。逻辑、绘制/空闲绘制、UDP 和触摸/输入线程使用 nice=-4；supervisor、心跳、配置写回、物资刷新、DFCOL 加载、传感器看门狗使用 nice=0。共享组件设置失败会记录诊断并继续，supervisor 设置失败则终止启动。仅修改调用线程，不改 SF/main 或 RenderEngine；保留正常的帧率等待、socket/read 阻塞和条件变量等待。这不提供 wake lock 或禁止系统休眠，也不更改进程 cgroup。

入口设置后回读 policy、实时 priority 和 nice，值不匹配也按设置失败处理。开启 ESPFRAME_NATIVE_LOG 时，payload.thread.start 记录工作线程名称与 TID，payload.thread.scheduling.verified 记录该 TID 的实际调度值；这只证明入口时的状态，不证明运行期间不会阻塞或被重新调整。排查“后台暂停”需在故障发生时结合线程的 stat、sched、wchan、cgroup 和心跳授权状态：继承 FIFO/RR 后的实时限流、等待授权、等待目标帧变化、系统挂起与停止合成是不同原因，不能仅靠提高 nice 优先级判断或解决。

菜单改为双击屏幕左上角切换：复用原内核触摸输入，espframe/window/input/top_left.rs 识别手势，host 继续调用原 ToggleMenu。区域边长为屏幕短边的 8%，两次点击间隔小于 500 ms，长按和拖动不触发。无需依赖 system_server 音量键 hook，也不增加设备按键读取线程。

陀螺仪输出使用 [内核传感器控制器](../../sensor/README.md)；可选的 `gyro-watchdog` 属于上述 nice=0 的用户态服务线程，超时策略由调用方指定，内核配置本身不超时。

## Android compatibility

`ro.build.version.sdk` selects Android 15 / 16 / 17 (API 35 / 36 / 37).
No Build ID whitelist and no device-name matching. The shared submission path
uses symbol lookup rather than fixed drawing-end instruction offsets.

Matrix reset uses the common SkMatrix overload; paint color uses the floating-point overload. Data creation directly uses the shared PrivateNewWithCopy entry. Canvas scopes directly use empty-bounds saveBehind and public restore; no save/restoreToCount selection remains. Output::dirtyEntireOutput is preferred when available; the existing Android 15 layout fallback remains. Android 17 adds Graphite submission and needs 96-byte SkPaint storage.

The Android 15 dirty-output fallback now derives offsets from checked inline
instructions and constructs the rectangle from display bounds instead of
viewport. ImageInfo creation always uses checked MakeN32Premul, with texture
premultiplication at creation and the necessary destructor distinction.
See [bounds and ImageInfo revision](BOUNDS_INFO.md).
For API 35-37, DisplaySettings physical/clip offsets remain 24/40; the
orientation offset is derived from checked initCanvas instructions (136 in
the earlier samples, 208 in the NP06J sample). Unknown instruction forms
reject initialization. The original NP06J adaptation report (2026-10-24) is not bundled with this extraction; the local layout fixtures retain the instruction checks.
Physical outputs use decimal DisplayId classification rather than a fixed panel ID.
RegionSampling is excluded; the existing skip_screenshot option controls virtual outputs.

See [compatibility evidence](ROM_COMPATIBILITY.md). No extra Surface/Layer,
AndroidInject, second ImGui, or linked Skia library is introduced.

## 验证

cargo test -p espframe --lib render::skia 覆盖 capture 嵌套/失配/溢出、四方向投影，以及真实当前 imgui-rs 的文字、图片、裁剪、采样、超过 65535 顶点的偏移和纹理生命周期。另需 Android ARM64 编译、链接及 host 的管理/渲染生命周期回归。

本次迁移尚未注入实机验证；参考工程的实测不能替代本 payload 的信号同步安装、线程实际优先级、Binder 自进程刷新、输入旋转、连续绘制和停止恢复验证。主机回归额外覆盖取消与信号到达并发时不遗留暂停状态；这不能替代设备上的实际信号投递验证。

## First common-hook revision

This revision preserves host and imgui-rs interfaces and only targets API 35?37. The three supplied device samples resolve all required symbols statically. Official emulator 15/16/17 samples still lack 7/7/6 required symbols respectively (Canvas/paint/image lifetime and cache interfaces); they must not be described as supported by this revision. See EMULATOR_SYMBOL_AUDIT.md and build/skia-common-hooks/static-symbol-check.json. Existing scope test cases were adjusted to the new lifecycle; no tests were executed for this revision per the requested static-only workflow.

## Inline adapter revision

The user confirmed the preceding common-hook revision on their device. This revision keeps that composition path and adds fallbacks for inlined Canvas, Paint, ImageInfo, SkData and request-cache interfaces. All six official/device Android 15?17 samples pass static symbol and selected layout checks; no tests were run and no universal ROM compatibility is claimed. See [inline adapter evidence and limits](INLINE_ADAPTERS.md). That revision left Android 12?14 disabled; the current legacy adapter is documented below.

## Shared primitive simplification

Canvas save/restore, SkData creation and request-cache handling now use common paths across the six inspected Android 15-17 samples. The original save, restoreToCount, MakeWithCopy and RequestCache::exists symbol branches have been removed. Cache handling always hooks composeSurfaces, with its member offset discovered before installation. Other alternatives remain only where the common entry is missing in a sample or the object ABI differs. Oversized aligned storage does not replace field-offset and ownership validation when fields are accessed directly. See INLINE_ADAPTERS.md and AUTO_LAYOUT.md.

## Android 12?14 integration (current)

API 31/32/33/34 now select legacy adapters in `legacy.rs`; API 35?37 retain the existing submission path. See [legacy implementation and limits](LEGACY_ANDROID.md). The four official legacy samples and six existing modern samples pass static resolution and selected instruction checks. This does not establish runtime compatibility on untested ROMs.

## Partial-composition damage

An optional BufferDamage hook expands damage before the ROM records buffer-age
history, so moving overlay pixels are included in background redraw. See
[evidence and limits](PARTIAL_DAMAGE.md). It uses symbol capability detection
and libui Region methods without adding private member offsets.

## Minimal viewport query

SkiaWindowBackend uses `surface::PrimaryDisplayQuery`: enumerate physical
tokens, select the display carrying layer stack 0, and query only native
`ui::DisplayState` (layer stack, rotation and logical width/height). libgui
handles Binder transport; Skia does not decode Java DisplayInfo, display
addresses, product metadata or cutouts. The owned token is reused and
reacquired once after query failure or a primary-stack change. Queries run
on the viewport owner thread, never an SF/RenderEngine hook callback.

This reduces the private ABI surface; it does not make it a public stable
Android API. Existing Android 12-17 ELF samples export the three required
libgui entry points. The pandora API 37 device probe returns 1220x2656
without Java runtime loading. The original device review (2026-10-23) is not bundled with this extraction; this historical result does not establish compatibility on other devices.
