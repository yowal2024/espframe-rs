# 直接访问字段核对（2026-10-13）

范围：已提取的官方 Android 15/16/17 ARM64 镜像，以及用户提供的三个对应版本设备库。核对当前 `abi.rs`、`scene.rs`、`hooks.rs` 的直接字段访问；不执行设备测试。

结论：在这六份样本及当前选择的分支中，没有发现此次核对涉及的字段偏移写错。确实存在不同布局，不能把所有差异视为尾部扩展。下表中的数值均为相对对象起点的**字节偏移**。

后续语义复核补充：Android 15 dirty-output 虽然访问了有效 viewport 字段，但系统内联整屏刷新实际使用显示 bounds，不能由 getDirtyRegion 的求交集逻辑推导刷新赋值来源。详见 [剩余项复核](REMAINING_REVIEW.md)。本表的字段地址核对不等于证明该替代逻辑与系统语义一致。

| 字段 | 官方 15/16/17 | 提供的 15 | 提供的 16 | 提供的 17 | 当前处理 |
| --- | --- | --- | --- | --- | --- |
| SkPaint shader | 8 | 8 | 8 | 8 | 官方缺失 setter 时转交一份引用到 +8；其他路径调用系统 setShader。 |
| SkPaint RGBA | 48 | 48 | 56 | 56 | 颜色均由系统 setColor 写入。 |
| SkPaint alpha | 60 | 60 | 68 | 68 | 仅经检查的紧凑构造分支直接写 +60。 |
| SkPaint width / miter | 64 / 68 | 64 / 68 | 72 / 76 | 72 / 76 | 紧凑分支写 miter=4；设备库调用系统构造函数。 |
| SkPaint flags | 72 | 72 | 80 | 80 | 紧凑分支初始化为 0；设备库由系统初始化。 |
| DisplaySettings physical / clip / orientation | 24 / 40 / 136 | 同左 | 同左 | 同左 | 与各自 initCanvas 的读取位置一致。 |
| SkVertices 引用计数 | 0 | 0 | 0 | 0 | Builder 初始化为 1；使用非虚引用计数。 |
| SkImage / SkShader 引用计数 | 8 | 8 | 8 | 8 | 系统工厂及释放分支佐证；最终释放调用 vtable +16。 |
| Output request-cache 指针 | 104（0x68） | 112（0x70） | 856（0x358） | 888（0x378） | 后续统一使用 composeSurfaces；从配置函数指令提取偏移，并交叉检查读取位置，详见 AUTO_LAYOUT.md。 |
| request-cache capacity | 0 | 0 | 0 | 0 | 工厂将 uint32 容量写在 cache+0。 |

## 大小与生命周期

- 紧凑 SkPaint 的构造/移动函数写入到 +75，含尾部对齐的存储为 80 字节；提供的 16/17 移动函数分别复制到 +87 / +95。当前预留 96 字节、16 字节对齐，后置 16 字节 canary，能容纳这几种已观察到的布局。空间足够不等于可以混用颜色和 flags 的偏移。
- SkImageInfo 的核心颜色信息在 +0，宽高在 +16/+20；官方及提供的 15 使用 24 字节布局。提供的 16/17 在 +24 有额外的受引用计数管理指针，总计 32 字节；其析构还会释放核心颜色信息。当前预留 32 字节、另加 canary，使用系统工厂/析构，不手工猜测这个额外字段的类型。空 colorspace 的 no-op 析构仅用于已确认分支。
- Sampling 当前占 24 字节：maxAniso +0，useCubic 字节 +4，B/C +8/+12，filter/mipmap +16/+20。六份 MakeSubset 均读取 +4/+8/+12，并复制前 24 字节的 sampling。当前用 u32 承载 useCubic 及其三字节填充，初始化为 0。
- SkMatrix 前 36 字节为九个 float，尾部 type mask 在 +36。六份 setMatrix 重载从矩阵 +0 至 +32 取值后构造内部矩阵；没有把 Canvas 私有字段复制到我们自己的对象中。
- 输出名称使用 libc++ string 的首字节短/长标记，长字符串 size/data 位于 +8/+16。DisplaySettings 的首个成员即名称，后面的矩形起于 +24；现有解析与已检查的复制/使用路径一致。
- 提供的 Android 15 dirty-output 分支仍需 vtable-0x258 的虚基类偏移、虚基 vtable+0xb0 的 editState、state+0xb0 的 dirty region、state+0x18 的 viewport。该样本的 beginFrame/getDirtyRegion 与代码一致；其他五份样本调用系统 dirtyEntireOutput，不使用这组偏移。

## 反汇编依据

完整新增证据：`build/emulator-sf-analysis/field-evidence.json` 记录函数名称、地址、长度；各样本 `field-evidence/` 保存 `paint_color`、`paint_shader`、`vertices_init`、`image_shader`、`info_make`、`info_drop`、`init_canvas`、`begin_frame`、`dirty_region` 等反汇编。`sampling_subset.asm` 补充采样参数读取证据。此前构造、移动、缓存配置反汇编仍在各样本 `abi-evidence/`。

关键核对点：

- 颜色写入：官方 15/16/17 为 0x4aff50 / 0x54fb48 / 0x5df84c，提供的 15/16/17 为 0x3e4210 / 0x60ec70 / 0x7d02d8；前四处基址递增 0x30，后两处递增 0x38。
- 设备 shader 写入：0x3e4ac8 / 0x60f694 / 0x7d0d60 均写 paint+8；被替换的旧 shader 在 refcount+8 减引用，最后调用 vtable+16。
- 设备缓存指针写入：0x2e201c / 0x49f3a0 / 0x5d148c 分别写 Output+0x70 / +0x358 / +0x378。
- 设备扩展 ImageInfo：0x524bf8 / 0x6236ec 从 +0x18 读取额外指针；工厂同时把该指针初始化为 null。

这是静态样本核对，不代表未知 ROM 的私有 ABI 稳定。本次仅记录核对结果，没有修改运行代码或生成新的 APK。
