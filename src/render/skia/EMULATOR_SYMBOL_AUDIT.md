# Android 12–17 ARM64 SurfaceFlinger 符号核对

日期：2026-10-12。范围：7 个官方 ARM64 模拟器镜像（12、12L、13、14、15、16、17），以及已有 Android 15/16/17 三个真机样本，共 10 个样本。只做文件提取、符号与源码核对，没有启动模拟器、运行测试或修改 hook 实现。

## 提取结果

资料目录：`build/emulator-sf-analysis/`。每个版本保存 `files/`、`symbols/modules.json`、`symbols/all.txt`、解压后的 `.gnu_debugdata`、文件 SHA256 和来源信息。

| Android | API | 官方镜像 | 实现所在文件 | 当前代码情况 |
| --- | --- | --- | --- | --- |
| 12 | 31 | default ARM64 r03，本地已安装 | `/system/bin/surfaceflinger` | 版本入口未开放；不能复用当前完整链路 |
| 12L | 32 | default ARM64 r02 | 同上 | 版本入口未开放；与 12 同属旧接口系列 |
| 13 | 33 | default ARM64 r02 | 同上 | 版本入口未开放；仍使用旧 GL 类的 initCanvas |
| 14 | 34 | default ARM64 r04 | 同上 | 版本入口未开放；提交接口参数与 15+ 不同 |
| 15 | 35 | default ARM64 r02 | 同上 | 当前 28 个必需精确符号缺 8 个 |
| 16 | 36 | default ARM64 r02 | 同上 | 当前 29 个必需精确符号缺 11 个 |
| 17 | 37 | google_apis ARM64 37.0 r06 | 同上 | 当前 30 个必需精确符号缺 9 个 |

下载的 6 个压缩包均与官方 SDK 仓库的整包 SHA1 一致；12 使用本地已安装镜像，其文件另记录 SHA256。动态分区提取检查了 LP 元数据与表的校验和，提取文件检查 ELF64/AArch64。解析动态、普通及压缩调试符号后，用 LLVM nm 独立核对函数名，结果一致。

已有三个真机样本按各自版本分支核对，必需符号均齐全。**这不等于同版本所有厂商构建都兼容。** 官方模拟器样本已经展示了同版本不同构建的符号差异，现有代码在上述官方 15/16/17 样本上会遇到符号解析失败。

## 共同保留的候选

10 个样本的精确函数符号交集为 3,032 个。下列函数在所有样本中都有相同 mangled name；这里只证明符号及编码的参数类型一致，不证明返回 ABI、私有对象布局、调用时机或任意其他厂商版本一致。

| 函数 | 覆盖 | 适用方向和限制 |
| --- | --- | --- |
| `Output::beginFrame()` | 10/10 | 当前已使用，可作为输出帧状态入口；本身不提供 Canvas，也不一定处于实际 Skia 绘制线程。 |
| `Output::prepareFrame()`、`Output::present(CompositionRefreshArgs const&)` | 10/10 | 可跟踪输出生命周期；不能仅在回调返回后直接绘制，RenderEngine 可能异步运行。 |
| `Output::cacheClientCompositionRequests(uint32_t)` | 10/10 | 值得研究的缓存控制接口。AOSP 实现中参数 0 会清除 client-composition request cache；需要在正确线程操作并处理状态恢复。不是可直接替换的 exists 回调。 |
| `Output::setLayerCachingEnabled(bool)` | 10/10 | 管理 planner 的 layer cache，和上面的 request cache 是不同机制，不可混用。 |
| `SkCanvas::drawVertices(SkVertices const*, SkBlendMode, SkPaint const&)` | 10/10 | 适合继续承接当前 imgui-rs 顶点绘制。 |
| `SkVertices::MakeCopy(...)` | 10/10 | 顶点创建入口；对象释放和所有权仍需核对。 |
| `SkCanvas::clipRect(SkRect const&, SkClipOp, bool)` | 10/10 | 公共裁剪接口。 |
| `SkCanvas::setMatrix(SkMatrix const&)` | 10/10 | 比依赖 resetMatrix 或 SkM44 重载覆盖更广；SkMatrix 对象构造仍需正确处理。 |
| `SkCanvas::translate(float,float)`、`scale(float,float)`、`getBaseLayerSize() const` | 10/10 | 可复用的基本变换及尺寸接口。 |
| `SkPaint::setColor(SkRGBA4f<unpremul> const&, SkColorSpace*)` | 10/10 | 比 uint32 颜色重载覆盖更广；SkPaint 的构造/布局不能因此省略适配。 |
| `SkImageShader::Make(sk_sp<SkImage>, ..., bool)` | 10/10 | 纹理 shader 创建候选，需保留 sk_sp 参数及返回值所有权规则。 |

候选函数的精确符号、各样本是否存在和地址保存在 `cross-sample-matrix.csv`、`common-symbols.json`、各样本的 `symbols/modules.json`。

## 当前不稳定的依赖

| 依赖 | 观察到的差异 |
| --- | --- |
| `SkiaCapture::tryCapture(SkSurface*)` | 8/10 有独立符号；官方 16、17 无精确入口。名称出现在 lambda 符号中不代表函数本身可 hook。 |
| `SkiaCapture::endCapture()` | 7/10；官方 16、17 和真机 17 无独立入口。 |
| `initCanvas` | 官方 12/12L/13 属于 `SkiaGLRenderEngine`；14+ 属于 `SkiaRenderEngine`。两个入口合计覆盖 10/10，但仍需核对 DisplaySettings 布局。 |
| `flushAndSubmit` | 当前 `(SkiaGpuContext*, sk_sp<SkSurface>)` 签名覆盖所有 15+ 样本。官方 14 的 GL/Vk 版本只接收 `GrDirectContext*`，没有 surface 参数；12/13 无这组入口。 |
| `ClientCompositionRequestCache::exists` | 多个官方样本无独立符号，不能作为唯一缓存控制入口。 |
| Canvas `save` / `restoreToCount` / `getCanvas` | 部分构建无独立符号。`internalSave`、`internalRestore` 即使存在，也不能直接等价替换公共方法。 |
| Paint 默认构造、`setShader`、整数 `setColor` | 多个官方样本缺失；不能只调整 Android 版本分支。 |
| `SkData::MakeWithCopy` / `PrivateNewWithCopy` | 前者覆盖 3/10，后者覆盖 9/10；二者并集覆盖 10/10，可作为后续动态选择候选，仍需核对 ABI。 |
| `SkImageInfo::Make`、图片工厂及析构 | 重载、命名空间和独立符号保留情况不同；12–14 有 `SkImage::MakeRasterData`，15+ 有 `SkImages::RasterFromData`。 |

`tryOffscreenCapture` / `endOffscreenCapture` 虽然也是 10/10 共同符号，但处理的是离屏捕获，不能当成最终屏幕每帧提交点。参考 AOSP SkiaCapture 源码已保存到资料目录，不能为了追求共同名称而更换为语义不符的 hook。

## 后续适配方向

目前没有从这些符号中确认一组可直接覆盖 12–17、所有厂商的完整绘制 hook 链路。共同的绘制原语比较多，真正的缺口是最终输出识别、Canvas 获取、每帧提交时机、缓存和对象生命周期。

保留按 Android 版本选择 ABI 系列；在系列内按实际符号选择经过核对的接口组合，不检查 Build ID、不按设备名判断。优先使用以上共同保留的公共方法，减少依赖容易内联的小函数和固定 vtable/结构偏移。当前 Android 15 dirty-region 分支仍含固定私有偏移，不能因版本相同就推定其他 ROM 可用。

15+ 的 GL/Ganesh 提交签名在现有样本中较一致，适合继续研究；14 需要独立提交适配；12/13 需要另找旧绘制流程中的插入点。任何新候选都先确认最终输出和资源生命周期，再接入现有 espframe / imgui-rs 接口。

以上记录的是提取与调查阶段的结果。后续第一版共用 hook 已修改：drawLayersInternal/fade 合成范围、可选 tryCapture、共用 SkMatrix/浮点颜色、数据工厂动态选择。三个真机样本静态符号齐全；官方 15/16/17 仍缺 7/7/6 个必需符号，尚未完成其绘制资源适配。没有运行测试。

## 推荐实现结构（调用链复核后）

优先收敛 15–17：六个官方/真机样本均保留相同参数签名的 `SkiaRenderEngine::drawLayersInternal`，函数体约 10–36 KiB。这是比 capture 辅助函数更合适的合成范围入口候选。六份主函数及两份真机 fade 函数的反汇编保存在 `draw-entry-evidence.json` 所列路径；函数体较大只是降低被完整内联的可能，不是稳定 ABI 保证。

建议在此入口建立线程局部的合成上下文，原函数返回时无条件清理，提前退出也不能留下状态。记录 DisplaySettings、输出身份、RenderEngine，并只允许当前范围内匹配的最终 surface 在提交前绘制一次。`drawLayersFadeInternal` 在两个真机样本中存在，应作为已知可选入口处理，避免漏掉厂商分支。AOSP 16 的 gainmap 流程同样调用 flushAndSubmit，证明不能只 hook 提交然后无条件绘制。

目标结构：

1. 保持 host、Frame/Texture、imgui-rs 和 Scene 顶点转换接口不变。
2. 按版本选择 draw 入口和提交 ABI：12/12L、13、14、15+；17 增加 Graphite 后端。13 的 drawLayersInternal 返回结果类型不同，不能与 12 合并为同一函数签名。
3. 在 ABI 系列内解析经过确认的符号候选，生成一次性的能力表；不在每帧探测，不进行设备名或 Build ID 分流。
4. 共用 drawVertices / MakeCopy / clipRect 等绘制原语。矩阵优先使用覆盖更广的 SkMatrix 重载，颜色优先使用浮点重载。纹理工厂和 sk_sp 释放仍由适配层负责。
5. 用合成范围替代对 tryCapture 的强制依赖；最终 surface 身份与 Canvas 获取仍必须单独解决，不能保留 initCanvas 的录制画布到 endCapture 之后，也不能仅按尺寸认定目标 surface。
6. 缓存优先研究 Output 的高层控制接口，避免依赖 exists 是否被内联。必须保存/恢复原状态，不把 planner layer cache 与 request cache 当成同一机制。

还不能直接编码替换的部分：官方 15 的 getCanvas、多个版本的 save/restore、Paint 初始化/setShader 和 ImageInfo 生命周期。需核对可替代 API 的语义和对象布局；不能用 internalSave 顶替 save、用 reset 初始化未构造对象或复制其他 ROM 的字段偏移。12–14 的最终提交和 Canvas 生命周期也需要各自确认。因而推荐先完善 15–17 的共同链路，再接旧版本适配，不将未完成的版本标记为支持。

## 后续接口补齐记录

第二版已补齐官方 15/16/17 的 Canvas、Paint、ImageInfo、SkData 和合成缓存缺口。六份 15–17 样本的静态解析及所选布局检查均通过，详见 [INLINE_ADAPTERS.md](INLINE_ADAPTERS.md)。以上缺失数量保留为调查和第一版历史记录，不代表第二版结果。没有运行测试，12–14 仍未启用。
