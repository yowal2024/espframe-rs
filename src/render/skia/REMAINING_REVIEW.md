# auto-cache 实测后的剩余项复核

用户已确认 auto-cache 在所提供样本对应设备上正常。本次只分析剩余项，不修改运行代码，不生成 APK，不运行测试。DisplaySettings 按用户要求不改。

后续实施：用户确认开始修改后，整屏刷新语义及偏移识别、ImageInfo 统一创建已落实，详见 [BOUNDS_INFO.md](BOUNDS_INFO.md)。下文保留为修改前调查记录。

## 1. Android 15 整屏刷新：发现语义差异，优先修正

当前 `dirty_android15` 用 state+0x18 的矩形调用 Region::set。它来自 getDirtyRegion 的读取位置，但 getDirtyRegion 是求交集，不能据此确定 dirtyEntireOutput 的赋值来源。

在提供的 Android 15 二进制中，dirtyEntireOutput 虽没有独立符号，其实现内联在两个入口中：

- setLayerFilter：0x2e1898 从 state+0x64 读取宽高；0x2e189c 取 dirtyRegion+0xb0；0x2e18a4 构造 `{0,0,width,height}`；0x2e18a8 调 Region::set。
- setDisplaySize：0x2e17b0 至 0x2e17c0 同样使用 state+0x64 的宽高，而不是 state+0x18 的矩形。
- 官方 15/16/17 和提供的 16/17 的独立 dirtyEntireOutput 也使用显示边界。

因此原代码的地址确实指向有效字段，但源矩形语义与系统整屏刷新不一致。用户当前实测通过，不能据此宣称已经出现画面故障；差异可能在旋转、投影或裁剪配置中体现。

建议从上述内联实现识别虚基类调整、editState 槽位、dirtyRegion 偏移和 bounds 偏移，并与 beginFrame/getDirtyRegion 交叉检查。不要用同版本固定常量替代识别，也不要直接调用 setLayerFilter 触发刷新，因为它还会修改过滤状态。

## 2. Paint：保留已检查分支

六份样本都有移动构造和 reset，但默认构造/setShader 不完全一致。提供的 16/17 在 RGBA 之前插入字段，RGBA 起点由 +48 变为 +56，移动复制范围也不同。

reset 的语义是 `*this = SkPaint()`，包括对旧对象的赋值和资源释放，不是未构造存储的初始化入口。不能为了统一接口在零内存上直接调用 reset。

当前缺失接口的紧凑布局分支有完整指令检查；其余用 ROM 构造/析构，不存在本次确认的新故障。若进一步统一，应识别完整初始化布局和默认值，不能只识别 RGBA 偏移或增加分配大小。收益低于先修整屏刷新。

## 3. ImageInfo：创建入口可以进一步统一，析构仍需区分

`SkImageInfo::MakeN32Premul(int,int)` 六份样本全部存在。官方三份和提供的 15 是直接写字段；提供的 16/17 调 SkColorInfo 构造并把额外 +24 指针初始化为 null。

六份实现都生成 RGBA_8888（4）和 premul（2）。提供的 15 比官方紧凑函数多一个 BTI 前缀，所以不能原样套用当前精确指令数组。提供的 16/17 是完整工厂，须检查传参/返回及 ROM 析构，不能套用紧凑 no-op 析构。

可以统一创建入口，并把输入纹理统一转换成预乘 RGBA；代价是原先 straight-alpha 路径也会多一次像素转换，存在整数舍入差异。未知构建的 N32 通道顺序仍需确认，不能仅凭函数名称假设 RGBA。当前分支工作正常，此项属于简化而不是必修错误。

## 4. 缓存：存在可优化开销，但保留已实测策略

启用缓存的 Output 在每次 active compose 前会调用配置函数创建一个 56 字节空 cache 并释放旧 cache，然后临时移除指针，返回时恢复空 cache。配置为无缓存时不分配。

不能只保留原缓存、每帧 detach/restore：旧缓存记录可能仍声称某个缓冲区包含原始图层内容，而缓冲区已被 overlay 改写，后续复用会错误。当前清空策略避免该问题。

只清一次需要跟踪 Output/缓存生命周期、启停和地址复用，或读取并检查容器是否为空；两者都引入新的状态或私有布局。尚无性能测量证明这处分配是瓶颈，暂不改动 auto-cache 的已实测行为。

## 范围和证据

Android 12–14 仍是独立的旧提交接口适配工作，不应顺带开放版本开关。

新增反汇编保存于 `build/skia-remaining-review/`：六份 dirty、getDirtyRegion、beginFrame、N32、Paint move/reset；`evidence.json` 记录地址、大小与函数名。提供的 15 的内联整屏刷新证据另存为 `vendor-15-layer_filter.asm` 和 `vendor-15-display_size.asm`。原始 ELF 与符号仍在 `build/emulator-sf-analysis/`。
